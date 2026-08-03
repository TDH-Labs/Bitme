//! Builds an unsigned sweep PSBT moving a set of UTXOs from an OLD descriptor to a destination
//! address - the mechanism for replacing a lost/destroyed SATOCHIP, phone, or server without
//! the old device ever needing to work again.
//!
//! Scope is deliberately narrow: this only *builds* the unsigned PSBT. Signing still goes
//! through the normal channels - SATOCHIP/MOBILE sign with their own app, and the OLD wallet's
//! own `cosigner serve` still does the SERVER co-sign via its ordinary `/sign_psbt` endpoint,
//! subject to the same policy/hold/notify flow as any other spend (a RECOVERY-path sweep goes
//! through `evaluate_recovery_policy`, same as it would if the PSBT had been built any other
//! way). Broadcasting is left to the caller's own bitcoind/wallet tooling.
//!
//! UTXO discovery is the caller's responsibility (pass the outpoints explicitly) rather than an
//! automatic chain scan: `ChainSource` has only ever needed to answer "does this ONE outpoint
//! exist" (see `chain.rs`), and adding a full wallet-scan capability just for a rare, one-off
//! migration isn't worth the extra surface. `bitcoin-cli listunspent` (against a watch-only
//! import of the OLD descriptor) or any block explorer already does this.

use anyhow::{bail, Context, Result};
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::chain::ChainSource;
use crate::descriptor::{self, BuiltDescriptor, Chain};

/// Which spending path the sweep will actually be signed with. This determines the nSequence
/// value committed into the unsigned transaction - BIP68's relative locktime is read from
/// nSequence at the consensus level, so it must already be correct here, not patched in later
/// once whoever's signing decides which two keys they actually have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepPath {
    /// SATOCHIP + SERVER, no timelock needed - a proactive migration (e.g. rotating the SERVER
    /// or MOBILE key) where the SATOCHIP is fine and available.
    Hot,
    /// SATOCHIP + MOBILE, or MOBILE + SERVER, only valid once `old_timelock_blocks` deep - use
    /// this when the SATOCHIP is the device being replaced.
    Recovery,
}

#[derive(Debug)]
pub struct SweepPlan {
    pub psbt: Psbt,
    pub total_in: Amount,
    pub fee: Amount,
    pub destination_amount: Amount,
}

/// Builds an unsigned PSBT spending every one of `outpoints` (all must belong to `old_wallet`,
/// verified the same way `/inspect` verifies inputs - by re-deriving and matching scriptPubkeys,
/// never by trusting caller-supplied metadata) to a single `destination` output, fee subtracted
/// from that output (a full sweep has nothing left over to send change to).
#[allow(clippy::too_many_arguments)]
pub fn build_sweep_psbt(
    old_wallet: &BuiltDescriptor,
    chain: &dyn ChainSource,
    gap_limit: u32,
    outpoints: &[OutPoint],
    destination: &Address,
    path: SweepPath,
    old_timelock_blocks: u16,
    fee_rate_sat_per_vb: f64,
) -> Result<SweepPlan> {
    if outpoints.is_empty() {
        bail!("at least one UTXO is required");
    }
    if fee_rate_sat_per_vb <= 0.0 {
        bail!("fee rate must be positive");
    }

    let sequence = match path {
        SweepPath::Hot => Sequence::ENABLE_RBF_NO_LOCKTIME,
        SweepPath::Recovery => Sequence::from_height(old_timelock_blocks),
    };

    let mut total_in = Amount::ZERO;
    let mut tx_inputs = Vec::with_capacity(outpoints.len());
    let mut psbt_inputs = Vec::with_capacity(outpoints.len());

    for &outpoint in outpoints {
        let utxo = chain
            .get_utxo(outpoint)
            .with_context(|| format!("looking up {outpoint}"))?
            .with_context(|| format!("{outpoint} does not exist, or is already spent"))?;

        let owned = descriptor::find_owner(old_wallet, &utxo.txout.script_pubkey, gap_limit)
            .with_context(|| format!("checking whether {outpoint} belongs to the OLD descriptor"))?
            .with_context(|| {
                format!(
                    "{outpoint}'s scriptPubkey was not found within the OLD descriptor's gap \
                     limit ({gap_limit}) - wrong --old-config, or an unusually large unused gap"
                )
            })?;

        let desc = match owned.chain {
            Chain::External => &old_wallet.external,
            Chain::Internal => &old_wallet.internal,
        };
        let definite = descriptor::at_index(desc, owned.index)?;
        let witness_script = definite
            .explicit_script()
            .context("computing witness script")?;

        total_in += utxo.txout.value;
        tx_inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        });
        psbt_inputs.push(PsbtInput {
            witness_utxo: Some(utxo.txout),
            witness_script: Some(witness_script),
            ..Default::default()
        });
    }

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: tx_inputs,
        // Placeholder value - overwritten below once the fee is known. Weight estimation below
        // only depends on script/witness *sizes*, never on amounts, so building this once and
        // mutating the value in place afterwards is exact, not an approximation.
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: destination.script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).context("building PSBT skeleton")?;
    psbt.inputs = psbt_inputs;

    let our_witness_weight = old_wallet
        .external
        .max_weight_to_satisfy()
        .context("computing max satisfaction weight")?;
    let vsize = crate::inspect::estimate_weight(&psbt, our_witness_weight).to_vbytes_ceil();
    let fee = Amount::from_sat((vsize as f64 * fee_rate_sat_per_vb).ceil() as u64);

    if fee >= total_in {
        bail!(
            "estimated fee ({fee}) is >= total input value ({total_in}) - nothing left to sweep; \
             lower --fee-rate or add more UTXOs"
        );
    }
    let destination_amount = total_in - fee;
    psbt.unsigned_tx.output[0].value = destination_amount;

    Ok(SweepPlan {
        psbt,
        total_in,
        fee,
        destination_amount,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    use super::*;
    use crate::chain::mock::MockChainSource;
    use crate::chain::Utxo;
    use crate::config::WalletConfig;
    use crate::test_util::test_wallet_config;

    const GAP_LIMIT: u32 = 5;

    fn wallet_and_config(timelock: u16) -> (BuiltDescriptor, WalletConfig) {
        let cfg = test_wallet_config(timelock);
        let wallet = descriptor::build_descriptor(&cfg).unwrap();
        (wallet, cfg)
    }

    fn fake_outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout,
        }
    }

    /// Any validly-encoded destination address works here, since `build_sweep_psbt` never
    /// broadcasts - a far-away index of the wallet's own change chain is a convenient one,
    /// without needing to hand-construct an unrelated key/address from scratch.
    fn destination_address(wallet: &BuiltDescriptor) -> Address {
        descriptor::address_at(&wallet.internal, 999, crate::config::ChainNetwork::Signet).unwrap()
    }

    #[test]
    fn sweeps_a_single_hot_utxo_minus_the_fee() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let addr = descriptor::address_at(&wallet.external, 0, crate::config::ChainNetwork::Signet)
            .unwrap();
        let outpoint = fake_outpoint(0x01, 0);
        let chain = MockChainSource::new();
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(1_000_000),
                    script_pubkey: addr.script_pubkey(),
                },
                confirmations: 100,
            },
        );

        let dest = destination_address(&wallet);
        let plan = build_sweep_psbt(
            &wallet,
            &chain,
            GAP_LIMIT,
            &[outpoint],
            &dest,
            SweepPath::Hot,
            4320,
            10.0,
        )
        .unwrap();

        assert_eq!(plan.total_in, Amount::from_sat(1_000_000));
        assert!(plan.fee.to_sat() > 0, "fee should be nonzero at 10 sat/vb");
        assert_eq!(plan.destination_amount, plan.total_in - plan.fee);
        assert_eq!(plan.psbt.unsigned_tx.output.len(), 1);
        assert_eq!(
            plan.psbt.unsigned_tx.output[0].value,
            plan.destination_amount
        );
        assert_eq!(
            plan.psbt.unsigned_tx.input[0].sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
    }

    #[test]
    fn recovery_path_sets_the_old_timelock_as_sequence() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let addr = descriptor::address_at(&wallet.external, 0, crate::config::ChainNetwork::Signet)
            .unwrap();
        let outpoint = fake_outpoint(0x02, 0);
        let chain = MockChainSource::new();
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(500_000),
                    script_pubkey: addr.script_pubkey(),
                },
                confirmations: 100,
            },
        );

        let plan = build_sweep_psbt(
            &wallet,
            &chain,
            GAP_LIMIT,
            &[outpoint],
            &destination_address(&wallet),
            SweepPath::Recovery,
            4320,
            5.0,
        )
        .unwrap();

        assert_eq!(
            plan.psbt.unsigned_tx.input[0].sequence,
            Sequence::from_height(4320)
        );
    }

    #[test]
    fn sums_multiple_utxos_across_both_chains() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let recv0 =
            descriptor::address_at(&wallet.external, 0, crate::config::ChainNetwork::Signet)
                .unwrap();
        let change0 =
            descriptor::address_at(&wallet.internal, 0, crate::config::ChainNetwork::Signet)
                .unwrap();
        let op1 = fake_outpoint(0x03, 0);
        let op2 = fake_outpoint(0x04, 1);
        let chain = MockChainSource::new();
        chain.insert(
            op1,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(300_000),
                    script_pubkey: recv0.script_pubkey(),
                },
                confirmations: 10,
            },
        );
        chain.insert(
            op2,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(200_000),
                    script_pubkey: change0.script_pubkey(),
                },
                confirmations: 10,
            },
        );

        let plan = build_sweep_psbt(
            &wallet,
            &chain,
            GAP_LIMIT,
            &[op1, op2],
            &destination_address(&wallet),
            SweepPath::Hot,
            4320,
            1.0,
        )
        .unwrap();

        assert_eq!(plan.total_in, Amount::from_sat(500_000));
        assert_eq!(plan.psbt.unsigned_tx.input.len(), 2);
    }

    #[test]
    fn refuses_a_utxo_that_does_not_belong_to_the_descriptor() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let outpoint = fake_outpoint(0x05, 0);
        let chain = MockChainSource::new();
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: destination_address(&wallet).script_pubkey(),
                },
                confirmations: 1,
            },
        );

        let err = build_sweep_psbt(
            &wallet,
            &chain,
            GAP_LIMIT,
            &[outpoint],
            &destination_address(&wallet),
            SweepPath::Hot,
            4320,
            1.0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("gap limit"), "got: {err}");
    }

    #[test]
    fn refuses_a_nonexistent_utxo() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let outpoint = fake_outpoint(0x06, 0);
        let chain = MockChainSource::new();

        let err = build_sweep_psbt(
            &wallet,
            &chain,
            GAP_LIMIT,
            &[outpoint],
            &destination_address(&wallet),
            SweepPath::Hot,
            4320,
            1.0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not exist"), "got: {err}");
    }

    #[test]
    fn refuses_a_fee_that_would_eat_the_entire_sweep() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let addr = descriptor::address_at(&wallet.external, 0, crate::config::ChainNetwork::Signet)
            .unwrap();
        let outpoint = fake_outpoint(0x07, 0);
        let chain = MockChainSource::new();
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(100),
                    script_pubkey: addr.script_pubkey(),
                },
                confirmations: 1,
            },
        );

        let err = build_sweep_psbt(
            &wallet,
            &chain,
            GAP_LIMIT,
            &[outpoint],
            &destination_address(&wallet),
            SweepPath::Hot,
            4320,
            1_000_000.0,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("nothing left to sweep"),
            "got: {err}"
        );
    }

    #[test]
    fn refuses_an_empty_utxo_list() {
        let (wallet, _cfg) = wallet_and_config(4320);
        let err = build_sweep_psbt(
            &wallet,
            &MockChainSource::new(),
            GAP_LIMIT,
            &[],
            &destination_address(&wallet),
            SweepPath::Hot,
            4320,
            1.0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one UTXO"), "got: {err}");
    }
}
