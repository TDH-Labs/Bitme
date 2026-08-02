//! Parses an untrusted PSBT into the intent a human (or the M3 policy engine) needs to see:
//! what's being spent, where it's going, the fee, and which spending path it uses - trusting
//! nothing the PSBT claims about itself that we can independently re-derive or verify on chain.

use anyhow::anyhow;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Weight};
use miniscript::Satisfier;
use thiserror::Error;

use crate::chain::ChainSource;
use crate::config::WalletConfig;
use crate::descriptor::{self, BuiltDescriptor, Chain};

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("transaction is malformed: {0}")]
    InvalidTransaction(String),
    #[error("input {input_index} ({outpoint}) does not reference a known, unspent UTXO")]
    UnknownUtxo {
        input_index: usize,
        outpoint: OutPoint,
    },
    #[error("input {input_index} ({outpoint}) claims a different value/script than the chain has on record")]
    TamperedUtxo {
        input_index: usize,
        outpoint: OutPoint,
    },
    #[error("input {input_index} ({outpoint}) is not derived from the registered descriptor")]
    ForeignInput {
        input_index: usize,
        outpoint: OutPoint,
    },
    #[error("output {output_index} claims to be change (has bip32_derivation) but does not derive from our internal chain")]
    SpoofedChange { output_index: usize },
    #[error("failed querying chain state: {0}")]
    Chain(#[source] anyhow::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputKind {
    /// Verified (by independent derivation, not by trusting the PSBT) to be our internal
    /// chain: this is change coming back to the wallet.
    Change,
    /// Verified to be our external chain: unusual (paying yourself at a fresh receive
    /// address) but not a policy problem - reported distinctly from `Destination` so a human
    /// or the policy engine can decide what to make of it.
    OwnReceive,
    /// Not ours: this is where funds are actually leaving the wallet.
    Destination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendingPath {
    /// Every input is consistent only with SATOCHIP + SERVER signing immediately.
    Hot,
    /// Every input is consistent only with SATOCHIP + MOBILE signing after the timelock.
    Recovery,
    /// Inputs disagree, or at least one input's PSBT state (partial sigs + nSequence) so far
    /// doesn't yet rule out either path. Refuse to guess.
    Ambiguous,
}

#[derive(Debug, Clone)]
pub struct InputReport {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub confirmations: u32,
    pub chain: Chain,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct OutputReport {
    pub script_pubkey: ScriptBuf,
    pub address: Option<Address>,
    pub amount: Amount,
    pub kind: OutputKind,
}

#[derive(Debug, Clone)]
pub struct InspectionReport {
    pub inputs: Vec<InputReport>,
    pub outputs: Vec<OutputReport>,
    pub total_in: Amount,
    pub total_out: Amount,
    pub fee: Amount,
    pub estimated_vsize: u64,
    pub fee_rate_sat_per_vb: f64,
    pub spending_path: SpendingPath,
}

pub fn inspect(
    psbt: &Psbt,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    chain: &dyn ChainSource,
    gap_limit: u32,
) -> Result<InspectionReport, InspectError> {
    let tx = &psbt.unsigned_tx;
    if tx.input.is_empty() {
        return Err(InspectError::InvalidTransaction("no inputs".into()));
    }
    if tx.output.is_empty() {
        return Err(InspectError::InvalidTransaction("no outputs".into()));
    }

    let mut inputs = Vec::with_capacity(tx.input.len());
    let mut total_in = Amount::ZERO;
    let mut input_paths = Vec::with_capacity(tx.input.len());

    for (i, txin) in tx.input.iter().enumerate() {
        let outpoint = txin.previous_output;
        let utxo = chain
            .get_utxo(outpoint)
            .map_err(InspectError::Chain)?
            .ok_or(InspectError::UnknownUtxo {
                input_index: i,
                outpoint,
            })?;

        let psbt_input = &psbt.inputs[i];
        if let Some(claimed) = &psbt_input.witness_utxo {
            if claimed != &utxo.txout {
                return Err(InspectError::TamperedUtxo {
                    input_index: i,
                    outpoint,
                });
            }
        }
        if let Some(prev_tx) = &psbt_input.non_witness_utxo {
            if let Some(claimed) = prev_tx.output.get(outpoint.vout as usize) {
                if claimed != &utxo.txout {
                    return Err(InspectError::TamperedUtxo {
                        input_index: i,
                        outpoint,
                    });
                }
            }
        }

        let owned = descriptor::find_owner(wallet, &utxo.txout.script_pubkey, gap_limit)
            .map_err(InspectError::Chain)?
            .ok_or(InspectError::ForeignInput {
                input_index: i,
                outpoint,
            })?;

        let role_keys = descriptor::role_keys_at(wallet, cfg, owned.chain, owned.index)
            .map_err(InspectError::Chain)?;
        input_paths.push(classify_input_path(
            psbt_input,
            txin.sequence,
            &role_keys,
            cfg.timelock_blocks,
        ));

        total_in += utxo.txout.value;
        inputs.push(InputReport {
            outpoint,
            amount: utxo.txout.value,
            confirmations: utxo.confirmations,
            chain: owned.chain,
            index: owned.index,
        });
    }

    let mut outputs = Vec::with_capacity(tx.output.len());
    let mut total_out = Amount::ZERO;

    for (i, txout) in tx.output.iter().enumerate() {
        let owned = descriptor::find_owner(wallet, &txout.script_pubkey, gap_limit)
            .map_err(InspectError::Chain)?;
        let claims_change = !psbt.outputs[i].bip32_derivation.is_empty();

        let kind = match owned {
            Some(descriptor::Owned {
                chain: Chain::Internal,
                ..
            }) => OutputKind::Change,
            Some(descriptor::Owned {
                chain: Chain::External,
                ..
            }) => OutputKind::OwnReceive,
            None if claims_change => return Err(InspectError::SpoofedChange { output_index: i }),
            None => OutputKind::Destination,
        };

        let address =
            Address::from_script(&txout.script_pubkey, cfg.network.to_bitcoin_network()).ok();
        total_out += txout.value;
        outputs.push(OutputReport {
            script_pubkey: txout.script_pubkey.clone(),
            address,
            amount: txout.value,
            kind,
        });
    }

    if total_out >= total_in {
        return Err(InspectError::InvalidTransaction(format!(
            "outputs ({total_out}) must be strictly less than inputs ({total_in}); fee would be zero or negative"
        )));
    }
    let fee = total_in - total_out;

    let our_witness_weight = wallet
        .external
        .max_weight_to_satisfy()
        .map_err(|e| InspectError::Chain(anyhow!("computing max satisfaction weight: {e}")))?;
    let weight = estimate_weight(psbt, our_witness_weight);
    let vsize = weight.to_vbytes_ceil();
    let fee_rate_sat_per_vb = fee.to_sat() as f64 / vsize as f64;

    let spending_path = combine_paths(&input_paths);

    Ok(InspectionReport {
        inputs,
        outputs,
        total_in,
        total_out,
        fee,
        estimated_vsize: vsize,
        fee_rate_sat_per_vb,
        spending_path,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputPath {
    Hot,
    Recovery,
    Ambiguous,
}

fn classify_input_path(
    psbt_input: &bitcoin::psbt::Input,
    sequence: Sequence,
    role_keys: &descriptor::RoleKeys,
    timelock_blocks: u16,
) -> InputPath {
    let required = bitcoin::relative::LockTime::from_height(timelock_blocks);
    let older_satisfied = Satisfier::<bitcoin::PublicKey>::check_older(&sequence, required);

    if !older_satisfied {
        // The RECOVERY branch's `older(N)` check is a consensus-level constraint on this
        // input's nSequence: if it isn't met, no witness for that branch can ever be valid,
        // regardless of what gets signed. HOT has no such constraint.
        return InputPath::Hot;
    }

    if psbt_input.partial_sigs.contains_key(&role_keys.mobile) {
        InputPath::Recovery
    } else if psbt_input.partial_sigs.contains_key(&role_keys.server) {
        InputPath::Hot
    } else {
        InputPath::Ambiguous
    }
}

fn combine_paths(paths: &[InputPath]) -> SpendingPath {
    if paths.iter().all(|p| *p == InputPath::Hot) {
        SpendingPath::Hot
    } else if paths.iter().all(|p| *p == InputPath::Recovery) {
        SpendingPath::Recovery
    } else {
        SpendingPath::Ambiguous
    }
}

/// Estimates transaction weight per BIP141: `4 * base_size + witness_size`. For each of our
/// own inputs still missing a final witness, uses the descriptor's own worst-case witness
/// weight (`our_witness_weight`, in weight units) rather than guessing a byte count -
/// conservative, so a fee rate computed from this estimate is never overstated.
fn estimate_weight(psbt: &Psbt, our_witness_weight: Weight) -> Weight {
    let tx = &psbt.unsigned_tx;

    let mut base: u64 = 4 // version
        + 4 // locktime
        + bitcoin::VarInt(tx.input.len() as u64).size() as u64
        + bitcoin::VarInt(tx.output.len() as u64).size() as u64;
    for txin in &tx.input {
        base += 36 /* outpoint */ + 4 /* sequence */;
        base += bitcoin::VarInt(txin.script_sig.len() as u64).size() as u64
            + txin.script_sig.len() as u64;
    }
    for txout in &tx.output {
        base += 8;
        base += bitcoin::VarInt(txout.script_pubkey.len() as u64).size() as u64
            + txout.script_pubkey.len() as u64;
    }

    let mut witness: u64 = 2; // segwit marker + flag
    for input in &psbt.inputs {
        witness += match &input.final_script_witness {
            Some(w) => w.size() as u64,
            None => our_witness_weight.to_wu(),
        };
    }

    Weight::from_wu(base * 4 + witness)
}

impl InspectError {
    /// A stable string discriminant, for HTTP status mapping and structured logging.
    pub fn code(&self) -> &'static str {
        match self {
            InspectError::InvalidTransaction(_) => "invalid_transaction",
            InspectError::UnknownUtxo { .. } => "unknown_utxo",
            InspectError::TamperedUtxo { .. } => "tampered_utxo",
            InspectError::ForeignInput { .. } => "foreign_input",
            InspectError::SpoofedChange { .. } => "spoofed_change",
            InspectError::Chain(_) => "chain_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::bip32::{DerivationPath, Fingerprint, KeySource};
    use bitcoin::hashes::Hash;
    use bitcoin::{absolute, transaction, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};

    use super::*;
    use crate::chain::mock::MockChainSource;
    use crate::chain::Utxo;
    use crate::descriptor::{at_index, build_descriptor, role_keys_at};
    use crate::test_util::{test_signature, test_signer, test_wallet_config};

    fn fake_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    fn txin(outpoint: OutPoint, sequence: Sequence) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }
    }

    fn foreign_script() -> ScriptBuf {
        // A well-formed (but not ours) P2WSH scriptPubkey: OP_0 <32-byte hash>.
        let mut bytes = vec![0x00, 0x20];
        bytes.extend_from_slice(&[0xAB; 32]);
        ScriptBuf::from(bytes)
    }

    fn any_sig() -> bitcoin::ecdsa::Signature {
        test_signature(&test_signer(0x77).secret)
    }

    fn dummy_key_source() -> KeySource {
        (Fingerprint::from([0u8; 4]), DerivationPath::master())
    }

    struct Fixture {
        cfg: WalletConfig,
        wallet: BuiltDescriptor,
        chain: MockChainSource,
    }

    fn fixture(timelock_blocks: u16) -> Fixture {
        let cfg = test_wallet_config(timelock_blocks);
        let wallet = build_descriptor(&cfg).unwrap();
        Fixture {
            cfg,
            wallet,
            chain: MockChainSource::new(),
        }
    }

    impl Fixture {
        /// Registers a UTXO of `our` descriptor at (chain, index) worth `amount_sat`, and
        /// returns its outpoint plus the txout as bitcoind would report it.
        fn own_utxo(
            &self,
            chain: Chain,
            index: u32,
            outpoint: OutPoint,
            amount_sat: u64,
            confirmations: u32,
        ) -> TxOut {
            let desc = match chain {
                Chain::External => &self.wallet.external,
                Chain::Internal => &self.wallet.internal,
            };
            let script_pubkey = at_index(desc, index).unwrap().script_pubkey();
            let txout = TxOut {
                value: Amount::from_sat(amount_sat),
                script_pubkey,
            };
            self.chain.insert(
                outpoint,
                Utxo {
                    txout: txout.clone(),
                    confirmations,
                },
            );
            txout
        }
    }

    #[test]
    fn accepts_and_classifies_hot_path() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(1), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);

        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let role_keys = role_keys_at(&f.wallet, &f.cfg, Chain::External, 0).unwrap();
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.satochip, any_sig());

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.inputs.len(), 1);
        assert_eq!(report.inputs[0].chain, Chain::External);
        assert_eq!(report.inputs[0].index, 0);
        assert_eq!(report.total_in, Amount::from_sat(100_000));
        assert_eq!(report.total_out, Amount::from_sat(90_000));
        assert_eq!(report.fee, Amount::from_sat(10_000));
        assert!(report.fee_rate_sat_per_vb > 0.0);
        assert_eq!(report.spending_path, SpendingPath::Hot);
        assert_eq!(report.outputs[0].kind, OutputKind::Destination);
    }

    #[test]
    fn hot_path_is_recognized_by_server_signature_even_when_sequence_would_allow_recovery() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(2), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };

        // Sequence satisfies older(N) - by itself ambiguous - but SERVER has signed, which
        // only appears in the HOT branch, so this must resolve to Hot regardless of sequence.
        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::from_height(12960))],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let role_keys = role_keys_at(&f.wallet, &f.cfg, Chain::External, 0).unwrap();
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.satochip, any_sig());
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.server, any_sig());

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Hot);
    }

    #[test]
    fn accepts_and_classifies_recovery_path() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(3), 0);
        let our_txout = f.own_utxo(Chain::External, 2, outpoint, 100_000, 20_000);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };

        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::from_height(12960))],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let role_keys = role_keys_at(&f.wallet, &f.cfg, Chain::External, 2).unwrap();
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.satochip, any_sig());
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.mobile, any_sig());

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Recovery);
    }

    #[test]
    fn insufficient_sequence_is_hot_even_with_a_mobile_signature() {
        // One block short of the timelock: the RECOVERY witness is consensus-invalid no
        // matter what's signed, so this can only ever be HOT.
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(4), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };

        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::from_height(12959))],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let role_keys = role_keys_at(&f.wallet, &f.cfg, Chain::External, 0).unwrap();
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.satochip, any_sig());
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.mobile, any_sig());

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Hot);
    }

    #[test]
    fn ambiguous_when_only_satochip_has_signed_and_sequence_allows_either_path() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(5), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };

        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::from_height(12960))],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let role_keys = role_keys_at(&f.wallet, &f.cfg, Chain::External, 0).unwrap();
        psbt.inputs[0]
            .partial_sigs
            .insert(role_keys.satochip, any_sig());

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Ambiguous);
    }

    #[test]
    fn rejects_input_not_derived_from_our_descriptor() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(6), 0);
        f.chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: foreign_script(),
                },
                confirmations: 6,
            },
        );
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };
        let psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest],
        ))
        .unwrap();

        let err = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap_err();
        assert_eq!(err.code(), "foreign_input");
    }

    #[test]
    fn rejects_input_whose_utxo_is_unknown_to_the_chain() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(7), 0); // never inserted into the mock chain
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };
        let psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest],
        ))
        .unwrap();

        let err = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap_err();
        assert_eq!(err.code(), "unknown_utxo");
    }

    #[test]
    fn rejects_a_witness_utxo_that_disagrees_with_the_chain() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(8), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest],
        ))
        .unwrap();

        // The PSBT lies about the amount: chain says 100_000, PSBT claims 1_000_000.
        let mut lied = our_txout;
        lied.value = Amount::from_sat(1_000_000);
        psbt.inputs[0].witness_utxo = Some(lied);

        let err = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap_err();
        assert_eq!(err.code(), "tampered_utxo");
    }

    #[test]
    fn recognizes_change_by_derivation_not_by_trusting_bip32_derivation() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(9), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);

        let change_script = at_index(&f.wallet.internal, 4).unwrap().script_pubkey();
        let change = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: change_script,
        };
        let dest = TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: foreign_script(),
        };

        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest, change],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);
        // Deliberately no bip32_derivation on the change output - it must still be recognized
        // as change purely by independently re-deriving it, per the M2 spec.

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.outputs[0].kind, OutputKind::Destination);
        assert_eq!(report.outputs[1].kind, OutputKind::Change);
        assert_eq!(report.fee, Amount::from_sat(10_000));
    }

    #[test]
    fn recognizes_paying_your_own_receive_chain_distinctly_from_change() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(10), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);

        let own_receive = at_index(&f.wallet.external, 9).unwrap().script_pubkey();
        let out = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: own_receive,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![out],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap();
        assert_eq!(report.outputs[0].kind, OutputKind::OwnReceive);
    }

    #[test]
    fn rejects_an_output_that_claims_to_be_change_but_is_not_ours() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(11), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let spoofed = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };

        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![spoofed],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);
        // Attacker-controlled output, dressed up with change-looking metadata.
        psbt.outputs[0].bip32_derivation.insert(
            role_keys_at(&f.wallet, &f.cfg, Chain::External, 0)
                .unwrap()
                .satochip
                .inner,
            dummy_key_source(),
        );

        let err = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap_err();
        assert_eq!(err.code(), "spoofed_change");
    }

    #[test]
    fn rejects_zero_or_negative_fee() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(12), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: foreign_script(),
        };

        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let err = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 50).unwrap_err();
        assert_eq!(err.code(), "invalid_transaction");
    }

    #[test]
    fn respects_gap_limit_when_searching_for_ownership() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(13), 0);
        // Index 40 is beyond a gap limit of 10.
        let our_txout = f.own_utxo(Chain::External, 40, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest],
        ))
        .unwrap();
        psbt.inputs[0].witness_utxo = Some(our_txout);

        let err = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 10).unwrap_err();
        assert_eq!(err.code(), "foreign_input");

        let report = inspect(&psbt, &f.wallet, &f.cfg, &f.chain, 41).unwrap();
        assert_eq!(report.inputs[0].index, 40);
    }

    #[test]
    fn uses_actual_size_for_finalized_inputs_instead_of_the_worst_case_estimate() {
        let f = fixture(12960);
        let outpoint = OutPoint::new(fake_txid(14), 0);
        let our_txout = f.own_utxo(Chain::External, 0, outpoint, 100_000, 6);
        let dest = TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: foreign_script(),
        };

        let unsigned_tx = tx(
            vec![txin(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![dest.clone()],
        );
        let mut unsigned = Psbt::from_unsigned_tx(unsigned_tx.clone()).unwrap();
        unsigned.inputs[0].witness_utxo = Some(our_txout.clone());
        let unsigned_report = inspect(&unsigned, &f.wallet, &f.cfg, &f.chain, 50).unwrap();

        // A tiny finalized witness (smaller than our worst-case estimate) should produce a
        // smaller estimated vsize, proving the actual size is used once finalized.
        let mut finalized = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        finalized.inputs[0].witness_utxo = Some(our_txout);
        finalized.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![0u8; 1]]));
        let finalized_report = inspect(&finalized, &f.wallet, &f.cfg, &f.chain, 50).unwrap();

        assert!(finalized_report.estimated_vsize < unsigned_report.estimated_vsize);
    }
}
