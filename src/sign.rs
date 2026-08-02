//! Orchestrates `POST /sign_psbt`: gate on policy (checked atomically against the ledger so
//! concurrent requests can't race past a rolling limit), sign, and stop - this service never
//! finalizes or broadcasts anything itself.
//!
//! Deliberately does *not* call `inspect::inspect` itself: that does blocking bitcoind RPC
//! I/O, while this function does async SQLite I/O (`sqlx`) - mixing the two in one async fn
//! would either block the async runtime's worker thread on network I/O, or require awaiting
//! from inside a blocking task, neither of which is clean. The caller (the HTTP handler) runs
//! `inspect()` inside `spawn_blocking` first - exactly as `/inspect` already does - and passes
//! the resulting report in here.
//!
//! Ordering is deliberate: evaluating policy and recording the spend *before* attempting to
//! sign would let a failed signature still burn budget; recording *after* signing (and before
//! the ledger transaction commits) means a crash or error mid-signature leaves nothing
//! recorded, and returning only after `commit()` succeeds satisfies "record before returning."

use bitcoin::psbt::Psbt;
use thiserror::Error;

use crate::config::WalletConfig;
use crate::descriptor::BuiltDescriptor;
use crate::inspect::{InspectionReport, SpendingPath};
use crate::ledger::Ledger;
use crate::policy::{self, CompiledPolicy, PolicyDecision, PolicyViolation};
use crate::signing::{self, ServerSigningKey, SigningError};

#[derive(Debug, Error)]
pub enum SignPsbtError {
    #[error(
        "PSBT does not use the HOT spending path (SATOCHIP+SERVER, immediately) - this \
         service only ever countersigns that path"
    )]
    NotHotPath,
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error("policy denied this transaction")]
    Denied(Vec<PolicyViolation>),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerOutcome {
    /// A new ledger row was written for this transaction.
    Recorded,
    /// This exact transaction (by unsigned txid) was already recorded by an earlier call;
    /// re-signed and returned again without writing a second row or re-checking policy.
    AlreadyRecorded,
}

#[derive(Debug)]
pub struct SignPsbtResult {
    pub psbt: Psbt,
    pub report: InspectionReport,
    pub ledger: LedgerOutcome,
}

/// `report` must be the result of inspecting this exact `psbt` (see the module docs for why
/// that's the caller's job, not this function's). `now` (unix seconds) is threaded in
/// explicitly - the underlying steps are otherwise all deterministic given their inputs, and
/// tests need to control it.
#[allow(clippy::too_many_arguments)]
pub async fn sign_psbt(
    mut psbt: Psbt,
    report: InspectionReport,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    server_key: &ServerSigningKey,
    ledger: &Ledger,
    policy: &CompiledPolicy,
    now: i64,
) -> Result<SignPsbtResult, SignPsbtError> {
    if report.spending_path != SpendingPath::Hot {
        return Err(SignPsbtError::NotHotPath);
    }

    // Stable across however many parties have signed so far: segwit txids never depend on
    // witness data, so this is the same identifier regardless of signing order or retries.
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let spend_sat = policy::destination_total_sat(&report);
    let fee_sat = report.fee.to_sat();

    let mut ltx = ledger.begin().await?;

    if ltx.already_recorded(&txid).await? {
        // Nothing to write - roll back the (read-only) transaction and just re-sign. ECDSA
        // signing is deterministic, so this reproduces byte-identical signatures; it does not
        // re-evaluate policy, since this exact spend was already approved once.
        ltx.rollback().await?;
        signing::sign_hot_inputs(&mut psbt, wallet, cfg, server_key, &report.inputs)?;
        return Ok(SignPsbtResult {
            psbt,
            report,
            ledger: LedgerOutcome::AlreadyRecorded,
        });
    }

    let rolling = ltx.rolling_totals(now).await?;
    match policy::evaluate_policy(&report, &rolling, policy) {
        PolicyDecision::Deny(violations) => {
            ltx.rollback().await?;
            Err(SignPsbtError::Denied(violations))
        }
        PolicyDecision::Allow => {
            // If signing fails here, `ltx` is dropped by the `?` early return without a
            // commit - sqlx rolls back automatically, so nothing gets recorded for a spend
            // that was never actually signed.
            signing::sign_hot_inputs(&mut psbt, wallet, cfg, server_key, &report.inputs)?;
            ltx.record_spend(&txid, now, spend_sat, fee_sat).await?;
            ltx.commit().await?;
            Ok(SignPsbtResult {
                psbt,
                report,
                ledger: LedgerOutcome::Recorded,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Txid, Witness,
    };

    use super::*;
    use crate::chain::mock::MockChainSource;
    use crate::chain::{ChainSource, Utxo};
    use crate::config::{ChainNetwork, ServerSigningConfig};
    use crate::descriptor::{self, build_descriptor, Chain};
    use crate::inspect;
    use crate::policy::PolicyConfig;
    use crate::test_util::{test_server_xpriv, test_wallet_config};

    fn fake_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn foreign_script(fill: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x20];
        bytes.extend_from_slice(&[fill; 32]);
        ScriptBuf::from(bytes)
    }

    fn load_test_server_key(cfg: &WalletConfig, env_var: &str) -> ServerSigningKey {
        let xprv = test_server_xpriv();
        // SAFETY: test-only; each test uses a distinct env var name to avoid cross-test races.
        unsafe { std::env::set_var(env_var, xprv.to_string()) };
        let signing_cfg = ServerSigningConfig {
            xprv_file: None,
            xprv_env_var: Some(env_var.to_string()),
        };
        ServerSigningKey::load(&signing_cfg, &cfg.keys.server.xpub, cfg.network).unwrap()
    }

    fn policy_with_caps(
        network: ChainNetwork,
        max_tx_sat: u64,
        max_daily_sat: u64,
    ) -> CompiledPolicy {
        PolicyConfig {
            max_tx_sat,
            max_daily_sat,
            max_weekly_sat: u64::MAX,
            max_monthly_sat: u64::MAX,
            max_fee_sat: u64::MAX,
            max_fee_rate_sat_per_vb: f64::MAX,
            destination_whitelist: None,
        }
        .compile(network)
        .unwrap()
    }

    /// An unsigned HOT-path PSBT: spends `amount_sat` from our external chain at `index`
    /// (funded into `chain` first), sending `amount_sat - fee_sat` to a distinct foreign
    /// destination. `Sequence::ENABLE_RBF_NO_LOCKTIME` doesn't satisfy any relative timelock,
    /// so this classifies as HOT regardless of which (if any) signatures are attached - no
    /// need to fake a SATOCHIP signature just to exercise the policy/ledger orchestration.
    fn hot_psbt(
        chain: &MockChainSource,
        wallet: &BuiltDescriptor,
        txid_byte: u8,
        index: u32,
        amount_sat: u64,
        fee_sat: u64,
    ) -> Psbt {
        let script_pubkey = descriptor::at_index(&wallet.external, index)
            .unwrap()
            .script_pubkey();
        let outpoint = OutPoint::new(fake_txid(txid_byte), 0);
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(amount_sat),
                    script_pubkey: script_pubkey.clone(),
                },
                confirmations: 6,
            },
        );

        let dest = TxOut {
            value: Amount::from_sat(amount_sat - fee_sat),
            script_pubkey: foreign_script(txid_byte),
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![dest],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey,
        });
        psbt
    }

    #[tokio::test]
    async fn allows_and_records_a_spend_within_policy() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = MockChainSource::new();
        let server_key = load_test_server_key(&cfg, "COSIGNER_TEST_SIGN_ALLOW");
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let policy = policy_with_caps(cfg.network, u64::MAX, u64::MAX);

        let psbt = hot_psbt(&chain, &wallet, 1, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &wallet, &cfg, &chain, 50).unwrap();

        let result = sign_psbt(
            psbt,
            report,
            &wallet,
            &cfg,
            &server_key,
            &ledger,
            &policy,
            1_000_000,
        )
        .await
        .unwrap();
        assert_eq!(result.ledger, LedgerOutcome::Recorded);

        let role_keys = descriptor::role_keys_at(&wallet, &cfg, Chain::External, 0).unwrap();
        assert!(result.psbt.inputs[0]
            .partial_sigs
            .contains_key(&role_keys.server));

        let totals = ledger.rolling_totals(1_000_000).await.unwrap();
        assert_eq!(totals.day_sat, 99_000);
    }

    #[tokio::test]
    async fn denies_and_does_not_record_a_spend_over_the_cap() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = MockChainSource::new();
        let server_key = load_test_server_key(&cfg, "COSIGNER_TEST_SIGN_DENY");
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let policy = policy_with_caps(cfg.network, 50_000, u64::MAX);

        let psbt = hot_psbt(&chain, &wallet, 2, 0, 100_000, 1_000); // 99_000 sat destination, over the 50_000 cap
        let report = inspect::inspect(&psbt, &wallet, &cfg, &chain, 50).unwrap();

        let err = sign_psbt(
            psbt,
            report,
            &wallet,
            &cfg,
            &server_key,
            &ledger,
            &policy,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SignPsbtError::Denied(_)));

        let totals = ledger.rolling_totals(1_000_000).await.unwrap();
        assert_eq!(
            totals,
            crate::ledger::RollingTotals::default(),
            "a denied spend must not be recorded"
        );
    }

    #[tokio::test]
    async fn idempotent_replay_signs_again_without_double_recording() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = MockChainSource::new();
        let server_key = load_test_server_key(&cfg, "COSIGNER_TEST_SIGN_IDEMPOTENT");
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let policy = policy_with_caps(cfg.network, u64::MAX, u64::MAX);

        let build_and_inspect = || {
            let psbt = hot_psbt(&chain, &wallet, 3, 0, 100_000, 1_000);
            let report = inspect::inspect(&psbt, &wallet, &cfg, &chain, 50).unwrap();
            (psbt, report)
        };

        let (psbt_a, report_a) = build_and_inspect();
        let first = sign_psbt(
            psbt_a,
            report_a,
            &wallet,
            &cfg,
            &server_key,
            &ledger,
            &policy,
            1_000_000,
        )
        .await
        .unwrap();
        assert_eq!(first.ledger, LedgerOutcome::Recorded);

        let (psbt_b, report_b) = build_and_inspect();
        let second = sign_psbt(
            psbt_b,
            report_b,
            &wallet,
            &cfg,
            &server_key,
            &ledger,
            &policy,
            1_000_100,
        )
        .await
        .unwrap();
        assert_eq!(second.ledger, LedgerOutcome::AlreadyRecorded);

        let role_keys = descriptor::role_keys_at(&wallet, &cfg, Chain::External, 0).unwrap();
        assert_eq!(
            first.psbt.inputs[0].partial_sigs.get(&role_keys.server),
            second.psbt.inputs[0].partial_sigs.get(&role_keys.server),
            "replay must still return a valid (byte-identical) signature"
        );

        let totals = ledger.rolling_totals(1_000_100).await.unwrap();
        assert_eq!(totals.day_sat, 99_000, "must count once, not twice");
    }

    #[tokio::test]
    async fn rejects_a_non_hot_spending_path() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = MockChainSource::new();
        let server_key = load_test_server_key(&cfg, "COSIGNER_TEST_SIGN_NOT_HOT");
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let policy = policy_with_caps(cfg.network, u64::MAX, u64::MAX);

        // A sequence that satisfies the recovery timelock, with no signatures attached at all,
        // classifies as Ambiguous (see inspect.rs) - not Hot, so this must be refused.
        let script_pubkey = descriptor::at_index(&wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let outpoint = OutPoint::new(fake_txid(4), 0);
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: script_pubkey.clone(),
                },
                confirmations: 20_000,
            },
        );
        let dest = TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: foreign_script(4),
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(12960),
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![dest],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });

        let report = inspect::inspect(&psbt, &wallet, &cfg, &chain, 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Ambiguous);

        let err = sign_psbt(
            psbt,
            report,
            &wallet,
            &cfg,
            &server_key,
            &ledger,
            &policy,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SignPsbtError::NotHotPath));

        let totals = ledger.rolling_totals(1_000_000).await.unwrap();
        assert_eq!(totals, crate::ledger::RollingTotals::default());
    }

    /// The concurrency guarantee the M4 spec calls for: fire several genuinely concurrent
    /// (multi-threaded) `/sign_psbt`-equivalent calls for *distinct* transactions that
    /// individually fit the per-transaction cap but collectively would blow past a shared
    /// rolling daily cap, and confirm the cap is never exceeded no matter how they interleave.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_cannot_race_past_a_rolling_cap() {
        const SPEND_SAT: u64 = 100;
        const FEE_SAT: u64 = 1_000;
        const DAILY_CAP_SAT: u64 = 250; // fits exactly floor(250/100) = 2 spends of 100, never 3
        const N: u8 = 5;

        let cfg = Arc::new(test_wallet_config(12960));
        let wallet = Arc::new(build_descriptor(&cfg).unwrap());
        let chain = Arc::new(MockChainSource::new());
        let server_key = Arc::new(load_test_server_key(&cfg, "COSIGNER_TEST_SIGN_CONCURRENCY"));
        let ledger = Arc::new(Ledger::connect_in_memory().await.unwrap());
        let policy = Arc::new(policy_with_caps(cfg.network, u64::MAX, DAILY_CAP_SAT));

        let mut handles = Vec::new();
        for i in 0..N {
            let cfg = cfg.clone();
            let wallet = wallet.clone();
            let chain = chain.clone();
            let server_key = server_key.clone();
            let ledger = ledger.clone();
            let policy = policy.clone();
            handles.push(tokio::spawn(async move {
                let psbt = hot_psbt(
                    &chain,
                    &wallet,
                    100 + i,
                    i as u32,
                    SPEND_SAT + FEE_SAT,
                    FEE_SAT,
                );
                let report =
                    inspect::inspect(&psbt, &wallet, &cfg, chain.as_ref() as &dyn ChainSource, 50)
                        .unwrap();
                sign_psbt(
                    psbt,
                    report,
                    &wallet,
                    &cfg,
                    &server_key,
                    &ledger,
                    &policy,
                    1_000_000,
                )
                .await
            }));
        }

        let mut allowed = 0;
        let mut denied = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(result) => {
                    assert_eq!(result.ledger, LedgerOutcome::Recorded);
                    allowed += 1;
                }
                Err(SignPsbtError::Denied(_)) => denied += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert_eq!(
            allowed, 2,
            "exactly 2 spends of 100 sat fit under a 250 sat cap, regardless of arrival order"
        );
        assert_eq!(denied, 3);

        let totals = ledger.rolling_totals(1_000_000).await.unwrap();
        assert_eq!(
            totals.day_sat, 200,
            "the cap must never be exceeded and no write may be lost"
        );
    }
}
