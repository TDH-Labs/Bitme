//! Orchestrates `/sign_psbt`'s notify-then-hold-then-sign flow. Nothing here ever signs a
//! brand-new spend on the spot: [`submit_for_signing`] fast-checks policy, queues the spend in
//! the ledger's `pending_signatures` table, and sends an out-of-band notification; only the
//! background sweeper, via [`process_due_pending_row`] once the hold has elapsed, actually
//! signs and records it - unless a human calls `POST /veto/{id}` first. This service still
//! never finalizes or broadcasts anything itself.
//!
//! Deliberately does *not* call `inspect::inspect` itself for a fresh submission: that does
//! blocking bitcoind RPC I/O, while this module does async SQLite I/O (`sqlx`) - mixing the
//! two in one async fn would either block the async runtime's worker thread on network I/O, or
//! require awaiting from inside a blocking task, neither of which is clean. The HTTP handler
//! runs `inspect()` inside `spawn_blocking` first - exactly as `/inspect` already does - and
//! passes the resulting report in here. [`process_due_pending_row`], which re-inspects a
//! *stored* PSBT at fire time (chain state may have moved since submission), does its own
//! `spawn_blocking` internally, since the sweeper has no other caller to do it for it.
//!
//! [`decide_and_sign`] is the one piece of authoritative policy-then-sign logic, shared by
//! three callers that must each run it inside exactly one already-open ledger transaction:
//! the immediate idempotent-replay fast path (in both [`sign_psbt`] and
//! [`submit_for_signing`]), and fire-time processing (in [`process_due_pending_row`]). It's a
//! deliberate constraint, not a style choice: this ledger's pool is capped at one connection
//! (see `ledger.rs`), so opening a *second* transaction from inside a task that's still
//! holding one open would deadlock forever waiting for a connection that can't free up.
//!
//! Ordering is deliberate throughout: evaluating policy and recording the spend *before*
//! attempting to sign would let a failed signature still burn budget; recording *after*
//! signing (and before the ledger transaction commits) means a crash or error mid-signature
//! leaves nothing recorded, and returning only after `commit()` succeeds satisfies "record
//! before returning."

use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoin::psbt::Psbt;
use thiserror::Error;

use crate::chain::ChainSource;
use crate::config::{RecoveryConfig, WalletConfig};
use crate::descriptor::BuiltDescriptor;
use crate::inspect::{self, InspectError, InspectionReport, OutputKind, SpendingPath};
use crate::ledger::{Ledger, LedgerTx, PendingStatus};
use crate::notify::{Notifier, PendingNotice};
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

#[derive(Debug)]
enum DecideOutcome {
    Recorded(Psbt),
    AlreadyRecorded(Psbt),
    Denied(Vec<PolicyViolation>),
}

/// The one piece of authoritative "is this still allowed, and if so sign it" logic - see the
/// module doc for why every caller must supply an already-open `ltx` rather than opening its
/// own. Stable across however many parties have signed so far: segwit txids never depend on
/// witness data, so `txid` is the same identifier regardless of signing order or retries.
#[allow(clippy::too_many_arguments)]
async fn decide_and_sign(
    ltx: &mut LedgerTx,
    mut psbt: Psbt,
    report: &InspectionReport,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    server_key: &ServerSigningKey,
    policy: &CompiledPolicy,
    recovery_whitelist: Option<&[bitcoin::Address]>,
    now: i64,
) -> Result<DecideOutcome, SignPsbtError> {
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let spend_sat = policy::destination_total_sat(report);
    let fee_sat = report.fee.to_sat();

    if ltx.already_recorded(&txid).await? {
        // ECDSA signing is deterministic, so re-signing an already-recorded spend reproduces
        // a byte-identical signature; it does not re-evaluate policy, since this exact spend
        // was already approved once.
        signing::sign_hot_inputs(&mut psbt, wallet, cfg, server_key, &report.inputs)?;
        return Ok(DecideOutcome::AlreadyRecorded(psbt));
    }

    // Which rules apply depends on which path this is. A recovery spend is a whole-balance
    // sweep by nature, so the ordinary caps would deny exactly the thing the path exists for -
    // see `policy::evaluate_recovery_policy`.
    let decision = match report.spending_path {
        SpendingPath::Recovery => policy::evaluate_recovery_policy(report, recovery_whitelist),
        _ => {
            let rolling = ltx.rolling_totals(now).await?;
            policy::evaluate_policy(report, &rolling, policy)
        }
    };

    match decision {
        PolicyDecision::Deny(violations) => Ok(DecideOutcome::Denied(violations)),
        PolicyDecision::Allow => {
            signing::sign_hot_inputs(&mut psbt, wallet, cfg, server_key, &report.inputs)?;
            // Recovery spends are recorded too. They don't consume the rolling budget in any
            // meaningful sense (the caps don't gate them), but the ledger is the audit trail
            // of every signature this service has ever produced, and a recovery signature is
            // the one you'd most want a record of.
            ltx.record_spend(&txid, now, spend_sat, fee_sat).await?;
            Ok(DecideOutcome::Recorded(psbt))
        }
    }
}

/// `report` must be the result of inspecting this exact `psbt` (see the module docs for why
/// that's the caller's job, not this function's). `now` (unix seconds) is threaded in
/// explicitly - the underlying steps are otherwise all deterministic given their inputs, and
/// tests need to control it.
///
/// Only ever reaches a `Recorded` outcome via the idempotent-replay path: a *new* approved
/// spend is never signed here - see [`submit_for_signing`], which queues it instead.
#[allow(clippy::too_many_arguments)]
pub async fn sign_psbt(
    psbt: Psbt,
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

    let mut ltx = ledger.begin().await?;
    match decide_and_sign(
        &mut ltx, psbt, &report, wallet, cfg, server_key, policy, None, now,
    )
    .await?
    {
        DecideOutcome::AlreadyRecorded(psbt) => {
            ltx.rollback().await?;
            Ok(SignPsbtResult {
                psbt,
                report,
                ledger: LedgerOutcome::AlreadyRecorded,
            })
        }
        DecideOutcome::Recorded(psbt) => {
            ltx.commit().await?;
            Ok(SignPsbtResult {
                psbt,
                report,
                ledger: LedgerOutcome::Recorded,
            })
        }
        DecideOutcome::Denied(violations) => {
            ltx.rollback().await?;
            Err(SignPsbtError::Denied(violations))
        }
    }
}

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error(
        "PSBT does not use a spending path this service co-signs. It signs SATOCHIP+SERVER, \
         and (unless disabled) MOBILE+SERVER recovery spends; it cannot help with \
         SATOCHIP+MOBILE, which doesn't need it"
    )]
    NotHotPath,
    #[error(
        "this is a MOBILE+SERVER recovery spend, but recovery co-signing is disabled \
         ([recovery] enabled = false)"
    )]
    RecoveryDisabled,
    #[error("signing is frozen: {0}")]
    Frozen(String),
    #[error("policy denied this transaction")]
    Denied(Vec<PolicyViolation>),
    #[error("this exact transaction was already vetoed - resubmit a materially different PSBT to try again")]
    Vetoed,
    #[error("this exact transaction was already denied when its hold elapsed: {0}")]
    PreviouslyDenied(String),
    #[error("this exact transaction previously failed to sign: {0}")]
    PreviouslyFailed(String),
    #[error("failed to deliver the out-of-band notification - refusing to queue this spend: {0}")]
    NotifyFailed(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug)]
pub enum SubmitOutcome {
    /// This exact transaction was already fully processed by an earlier submission - signed
    /// immediately, just like the pre-M5 idempotent replay. No new hold, no new notification.
    AlreadySigned(Box<SignPsbtResult>),
    /// Newly queued (or an idempotent re-submission of one already queued and still pending).
    Queued { txid: String, hold_until: i64 },
}

/// The entry point for a spend this service has not seen before: fast-checks policy against
/// the ledger as it stands right now (so an obviously-over-cap spend is refused immediately,
/// without notifying anyone or starting a hold), then queues it and notifies. The fast check
/// is *not* authoritative - [`process_due_pending_row`] re-evaluates policy again at fire time,
/// since other spends may consume the same rolling budget while this one is held.
#[allow(clippy::too_many_arguments)]
pub async fn submit_for_signing(
    psbt: Psbt,
    report: InspectionReport,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    server_key: &ServerSigningKey,
    ledger: &Ledger,
    policy: &CompiledPolicy,
    recovery: &RecoveryConfig,
    notifier: &dyn Notifier,
    hold_seconds: i64,
    now: i64,
) -> Result<SubmitOutcome, SubmitError> {
    // Freeze is checked first and unconditionally: it's the "something is wrong, stop
    // everything" control, so it must not be reachable-around by any path below.
    if ledger.is_frozen().await? {
        return Err(SubmitError::Frozen(
            "co-signing is frozen; unfreeze with a SATOCHIP-signed POST /unfreeze or the \
             `cosigner unfreeze` CLI"
                .to_string(),
        ));
    }

    let is_recovery = match report.spending_path {
        SpendingPath::Hot => false,
        SpendingPath::Recovery if recovery.enabled => true,
        SpendingPath::Recovery => return Err(SubmitError::RecoveryDisabled),
        SpendingPath::Ambiguous => return Err(SubmitError::NotHotPath),
    };
    // A recovery spend waits far longer than a normal one - for a UTXO already older than the
    // script timelock, this hold is the *only* thing standing between a stolen phone and the
    // coins, so it is the primary control rather than a backstop.
    let hold_seconds = if is_recovery {
        recovery.hold_seconds
    } else {
        hold_seconds
    };
    let recovery_whitelist = recovery
        .compiled_whitelist(cfg.network)
        .map_err(SubmitError::Internal)?;
    let recovery_whitelist = recovery_whitelist.as_deref();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let mut ltx = ledger.begin().await?;

    if ltx.already_recorded(&txid).await? {
        let outcome = decide_and_sign(
            &mut ltx,
            psbt,
            &report,
            wallet,
            cfg,
            server_key,
            policy,
            recovery_whitelist,
            now,
        )
        .await
        .map_err(|e| SubmitError::Internal(anyhow::anyhow!(e)))?;
        ltx.rollback().await?;
        let DecideOutcome::AlreadyRecorded(signed) = outcome else {
            return Err(SubmitError::Internal(anyhow::anyhow!(
                "already_recorded=true but decide_and_sign returned {outcome:?}"
            )));
        };
        return Ok(SubmitOutcome::AlreadySigned(Box::new(SignPsbtResult {
            psbt: signed,
            report,
            ledger: LedgerOutcome::AlreadyRecorded,
        })));
    }

    if let Some(row) = ltx.get_pending(&txid).await? {
        ltx.rollback().await?;
        return match row.status {
            PendingStatus::Pending => Ok(SubmitOutcome::Queued {
                txid,
                hold_until: row.hold_until,
            }),
            PendingStatus::Vetoed => Err(SubmitError::Vetoed),
            PendingStatus::Denied => Err(SubmitError::PreviouslyDenied(
                row.message.unwrap_or_default(),
            )),
            PendingStatus::Failed => Err(SubmitError::PreviouslyFailed(
                row.message.unwrap_or_default(),
            )),
            PendingStatus::Signed => Err(SubmitError::Internal(anyhow::anyhow!(
                "pending row for {txid} is signed but the ledger has no matching record"
            ))),
        };
    }

    let submission_decision = if is_recovery {
        policy::evaluate_recovery_policy(&report, recovery_whitelist)
    } else {
        let rolling = ltx.rolling_totals(now).await?;
        policy::evaluate_policy(&report, &rolling, policy)
    };
    if let PolicyDecision::Deny(violations) = submission_decision {
        ltx.rollback().await?;
        return Err(SubmitError::Denied(violations));
    }

    let spend_sat = policy::destination_total_sat(&report);
    let fee_sat = report.fee.to_sat();
    let hold_until = now + hold_seconds;
    let psbt_base64 = psbt.to_string();
    ltx.insert_pending(&txid, &psbt_base64, spend_sat, fee_sat, now, hold_until)
        .await?;
    ltx.commit().await?;

    // Notification happens outside the transaction (it's network I/O) - see the module doc on
    // why failure here must roll the queue entry to a terminal `failed` state rather than
    // silently leaving an un-notified hold ticking down toward an unsupervised signature.
    let destinations: Vec<String> = report
        .outputs
        .iter()
        .filter(|o| o.kind == OutputKind::Destination)
        .map(|o| {
            o.address
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_else(|| o.script_pubkey.to_hex_string())
        })
        .collect();
    let notice = PendingNotice {
        txid: &txid,
        spend_sat,
        fee_sat,
        destinations: &destinations,
        hold_until,
    };
    if let Err(e) = notifier.notify(&notice).await {
        let message = format!("notification delivery failed: {e}");
        let mut ltx = ledger.begin().await?;
        ltx.mark_pending_failed(&txid, &message).await?;
        ltx.commit().await?;
        return Err(SubmitError::NotifyFailed(e.to_string()));
    }

    Ok(SubmitOutcome::Queued { txid, hold_until })
}

#[derive(Debug)]
pub enum PendingOutcome {
    Signed(Psbt),
    Denied(Vec<PolicyViolation>),
    Failed(String),
    /// The row was resolved (or vetoed) by something else between being listed as due and
    /// being processed - nothing to do.
    Skipped,
}

/// Fire-time processing of one due pending row: re-inspects the *stored* PSBT against live
/// chain state (never trusts the submission-time snapshot - a reorg or another spend of the
/// same UTXO could have happened during the hold) and re-evaluates policy from scratch, inside
/// one ledger transaction shared with [`decide_and_sign`].
#[allow(clippy::too_many_arguments)]
pub async fn process_due_pending_row(
    ledger: &Ledger,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    server_key: &ServerSigningKey,
    policy: &CompiledPolicy,
    recovery: &RecoveryConfig,
    chain: &Arc<dyn ChainSource>,
    gap_limit: u32,
    txid: &str,
    now: i64,
) -> Result<PendingOutcome> {
    // A freeze holds due rows in place rather than failing them: the point is to stop signing
    // while you sort something out, then resume - not to destroy the queue.
    if ledger.is_frozen().await? {
        return Ok(PendingOutcome::Skipped);
    }
    // Read outside any open transaction first: the chain I/O below can be slow, and holding
    // the ledger's single connection for its duration would block every other ledger user
    // (including `POST /veto/{id}`) for no reason.
    let psbt_base64 = match ledger.get_pending(txid).await? {
        Some(row) if row.status == PendingStatus::Pending => row.psbt_base64,
        _ => return Ok(PendingOutcome::Skipped),
    };
    let psbt = Psbt::from_str(&psbt_base64).context("parsing stored pending psbt")?;

    let wallet_owned = wallet.clone();
    let cfg_owned = cfg.clone();
    let chain_owned = chain.clone();
    let psbt_for_inspect = psbt.clone();
    let inspect_result: std::result::Result<InspectionReport, InspectError> =
        tokio::task::spawn_blocking(move || {
            inspect::inspect(
                &psbt_for_inspect,
                &wallet_owned,
                &cfg_owned,
                chain_owned.as_ref(),
                gap_limit,
            )
        })
        .await
        .context("inspect task panicked")?;

    let report = match inspect_result {
        Ok(report) => report,
        Err(InspectError::Chain(e)) => {
            // Transient (RPC hiccup, node temporarily unreachable): leave the row `pending` so
            // the next sweep tick retries, rather than permanently failing it.
            return Err(e.context(format!("re-inspecting pending spend {txid} at fire time")));
        }
        Err(e) => {
            let message = e.to_string();
            let mut ltx = ledger.begin().await?;
            ltx.mark_pending_failed(txid, &message).await?;
            ltx.commit().await?;
            return Ok(PendingOutcome::Failed(message));
        }
    };

    let mut ltx = ledger.begin().await?;
    // Re-check status inside the transaction: a veto may have landed between the read above
    // and now.
    match ltx.get_pending(txid).await? {
        Some(row) if row.status == PendingStatus::Pending => {}
        _ => {
            ltx.rollback().await?;
            return Ok(PendingOutcome::Skipped);
        }
    }

    let path_ok = match report.spending_path {
        SpendingPath::Hot => true,
        SpendingPath::Recovery => recovery.enabled,
        SpendingPath::Ambiguous => false,
    };
    if !path_ok {
        let message = format!(
            "no longer a co-signable spending path at fire time (now {:?})",
            report.spending_path
        );
        ltx.mark_pending_failed(txid, &message).await?;
        ltx.commit().await?;
        return Ok(PendingOutcome::Failed(message));
    }
    let recovery_whitelist = recovery.compiled_whitelist(cfg.network)?;

    match decide_and_sign(
        &mut ltx,
        psbt,
        &report,
        wallet,
        cfg,
        server_key,
        policy,
        recovery_whitelist.as_deref(),
        now,
    )
    .await
    {
        Ok(DecideOutcome::Recorded(signed)) | Ok(DecideOutcome::AlreadyRecorded(signed)) => {
            ltx.mark_pending_signed(txid, &signed.to_string()).await?;
            ltx.commit().await?;
            Ok(PendingOutcome::Signed(signed))
        }
        Ok(DecideOutcome::Denied(violations)) => {
            let message = violations
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            ltx.mark_pending_denied(txid, &message).await?;
            ltx.commit().await?;
            Ok(PendingOutcome::Denied(violations))
        }
        Err(SignPsbtError::Signing(signing_err)) => {
            // A structural signing failure (bad sighash type, key mismatch): permanent, will
            // never succeed on retry - drop `ltx` (auto-rollback) and mark it failed in a
            // fresh, short transaction.
            drop(ltx);
            let message = signing_err.to_string();
            let mut ltx = ledger.begin().await?;
            ltx.mark_pending_failed(txid, &message).await?;
            ltx.commit().await?;
            Ok(PendingOutcome::Failed(message))
        }
        Err(e) => {
            // A DB/internal error: `ltx` drops without commit (auto-rollback), leaving the row
            // `pending` so the next sweep tick retries.
            Err(anyhow::anyhow!(e).context(format!("processing pending spend {txid}")))
        }
    }
}

/// Processes every currently-due pending row. Each row's own failure is captured in its result
/// entry rather than aborting the sweep - one bad row (e.g. a transient chain RPC error) must
/// never block every other due row from firing.
#[allow(clippy::too_many_arguments)]
pub async fn sweep_due(
    ledger: &Ledger,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    server_key: &ServerSigningKey,
    policy: &CompiledPolicy,
    recovery: &RecoveryConfig,
    chain: &Arc<dyn ChainSource>,
    gap_limit: u32,
    now: i64,
) -> Vec<(String, Result<PendingOutcome>)> {
    let due = match ledger.due_pending(now).await {
        Ok(due) => due,
        Err(e) => return vec![("*".to_string(), Err(e))],
    };
    let mut results = Vec::with_capacity(due.len());
    for txid in due {
        let outcome = process_due_pending_row(
            ledger, wallet, cfg, server_key, policy, recovery, chain, gap_limit, &txid, now,
        )
        .await;
        results.push((txid, outcome));
    }
    results
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
    use crate::notify::mock::RecordingNotifier;
    use crate::policy::PolicyConfig;
    use crate::test_util::{test_server_xpriv, test_wallet_config};

    pub(super) fn fake_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    pub(super) fn foreign_script(fill: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x20];
        bytes.extend_from_slice(&[fill; 32]);
        ScriptBuf::from(bytes)
    }

    pub(super) fn load_test_server_key(cfg: &WalletConfig, env_var: &str) -> ServerSigningKey {
        let xprv = test_server_xpriv();
        // SAFETY: test-only; each test uses a distinct env var name to avoid cross-test races.
        unsafe { std::env::set_var(env_var, xprv.to_string()) };
        let signing_cfg = ServerSigningConfig {
            xprv_file: None,
            xprv_env_var: Some(env_var.to_string()),
        };
        ServerSigningKey::load(&signing_cfg, &cfg.keys.server.xpub, cfg.network).unwrap()
    }

    pub(super) fn policy_with_caps(
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
    pub(super) fn hot_psbt(
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

    /// A MOBILE + SERVER recovery-shaped PSBT: nSequence satisfies `older(N)` and a MOBILE
    /// signature is already attached, which is what makes `inspect` classify it as `Recovery`.
    /// The MOBILE signature here is a stand-in (the classifier only checks that one is present
    /// for the right key), which is enough to exercise the recovery gate and policy.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn recovery_psbt(
        chain: &MockChainSource,
        wallet: &BuiltDescriptor,
        cfg: &WalletConfig,
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
                confirmations: 100_000,
            },
        );
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(cfg.timelock_blocks),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amount_sat - fee_sat),
                script_pubkey: foreign_script(txid_byte),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey,
        });
        let role_keys = descriptor::role_keys_at(wallet, cfg, Chain::External, index).unwrap();
        psbt.inputs[0].partial_sigs.insert(
            role_keys.mobile,
            crate::test_util::test_signature(&crate::test_util::test_signer(0x99).secret),
        );
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

    // ---- M5: submit_for_signing / process_due_pending_row / sweep_due ----

    pub(super) struct QueueFixture {
        pub(super) cfg: WalletConfig,
        pub(super) wallet: BuiltDescriptor,
        pub(super) chain: Arc<MockChainSource>,
        pub(super) server_key: ServerSigningKey,
        pub(super) ledger: Ledger,
        pub(super) policy: CompiledPolicy,
    }

    pub(super) async fn queue_fixture(
        env_var: &str,
        max_tx_sat: u64,
        max_daily_sat: u64,
    ) -> QueueFixture {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = Arc::new(MockChainSource::new());
        let server_key = load_test_server_key(&cfg, env_var);
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let policy = policy_with_caps(cfg.network, max_tx_sat, max_daily_sat);
        QueueFixture {
            cfg,
            wallet,
            chain,
            server_key,
            ledger,
            policy,
        }
    }

    impl QueueFixture {
        pub(super) fn chain_as_dyn(&self) -> Arc<dyn ChainSource> {
            self.chain.clone()
        }
    }

    #[tokio::test]
    async fn submit_queues_a_new_spend_and_notifies_once() {
        let f = queue_fixture("COSIGNER_TEST_SUBMIT_QUEUE", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let psbt = hot_psbt(&f.chain, &f.wallet, 1, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid = psbt.unsigned_tx.compute_txid().to_string();

        let outcome = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap();

        match outcome {
            SubmitOutcome::Queued {
                txid: got_txid,
                hold_until,
            } => {
                assert_eq!(got_txid, txid);
                assert_eq!(hold_until, 1_000_300);
            }
            other => panic!("expected Queued, got {other:?}"),
        }
        assert_eq!(
            notifier.sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&txid)
        );

        let row = f.ledger.get_pending(&txid).await.unwrap().unwrap();
        assert_eq!(row.status, PendingStatus::Pending);
        // Nothing is recorded against the ledger (and thus the rolling budget) until it fires.
        assert_eq!(
            f.ledger.rolling_totals(1_000_000).await.unwrap(),
            crate::ledger::RollingTotals::default()
        );
    }

    #[tokio::test]
    async fn resubmitting_a_still_pending_spend_is_idempotent_and_does_not_renotify() {
        let f = queue_fixture("COSIGNER_TEST_SUBMIT_IDEMPOTENT", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let build = || {
            let psbt = hot_psbt(&f.chain, &f.wallet, 2, 0, 100_000, 1_000);
            let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
            (psbt, report)
        };

        let (psbt_a, report_a) = build();
        let first = submit_for_signing(
            psbt_a,
            report_a,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap();

        let (psbt_b, report_b) = build();
        let second = submit_for_signing(
            psbt_b,
            report_b,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_100,
        )
        .await
        .unwrap();

        let (
            SubmitOutcome::Queued { hold_until: h1, .. },
            SubmitOutcome::Queued { hold_until: h2, .. },
        ) = (first, second)
        else {
            panic!("expected both submissions to queue");
        };
        assert_eq!(
            h1, h2,
            "the hold clock must not restart on a duplicate submission"
        );
        assert_eq!(
            notifier.sent.lock().unwrap().len(),
            1,
            "must not notify twice for the same unsigned transaction"
        );
    }

    #[tokio::test]
    async fn sweep_before_hold_elapses_does_nothing() {
        let f = queue_fixture("COSIGNER_TEST_SWEEP_NOT_DUE", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let psbt = hot_psbt(&f.chain, &f.wallet, 3, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap();

        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_299,
        )
        .await;
        assert!(results.is_empty(), "hold has not elapsed yet: {results:?}");
        assert_eq!(
            f.ledger.rolling_totals(1_000_299).await.unwrap(),
            crate::ledger::RollingTotals::default()
        );
    }

    #[tokio::test]
    async fn sweep_after_hold_elapses_signs_and_records() {
        let f = queue_fixture("COSIGNER_TEST_SWEEP_DUE", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let psbt = hot_psbt(&f.chain, &f.wallet, 4, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap();

        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_300,
        )
        .await;
        assert_eq!(results.len(), 1);
        let (got_txid, outcome) = &results[0];
        assert_eq!(got_txid, &txid);
        let signed_psbt = match outcome.as_ref().unwrap() {
            PendingOutcome::Signed(psbt) => psbt.clone(),
            other => panic!("expected Signed, got {other:?}"),
        };
        let role_keys = descriptor::role_keys_at(&f.wallet, &f.cfg, Chain::External, 0).unwrap();
        assert!(signed_psbt.inputs[0]
            .partial_sigs
            .contains_key(&role_keys.server));

        let row = f.ledger.get_pending(&txid).await.unwrap().unwrap();
        assert_eq!(row.status, PendingStatus::Signed);
        assert_eq!(
            row.signed_psbt_base64.as_deref(),
            Some(signed_psbt.to_string().as_str())
        );

        assert_eq!(
            f.ledger.rolling_totals(1_000_300).await.unwrap().day_sat,
            99_000
        );

        // A second sweep at the same (or later) time must not re-process an already-resolved row.
        let again = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_301,
        )
        .await;
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn veto_before_hold_elapses_prevents_signing_and_blocks_resubmission() {
        let f = queue_fixture("COSIGNER_TEST_VETO", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let psbt = hot_psbt(&f.chain, &f.wallet, 5, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap();

        assert_eq!(
            f.ledger.veto_pending(&txid).await.unwrap(),
            Some(PendingStatus::Vetoed)
        );

        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_300,
        )
        .await;
        assert!(
            results.is_empty(),
            "a vetoed row must never be due: {results:?}"
        );
        assert_eq!(
            f.ledger.rolling_totals(1_000_300).await.unwrap(),
            crate::ledger::RollingTotals::default()
        );

        // Resubmitting the identical PSBT must not silently re-queue it.
        let psbt2 = hot_psbt(&f.chain, &f.wallet, 5, 0, 100_000, 1_000);
        let report2 = inspect::inspect(&psbt2, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let err = submit_for_signing(
            psbt2,
            report2,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_301,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SubmitError::Vetoed));
    }

    /// The race M5's design is built to close: two spends each pass the fast, submission-time
    /// policy pre-check (since neither has been recorded yet), so both get queued and
    /// notified - but only one of them can actually fit the rolling cap. The *fire-time*
    /// re-evaluation inside `process_due_pending_row` is what must catch this, not the
    /// submission-time check.
    #[tokio::test]
    async fn policy_denied_at_fire_time_even_though_allowed_at_submission() {
        // Cap fits exactly one of the two 100_000 sat destination spends, not both.
        let f = queue_fixture("COSIGNER_TEST_FIRE_TIME_DENY", u64::MAX, 150_000).await;
        let notifier = RecordingNotifier::new();

        let psbt_a = hot_psbt(&f.chain, &f.wallet, 6, 0, 101_000, 1_000);
        let report_a = inspect::inspect(&psbt_a, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid_a = psbt_a.unsigned_tx.compute_txid().to_string();
        let outcome_a = submit_for_signing(
            psbt_a,
            report_a,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            0,
            1_000_000,
        )
        .await
        .unwrap();
        assert!(matches!(outcome_a, SubmitOutcome::Queued { .. }));

        let psbt_b = hot_psbt(&f.chain, &f.wallet, 7, 1, 101_000, 1_000);
        let report_b = inspect::inspect(&psbt_b, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid_b = psbt_b.unsigned_tx.compute_txid().to_string();
        let outcome_b = submit_for_signing(
            psbt_b,
            report_b,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            0,
            1_000_000,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome_b, SubmitOutcome::Queued { .. }),
            "must still be accepted at submission time - neither spend is recorded yet"
        );

        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_000,
        )
        .await;
        assert_eq!(results.len(), 2);

        let mut outcomes: std::collections::HashMap<String, PendingOutcome> = results
            .into_iter()
            .map(|(txid, r)| (txid, r.unwrap()))
            .collect();
        assert!(matches!(
            outcomes.remove(&txid_a).unwrap(),
            PendingOutcome::Signed(_)
        ));
        let denied = outcomes.remove(&txid_b).unwrap();
        assert!(
            matches!(denied, PendingOutcome::Denied(_)),
            "the second spend must be denied at fire time once the first consumed the budget: {denied:?}"
        );

        let row_b = f.ledger.get_pending(&txid_b).await.unwrap().unwrap();
        assert_eq!(row_b.status, PendingStatus::Denied);
        assert!(row_b.message.unwrap().contains("daily"));

        assert_eq!(
            f.ledger.rolling_totals(1_000_000).await.unwrap().day_sat,
            100_000,
            "only the first (signed) spend may count against the rolling budget"
        );
    }

    #[tokio::test]
    async fn notify_failure_marks_the_pending_row_failed_and_returns_an_error() {
        let f = queue_fixture("COSIGNER_TEST_NOTIFY_FAIL", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::failing();

        let psbt = hot_psbt(&f.chain, &f.wallet, 8, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid = psbt.unsigned_tx.compute_txid().to_string();

        let err = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SubmitError::NotifyFailed(_)));

        let row = f.ledger.get_pending(&txid).await.unwrap().unwrap();
        assert_eq!(row.status, PendingStatus::Failed);

        // And it must never become due for signing.
        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_300,
        )
        .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn submit_rejects_a_non_hot_spending_path_without_queuing() {
        let f = queue_fixture("COSIGNER_TEST_SUBMIT_NOT_HOT", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let script_pubkey = descriptor::at_index(&f.wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let outpoint = OutPoint::new(fake_txid(9), 0);
        f.chain.insert(
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
            script_pubkey: foreign_script(9),
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
        let txid = psbt.unsigned_tx.compute_txid().to_string();

        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Ambiguous);

        let err = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SubmitError::NotHotPath));
        assert!(f.ledger.get_pending(&txid).await.unwrap().is_none());
        assert!(notifier.sent.lock().unwrap().is_empty());
    }
}

/// Re-notifies about spends still holding, so a single missed message can't silently cost you
/// the veto window. Called on the same tick as [`sweep_due`]; `interval_seconds` is how long
/// to leave between reminders for a given spend.
pub async fn renotify_pending(
    ledger: &Ledger,
    notifier: &dyn Notifier,
    interval_seconds: i64,
    now: i64,
) -> Result<usize> {
    let rows = ledger
        .pending_needing_renotify(now, interval_seconds)
        .await?;
    let mut sent = 0usize;
    for row in rows {
        let notice = PendingNotice {
            txid: &row.txid,
            spend_sat: row.spend_amount_sat,
            fee_sat: row.fee_sat,
            // Destinations aren't stored on the row; the reminder is a nudge to go look, and
            // re-deriving them would mean re-inspecting against the chain on every tick.
            destinations: &[],
            hold_until: row.hold_until,
        };
        if let Err(e) = notifier.notify(&notice).await {
            // A failed reminder must not stop the others, and must not fail the spend - the
            // original notification already went out at submission time.
            tracing::warn!(txid = %row.txid, error = %e, "reminder notification failed");
            continue;
        }
        ledger.mark_notified(&row.txid, now).await?;
        sent += 1;
    }
    Ok(sent)
}

#[cfg(test)]
mod recovery_and_freeze_tests {
    use super::tests::*;
    use super::*;
    use crate::notify::mock::RecordingNotifier;

    /// Freeze must stop a submission dead, before anything is queued or notified.
    #[tokio::test]
    async fn a_freeze_blocks_new_submissions_entirely() {
        let f = queue_fixture("COSIGNER_TEST_FREEZE_SUBMIT", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();
        f.ledger.set_frozen(true, 0, Some("test")).await.unwrap();

        let psbt = hot_psbt(&f.chain, &f.wallet, 60, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        let txid = psbt.unsigned_tx.compute_txid().to_string();

        let err = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SubmitError::Frozen(_)), "got {err:?}");
        assert!(f.ledger.get_pending(&txid).await.unwrap().is_none());
        assert!(notifier.sent.lock().unwrap().is_empty());
    }

    /// A freeze applied *after* something is already queued must stop it firing, and lifting
    /// the freeze must let it through - held, not destroyed.
    #[tokio::test]
    async fn a_freeze_holds_already_queued_spends_then_releases_them() {
        let f = queue_fixture("COSIGNER_TEST_FREEZE_SWEEP", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let psbt = hot_psbt(&f.chain, &f.wallet, 61, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            0,
            1_000_000,
        )
        .await
        .unwrap();

        f.ledger.set_frozen(true, 1_000_001, None).await.unwrap();
        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_100,
        )
        .await;
        assert!(
            results
                .iter()
                .all(|(_, r)| matches!(r.as_ref().unwrap(), PendingOutcome::Skipped)),
            "a frozen sweep must skip, not sign: {results:?}"
        );
        assert_eq!(
            f.ledger.rolling_totals(1_000_100).await.unwrap(),
            crate::ledger::RollingTotals::default()
        );

        f.ledger.set_frozen(false, 1_000_200, None).await.unwrap();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &RecoveryConfig::default(),
            &chain_dyn,
            50,
            1_000_300,
        )
        .await;
        assert!(
            matches!(results[0].1.as_ref().unwrap(), PendingOutcome::Signed(_)),
            "unfreezing must release the held spend: {results:?}"
        );
    }

    #[tokio::test]
    async fn recovery_disabled_refuses_the_no_hardware_path() {
        let f = queue_fixture("COSIGNER_TEST_RECOVERY_OFF", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();
        let disabled = RecoveryConfig {
            enabled: false,
            ..RecoveryConfig::default()
        };

        // A recovery-shaped PSBT: sequence satisfies older(N) and MOBILE has signed.
        let psbt = recovery_psbt(&f.chain, &f.wallet, &f.cfg, 62, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Recovery);

        let err = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &disabled,
            &notifier,
            300,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SubmitError::RecoveryDisabled), "got {err:?}");
    }

    /// The point of the whole descriptor change: with the SATOCHIP gone, MOBILE + SERVER must
    /// actually get co-signed - and it must ignore the ordinary per-tx cap, because sweeping
    /// the balance is the entire purpose.
    #[tokio::test]
    async fn recovery_spend_is_cosigned_and_ignores_the_ordinary_caps() {
        // A per-tx cap far below the spend: a HOT spend this size would be denied outright.
        let f = queue_fixture("COSIGNER_TEST_RECOVERY_ON", 1_000, 1_000).await;
        let notifier = RecordingNotifier::new();
        let recovery = RecoveryConfig::default();

        let psbt = recovery_psbt(&f.chain, &f.wallet, &f.cfg, 63, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        assert_eq!(report.spending_path, SpendingPath::Recovery);

        let outcome = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &recovery,
            &notifier,
            0,
            1_000_000,
        )
        .await
        .unwrap();
        let SubmitOutcome::Queued { hold_until, .. } = outcome else {
            panic!("expected Queued, got {outcome:?}");
        };
        // It used the recovery hold, not the caller's hold_seconds of 0.
        assert_eq!(hold_until, 1_000_000 + recovery.hold_seconds);

        let chain_dyn = f.chain_as_dyn();
        let results = sweep_due(
            &f.ledger,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.policy,
            &recovery,
            &chain_dyn,
            50,
            1_000_000 + recovery.hold_seconds,
        )
        .await;
        assert!(
            matches!(results[0].1.as_ref().unwrap(), PendingOutcome::Signed(_)),
            "MOBILE+SERVER recovery must be co-signed despite the 1000 sat cap: {results:?}"
        );
    }

    #[tokio::test]
    async fn recovery_whitelist_blocks_an_unlisted_destination() {
        let f = queue_fixture("COSIGNER_TEST_RECOVERY_WL", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();
        let recovery = RecoveryConfig {
            // A valid signet address that is deliberately NOT where this PSBT pays.
            destination_whitelist: Some(vec![crate::descriptor::address_at(
                &f.wallet.external,
                9,
                f.cfg.network,
            )
            .unwrap()
            .to_string()]),
            ..RecoveryConfig::default()
        };

        let psbt = recovery_psbt(&f.chain, &f.wallet, &f.cfg, 64, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();

        let err = submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &recovery,
            &notifier,
            0,
            1_000_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SubmitError::Denied(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn reminders_fire_on_interval_and_only_while_still_holding() {
        let f = queue_fixture("COSIGNER_TEST_RENOTIFY", u64::MAX, u64::MAX).await;
        let notifier = RecordingNotifier::new();

        let psbt = hot_psbt(&f.chain, &f.wallet, 65, 0, 100_000, 1_000);
        let report = inspect::inspect(&psbt, &f.wallet, &f.cfg, f.chain.as_ref(), 50).unwrap();
        submit_for_signing(
            psbt,
            report,
            &f.wallet,
            &f.cfg,
            &f.server_key,
            &f.ledger,
            &f.policy,
            &RecoveryConfig::default(),
            &notifier,
            10_000,
            1_000_000,
        )
        .await
        .unwrap();
        assert_eq!(
            notifier.sent.lock().unwrap().len(),
            1,
            "initial notification"
        );

        // Too soon: the submission notification counts as the last one sent.
        let n = renotify_pending(&f.ledger, &notifier, 3_600, 1_001_000)
            .await
            .unwrap();
        assert_eq!(n, 0, "must not remind before the interval elapses");

        let n = renotify_pending(&f.ledger, &notifier, 3_600, 1_004_000)
            .await
            .unwrap();
        assert_eq!(n, 1, "must remind once the interval has elapsed");
        assert_eq!(notifier.sent.lock().unwrap().len(), 2);

        // And immediately again is too soon once more.
        let n = renotify_pending(&f.ledger, &notifier, 3_600, 1_004_100)
            .await
            .unwrap();
        assert_eq!(n, 0);

        // Past the hold, it's due rather than holding - the sweeper's job now, not the
        // reminder's.
        let n = renotify_pending(&f.ledger, &notifier, 3_600, 1_020_000)
            .await
            .unwrap();
        assert_eq!(n, 0, "must not remind about a spend that's already due");
    }
}
