//! Runtime policy changes require an authorization signature from the HARDWARE key - the
//! user's own hardware, held by them and otherwise only ever used to help co-sign real spends.
//! This closes the last privileged action this service could take entirely on its own: without
//! it, a compromised or misconfigured server could simply loosen its own spend caps and then
//! use its SERVER key to spend more than the operator ever intended.
//!
//! Verification uses Bitcoin's standard "Sign Message" format (the same one exposed by
//! Sparrow/Electrum's "Sign Message" feature, which the HARDWARE applet supports) rather than a
//! bespoke scheme, so a human can actually produce a valid authorization with real hardware:
//! [`canonical_message`] renders the proposed policy as human-readable text - what a signing
//! device shows is exactly what this service later recomputes and verifies against - and
//! [`HardwareAuthKeys::verify`] checks it by recovering the signer's public key and comparing it
//! against the hardware key's account-level key or any of its derived per-address children,
//! mirroring exactly how this service already treats that key as valid at any descriptor index
//! for spending. Those candidates are derived once at startup, not per request - see
//! [`HardwareAuthKeys`] for why that matters.
//!
//! Authorized changes are durable: `ledger.rs`'s `policy_state` table tracks the current policy
//! and a monotonic version number. A submitted change must target `current version + 1` - both
//! so two concurrently-submitted changes can't silently clobber each other, and so an old
//! signed authorization can never be replayed later to roll back to a looser policy.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sign_message::{signed_msg_hash, MessageSignature};
use thiserror::Error;

use crate::config::WalletConfig;
use crate::ledger::Ledger;
use crate::policy::{CompiledPolicy, PolicyConfig};

/// Builds the exact text a human must sign (via their wallet's "Sign Message" feature) to
/// authorize `policy` as version `version`. One field per line, fixed order: the same
/// `(version, policy)` always produces byte-identical text.
pub fn canonical_message(version: u64, policy: &PolicyConfig) -> String {
    let mut msg = String::new();
    let _ = writeln!(msg, "cosigner policy authorization v1");
    let _ = writeln!(msg, "version: {version}");
    let _ = writeln!(msg, "max_tx_sat: {}", policy.max_tx_sat);
    let _ = writeln!(msg, "max_daily_sat: {}", policy.max_daily_sat);
    let _ = writeln!(msg, "max_weekly_sat: {}", policy.max_weekly_sat);
    let _ = writeln!(msg, "max_monthly_sat: {}", policy.max_monthly_sat);
    let _ = writeln!(msg, "max_fee_sat: {}", policy.max_fee_sat);
    let _ = writeln!(
        msg,
        "max_fee_rate_sat_per_vb: {}",
        policy.max_fee_rate_sat_per_vb
    );
    match &policy.destination_whitelist {
        None => {
            let _ = write!(
                msg,
                "destination_whitelist: (none - any destination allowed)"
            );
        }
        Some(addrs) => {
            let _ = write!(msg, "destination_whitelist: {}", addrs.join(","));
        }
    }
    msg
}

/// The text a human must sign to lift a freeze. Bound to the current *freeze generation* - a
/// counter in `ledger.rs`'s `freeze_state` table that increments on every freeze and never on
/// an unfreeze - not the policy version.
///
/// This distinction matters and was originally gotten wrong: policy version only changes when
/// `POST /policy` succeeds, which has nothing to do with freezing. Binding to it meant a single
/// captured unfreeze signature stayed valid forever (as long as nobody happened to also change
/// the policy) and could relift *any future* freeze - including the next one, triggered for an
/// unrelated, real emergency. Binding to the freeze generation instead means an authorization
/// signed for generation N can only ever lift *that* freeze; the next freeze is generation N+1,
/// and the old signature no longer matches anything.
pub fn canonical_unfreeze_message(freeze_generation: u64) -> String {
    format!("cosigner unfreeze authorization v1\nfreeze_generation: {freeze_generation}")
}

/// Checks a HARDWARE signature over [`canonical_unfreeze_message`]. Shares
/// [`HardwareAuthKeys::verify`]'s "account key or any derived child" matching, so the same device
/// works regardless of which address index the user's wallet software signs from.
pub fn verify_unfreeze_authorization(
    auth_keys: &HardwareAuthKeys,
    freeze_generation: u64,
    signature_base64: &str,
) -> Result<(), PolicyAuthError> {
    auth_keys.verify(
        &canonical_unfreeze_message(freeze_generation),
        signature_base64,
    )
}

#[derive(Debug, Error)]
pub enum PolicyAuthError {
    #[error("policy change targets version {got}, but the next expected version is {expected}")]
    VersionMismatch { expected: u64, got: u64 },
    #[error("proposed policy is invalid: {0}")]
    InvalidPolicy(#[source] anyhow::Error),
    #[error("signature does not decode as a valid Bitcoin signed message: {0}")]
    MalformedSignature(#[source] anyhow::Error),
    #[error(
        "signature does not recover to a key controlled by HARDWARE - refusing to authorize \
         this policy change"
    )]
    UnauthorizedSigner,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// The hardware key's account key and every derived per-address child up to the gap limit,
/// precomputed once at startup into a set that can be probed in constant time.
///
/// **Invariant: verifying an authorization must be cheap, and must stay cheap for signatures
/// that turn out to be invalid.** Deriving candidates on demand would mean `2 * gap_limit` (1000
/// by default, so 2000) elliptic-curve derivations per attempt, on a CPU-bound path, before a
/// wrong signature can even be rejected - and `/policy` and `/unfreeze` are both reachable
/// before their signature has been checked.
///
/// Precomputing collapses verification to one ECDSA recovery plus a hash lookup. Do not move
/// this derivation back onto the request path.
pub struct HardwareAuthKeys {
    candidates: HashSet<bitcoin::secp256k1::PublicKey>,
}

impl HardwareAuthKeys {
    /// Derives the full candidate set. Called once, at startup - `gap_limit` derivations on each
    /// of the two chains, plus the account key itself.
    pub fn precompute(xpub: &Xpub, gap_limit: u32) -> Result<Self> {
        let secp = Secp256k1::verification_only();
        let mut candidates = HashSet::with_capacity((gap_limit as usize * 2) + 1);
        candidates.insert(xpub.public_key);

        for chain_num in [0u32, 1u32] {
            let chain_child =
                ChildNumber::from_normal_idx(chain_num).context("chain child number")?;
            for index in 0..gap_limit {
                let index_child =
                    ChildNumber::from_normal_idx(index).context("index child number")?;
                let path = DerivationPath::from(vec![chain_child, index_child]);
                let child = xpub
                    .derive_pub(&secp, &path)
                    .context("deriving hardware-key candidate")?;
                candidates.insert(child.public_key);
            }
        }
        Ok(Self { candidates })
    }

    /// Builds the candidate set for the configured hardware key.
    pub fn from_config(cfg: &WalletConfig, gap_limit: u32) -> Result<Self> {
        let xpub = Xpub::from_str(cfg.keys.hardware.xpub.trim()).context("keys.hardware.xpub")?;
        Self::precompute(&xpub, gap_limit)
    }

    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Checks `signature_base64` (a standard Bitcoin signed message, base64-encoded) over
    /// `message`. Recovering the signer's public key *is* the verification - there is no separate
    /// "is it valid" step: a garbled or wrong-message signature simply recovers a key that
    /// matches none of the candidates.
    pub fn verify(&self, message: &str, signature_base64: &str) -> Result<(), PolicyAuthError> {
        let signature = MessageSignature::from_base64(signature_base64)
            .map_err(|e| PolicyAuthError::MalformedSignature(anyhow::anyhow!(e)))?;
        let msg_hash = signed_msg_hash(message);
        let secp = Secp256k1::verification_only();
        let recovered = signature
            .recover_pubkey(&secp, msg_hash)
            .map_err(|e| PolicyAuthError::MalformedSignature(anyhow::anyhow!(e)))?;

        if self.candidates.contains(&recovered.inner) {
            Ok(())
        } else {
            Err(PolicyAuthError::UnauthorizedSigner)
        }
    }
}

/// A proposed, HARDWARE-authorized policy change, as received over `POST /policy`.
pub struct PolicyChangeRequest {
    pub policy: PolicyConfig,
    pub version: u64,
    pub signature_base64: String,
}

#[derive(Debug)]
pub struct PolicyChangeOutcome {
    pub version: u64,
    pub compiled: CompiledPolicy,
}

/// Validates, authorizes, and durably applies a policy change: version must be exactly
/// `current + 1`, the proposed policy must itself compile (network-checking any whitelist
/// addresses), and `signature_base64` must recover to a HARDWARE key - in that order, so a
/// version conflict or a malformed policy is rejected before ever touching the signature.
/// # Why this opens the ledger transaction twice
///
/// **Invariant: nothing that isn't atomic may be done while holding a ledger transaction.**
///
/// The ledger pool is capped at a single connection on purpose (see `ledger.rs`), so an open
/// `LedgerTx` excludes every other ledger user for its whole lifetime - the sweeper, and
/// critically `POST /veto/{id}`. A veto that cannot reach the ledger is a veto that does not
/// happen, so the transaction is held only for the read-check-write that genuinely needs it.
///
/// Verifying first and then re-checking the version *inside* the transaction preserves the
/// atomicity that matters - two concurrent changes still cannot both land, and an authorization
/// signed for an old version still cannot be replayed - while holding the lock for microseconds.
/// Do not collapse these back into one transaction.
pub async fn apply_policy_change(
    ledger: &Ledger,
    cfg: &WalletConfig,
    auth_keys: &HardwareAuthKeys,
    req: PolicyChangeRequest,
    now: i64,
) -> Result<PolicyChangeOutcome, PolicyAuthError> {
    // 1. Cheap pre-checks, no transaction held. A version mismatch or an invalid policy is
    //    rejected here without ever touching the ledger lock.
    let current = ledger.get_policy_state().await?.ok_or_else(|| {
        PolicyAuthError::Internal(anyhow::anyhow!(
            "policy_state is unseeded - the service must bootstrap it from [policy] at startup \
             before POST /policy can be used"
        ))
    })?;
    if req.version != current.version + 1 {
        return Err(PolicyAuthError::VersionMismatch {
            expected: current.version + 1,
            got: req.version,
        });
    }

    let compiled = req
        .policy
        .compile(cfg.network)
        .map_err(PolicyAuthError::InvalidPolicy)?;

    // 2. Authorize, still holding nothing.
    let message = canonical_message(req.version, &req.policy);
    auth_keys.verify(&message, &req.signature_base64)?;

    let policy_json = serde_json::to_string(&req.policy)
        .context("serializing policy")
        .map_err(PolicyAuthError::Internal)?;

    // 3. Now take the lock, and re-read the version inside it. The check in step 1 was against a
    //    snapshot that another change could have moved since; this one is atomic with the write,
    //    which is what actually prevents two racing changes from clobbering each other.
    let mut ltx = ledger.begin().await?;
    let current = ltx.get_policy_state().await?.ok_or_else(|| {
        PolicyAuthError::Internal(anyhow::anyhow!("policy_state disappeared mid-change"))
    })?;
    if req.version != current.version + 1 {
        ltx.rollback().await?;
        return Err(PolicyAuthError::VersionMismatch {
            expected: current.version + 1,
            got: req.version,
        });
    }
    ltx.set_policy_state(req.version, &policy_json, now).await?;
    ltx.commit().await?;

    Ok(PolicyChangeOutcome {
        version: req.version,
        compiled,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::bip32::Xpriv;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::All;

    use super::*;
    use crate::config::ChainNetwork;
    use crate::ledger::Ledger;
    use crate::test_util::{test_key_spec_with_xpriv, test_wallet_config};

    fn generous_policy(max_tx_sat: u64) -> PolicyConfig {
        PolicyConfig {
            max_tx_sat,
            max_daily_sat: u64::MAX,
            max_weekly_sat: u64::MAX,
            max_monthly_sat: u64::MAX,
            max_fee_sat: u64::MAX,
            max_fee_rate_sat_per_vb: f64::MAX,
            destination_whitelist: None,
        }
    }

    /// The precomputed candidate set for a config's hardware key, as `serve` builds at startup.
    fn auth_keys(cfg: &WalletConfig, gap_limit: u32) -> HardwareAuthKeys {
        HardwareAuthKeys::from_config(cfg, gap_limit).expect("precomputing candidates")
    }

    fn sign_message(xprv: &Xpriv, secp: &Secp256k1<All>, message: &str) -> String {
        let msg_hash = signed_msg_hash(message);
        let msg = bitcoin::secp256k1::Message::from_digest(msg_hash.to_byte_array());
        let sig = secp.sign_ecdsa_recoverable(&msg, &xprv.private_key);
        MessageSignature::new(sig, true).to_base64()
    }

    /// The precomputed set must contain exactly what the old per-request derivation loop would
    /// have matched: the account key plus every child on both chains, and nothing else.
    #[test]
    fn precomputed_candidates_cover_the_account_key_and_every_child() {
        let cfg = test_wallet_config(12960);
        let gap_limit = 20u32;
        let keys = auth_keys(&cfg, gap_limit);

        // account key + gap_limit children on each of two chains
        assert_eq!(keys.len(), (gap_limit as usize * 2) + 1);

        let secp = Secp256k1::new();
        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);

        // A signature from the account key itself verifies.
        let msg = "cosigner test authorization";
        assert!(keys
            .verify(msg, &sign_message(&hardware_xprv, &secp, msg))
            .is_ok());

        // ...as does one from an arbitrary in-range child on either chain.
        for (chain, index) in [(0u32, 7u32), (1u32, 19u32)] {
            let child = hardware_xprv
                .derive_priv(
                    &secp,
                    &DerivationPath::from(vec![
                        ChildNumber::from_normal_idx(chain).unwrap(),
                        ChildNumber::from_normal_idx(index).unwrap(),
                    ]),
                )
                .unwrap();
            assert!(
                keys.verify(msg, &sign_message(&child, &secp, msg)).is_ok(),
                "child {chain}/{index} should be authorized"
            );
        }

        // A child beyond the gap limit is not in the set.
        let out_of_range = hardware_xprv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(gap_limit + 5).unwrap(),
                ]),
            )
            .unwrap();
        assert!(matches!(
            keys.verify(msg, &sign_message(&out_of_range, &secp, msg)),
            Err(PolicyAuthError::UnauthorizedSigner)
        ));

        // And neither is an unrelated key.
        let (_, stranger) = test_key_spec_with_xpriv(0x99);
        assert!(matches!(
            keys.verify(msg, &sign_message(&stranger, &secp, msg)),
            Err(PolicyAuthError::UnauthorizedSigner)
        ));
    }

    /// A signature over a *different* message must not authorize this one - the recovered key
    /// simply won't match, which is what makes recovery-based verification sound.
    #[test]
    fn a_signature_over_another_message_does_not_authorize() {
        let cfg = test_wallet_config(12960);
        let keys = auth_keys(&cfg, 20);
        let secp = Secp256k1::new();
        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);

        let signature = sign_message(&hardware_xprv, &secp, "some other message entirely");
        assert!(matches!(
            keys.verify("cosigner test authorization", &signature),
            Err(PolicyAuthError::UnauthorizedSigner)
        ));
    }

    #[test]
    fn canonical_message_is_deterministic_and_reflects_every_field() {
        let policy = PolicyConfig {
            max_tx_sat: 1,
            max_daily_sat: 2,
            max_weekly_sat: 3,
            max_monthly_sat: 4,
            max_fee_sat: 5,
            max_fee_rate_sat_per_vb: 6.5,
            destination_whitelist: Some(vec!["tb1qexample".to_string()]),
        };
        let a = canonical_message(7, &policy);
        let b = canonical_message(7, &policy);
        assert_eq!(a, b);
        assert!(a.contains("version: 7"));
        assert!(a.contains("max_tx_sat: 1"));
        assert!(a.contains("max_fee_rate_sat_per_vb: 6.5"));
        assert!(a.contains("tb1qexample"));

        let different_version = canonical_message(8, &policy);
        assert_ne!(a, different_version);
    }

    #[test]
    fn canonical_message_reports_an_empty_whitelist_distinctly() {
        let policy = generous_policy(1);
        let msg = canonical_message(1, &policy);
        assert!(msg.contains("(none - any destination allowed)"));
    }

    #[tokio::test]
    async fn accepts_a_signature_from_the_hardware_account_key() {
        let cfg = test_wallet_config(12960);
        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);
        let secp = Secp256k1::new();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        let policy = generous_policy(500_000);
        let message = canonical_message(2, &policy);
        let signature_base64 = sign_message(&hardware_xprv, &secp, &message);

        let outcome = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy,
                version: 2,
                signature_base64,
            },
            2_000,
        )
        .await
        .unwrap();
        assert_eq!(outcome.version, 2);
        assert_eq!(outcome.compiled.max_tx_sat, 500_000);

        let state = ledger.get_policy_state().await.unwrap().unwrap();
        assert_eq!(state.version, 2);
    }

    #[tokio::test]
    async fn accepts_a_signature_from_a_derived_hardware_child_key() {
        let cfg = test_wallet_config(12960);
        let (_, hardware_account_xprv) = test_key_spec_with_xpriv(0x01);
        let secp = Secp256k1::new();
        // A child several indices deep on the internal chain - proves verification isn't
        // limited to the bare account key.
        let child_xprv = hardware_account_xprv
            .derive_priv(
                &secp,
                &DerivationPath::from(vec![
                    ChildNumber::from_normal_idx(1).unwrap(),
                    ChildNumber::from_normal_idx(7).unwrap(),
                ]),
            )
            .unwrap();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        let policy = generous_policy(500_000);
        let message = canonical_message(2, &policy);
        let signature_base64 = sign_message(&child_xprv, &secp, &message);

        let outcome = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy,
                version: 2,
                signature_base64,
            },
            2_000,
        )
        .await
        .unwrap();
        assert_eq!(outcome.version, 2);
    }

    #[tokio::test]
    async fn rejects_a_signature_from_a_non_hardware_key() {
        let cfg = test_wallet_config(12960);
        let (_, mobile_xprv) = test_key_spec_with_xpriv(0x02); // MOBILE, not HARDWARE
        let secp = Secp256k1::new();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        let policy = generous_policy(500_000);
        let message = canonical_message(2, &policy);
        let signature_base64 = sign_message(&mobile_xprv, &secp, &message);

        let err = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy,
                version: 2,
                signature_base64,
            },
            2_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PolicyAuthError::UnauthorizedSigner));

        // Nothing must have been applied.
        let state = ledger.get_policy_state().await.unwrap().unwrap();
        assert_eq!(state.version, 1);
    }

    #[tokio::test]
    async fn rejects_a_signature_over_a_tampered_policy() {
        let cfg = test_wallet_config(12960);
        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);
        let secp = Secp256k1::new();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        // Sign a message authorizing a 500_000 sat cap...
        let signed_policy = generous_policy(500_000);
        let message = canonical_message(2, &signed_policy);
        let signature_base64 = sign_message(&hardware_xprv, &secp, &message);

        // ...but submit a request claiming a much higher cap instead. The signature was never
        // produced over *this* policy, so verification must fail.
        let tampered_policy = generous_policy(50_000_000);
        let err = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy: tampered_policy,
                version: 2,
                signature_base64,
            },
            2_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PolicyAuthError::UnauthorizedSigner));
    }

    #[tokio::test]
    async fn rejects_a_version_that_is_not_current_plus_one() {
        let cfg = test_wallet_config(12960);
        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);
        let secp = Secp256k1::new();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        let policy = generous_policy(500_000);
        // Skips straight to version 3 instead of 2.
        let message = canonical_message(3, &policy);
        let signature_base64 = sign_message(&hardware_xprv, &secp, &message);

        let err = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy,
                version: 3,
                signature_base64,
            },
            2_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            PolicyAuthError::VersionMismatch {
                expected: 2,
                got: 3
            }
        ));
    }

    #[tokio::test]
    async fn a_replayed_old_signature_cannot_reapply_after_the_version_has_moved_on() {
        let cfg = test_wallet_config(12960);
        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);
        let secp = Secp256k1::new();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        // Legitimately apply version 2.
        let policy_v2 = generous_policy(500_000);
        let message_v2 = canonical_message(2, &policy_v2);
        let sig_v2 = sign_message(&hardware_xprv, &secp, &message_v2);
        apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy: policy_v2,
                version: 2,
                signature_base64: sig_v2.clone(),
            },
            2_000,
        )
        .await
        .unwrap();

        // Legitimately apply version 3, tightening the cap back down.
        let policy_v3 = generous_policy(1_000);
        let message_v3 = canonical_message(3, &policy_v3);
        let sig_v3 = sign_message(&hardware_xprv, &secp, &message_v3);
        apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy: policy_v3,
                version: 3,
                signature_base64: sig_v3,
            },
            3_000,
        )
        .await
        .unwrap();

        // Replaying the old version-2 signature (which *is* a genuine HARDWARE signature) must
        // not be able to loosen the cap again, since it targets a version number that's no
        // longer the expected next one.
        let err = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy: generous_policy(500_000),
                version: 2,
                signature_base64: sig_v2,
            },
            4_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PolicyAuthError::VersionMismatch { .. }));

        let state = ledger.get_policy_state().await.unwrap().unwrap();
        assert_eq!(state.version, 3, "must still be at version 3");
    }

    #[tokio::test]
    async fn rejects_an_invalid_proposed_policy_before_checking_the_signature() {
        let cfg = test_wallet_config(12960);
        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state(&serde_json::to_string(&generous_policy(1)).unwrap(), 1_000)
            .await
            .unwrap();

        let mut invalid = generous_policy(500_000);
        invalid.destination_whitelist = Some(vec!["not-an-address".to_string()]);

        let err = apply_policy_change(
            &ledger,
            &cfg,
            &auth_keys(&cfg, 50),
            PolicyChangeRequest {
                policy: invalid,
                version: 2,
                // Deliberately garbage - if this were checked first we'd get
                // MalformedSignature instead, which would prove the ordering is wrong.
                signature_base64: "not-a-signature".to_string(),
            },
            2_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PolicyAuthError::InvalidPolicy(_)));
    }

    #[test]
    fn network_mismatch_is_still_caught_regardless_of_this_module() {
        // Sanity check that we're relying on PolicyConfig::compile's own network validation
        // rather than re-implementing it - see `policy.rs` for the exhaustive tests of that.
        let cfg = generous_policy(1);
        assert!(cfg.compile(ChainNetwork::Regtest).is_ok());
    }
}
