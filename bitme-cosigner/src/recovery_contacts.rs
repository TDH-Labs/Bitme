//! Social recovery: people you trust can vouch for you, by quorum, to release a spend that is
//! already queued and already within policy.
//!
//! # What a quorum can and cannot do
//!
//! This is the whole security argument, so it is stated first and enforced by test:
//!
//! **A quorum can only ever bring forward the hold on a spend this service had already approved.
//! It cannot create a spend, raise a cap, change a policy, or reach a destination the policy
//! forbids.** Every constraint that Bitcoin enforces, and every constraint `policy.rs` enforces,
//! still applies afterwards - `sign::process_due_pending_row` re-evaluates policy from scratch at
//! fire time regardless of how the row became due. What the quorum removes is *this service's own
//! waiting period*, and nothing else.
//!
//! That boundary is deliberate and load-bearing. This service's central claim is that its delay
//! is a consensus rule rather than a server promise; a social-recovery feature that could
//! authorize spending would hand that back. So the quorum is wired to the one thing that is
//! genuinely just a server-side timer.
//!
//! # Why npubs
//!
//! A recovery contact needs an identity you can name in advance and verify later, that they
//! already have or can create in seconds, and that costs them nothing to hold. A Nostr keypair is
//! exactly that, and `nostr_transport.rs` already establishes the pattern of an allowlist of
//! npubs whose signatures authorize actions. Contacts sign an ordinary Nostr event whose content
//! is [`canonical_approval_message`] - which is what every Nostr client and browser extension
//! already knows how to do - and this module checks the signature, the author, and the content.
//!
//! Contacts hold no key material belonging to the wallet. Losing a contact loses nothing; a
//! contact turning hostile costs you one of `threshold` votes and no more.

use std::collections::HashSet;

use anyhow::{Context, Result};
use nostr_sdk::prelude::*;
use serde::Deserialize;
use thiserror::Error;

/// Config for `[recovery_contacts]`. Absent means the feature is off, which is the default: a
/// quorum that nobody configured must never be able to do anything.
#[derive(Debug, Clone, Deserialize)]
pub struct RecoveryContactsConfig {
    /// npubs (bech32) allowed to vote. Each contact counts once no matter how many signatures
    /// they submit.
    pub npubs: Vec<String>,
    /// How many distinct contacts must agree. Must be at least 2 and at most `npubs.len()`.
    pub threshold: usize,
}

impl RecoveryContactsConfig {
    pub fn validate(&self) -> Result<()> {
        if self.npubs.is_empty() {
            anyhow::bail!("recovery_contacts.npubs must not be empty - remove the section instead");
        }
        // A threshold of 1 would make a single compromised or coerced contact sufficient. Bitkey's
        // social recovery works that way and documents the tradeoff; this refuses it, because the
        // whole point of naming several people is that no one of them is a single point of
        // failure.
        if self.threshold < 2 {
            anyhow::bail!(
                "recovery_contacts.threshold must be at least 2 - a threshold of 1 means any \
                 single contact can act alone, which is not meaningfully different from having no \
                 contacts at all"
            );
        }
        if self.threshold > self.npubs.len() {
            anyhow::bail!(
                "recovery_contacts.threshold ({}) exceeds the number of contacts ({}) - no \
                 quorum could ever be reached",
                self.threshold,
                self.npubs.len()
            );
        }

        let mut seen = HashSet::new();
        for npub in &self.npubs {
            let key = PublicKey::from_bech32(npub.trim()).with_context(|| {
                format!("recovery_contacts.npubs entry {npub:?} is not a valid npub")
            })?;
            if !seen.insert(key) {
                anyhow::bail!(
                    "recovery_contacts.npubs contains {npub:?} more than once - duplicates would \
                     let one person cast several votes"
                );
            }
        }
        Ok(())
    }

    pub fn compiled(&self) -> Result<HashSet<PublicKey>> {
        self.npubs
            .iter()
            .map(|s| {
                PublicKey::from_bech32(s.trim())
                    .with_context(|| format!("recovery_contacts.npubs entry {s:?}"))
            })
            .collect()
    }
}

/// The exact text a contact signs to vouch for one queued spend.
///
/// Bound to the txid, so an approval is good for that spend and nothing else. There is no
/// expiry and none is needed: the txid names a specific, already-queued transaction, which can
/// only be signed once and cannot be resubmitted after it resolves.
pub fn canonical_approval_message(txid: &str) -> String {
    format!("cosigner recovery approval v1\ntxid: {txid}\naction: release the remaining hold")
}

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("recovery contacts are not configured on this service")]
    NotConfigured,
    #[error("no spend with id {0} is currently pending")]
    NotPending(String),
    #[error("signature {index} is not a valid signed Nostr event: {message}")]
    Malformed { index: usize, message: String },
    #[error(
        "signature {index} vouches for different text than this spend's approval message - it \
         may have been signed for a different transaction"
    )]
    WrongMessage { index: usize },
    #[error("only {got} of {needed} required contacts have approved")]
    ShortOfQuorum { got: usize, needed: usize },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Counts how many *distinct* allowlisted contacts have validly vouched for `txid`.
///
/// Every submitted event must verify cryptographically, be authored by an allowlisted contact,
/// and carry exactly the expected message. Duplicates from one contact collapse to a single vote,
/// which is what stops someone reaching a quorum on their own by submitting the same signature
/// several times.
pub fn count_distinct_approvals(
    txid: &str,
    events: &[String],
    allowed: &HashSet<PublicKey>,
) -> Result<HashSet<PublicKey>, ApprovalError> {
    let expected = canonical_approval_message(txid);
    let mut voters = HashSet::new();

    for (index, raw) in events.iter().enumerate() {
        let event: Event = Event::from_json(raw.trim()).map_err(|e| ApprovalError::Malformed {
            index,
            message: e.to_string(),
        })?;
        // Checks the id commitment and the schnorr signature. Without this an attacker could
        // simply assert any pubkey they liked.
        event.verify().map_err(|e| ApprovalError::Malformed {
            index,
            message: e.to_string(),
        })?;
        if event.content.trim() != expected {
            return Err(ApprovalError::WrongMessage { index });
        }
        // Not on the list is silently skipped rather than an error: a well-meaning third party
        // signing something must not be able to fail the whole submission for everyone else.
        if allowed.contains(&event.pubkey) {
            voters.insert(event.pubkey);
        }
    }

    Ok(voters)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact() -> Keys {
        Keys::generate()
    }

    fn approval(keys: &Keys, message: &str) -> String {
        EventBuilder::text_note(message)
            .sign_with_keys(keys)
            .expect("signing")
            .as_json()
    }

    fn config(contacts: &[&Keys], threshold: usize) -> RecoveryContactsConfig {
        RecoveryContactsConfig {
            npubs: contacts
                .iter()
                .map(|k| k.public_key().to_bech32().unwrap())
                .collect(),
            threshold,
        }
    }

    #[test]
    fn a_quorum_of_distinct_contacts_is_counted() {
        let (a, b, c) = (contact(), contact(), contact());
        let cfg = config(&[&a, &b, &c], 2);
        let allowed = cfg.compiled().unwrap();
        let txid = "aa".repeat(32);
        let msg = canonical_approval_message(&txid);

        let voters =
            count_distinct_approvals(&txid, &[approval(&a, &msg), approval(&b, &msg)], &allowed)
                .unwrap();
        assert_eq!(voters.len(), 2);
        assert!(voters.len() >= cfg.threshold);
    }

    /// The obvious attack: one contact submitting their own signature repeatedly to reach a
    /// threshold alone.
    #[test]
    fn one_contact_cannot_reach_a_quorum_by_repeating_themselves() {
        let (a, b) = (contact(), contact());
        let cfg = config(&[&a, &b], 2);
        let allowed = cfg.compiled().unwrap();
        let txid = "bb".repeat(32);
        let msg = canonical_approval_message(&txid);

        let sig = approval(&a, &msg);
        let voters =
            count_distinct_approvals(&txid, &[sig.clone(), sig.clone(), sig], &allowed).unwrap();
        assert_eq!(voters.len(), 1, "duplicates must collapse to one vote");
        assert!(voters.len() < cfg.threshold);
    }

    /// An approval is bound to one txid. Capturing one and replaying it against a different
    /// spend must fail - otherwise a single genuine recovery would authorize every later one.
    #[test]
    fn an_approval_for_one_txid_does_not_authorize_another() {
        let a = contact();
        let cfg = config(&[&a, &contact()], 2);
        let allowed = cfg.compiled().unwrap();

        let signed_for = "cc".repeat(32);
        let event = approval(&a, &canonical_approval_message(&signed_for));

        let other = "dd".repeat(32);
        let err = count_distinct_approvals(&other, &[event], &allowed).unwrap_err();
        assert!(matches!(err, ApprovalError::WrongMessage { index: 0 }));
    }

    #[test]
    fn a_stranger_does_not_count_but_does_not_break_the_submission() {
        let (a, b, stranger) = (contact(), contact(), contact());
        let cfg = config(&[&a, &b], 2);
        let allowed = cfg.compiled().unwrap();
        let txid = "ee".repeat(32);
        let msg = canonical_approval_message(&txid);

        let voters = count_distinct_approvals(
            &txid,
            &[
                approval(&stranger, &msg),
                approval(&a, &msg),
                approval(&b, &msg),
            ],
            &allowed,
        )
        .unwrap();
        assert_eq!(
            voters.len(),
            2,
            "the stranger is ignored, the rest still count"
        );
    }

    #[test]
    fn a_forged_event_is_rejected() {
        let a = contact();
        let cfg = config(&[&a, &contact()], 2);
        let allowed = cfg.compiled().unwrap();
        let txid = "ff".repeat(32);
        let msg = canonical_approval_message(&txid);

        // Tamper with the content after signing: the id/signature no longer commit to it.
        let mut json: serde_json::Value = serde_json::from_str(&approval(&a, &msg)).unwrap();
        json["content"] = serde_json::Value::String(msg.replace("release", "RELEASE"));
        let err = count_distinct_approvals(&txid, &[json.to_string()], &allowed).unwrap_err();
        assert!(matches!(err, ApprovalError::Malformed { .. }), "{err:?}");
    }

    #[test]
    fn a_threshold_of_one_is_refused() {
        let err = config(&[&contact(), &contact()], 1)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least 2"), "{err}");
    }

    #[test]
    fn a_threshold_nobody_could_reach_is_refused() {
        let err = config(&[&contact(), &contact()], 3)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn a_duplicated_contact_is_refused() {
        let a = contact();
        let err = config(&[&a, &a], 2).validate().unwrap_err().to_string();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn a_valid_config_validates() {
        config(&[&contact(), &contact(), &contact()], 2)
            .validate()
            .expect("should validate");
    }
}
