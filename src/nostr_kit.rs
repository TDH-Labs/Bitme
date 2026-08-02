//! Publishes/fetches the recovery kit blob (see `recovery_kit.rs`) to/from Nostr relays, as
//! decentralized off-machine storage - no single cloud account (iCloud, Google Drive) to
//! compromise or lose access to, and no dependency on this project's own infrastructure.
//!
//! The Nostr identity used to publish/locate the backup is deterministically derived from the
//! SAME passphrase used to encrypt it in `recovery_kit::export`, via a fixed-cost, domain
//! separated scrypt KDF (see [`derive_nostr_keys`]) - so there is exactly one secret to
//! remember, not two. This identity carries no fund-security weight of its own: the passphrase
//! is what actually protects the backup's contents (age/scrypt, per `recovery_kit.rs`). This key
//! only controls who can publish a *new* backup under this identifier on a given relay (i.e. who
//! can replace it), via NIP-78 "application-specific data" parameterized-replaceable events
//! (kind 30078, <https://github.com/nostr-protocol/nips/blob/master/78.md>).
//!
//! Deliberately outbound-only: this only ever opens connections *to* relays to publish or query,
//! and never listens for inbound connections. Relays are treated as commodity storage, nothing
//! more - the content published is already opaque, passphrase-encrypted ciphertext, so no relay
//! operator learns anything about the wallet from it beyond "this pubkey stored something here
//! on this date."

use std::time::Duration;

use anyhow::{bail, Context, Result};
use nostr_sdk::prelude::*;

/// Domain-separation label for deriving the Nostr identity from the recovery kit passphrase.
/// Fixed forever: changing it (or the scrypt params below) changes which identity a given
/// passphrase derives, silently breaking anyone's ability to re-locate an existing backup.
const NOSTR_IDENTITY_DOMAIN: &[u8] = b"bitme-cosigner/recovery-kit/nostr-identity/v1";

/// The `d` tag identifying this service's recovery kit event, so it doesn't collide with any
/// other NIP-78 application data the same derived identity might otherwise ever publish.
const RECOVERY_KIT_D_TAG: &str = "bitme-cosigner-recovery-kit";

/// How long to wait for relays to answer a fetch query before giving up on the ones that haven't.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Deterministically derives a Nostr keypair from the recovery kit passphrase.
///
/// Fixed (not auto-tuned) scrypt cost parameters, unlike `age`'s own passphrase KDF: there's no
/// side channel here to store chosen parameters in (no accompanying ciphertext header), so they
/// must be identical on every call for the same passphrase to always re-derive the same
/// identity. log_n=15 (2^15 rounds) costs roughly a few hundred ms to ~1s on modest hardware -
/// deliberately slow, matching age's own target order of magnitude, so that recovering this
/// derivation from a leaked pubkey is not meaningfully easier than brute-forcing the passphrase
/// against the age-encrypted blob itself.
fn derive_nostr_keys(passphrase: &str) -> Result<Keys> {
    let params = scrypt::Params::new(15, 8, 1, 32).context("invalid scrypt params")?;
    let mut output = [0u8; 32];
    scrypt::scrypt(
        passphrase.as_bytes(),
        NOSTR_IDENTITY_DOMAIN,
        &params,
        &mut output,
    )
    .map_err(|e| anyhow::anyhow!("scrypt key derivation failed: {e}"))?;
    let secret_key = SecretKey::from_slice(&output).context(
        "derived bytes are not a valid secp256k1 secret key (astronomically unlikely - \
                   scrypt output is effectively uniform)",
    )?;
    Ok(Keys::new(secret_key))
}

/// The outcome of a [`publish`] call.
pub struct PublishOutcome {
    /// The bech32-encoded public key (`npub1...`) this backup was published under - the same
    /// passphrase always re-derives this same identity, so it's shown for the user's own
    /// sanity-checking, not because it needs to be recorded anywhere.
    pub npub: String,
    pub relays_succeeded: usize,
    pub relays_failed: Vec<(String, String)>,
}

/// Publishes an already-encrypted recovery kit blob (the output of `recovery_kit::export`) to
/// the given relays. `armored_backup` is NOT re-encrypted here - it is already opaque
/// age/scrypt ciphertext, and re-encrypting it under the Nostr identity would just add a second,
/// weaker-KDF layer around the same passphrase for no real gain.
pub async fn publish(
    armored_backup: &str,
    passphrase: &str,
    relay_urls: &[String],
) -> Result<PublishOutcome> {
    if relay_urls.is_empty() {
        bail!("at least one relay URL is required");
    }
    let keys = derive_nostr_keys(passphrase)?;
    let event = EventBuilder::new(Kind::ApplicationSpecificData, armored_backup)
        .tag(Tag::identifier(RECOVERY_KIT_D_TAG))
        .sign_with_keys(&keys)
        .context("signing recovery kit event")?;

    let client = Client::new(keys.clone());
    for url in relay_urls {
        client
            .add_relay(url.as_str())
            .await
            .with_context(|| format!("adding relay {url}"))?;
    }
    client.connect().await;

    let result = client.send_event(&event).await;
    client.disconnect().await;

    let output = result.context("publishing recovery kit event to relay pool")?;
    let relays_succeeded = output.success.len();
    let relays_failed = output
        .failed
        .into_iter()
        .map(|(url, reason)| (url.to_string(), reason))
        .collect();

    Ok(PublishOutcome {
        npub: keys.public_key().to_bech32().context("encoding npub")?,
        relays_succeeded,
        relays_failed,
    })
}

/// Fetches the latest recovery kit event for the identity derived from `passphrase`, across the
/// given relays, and returns its (still-encrypted) content - feed this straight into
/// `recovery_kit::import`. Returns `Ok(None)` if no relay had a matching event, which is not
/// itself an error (wrong passphrase and "never published" look identical from here - the
/// underlying `recovery_kit::import` call is where a wrong passphrase actually gets diagnosed).
pub async fn fetch(passphrase: &str, relay_urls: &[String]) -> Result<Option<String>> {
    if relay_urls.is_empty() {
        bail!("at least one relay URL is required");
    }
    let keys = derive_nostr_keys(passphrase)?;
    let client = Client::default();
    for url in relay_urls {
        client
            .add_relay(url.as_str())
            .await
            .with_context(|| format!("adding relay {url}"))?;
    }
    client.connect().await;

    let filter = Filter::new()
        .author(keys.public_key())
        .kind(Kind::ApplicationSpecificData)
        .identifier(RECOVERY_KIT_D_TAG)
        .limit(1);
    let result = client.fetch_events(filter, FETCH_TIMEOUT).await;
    client.disconnect().await;

    let events = result.context("fetching recovery kit event from relay pool")?;
    // Parameterized-replaceable events keep only the latest per (kind, pubkey, d-tag) *per
    // relay*, but different relays may not agree on which one that is (one could be stale) -
    // take the newest across all of them, not just whichever relay answered.
    let latest = events.into_iter().max_by_key(|e| e.created_at);
    Ok(latest.map(|e| e.content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_for_the_same_passphrase() {
        let a = derive_nostr_keys("correct horse battery staple").unwrap();
        let b = derive_nostr_keys("correct horse battery staple").unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn different_passphrases_derive_different_identities() {
        let a = derive_nostr_keys("correct horse battery staple").unwrap();
        let b = derive_nostr_keys("another passphrase entirely").unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    /// Live-relay round trip. Skips gracefully without `COSIGNER_NOSTR_RELAY_URLS` set (a
    /// comma-separated list of relay URLs) - the same "write it correctly, verify structurally
    /// here, flag live-network verification as pending" pattern used for the regtest tests,
    /// since this sandbox has no route to real Nostr relays.
    ///
    /// ```sh
    /// COSIGNER_NOSTR_RELAY_URLS=wss://relay.damus.io,wss://nos.lol \
    /// cargo test --lib nostr_kit::tests::publish_then_fetch_round_trips_over_real_relays -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "needs COSIGNER_NOSTR_RELAY_URLS and real network access - see doc comment"]
    async fn publish_then_fetch_round_trips_over_real_relays() {
        let Ok(raw) = std::env::var("COSIGNER_NOSTR_RELAY_URLS") else {
            eprintln!("COSIGNER_NOSTR_RELAY_URLS not set - skipping live relay test");
            return;
        };
        let relays: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).collect();

        // A unique-per-run passphrase, so repeated test runs don't collide on the same `d` tag
        // identity and don't leave a nonsense trail of well-known test backups on real relays.
        let passphrase = format!(
            "cosigner-nostr-kit-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let fake_backup = "-----BEGIN AGE ENCRYPTED FILE-----\ntest payload, not a real backup\n-----END AGE ENCRYPTED FILE-----\n";

        let published = publish(fake_backup, &passphrase, &relays)
            .await
            .expect("publish should succeed against at least one relay");
        assert!(
            published.relays_succeeded >= 1,
            "no relay accepted the event"
        );

        let fetched = fetch(&passphrase, &relays)
            .await
            .expect("fetch should succeed")
            .expect("should find the event just published");
        assert_eq!(fetched, fake_backup);
    }
}
