//! Encrypted, off-machine backup of everything needed to reconstruct this service's config and
//! SERVER signing capability after losing the machine that held `wallet.toml` - even though the
//! SATOCHIP, MOBILE, and SERVER keys themselves are all still intact and unaffected.
//!
//! This is deliberately narrow: it backs up the *box*, not the keys. SATOCHIP and MOBILE already
//! have their own seed-backup procedures (the hardware wallet's own recovery phrase, the phone
//! wallet's own recovery phrase) - this module has nothing to add there and doesn't touch them.
//! What it backs up is the one thing that has no other backup path by default: the SERVER
//! account-level xprv (normally just a file on this one machine) plus the `wallet.toml` that
//! ties it to a specific descriptor shape, timelock, and the other two xpubs. Without this,
//! losing the box strands funds behind the RECOVERY path even though nothing was actually lost.
//!
//! Encryption is via the `age` crate (<https://age-encryption.org>), a well-reviewed file
//! encryption format with a scrypt-based passphrase recipient - not a hand-rolled KDF+AEAD
//! combination. The output is ASCII-armored, so it's safe to paste into a text file, a Nostr
//! event (see `nostr_kit.rs`), or print as a QR code for a paper backup.

use std::path::Path;

use age::secrecy::SecretString;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{ServerSigningConfig, WalletConfig};

/// Payload format version. Bump when the shape changes, so `import` can give a clear
/// "this backup is from a newer/older version of this tool" error instead of a confusing
/// deserialize failure.
const PAYLOAD_VERSION: u32 = 1;

/// Below this length, a passphrase is refused outright. This blob is meant to end up stored
/// somewhere *less* trusted than the machine it came from (a Nostr relay, a paper backup) - a
/// weak passphrase there is a real theft path, not a formality.
const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryKitPayload {
    version: u32,
    /// Unix seconds at export time - informational only, surfaced back on import so the user
    /// can sanity-check they're restoring the backup they think they are.
    created_at: i64,
    /// The exact bytes of the `wallet.toml` this kit was exported from, verbatim. Reconstructing
    /// it from typed fields would silently drop comments, formatting, and any section this
    /// module doesn't know about (`[notify]`, `[policy]`, `[recovery]`, ...).
    wallet_toml: String,
    /// The SERVER account-level xprv, exactly as read from `server_signing.xprv_file` /
    /// `xprv_env_var` at export time - the one piece of key material this service holds with no
    /// other backup by default.
    server_xprv: String,
}

/// What a decrypted recovery kit contains. Callers decide what to do with it (write to disk,
/// print, diff against an existing config); this module only decrypts and validates.
///
/// `Debug` is derived for test assertions only - `server_xprv` is live key material, so callers
/// must never actually log this value with `{:?}`.
#[derive(Debug)]
pub struct RecoveryKitContents {
    pub created_at: i64,
    pub wallet_toml: String,
    pub server_xprv: String,
}

/// Reads `config_path` and the SERVER xprv it points at, and returns an ASCII-armored,
/// passphrase-encrypted backup blob.
///
/// Fails closed: refuses a config that doesn't validate, one with no `[server_signing]` section
/// (nothing to back up), or a passphrase under [`MIN_PASSPHRASE_CHARS`] characters.
pub fn export(config_path: &Path, passphrase: &str) -> Result<String> {
    check_passphrase_strength(passphrase)?;

    let wallet_toml = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    // Loaded (and thus fully validated) even though only `server_signing` is used below - an
    // export must never succeed for a config that wouldn't actually `load()` on the other end.
    let cfg = WalletConfig::load(config_path)?;
    let signing_cfg = cfg
        .server_signing
        .as_ref()
        .context("config has no [server_signing] section - nothing to back up")?;
    let server_xprv = read_server_xprv(signing_cfg)?;

    let payload = RecoveryKitPayload {
        version: PAYLOAD_VERSION,
        created_at: now_unix(),
        wallet_toml,
        server_xprv,
    };
    let plaintext = serde_json::to_vec(&payload).context("serializing recovery kit payload")?;

    let recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_string()));
    age::encrypt_and_armor(&recipient, &plaintext).context("age-encrypting recovery kit")
}

/// Decrypts an armored backup blob produced by [`export`].
pub fn import(armored: &str, passphrase: &str) -> Result<RecoveryKitContents> {
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));
    let plaintext = age::decrypt(&identity, armored.as_bytes()).map_err(|e| {
        anyhow::anyhow!("decryption failed (wrong passphrase, or a corrupt/truncated backup): {e}")
    })?;
    let payload: RecoveryKitPayload = serde_json::from_slice(&plaintext)
        .context("decrypted data is not a recovery kit payload")?;
    if payload.version != PAYLOAD_VERSION {
        bail!(
            "recovery kit is format version {}, this build only understands version {PAYLOAD_VERSION}",
            payload.version
        );
    }
    Ok(RecoveryKitContents {
        created_at: payload.created_at,
        wallet_toml: payload.wallet_toml,
        server_xprv: payload.server_xprv,
    })
}

fn check_passphrase_strength(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!(
            "recovery kit passphrase must be at least {MIN_PASSPHRASE_CHARS} characters - this \
             blob may end up stored somewhere less trusted than this machine"
        );
    }
    Ok(())
}

fn read_server_xprv(cfg: &ServerSigningConfig) -> Result<String> {
    let raw = if let Some(path) = &cfg.xprv_file {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading server_signing.xprv_file {path}"))?
    } else if let Some(var) = &cfg.xprv_env_var {
        std::env::var(var).with_context(|| format!("reading server_signing.xprv_env_var {var}"))?
    } else {
        bail!("server_signing: one of xprv_file or xprv_env_var is required");
    };
    Ok(raw.trim().to_string())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_key_spec_with_xpriv;

    /// Writes a minimal-but-valid wallet.toml (three test keys + [server_signing] pointing at a
    /// sibling xprv file) into a fresh temp dir, and returns its path.
    fn fixture_config(test_name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cosigner-test-recovery-kit-{}-{test_name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let (satochip, _) = test_key_spec_with_xpriv(0x01);
        let (mobile, _) = test_key_spec_with_xpriv(0x02);
        let (server, server_xprv) = test_key_spec_with_xpriv(0x03);

        let xprv_path = dir.join("server.xprv");
        std::fs::write(&xprv_path, server_xprv.to_string()).unwrap();

        let toml = format!(
            r#"
            network = "signet"
            timelock_blocks = 4320

            [keys.satochip]
            master_fingerprint = "{}"
            derivation_path = "{}"
            xpub = "{}"

            [keys.mobile]
            master_fingerprint = "{}"
            derivation_path = "{}"
            xpub = "{}"

            [keys.server]
            master_fingerprint = "{}"
            derivation_path = "{}"
            xpub = "{}"

            [server_signing]
            xprv_file = "{}"
            "#,
            satochip.master_fingerprint,
            satochip.derivation_path,
            satochip.xpub,
            mobile.master_fingerprint,
            mobile.derivation_path,
            mobile.xpub,
            server.master_fingerprint,
            server.derivation_path,
            server.xpub,
            xprv_path.display(),
        );

        let config_path = dir.join("wallet.toml");
        std::fs::write(&config_path, toml).unwrap();
        config_path
    }

    #[test]
    fn export_then_import_round_trips_the_config_and_server_key() {
        let config_path = fixture_config("round_trips");
        let original_toml = std::fs::read_to_string(&config_path).unwrap();
        let (_, server_xprv) = test_key_spec_with_xpriv(0x03);

        let armored = export(&config_path, "correct horse battery staple").unwrap();
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let restored = import(&armored, "correct horse battery staple").unwrap();
        assert_eq!(restored.wallet_toml, original_toml);
        assert_eq!(restored.server_xprv, server_xprv.to_string());
        assert!(restored.created_at > 0);
    }

    #[test]
    fn import_with_wrong_passphrase_fails() {
        let config_path = fixture_config("wrong_passphrase");
        let armored = export(&config_path, "correct horse battery staple").unwrap();
        let err = import(&armored, "wrong passphrase entirely").unwrap_err();
        assert!(err.to_string().contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn export_refuses_a_weak_passphrase() {
        let config_path = fixture_config("weak_passphrase");
        let err = export(&config_path, "short").unwrap_err();
        assert!(err.to_string().contains("at least"), "got: {err}");
    }

    #[test]
    fn export_refuses_a_config_with_no_server_signing_section() {
        let dir = std::env::temp_dir().join(format!(
            "cosigner-test-recovery-kit-{}-no_server_signing",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (satochip, _) = test_key_spec_with_xpriv(0x01);
        let (mobile, _) = test_key_spec_with_xpriv(0x02);
        let (server, _) = test_key_spec_with_xpriv(0x03);
        let toml = format!(
            r#"
            network = "signet"
            timelock_blocks = 4320

            [keys.satochip]
            master_fingerprint = "{}"
            derivation_path = "{}"
            xpub = "{}"

            [keys.mobile]
            master_fingerprint = "{}"
            derivation_path = "{}"
            xpub = "{}"

            [keys.server]
            master_fingerprint = "{}"
            derivation_path = "{}"
            xpub = "{}"
            "#,
            satochip.master_fingerprint,
            satochip.derivation_path,
            satochip.xpub,
            mobile.master_fingerprint,
            mobile.derivation_path,
            mobile.xpub,
            server.master_fingerprint,
            server.derivation_path,
            server.xpub,
        );
        let config_path = dir.join("wallet.toml");
        std::fs::write(&config_path, toml).unwrap();

        let err = export(&config_path, "correct horse battery staple").unwrap_err();
        assert!(err.to_string().contains("server_signing"), "got: {err}");
    }

    #[test]
    fn import_rejects_a_future_payload_version() {
        // Simulate a backup from a hypothetical future format version: encrypt a payload with
        // version = PAYLOAD_VERSION + 1 directly, bypassing `export`.
        let payload = RecoveryKitPayload {
            version: PAYLOAD_VERSION + 1,
            created_at: 1,
            wallet_toml: String::new(),
            server_xprv: String::new(),
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let recipient = age::scrypt::Recipient::new(SecretString::from(
            "correct horse battery staple".to_string(),
        ));
        let armored = age::encrypt_and_armor(&recipient, &plaintext).unwrap();

        let err = import(&armored, "correct horse battery staple").unwrap_err();
        assert!(err.to_string().contains("format version"), "got: {err}");
    }
}
