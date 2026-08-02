//! TOML configuration for the wallet descriptor: three key origins + the recovery timelock.

use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::{Network, NetworkKind};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl ChainNetwork {
    pub fn to_bitcoin_network(self) -> Network {
        match self {
            ChainNetwork::Mainnet => Network::Bitcoin,
            ChainNetwork::Testnet => Network::Testnet,
            ChainNetwork::Signet => Network::Signet,
            ChainNetwork::Regtest => Network::Regtest,
        }
    }

    /// xpub/tpub version bytes only distinguish mainnet from "everything else" -
    /// testnet, signet and regtest all share the test version bytes.
    pub fn xpub_network_kind(self) -> NetworkKind {
        match self {
            ChainNetwork::Mainnet => NetworkKind::Main,
            ChainNetwork::Testnet | ChainNetwork::Signet | ChainNetwork::Regtest => {
                NetworkKind::Test
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeySpec {
    /// 8 hex character BIP32 master key fingerprint this xpub was derived from.
    pub master_fingerprint: String,
    /// BIP32 derivation path from the master key to `xpub` (e.g. "48h/1h/0h/2h").
    pub derivation_path: String,
    /// The extended public key AT `derivation_path`. No private material, ever.
    pub xpub: String,
}

impl KeySpec {
    fn validate(&self, role: &str, network: ChainNetwork) -> Result<()> {
        let fp = self.master_fingerprint.trim().to_lowercase();
        if fp.len() != 8 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "keys.{role}.master_fingerprint must be exactly 8 hex characters, got {:?}",
                self.master_fingerprint
            );
        }

        let path = DerivationPath::from_str(self.derivation_path.trim()).with_context(|| {
            format!(
                "keys.{role}.derivation_path {:?} is not a valid BIP32 derivation path",
                self.derivation_path
            )
        })?;

        let xpub = Xpub::from_str(self.xpub.trim())
            .with_context(|| format!("keys.{role}.xpub is not a valid extended public key"))?;

        if xpub.network != network.xpub_network_kind() {
            bail!(
                "keys.{role}.xpub was generated for {:?} but the config network is {:?}",
                xpub.network,
                network
            );
        }

        if xpub.depth as usize != path.len() {
            bail!(
                "keys.{role}.xpub has depth {} but keys.{role}.derivation_path has {} step(s) ({}); \
                 the xpub must be the extended public key AT that exact derivation path, not the \
                 master key or an intermediate one",
                xpub.depth,
                path.len(),
                self.derivation_path
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeysConfig {
    pub satochip: KeySpec,
    pub mobile: KeySpec,
    pub server: KeySpec,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletConfig {
    pub network: ChainNetwork,
    /// Refuses to build/run against mainnet unless explicitly set. See hard rules in README.
    #[serde(default)]
    pub i_understand_this_is_mainnet: bool,
    /// Relative timelock (in blocks) for the RECOVERY path (SATOCHIP + MOBILE). Default 12960 (~90 days).
    pub timelock_blocks: u16,
    pub keys: KeysConfig,
    /// Only required by `cosigner serve`; the descriptor CLI doesn't need a node.
    pub bitcoind: Option<BitcoindConfig>,
    /// Only required by `cosigner serve`.
    pub server: Option<ServerConfig>,
    /// Only required once policy-gated signing (`/sign_psbt`) is wired up; the descriptor
    /// CLI and `/inspect` don't consult it.
    pub policy: Option<crate::policy::PolicyConfig>,
    /// Only required by `/sign_psbt`. Never put an xprv directly in this file - point at a
    /// file path or an env var instead.
    pub server_signing: Option<ServerSigningConfig>,
    /// Only required by `/sign_psbt`. Governs the out-of-band notify-then-hold-then-sign flow:
    /// an approved spend is never signed immediately - it's queued, a notification is sent,
    /// and it only actually gets signed once `hold_seconds` has passed with no veto.
    pub notify: Option<NotifyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyConfig {
    /// How long an approved spend is held (and vetoable via `POST /veto/{id}`) before this
    /// service actually signs it. 0 means "sign on the next sweep tick" - still notifies
    /// first, but leaves essentially no veto window.
    #[serde(default)]
    pub hold_seconds: i64,
    /// How often the background sweeper checks for spends whose hold has elapsed.
    #[serde(default = "default_sweep_interval_seconds")]
    pub sweep_interval_seconds: u64,
    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
}

fn default_sweep_interval_seconds() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize)]
pub struct NtfyConfig {
    /// Full topic URL to POST to, e.g. "https://ntfy.sh/your-private-topic".
    pub url: String,
    /// Sent as a bearer token, if the topic requires auth (e.g. a self-hosted ntfy server).
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: String,
}

fn default_smtp_port() -> u16 {
    587
}

impl NotifyConfig {
    fn validate(&self) -> Result<()> {
        if self.hold_seconds < 0 {
            bail!("notify.hold_seconds must not be negative");
        }
        if self.ntfy.is_none() && self.smtp.is_none() {
            bail!(
                "notify: at least one of [notify.ntfy] or [notify.smtp] is required - a hold \
                 with no notification channel would silently sign with nobody able to veto it"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSigningConfig {
    /// Path to a file containing the SERVER account-level xprv (and nothing else). Mutually
    /// exclusive with `xprv_env_var`.
    #[serde(default)]
    pub xprv_file: Option<String>,
    /// Name of an environment variable holding the SERVER account-level xprv. Mutually
    /// exclusive with `xprv_file`.
    #[serde(default)]
    pub xprv_env_var: Option<String>,
}

impl ServerSigningConfig {
    fn validate(&self) -> Result<()> {
        match (&self.xprv_file, &self.xprv_env_var) {
            (Some(_), Some(_)) => {
                bail!("server_signing: set either xprv_file or xprv_env_var, not both")
            }
            (None, None) => bail!("server_signing: one of xprv_file or xprv_env_var is required"),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    /// e.g. "http://127.0.0.1:38332" for signet, "http://127.0.0.1:18443" for regtest.
    pub rpc_url: String,
    /// Path to bitcoind's .cookie file. Mutually exclusive with rpc_user/rpc_password.
    #[serde(default)]
    pub rpc_cookie_file: Option<String>,
    #[serde(default)]
    pub rpc_user: Option<String>,
    #[serde(default)]
    pub rpc_password: Option<String>,
}

impl BitcoindConfig {
    fn validate(&self) -> Result<()> {
        let has_cookie = self.rpc_cookie_file.is_some();
        let has_userpass = self.rpc_user.is_some() || self.rpc_password.is_some();
        if has_cookie && has_userpass {
            bail!("bitcoind: set either rpc_cookie_file or rpc_user/rpc_password, not both");
        }
        if !has_cookie && !has_userpass {
            bail!("bitcoind: one of rpc_cookie_file or rpc_user+rpc_password is required");
        }
        if has_userpass && (self.rpc_user.is_none() || self.rpc_password.is_none()) {
            bail!("bitcoind: both rpc_user and rpc_password are required when not using rpc_cookie_file");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// e.g. "127.0.0.1:8080". Bind to loopback unless you're deliberately exposing this
    /// service - it holds one of three keys and should sit behind your own network controls.
    pub bind_addr: String,
    /// How many unused addresses ahead of the last-seen one to check, on each of the
    /// external/internal chains, when deciding whether a scriptPubkey is ours.
    #[serde(default = "default_gap_limit")]
    pub gap_limit: u32,
    /// Path to the SQLite ledger database file (created if missing). Only required by
    /// `/sign_psbt`; `/inspect` alone doesn't touch it.
    #[serde(default)]
    pub ledger_db_path: Option<String>,
}

fn default_gap_limit() -> u32 {
    1000
}

impl WalletConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: WalletConfig = toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.network == ChainNetwork::Mainnet && !self.i_understand_this_is_mainnet {
            bail!(
                "network = \"mainnet\" but i_understand_this_is_mainnet is not true; \
                 this service only builds/runs against signet or regtest by default"
            );
        }
        if self.timelock_blocks == 0 {
            bail!("timelock_blocks must be non-zero (BIP68 relative locktimes start at 1 block)");
        }

        self.keys.satochip.validate("satochip", self.network)?;
        self.keys.mobile.validate("mobile", self.network)?;
        self.keys.server.validate("server", self.network)?;

        let fingerprints: HashSet<String> = [
            self.keys.satochip.master_fingerprint.trim().to_lowercase(),
            self.keys.mobile.master_fingerprint.trim().to_lowercase(),
            self.keys.server.master_fingerprint.trim().to_lowercase(),
        ]
        .into_iter()
        .collect();
        if fingerprints.len() != 3 {
            bail!(
                "keys.satochip, keys.mobile and keys.server must have distinct master_fingerprint values \
                 (SATOCHIP, MOBILE and SERVER must be three different keys)"
            );
        }

        let xpubs: HashSet<String> = [
            self.keys.satochip.xpub.trim().to_string(),
            self.keys.mobile.xpub.trim().to_string(),
            self.keys.server.xpub.trim().to_string(),
        ]
        .into_iter()
        .collect();
        if xpubs.len() != 3 {
            bail!(
                "keys.satochip, keys.mobile and keys.server must have distinct xpub values \
                 (SATOCHIP, MOBILE and SERVER must be three different keys)"
            );
        }

        if let Some(bitcoind) = &self.bitcoind {
            bitcoind.validate()?;
        }

        if let Some(policy) = &self.policy {
            policy.compile(self.network).context("[policy]")?;
        }

        if let Some(server_signing) = &self.server_signing {
            server_signing.validate()?;
        }

        if let Some(notify) = &self.notify {
            notify.validate().context("[notify]")?;
        }

        Ok(())
    }

    /// `cosigner serve` needs `[bitcoind]` and `[server]`; the descriptor CLI doesn't.
    pub fn require_server_config(&self) -> Result<(&BitcoindConfig, &ServerConfig)> {
        let bitcoind = self.bitcoind.as_ref().context(
            "config is missing the [bitcoind] section, required to run `cosigner serve`",
        )?;
        let server = self
            .server
            .as_ref()
            .context("config is missing the [server] section, required to run `cosigner serve`")?;
        Ok((bitcoind, server))
    }

    /// `/sign_psbt` additionally needs `[policy]` and `[server_signing]`.
    pub fn require_signing_config(
        &self,
    ) -> Result<(&crate::policy::PolicyConfig, &ServerSigningConfig)> {
        let policy = self
            .policy
            .as_ref()
            .context("config is missing the [policy] section, required for /sign_psbt")?;
        let server_signing = self
            .server_signing
            .as_ref()
            .context("config is missing the [server_signing] section, required for /sign_psbt")?;
        Ok((policy, server_signing))
    }

    /// `/sign_psbt`'s notify-then-hold-then-sign flow additionally needs `[notify]`.
    pub fn require_notify_config(&self) -> Result<&NotifyConfig> {
        self.notify
            .as_ref()
            .context("config is missing the [notify] section, required for /sign_psbt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_wallet_config;

    #[test]
    fn valid_config_passes() {
        let cfg = test_wallet_config(12960);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn mainnet_is_refused_without_explicit_opt_in() {
        let mut cfg = test_wallet_config(12960);
        cfg.network = ChainNetwork::Mainnet;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("i_understand_this_is_mainnet"), "got: {err}");
    }

    #[test]
    fn mainnet_opt_in_still_requires_mainnet_keys() {
        // The test fixture uses testnet-kind xpubs; even with the opt-in flag set, claiming
        // mainnet must fail because the xpub version bytes don't match.
        let mut cfg = test_wallet_config(12960);
        cfg.network = ChainNetwork::Mainnet;
        cfg.i_understand_this_is_mainnet = true;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(!err.contains("i_understand_this_is_mainnet"), "got: {err}");
        assert!(err.contains("network"), "got: {err}");
    }

    #[test]
    fn no_policy_section_is_valid() {
        let cfg = test_wallet_config(12960);
        assert!(cfg.policy.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn malformed_policy_whitelist_address_fails_validation() {
        let mut cfg = test_wallet_config(12960);
        cfg.policy = Some(crate::policy::PolicyConfig {
            max_tx_sat: 1,
            max_daily_sat: 1,
            max_weekly_sat: 1,
            max_monthly_sat: 1,
            max_fee_sat: 1,
            max_fee_rate_sat_per_vb: 1.0,
            destination_whitelist: Some(vec!["not-an-address".to_string()]),
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("policy"), "got: {err}");
    }

    #[test]
    fn no_notify_section_is_valid() {
        let cfg = test_wallet_config(12960);
        assert!(cfg.notify.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn notify_without_any_channel_fails_validation() {
        let mut cfg = test_wallet_config(12960);
        cfg.notify = Some(NotifyConfig {
            hold_seconds: 300,
            sweep_interval_seconds: 5,
            ntfy: None,
            smtp: None,
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("notify"), "got: {err}");
    }

    #[test]
    fn notify_with_ntfy_channel_and_zero_hold_is_valid() {
        let mut cfg = test_wallet_config(12960);
        cfg.notify = Some(NotifyConfig {
            hold_seconds: 0,
            sweep_interval_seconds: 5,
            ntfy: Some(NtfyConfig {
                url: "https://ntfy.sh/example".to_string(),
                auth_token: None,
            }),
            smtp: None,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn notify_rejects_negative_hold_seconds() {
        let mut cfg = test_wallet_config(12960);
        cfg.notify = Some(NotifyConfig {
            hold_seconds: -1,
            sweep_interval_seconds: 5,
            ntfy: Some(NtfyConfig {
                url: "https://ntfy.sh/example".to_string(),
                auth_token: None,
            }),
            smtp: None,
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("notify"), "got: {err}");
    }

    #[test]
    fn rejects_zero_timelock() {
        let cfg = test_wallet_config(0);
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("timelock_blocks"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_fingerprint() {
        let mut cfg = test_wallet_config(12960);
        cfg.keys.server.master_fingerprint = cfg.keys.satochip.master_fingerprint.clone();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_xpub() {
        let mut cfg = test_wallet_config(12960);
        cfg.keys.server.xpub = cfg.keys.satochip.xpub.clone();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_malformed_fingerprint() {
        let mut cfg = test_wallet_config(12960);
        cfg.keys.satochip.master_fingerprint = "not-hex!".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_short_fingerprint() {
        let mut cfg = test_wallet_config(12960);
        cfg.keys.satochip.master_fingerprint = "abcd".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_xpub_depth_path_mismatch() {
        let mut cfg = test_wallet_config(12960);
        // The fixture's xpub is at depth 4 (48h/1h/0h/2h); claim a 3-step path instead.
        cfg.keys.satochip.derivation_path = "48h/1h/0h".to_string();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("depth"), "got: {err}");
    }

    #[test]
    fn rejects_garbage_xpub() {
        let mut cfg = test_wallet_config(12960);
        cfg.keys.satochip.xpub = "not-an-xpub".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_garbage_derivation_path() {
        let mut cfg = test_wallet_config(12960);
        cfg.keys.satochip.derivation_path = "not-a-path".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_parses_toml_and_validates() {
        let dir = std::env::temp_dir().join(format!(
            "cosigner-test-config-{}-{}",
            std::process::id(),
            "load_parses_toml_and_validates"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.toml");
        let toml = r#"
            network = "regtest"
            timelock_blocks = 6

            [keys.satochip]
            master_fingerprint = "aabbccdd"
            derivation_path = "48h/1h/0h/2h"
            xpub = "not-checked-until-parse"

            [keys.server]
            master_fingerprint = "11223344"
            derivation_path = "48h/1h/0h/2h"
            xpub = "not-checked-until-parse"

            [keys.mobile]
            master_fingerprint = "55667788"
            derivation_path = "48h/1h/0h/2h"
            xpub = "not-checked-until-parse"
        "#;
        std::fs::write(&path, toml).unwrap();
        // Invalid xpubs, so this must fail - but only after successfully parsing the TOML,
        // proving `load` actually reads the file rather than e.g. silently defaulting.
        let err = WalletConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("xpub"), "got: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
