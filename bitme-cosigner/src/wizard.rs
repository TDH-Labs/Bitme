//! Interactive `wallet.toml` generation (`cosigner init`) - replaces hand-editing TOML with
//! ~30 fields by guided prompts, sensible defaults you can just press enter through, and
//! immediate validation of anything a typo could silently break (fingerprints, derivation
//! paths, xpubs, addresses).
//!
//! Split into three layers, each independently testable:
//! - Collection (`run_interactive`) takes a generic `BufRead`/`Write` pair rather than real
//!   stdin/stdout, so the whole prompt flow is testable by feeding it a canned answer script.
//! - Rendering (`render_toml`) is a pure function from [`WizardAnswers`] to TOML text - the
//!   thing actually worth unit-testing field-by-field.
//! - The caller (`main.rs`) is responsible for parsing the rendered text back through
//!   [`crate::config::WalletConfig::load`]-equivalent validation before writing it out, so a
//!   wizard bug can never hand back a config that only fails later, opaquely, on `serve`.

use std::io::{BufRead, Write};

use anyhow::{bail, Context, Result};
use bitcoin::bip32::{DerivationPath, Xpub};
use nostr_sdk::prelude::FromBech32;

use crate::config::ChainNetwork;

#[derive(Debug, Clone)]
pub struct KeyAnswer {
    pub fingerprint: String,
    pub derivation_path: String,
    pub xpub: String,
}

#[derive(Debug, Clone)]
pub enum ServerSigningAnswer {
    File(String),
    EnvVar(String),
}

#[derive(Debug, Clone)]
pub enum BitcoindAuthAnswer {
    Cookie(String),
    UserPass(String, String),
}

#[derive(Debug, Clone)]
pub struct PolicyAnswer {
    pub max_tx_sat: u64,
    pub max_daily_sat: u64,
    pub max_weekly_sat: u64,
    pub max_monthly_sat: u64,
    pub max_fee_sat: u64,
    pub max_fee_rate_sat_per_vb: f64,
    pub destination_whitelist: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct SmtpAnswer {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct NotifyAnswer {
    pub hold_seconds: i64,
    pub sweep_interval_seconds: u64,
    pub renotify_interval_seconds: i64,
    pub ntfy_url: Option<String>,
    pub ntfy_auth_token: Option<String>,
    pub smtp: Option<SmtpAnswer>,
}

#[derive(Debug, Clone)]
pub enum NostrNsecAnswer {
    File(String),
    EnvVar(String),
}

#[derive(Debug, Clone)]
pub struct NostrTransportAnswer {
    pub nsec: NostrNsecAnswer,
    pub relays: Vec<String>,
    pub allowed_npubs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WizardAnswers {
    pub network: ChainNetwork,
    pub timelock_blocks: u16,
    pub hardware: KeyAnswer,
    pub mobile: KeyAnswer,
    pub server: KeyAnswer,
    pub server_signing: ServerSigningAnswer,
    pub bitcoind_rpc_url: String,
    pub bitcoind_auth: BitcoindAuthAnswer,
    pub bind_addr: String,
    pub gap_limit: u32,
    pub ledger_db_path: String,
    pub policy: PolicyAnswer,
    pub notify: NotifyAnswer,
    pub recovery_hold_seconds: i64,
    pub recovery_destination_whitelist: Option<Vec<String>>,
    /// `None` means "not configured" - `cosigner serve` just runs HTTP only, same as an absent
    /// `[nostr_transport]` section. Optional and off by default in the wizard itself: setting it
    /// up needs relay URLs and device npubs the user may not have decided on yet.
    pub nostr_transport: Option<NostrTransportAnswer>,
}

// --- low-level prompt primitives -------------------------------------------------------------

fn read_line<R: BufRead>(input: &mut R) -> Result<String> {
    let mut buf = String::new();
    let n = input.read_line(&mut buf).context("reading input")?;
    if n == 0 {
        bail!("unexpected end of input while running the setup wizard");
    }
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

/// Prompts once, offering `default` if the user just presses enter. Loops (re-prompting) if
/// there's no default and the input is empty - required fields cannot be skipped by accident.
fn prompt<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: Option<&str>,
) -> Result<String> {
    loop {
        match default {
            Some(d) => write!(output, "{label} [{d}]: ")?,
            None => write!(output, "{label}: ")?,
        }
        output.flush()?;
        let line = read_line(input)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(d) = default {
                return Ok(d.to_string());
            }
            writeln!(output, "  this field is required")?;
            continue;
        }
        return Ok(trimmed.to_string());
    }
}

/// Like [`prompt`], but re-prompts until `validate` accepts the answer - so a typo'd
/// fingerprint or xpub is caught right where it was typed, not after the whole wizard finishes.
fn prompt_validated<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: Option<&str>,
    validate: impl Fn(&str) -> Result<(), String>,
) -> Result<String> {
    loop {
        let value = prompt(input, output, label, default)?;
        match validate(&value) {
            Ok(()) => return Ok(value),
            Err(e) => writeln!(output, "  {e}")?,
        }
    }
}

/// Prompts until the answer (case-insensitively) matches one of `choices`, returning the
/// matching canonical (lowercase) choice.
fn prompt_choice<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    choices: &[&str],
    default: &str,
) -> Result<String> {
    let list = choices.join("/");
    loop {
        let value = prompt(input, output, &format!("{label} ({list})"), Some(default))?;
        let lower = value.to_lowercase();
        if let Some(m) = choices.iter().find(|c| **c == lower) {
            return Ok(m.to_string());
        }
        writeln!(output, "  please enter one of: {list}")?;
    }
}

fn prompt_u64<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: u64,
) -> Result<u64> {
    let default_str = default.to_string();
    let s = prompt_validated(input, output, label, Some(&default_str), |v| {
        v.parse::<u64>()
            .map(|_| ())
            .map_err(|_| "not a whole number".to_string())
    })?;
    Ok(s.parse().expect("validated above"))
}

fn prompt_i64<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    default: i64,
) -> Result<i64> {
    let default_str = default.to_string();
    let s = prompt_validated(input, output, label, Some(&default_str), |v| {
        v.parse::<i64>()
            .map(|_| ())
            .map_err(|_| "not a whole number".to_string())
    })?;
    Ok(s.parse().expect("validated above"))
}

/// A comma-separated list, or empty for "not set". Only light structural cleanup here (trim
/// each entry) - the caller is responsible for validating individual entries as addresses.
fn prompt_optional_list<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
) -> Result<Option<Vec<String>>> {
    let raw = prompt(
        input,
        output,
        &format!("{label} (comma-separated, optional)"),
        Some(""),
    )?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(raw.split(',').map(|s| s.trim().to_string()).collect()))
}

/// Like [`prompt_optional_list`], but loops until at least one non-empty entry is given - for
/// lists where "none" isn't a valid answer (relay URLs, allowed npubs).
fn prompt_required_list<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
) -> Result<Vec<String>> {
    loop {
        let raw = prompt(input, output, &format!("{label} (comma-separated)"), None)?;
        let items: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !items.is_empty() {
            return Ok(items);
        }
        writeln!(output, "  at least one is required")?;
    }
}

/// Like [`prompt_required_list`], but re-prompts the whole list until every entry passes
/// `validate` - catching a typo'd relay URL or npub before the wizard finishes, same as the
/// per-field validation above.
fn prompt_required_list_validated<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    validate: impl Fn(&str) -> Result<(), String>,
) -> Result<Vec<String>> {
    loop {
        let items = prompt_required_list(input, output, label)?;
        match items
            .iter()
            .find_map(|item| validate(item).err().map(|e| (item.clone(), e)))
        {
            Some((bad, err)) => writeln!(output, "  {bad:?}: {err}")?,
            None => return Ok(items),
        }
    }
}

pub(crate) fn validate_relay_url(v: &str) -> Result<(), String> {
    if v.starts_with("wss://") || v.starts_with("ws://") {
        Ok(())
    } else {
        Err("relay URLs should start with wss:// (or ws:// for a local/test relay)".to_string())
    }
}

pub(crate) fn validate_npub(v: &str) -> Result<(), String> {
    nostr_sdk::PublicKey::from_bech32(v.trim())
        .map(|_| ())
        .map_err(|e| format!("not a valid npub: {e}"))
}

pub(crate) fn validate_fingerprint(v: &str) -> Result<(), String> {
    if v.len() == 8 && v.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("must be exactly 8 hex characters".to_string())
    }
}

pub(crate) fn validate_derivation_path(v: &str) -> Result<(), String> {
    v.parse::<DerivationPath>()
        .map(|_| ())
        .map_err(|e| format!("not a valid derivation path: {e}"))
}

/// Checks the xpub parses, is on the right network, and has the same depth as `path` - the
/// exact same checks `KeySpec::validate` runs later, surfaced here so a mismatch is caught
/// immediately instead of at the very end of the wizard.
pub(crate) fn validate_xpub_for(
    network: ChainNetwork,
    path: &str,
) -> impl Fn(&str) -> Result<(), String> {
    let path = path.to_string();
    move |v: &str| {
        let xpub: Xpub = v
            .parse()
            .map_err(|e| format!("not a valid extended public key: {e}"))?;
        let expected_kind = network.xpub_network_kind();
        if xpub.network != expected_kind {
            return Err(format!(
                "this xpub is for {:?}, but the network you chose is {:?}",
                xpub.network, network
            ));
        }
        let depth = path
            .parse::<DerivationPath>()
            .expect("validated earlier in the prompt chain")
            .len();
        if xpub.depth as usize != depth {
            return Err(format!(
                "this xpub has depth {}, but the derivation path above has {depth} step(s) - it \
                 must be the extended public key AT that exact path, not the master key",
                xpub.depth
            ));
        }
        Ok(())
    }
}

fn default_bitcoind_port(network: ChainNetwork) -> &'static str {
    match network {
        ChainNetwork::Mainnet => "8332",
        ChainNetwork::Testnet => "18332",
        ChainNetwork::Signet => "38332",
        ChainNetwork::Regtest => "18443",
    }
}

fn prompt_key<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    role: &str,
    network: ChainNetwork,
) -> Result<KeyAnswer> {
    writeln!(output, "\n-- {role} key --")?;
    let fingerprint = prompt_validated(
        input,
        output,
        &format!("{role} master fingerprint (8 hex chars)"),
        None,
        validate_fingerprint,
    )?;
    let derivation_path = prompt_validated(
        input,
        output,
        &format!("{role} derivation path"),
        Some("48h/1h/0h/2h"),
        validate_derivation_path,
    )?;
    let xpub = prompt_validated(
        input,
        output,
        &format!("{role} extended public key (xpub/tpub)"),
        None,
        validate_xpub_for(network, &derivation_path),
    )?;
    Ok(KeyAnswer {
        fingerprint: fingerprint.to_lowercase(),
        derivation_path,
        xpub,
    })
}

/// Runs the whole interactive wizard, prompting `output` and reading answers from `input`.
pub fn run_interactive<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
) -> Result<WizardAnswers> {
    writeln!(output, "Bitme Cosigner setup wizard")?;
    writeln!(
        output,
        "Press enter to accept a default shown in [brackets].\n"
    )?;

    let network_str = loop {
        let v = prompt(input, output, "Network", Some("signet"))?.to_lowercase();
        if ["mainnet", "testnet", "signet", "regtest"].contains(&v.as_str()) {
            if v == "mainnet" {
                let confirm = prompt(
                    input,
                    output,
                    "Type YES to confirm this is really mainnet",
                    None,
                )?;
                if confirm != "YES" {
                    writeln!(output, "  not confirmed - staying on network selection")?;
                    continue;
                }
            }
            break v;
        }
        writeln!(
            output,
            "  please enter one of: mainnet/testnet/signet/regtest"
        )?;
    };
    let network = match network_str.as_str() {
        "mainnet" => ChainNetwork::Mainnet,
        "testnet" => ChainNetwork::Testnet,
        "signet" => ChainNetwork::Signet,
        _ => ChainNetwork::Regtest,
    };

    let timelock_blocks: u16 = loop {
        let v = prompt(
            input,
            output,
            "Recovery timelock in blocks (4320 = ~30 days)",
            Some("4320"),
        )?;
        match v.parse::<u16>() {
            Ok(0) => writeln!(output, "  must be non-zero")?,
            Ok(n) => break n,
            Err(_) => writeln!(output, "  not a valid number of blocks (max 65535)")?,
        }
    };

    let hardware = prompt_key(input, output, "HARDWARE", network)?;
    let mobile = prompt_key(input, output, "MOBILE", network)?;
    let server = prompt_key(input, output, "SERVER", network)?;

    writeln!(output, "\n-- SERVER signing key --")?;
    let signing_kind = prompt_choice(
        input,
        output,
        "Where does the SERVER private key live?",
        &["file", "env"],
        "file",
    )?;
    let server_signing = if signing_kind == "file" {
        ServerSigningAnswer::File(prompt(
            input,
            output,
            "Path to the SERVER xprv file",
            Some("/etc/cosigner/server.xprv"),
        )?)
    } else {
        ServerSigningAnswer::EnvVar(prompt(
            input,
            output,
            "Environment variable holding the SERVER xprv",
            Some("COSIGNER_SERVER_XPRV"),
        )?)
    };

    writeln!(output, "\n-- bitcoind --")?;
    let default_rpc_url = format!("http://127.0.0.1:{}", default_bitcoind_port(network));
    let bitcoind_rpc_url = prompt(input, output, "bitcoind RPC URL", Some(&default_rpc_url))?;
    let auth_kind = prompt_choice(
        input,
        output,
        "bitcoind auth",
        &["cookie", "userpass"],
        "cookie",
    )?;
    let bitcoind_auth = if auth_kind == "cookie" {
        BitcoindAuthAnswer::Cookie(prompt(
            input,
            output,
            "Path to bitcoind's .cookie file",
            None,
        )?)
    } else {
        let user = prompt(input, output, "bitcoind RPC username", None)?;
        let pass = prompt(input, output, "bitcoind RPC password", None)?;
        BitcoindAuthAnswer::UserPass(user, pass)
    };

    writeln!(output, "\n-- this service --")?;
    let bind_addr = prompt(input, output, "Bind address", Some("127.0.0.1:8080"))?;
    let gap_limit = prompt_u64(input, output, "Gap limit", 1000)? as u32;
    let ledger_db_path = prompt(
        input,
        output,
        "Ledger database path",
        Some("/var/lib/cosigner/ledger.sqlite3"),
    )?;

    writeln!(
        output,
        "\n-- spending policy (bootstraps the ledger on first start only) --"
    )?;
    let policy = PolicyAnswer {
        max_tx_sat: prompt_u64(input, output, "Max sat per transaction", 500_000)?,
        max_daily_sat: prompt_u64(input, output, "Max sat per trailing 24h", 1_000_000)?,
        max_weekly_sat: prompt_u64(input, output, "Max sat per trailing 7d", 3_000_000)?,
        max_monthly_sat: prompt_u64(input, output, "Max sat per trailing 30d", 8_000_000)?,
        max_fee_sat: prompt_u64(input, output, "Max fee per transaction, in sat", 50_000)?,
        max_fee_rate_sat_per_vb: {
            let v = prompt(input, output, "Max fee rate (sat/vB)", Some("200.0"))?;
            v.parse().context("max fee rate must be a number")?
        },
        destination_whitelist: prompt_optional_list(
            input,
            output,
            "Destination whitelist addresses",
        )?,
    };

    writeln!(
        output,
        "\n-- notifications (at least one channel is required) --"
    )?;
    let channel = prompt_choice(
        input,
        output,
        "Notification channel",
        &["ntfy", "smtp", "both"],
        "ntfy",
    )?;
    let (ntfy_url, ntfy_auth_token) = if channel == "ntfy" || channel == "both" {
        let url = prompt(
            input,
            output,
            "ntfy topic URL",
            Some("https://ntfy.sh/replace-with-a-private-topic-name"),
        )?;
        let token = prompt(input, output, "ntfy auth token (optional)", Some(""))?;
        (Some(url), if token.is_empty() { None } else { Some(token) })
    } else {
        (None, None)
    };
    let smtp = if channel == "smtp" || channel == "both" {
        Some(SmtpAnswer {
            host: prompt(input, output, "SMTP host", None)?,
            port: prompt_u64(input, output, "SMTP port", 587)? as u16,
            username: prompt(input, output, "SMTP username", None)?,
            password: prompt(input, output, "SMTP password", None)?,
            from: prompt(input, output, "SMTP from address", None)?,
            to: prompt(input, output, "SMTP to address", None)?,
        })
    } else {
        None
    };
    let notify = NotifyAnswer {
        hold_seconds: prompt_i64(
            input,
            output,
            "Hold time before signing an ordinary spend, in seconds",
            900,
        )?,
        sweep_interval_seconds: prompt_u64(input, output, "Sweeper check interval, in seconds", 5)?,
        renotify_interval_seconds: prompt_i64(
            input,
            output,
            "Reminder interval while a spend holds, in seconds",
            21_600,
        )?,
        ntfy_url,
        ntfy_auth_token,
        smtp,
    };

    writeln!(
        output,
        "\n-- recovery (MOBILE + SERVER, if HARDWARE is lost) --"
    )?;
    let recovery_hold_seconds = prompt_i64(
        input,
        output,
        "Hold time before signing a recovery spend, in seconds",
        172_800,
    )?;
    let recovery_destination_whitelist =
        prompt_optional_list(input, output, "Recovery destination whitelist addresses")?;

    writeln!(
        output,
        "\n-- Nostr transport (optional - an alternate, authenticated front door for the same \
         API, no open port needed) --"
    )?;
    let enable_nostr = prompt_choice(input, output, "Enable it now?", &["y", "n"], "n")?;
    let nostr_transport = if enable_nostr == "y" {
        let signing_kind = prompt_choice(
            input,
            output,
            "Where does this service's Nostr nsec live?",
            &["file", "env"],
            "env",
        )?;
        let nsec = if signing_kind == "file" {
            NostrNsecAnswer::File(prompt(
                input,
                output,
                "Path to the nsec file",
                Some("/etc/cosigner/nostr.nsec"),
            )?)
        } else {
            NostrNsecAnswer::EnvVar(prompt(
                input,
                output,
                "Environment variable holding the nsec",
                Some("COSIGNER_NOSTR_NSEC"),
            )?)
        };
        let relays =
            prompt_required_list_validated(input, output, "Relay URLs", validate_relay_url)?;
        let allowed_npubs = prompt_required_list_validated(
            input,
            output,
            "Allowed npubs (one per device that may submit requests)",
            validate_npub,
        )?;
        Some(NostrTransportAnswer {
            nsec,
            relays,
            allowed_npubs,
        })
    } else {
        None
    };

    Ok(WizardAnswers {
        network,
        timelock_blocks,
        hardware,
        mobile,
        server,
        server_signing,
        bitcoind_rpc_url,
        bitcoind_auth,
        bind_addr,
        gap_limit,
        ledger_db_path,
        policy,
        notify,
        recovery_hold_seconds,
        recovery_destination_whitelist,
        nostr_transport,
    })
}

pub(crate) fn network_str(n: ChainNetwork) -> &'static str {
    match n {
        ChainNetwork::Mainnet => "mainnet",
        ChainNetwork::Testnet => "testnet",
        ChainNetwork::Signet => "signet",
        ChainNetwork::Regtest => "regtest",
    }
}

fn toml_list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("{s:?}")).collect();
    format!("[{}]", quoted.join(", "))
}

/// Renders collected answers as a complete `wallet.toml`, including the deployment-specific
/// `[bitcoind]` and `[server]` sections. This is what `cosigner init` writes: a standalone
/// config that `cosigner serve --config` can be pointed at directly.
///
/// Pure - no IO, so this is exhaustively unit-testable.
pub fn render_toml(a: &WizardAnswers) -> String {
    render(a, true)
}

/// Renders the same answers *without* `[bitcoind]` and `[server]`, for containerised
/// deployments where `docker-entrypoint.sh` appends those two sections itself on every start
/// from environment variables (see docs/DOCKER.md). Emitting them here too would produce
/// duplicate TOML tables the moment the entrypoint concatenated the two, so the web setup UI
/// must use this variant rather than [`render_toml`].
///
/// The result is still a valid [`crate::config::WalletConfig`] on its own - `bitcoind` and
/// `server` are both `Option` - so it can be parsed and validated before being written.
pub fn render_user_toml(a: &WizardAnswers) -> String {
    render(a, false)
}

fn render(a: &WizardAnswers, include_deployment: bool) -> String {
    let mut out = String::new();

    out.push_str(&format!("network = \"{}\"\n", network_str(a.network)));
    if a.network == ChainNetwork::Mainnet {
        out.push_str("i_understand_this_is_mainnet = true\n");
    }
    out.push_str(&format!("timelock_blocks = {}\n\n", a.timelock_blocks));

    for (section, key) in [
        ("hardware", &a.hardware),
        ("mobile", &a.mobile),
        ("server", &a.server),
    ] {
        out.push_str(&format!("[keys.{section}]\n"));
        out.push_str(&format!("master_fingerprint = \"{}\"\n", key.fingerprint));
        out.push_str(&format!("derivation_path = \"{}\"\n", key.derivation_path));
        out.push_str(&format!("xpub = \"{}\"\n\n", key.xpub));
    }

    if include_deployment {
        out.push_str("[bitcoind]\n");
        out.push_str(&format!("rpc_url = \"{}\"\n", a.bitcoind_rpc_url));
        match &a.bitcoind_auth {
            BitcoindAuthAnswer::Cookie(path) => {
                out.push_str(&format!("rpc_cookie_file = \"{path}\"\n\n"));
            }
            BitcoindAuthAnswer::UserPass(user, pass) => {
                out.push_str(&format!("rpc_user = \"{user}\"\n"));
                out.push_str(&format!("rpc_password = \"{pass}\"\n\n"));
            }
        }

        out.push_str("[server]\n");
        out.push_str(&format!("bind_addr = \"{}\"\n", a.bind_addr));
        out.push_str(&format!("gap_limit = {}\n", a.gap_limit));
        out.push_str(&format!("ledger_db_path = \"{}\"\n\n", a.ledger_db_path));
    }

    out.push_str("[server_signing]\n");
    match &a.server_signing {
        ServerSigningAnswer::File(path) => out.push_str(&format!("xprv_file = \"{path}\"\n\n")),
        ServerSigningAnswer::EnvVar(var) => out.push_str(&format!("xprv_env_var = \"{var}\"\n\n")),
    }

    out.push_str("# Only consulted once, to seed policy version 1 the first time this service\n");
    out.push_str(
        "# starts against a fresh ledger database - after that the running policy lives\n",
    );
    out.push_str("# in the database and can only change via a HARDWARE-authorized POST /policy.\n");
    out.push_str("[policy]\n");
    out.push_str(&format!("max_tx_sat = {}\n", a.policy.max_tx_sat));
    out.push_str(&format!("max_daily_sat = {}\n", a.policy.max_daily_sat));
    out.push_str(&format!("max_weekly_sat = {}\n", a.policy.max_weekly_sat));
    out.push_str(&format!("max_monthly_sat = {}\n", a.policy.max_monthly_sat));
    out.push_str(&format!("max_fee_sat = {}\n", a.policy.max_fee_sat));
    out.push_str(&format!(
        "max_fee_rate_sat_per_vb = {}\n",
        a.policy.max_fee_rate_sat_per_vb
    ));
    match &a.policy.destination_whitelist {
        Some(list) if !list.is_empty() => {
            out.push_str(&format!("destination_whitelist = {}\n\n", toml_list(list)));
        }
        _ => out.push_str("# destination_whitelist = [\"tb1q...\"]  # optional; omit to allow any destination\n\n"),
    }

    out.push_str("[notify]\n");
    out.push_str(&format!("hold_seconds = {}\n", a.notify.hold_seconds));
    out.push_str(&format!(
        "sweep_interval_seconds = {}\n",
        a.notify.sweep_interval_seconds
    ));
    out.push_str(&format!(
        "renotify_interval_seconds = {}\n\n",
        a.notify.renotify_interval_seconds
    ));
    if let Some(url) = &a.notify.ntfy_url {
        out.push_str("[notify.ntfy]\n");
        out.push_str(&format!("url = \"{url}\"\n"));
        if let Some(token) = &a.notify.ntfy_auth_token {
            out.push_str(&format!("auth_token = \"{token}\"\n"));
        }
        out.push('\n');
    }
    if let Some(smtp) = &a.notify.smtp {
        out.push_str("[notify.smtp]\n");
        out.push_str(&format!("host = \"{}\"\n", smtp.host));
        out.push_str(&format!("port = {}\n", smtp.port));
        out.push_str(&format!("username = \"{}\"\n", smtp.username));
        out.push_str(&format!("password = \"{}\"\n", smtp.password));
        out.push_str(&format!("from = \"{}\"\n", smtp.from));
        out.push_str(&format!("to = \"{}\"\n\n", smtp.to));
    }

    out.push_str(
        "# MOBILE + SERVER path - used if the HARDWARE is lost or destroyed. older(N) is a\n",
    );
    out.push_str(
        "# *relative* timelock: coins already older than timelock_blocks satisfy it right\n",
    );
    out.push_str(
        "# now, so hold_seconds below is the PRIMARY protection against a stolen phone.\n",
    );
    out.push_str("[recovery]\n");
    out.push_str(&format!("hold_seconds = {}\n", a.recovery_hold_seconds));
    match &a.recovery_destination_whitelist {
        Some(list) if !list.is_empty() => {
            out.push_str(&format!("destination_whitelist = {}\n", toml_list(list)));
        }
        _ => out.push_str(
            "# destination_whitelist = [\"tb1q...\"]  # strongly recommended: pre-commit to where you'd sweep\n",
        ),
    }

    if let Some(nostr) = &a.nostr_transport {
        out.push_str("\n# Alternate front door for the same HTTP API, over Nostr NIP-17 private\n");
        out.push_str("# messages - no open port needed. Every sender is cryptographically\n");
        out.push_str("# verified before allowed_npubs is even consulted; removing an npub here\n");
        out.push_str("# is how a lost or stolen device is cut off.\n");
        out.push_str("[nostr_transport]\n");
        match &nostr.nsec {
            NostrNsecAnswer::File(path) => out.push_str(&format!("nsec_file = \"{path}\"\n")),
            NostrNsecAnswer::EnvVar(var) => out.push_str(&format!("nsec_env_var = \"{var}\"\n")),
        }
        out.push_str(&format!("relays = {}\n", toml_list(&nostr.relays)));
        out.push_str(&format!(
            "allowed_npubs = {}\n",
            toml_list(&nostr.allowed_npubs)
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_key(seed: u8) -> KeyAnswer {
        let (spec, _) = crate::test_util::test_key_spec_with_xpriv(seed);
        KeyAnswer {
            fingerprint: spec.master_fingerprint,
            derivation_path: spec.derivation_path,
            xpub: spec.xpub,
        }
    }

    fn sample_answers() -> WizardAnswers {
        WizardAnswers {
            network: ChainNetwork::Signet,
            timelock_blocks: 4320,
            hardware: sample_key(0x01),
            mobile: sample_key(0x02),
            server: sample_key(0x03),
            server_signing: ServerSigningAnswer::EnvVar("COSIGNER_SERVER_XPRV".to_string()),
            bitcoind_rpc_url: "http://127.0.0.1:38332".to_string(),
            bitcoind_auth: BitcoindAuthAnswer::Cookie("/home/bitcoin/.cookie".to_string()),
            bind_addr: "127.0.0.1:8080".to_string(),
            gap_limit: 1000,
            ledger_db_path: "/var/lib/cosigner/ledger.sqlite3".to_string(),
            policy: PolicyAnswer {
                max_tx_sat: 500_000,
                max_daily_sat: 1_000_000,
                max_weekly_sat: 3_000_000,
                max_monthly_sat: 8_000_000,
                max_fee_sat: 50_000,
                max_fee_rate_sat_per_vb: 200.0,
                destination_whitelist: None,
            },
            notify: NotifyAnswer {
                hold_seconds: 900,
                sweep_interval_seconds: 5,
                renotify_interval_seconds: 21_600,
                ntfy_url: Some("https://ntfy.sh/topic".to_string()),
                ntfy_auth_token: None,
                smtp: None,
            },
            recovery_hold_seconds: 172_800,
            recovery_destination_whitelist: None,
            nostr_transport: None,
        }
    }

    #[test]
    fn rendered_toml_parses_and_validates_as_a_real_wallet_config() {
        let text = render_toml(&sample_answers());
        let cfg: crate::config::WalletConfig = toml::from_str(&text).expect("valid TOML");
        cfg.validate()
            .expect("wizard output should always validate");
        assert_eq!(cfg.network, ChainNetwork::Signet);
        assert_eq!(cfg.timelock_blocks, 4320);
    }

    #[test]
    fn mainnet_answers_render_the_explicit_acknowledgement() {
        let mut answers = sample_answers();
        answers.network = ChainNetwork::Mainnet;
        // Mainnet xpubs use different version bytes than the test fixtures generate, so swap in
        // a config that's internally consistent enough to validate - what's under test here is
        // only that the acknowledgement line is rendered, not full mainnet key validity.
        let text = render_toml(&answers);
        assert!(text.contains("i_understand_this_is_mainnet = true"));
    }

    #[test]
    fn destination_whitelists_render_as_toml_arrays() {
        let mut answers = sample_answers();
        answers.policy.destination_whitelist =
            Some(vec!["tb1qexample1".to_string(), "tb1qexample2".to_string()]);
        answers.recovery_destination_whitelist = Some(vec!["tb1qrecovery".to_string()]);
        let text = render_toml(&answers);
        assert!(text.contains("destination_whitelist = [\"tb1qexample1\", \"tb1qexample2\"]"));
        assert!(text.contains("destination_whitelist = [\"tb1qrecovery\"]"));
    }

    #[test]
    fn smtp_only_renders_smtp_section_and_no_ntfy() {
        let mut answers = sample_answers();
        answers.notify.ntfy_url = None;
        answers.notify.smtp = Some(SmtpAnswer {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "u".to_string(),
            password: "p".to_string(),
            from: "a@example.com".to_string(),
            to: "b@example.com".to_string(),
        });
        let text = render_toml(&answers);
        assert!(text.contains("[notify.smtp]"));
        assert!(!text.contains("[notify.ntfy]"));
        let cfg: crate::config::WalletConfig = toml::from_str(&text).unwrap();
        cfg.validate().unwrap();
    }

    /// Feeds a full, valid answer script through `run_interactive` (accepting every default by
    /// leaving lines empty where possible) and checks the result renders to a validating config
    /// - the actual end-to-end path a real terminal session takes, minus the terminal.
    #[test]
    fn interactive_wizard_produces_a_validating_config_when_every_default_is_accepted() {
        let (hardware, _) = crate::test_util::test_key_spec_with_xpriv(0x01);
        let (mobile, _) = crate::test_util::test_key_spec_with_xpriv(0x02);
        let (server, _) = crate::test_util::test_key_spec_with_xpriv(0x03);

        // Order must exactly match every `prompt*` call in `run_interactive`.
        let script = [
            "",                           // network -> default signet
            "4320",                       // timelock (no default accepted for parse safety here)
            &hardware.master_fingerprint, // HARDWARE fingerprint
            "",                           // HARDWARE path -> default
            &hardware.xpub,               // HARDWARE xpub
            &mobile.master_fingerprint,   // MOBILE fingerprint
            "",                           // MOBILE path -> default
            &mobile.xpub,                 // MOBILE xpub
            &server.master_fingerprint,   // SERVER fingerprint
            "",                           // SERVER path -> default
            &server.xpub,                 // SERVER xpub
            "",                           // server_signing kind -> default "file"
            "",                           // xprv file path -> default
            "",                           // bitcoind rpc url -> default
            "",                           // bitcoind auth kind -> default "cookie"
            "/home/bitcoin/.cookie",      // cookie path (no default)
            "",                           // bind_addr -> default
            "",                           // gap_limit -> default
            "",                           // ledger_db_path -> default
            "",                           // max_tx_sat -> default
            "",                           // max_daily_sat -> default
            "",                           // max_weekly_sat -> default
            "",                           // max_monthly_sat -> default
            "",                           // max_fee_sat -> default
            "",                           // max_fee_rate -> default
            "",                           // policy whitelist -> none
            "",                           // notify channel -> default "ntfy"
            "",                           // ntfy url -> default
            "",                           // ntfy auth token -> none
            "",                           // notify hold_seconds -> default
            "",                           // sweep_interval_seconds -> default
            "",                           // renotify_interval_seconds -> default
            "",                           // recovery hold_seconds -> default
            "",                           // recovery whitelist -> none
            "",                           // enable nostr transport -> default "n"
        ]
        .join("\n")
            + "\n";

        let mut input = Cursor::new(script.into_bytes());
        let mut output: Vec<u8> = Vec::new();
        let answers = run_interactive(&mut input, &mut output).expect("wizard should complete");
        assert!(
            answers.nostr_transport.is_none(),
            "declining nostr_transport should leave it unset"
        );

        let text = render_toml(&answers);
        let cfg: crate::config::WalletConfig = toml::from_str(&text).expect("valid TOML");
        cfg.validate()
            .expect("interactively-produced config should validate");
    }

    #[test]
    fn required_field_left_empty_reprompts_instead_of_accepting_blank() {
        // HARDWARE fingerprint has no default - an empty line must re-prompt, not silently
        // proceed with an empty fingerprint. Feed one blank line, then a real one.
        let script = "\nAABBCCDD\n";
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let value = prompt_validated(
            &mut input,
            &mut output,
            "fingerprint",
            None,
            validate_fingerprint,
        )
        .unwrap();
        assert_eq!(value, "AABBCCDD");
        assert!(
            String::from_utf8_lossy(&output).contains("required"),
            "should have re-prompted for the blank line"
        );
    }

    #[test]
    fn invalid_fingerprint_reprompts_until_valid() {
        let script = "not-hex\ntoolong123\n4ba43603\n";
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let value = prompt_validated(
            &mut input,
            &mut output,
            "fingerprint",
            None,
            validate_fingerprint,
        )
        .unwrap();
        assert_eq!(value, "4ba43603");
    }

    /// A real, freshly-generated npub - not a hand-typed bech32 string, so its checksum is
    /// guaranteed valid rather than trusted by eye.
    fn sample_npub() -> String {
        use nostr_sdk::prelude::ToBech32;
        nostr_sdk::Keys::generate()
            .public_key()
            .to_bech32()
            .unwrap()
    }

    #[test]
    fn nostr_transport_renders_and_validates_when_present() {
        let mut answers = sample_answers();
        answers.nostr_transport = Some(NostrTransportAnswer {
            nsec: NostrNsecAnswer::EnvVar("COSIGNER_NOSTR_NSEC".to_string()),
            relays: vec![
                "wss://relay.damus.io".to_string(),
                "wss://nos.lol".to_string(),
            ],
            allowed_npubs: vec![sample_npub()],
        });
        let text = render_toml(&answers);
        assert!(text.contains("[nostr_transport]"));
        assert!(text.contains("nsec_env_var = \"COSIGNER_NOSTR_NSEC\""));
        assert!(text.contains("relays = [\"wss://relay.damus.io\", \"wss://nos.lol\"]"));

        let cfg: crate::config::WalletConfig = toml::from_str(&text).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.nostr_transport.is_some());
    }

    #[test]
    fn absent_nostr_transport_renders_no_section() {
        let text = render_toml(&sample_answers());
        assert!(!text.contains("[nostr_transport]"));
    }

    #[test]
    fn interactive_wizard_can_enable_nostr_transport() {
        let (hardware, _) = crate::test_util::test_key_spec_with_xpriv(0x01);
        let (mobile, _) = crate::test_util::test_key_spec_with_xpriv(0x02);
        let (server, _) = crate::test_util::test_key_spec_with_xpriv(0x03);
        let npub = sample_npub();

        // Same prefix as `interactive_wizard_produces_a_validating_config_when_every_default_is_accepted`
        // (every field up through "recovery whitelist" via defaults), then diverges to actually
        // enable and fill in [nostr_transport].
        let script = [
            "",                                    // network -> default signet
            "4320",                                // timelock
            &hardware.master_fingerprint,          // HARDWARE fingerprint
            "",                                    // HARDWARE path -> default
            &hardware.xpub,                        // HARDWARE xpub
            &mobile.master_fingerprint,            // MOBILE fingerprint
            "",                                    // MOBILE path -> default
            &mobile.xpub,                          // MOBILE xpub
            &server.master_fingerprint,            // SERVER fingerprint
            "",                                    // SERVER path -> default
            &server.xpub,                          // SERVER xpub
            "",                                    // server_signing kind -> default "file"
            "",                                    // xprv file path -> default
            "",                                    // bitcoind rpc url -> default
            "",                                    // bitcoind auth kind -> default "cookie"
            "/home/bitcoin/.cookie",               // cookie path
            "",                                    // bind_addr -> default
            "",                                    // gap_limit -> default
            "",                                    // ledger_db_path -> default
            "",                                    // max_tx_sat -> default
            "",                                    // max_daily_sat -> default
            "",                                    // max_weekly_sat -> default
            "",                                    // max_monthly_sat -> default
            "",                                    // max_fee_sat -> default
            "",                                    // max_fee_rate -> default
            "",                                    // policy whitelist -> none
            "",                                    // notify channel -> default "ntfy"
            "",                                    // ntfy url -> default
            "",                                    // ntfy auth token -> none
            "",                                    // notify hold_seconds -> default
            "",                                    // sweep_interval_seconds -> default
            "",                                    // renotify_interval_seconds -> default
            "",                                    // recovery hold_seconds -> default
            "",                                    // recovery whitelist -> none
            "y",                                   // enable nostr transport
            "",                                    // nsec source -> default "env"
            "",                                    // env var name -> default COSIGNER_NOSTR_NSEC
            "wss://relay.damus.io, wss://nos.lol", // relays
            &npub,                                 // allowed npub
        ]
        .join("\n")
            + "\n";

        let mut input = Cursor::new(script.into_bytes());
        let mut output: Vec<u8> = Vec::new();
        let answers = run_interactive(&mut input, &mut output).expect("wizard should complete");

        let nostr = answers
            .nostr_transport
            .as_ref()
            .expect("should have enabled nostr_transport");
        assert_eq!(nostr.relays.len(), 2);
        assert_eq!(nostr.allowed_npubs.len(), 1);

        let text = render_toml(&answers);
        let cfg: crate::config::WalletConfig = toml::from_str(&text).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn invalid_relay_url_reprompts_the_whole_list() {
        let script = "not-a-relay\nwss://relay.damus.io\n";
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let relays =
            prompt_required_list_validated(&mut input, &mut output, "relays", validate_relay_url)
                .unwrap();
        assert_eq!(relays, vec!["wss://relay.damus.io".to_string()]);
    }

    #[test]
    fn invalid_npub_reprompts_the_whole_list() {
        let script = format!("not-an-npub\n{}\n", sample_npub());
        let mut input = Cursor::new(script.as_bytes());
        let mut output: Vec<u8> = Vec::new();
        let npubs = prompt_required_list_validated(&mut input, &mut output, "npubs", validate_npub)
            .unwrap();
        assert_eq!(npubs.len(), 1);
    }
}
