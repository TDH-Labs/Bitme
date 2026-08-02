use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use cosigner::chain::{BitcoindRpc, ChainSource};
use cosigner::config::{BitcoindConfig, WalletConfig};
use cosigner::descriptor::{self, BuiltDescriptor};
use cosigner::http::{self, AppState, PolicyHandle};
use cosigner::invariants::{self, InvariantReport, LabeledKey};
use cosigner::ledger::Ledger;
use cosigner::notify::{MultiNotifier, Notifier};
use cosigner::policy::CompiledPolicy;
use cosigner::sign;
use cosigner::signing::ServerSigningKey;
use miniscript::descriptor::DefiniteDescriptorKey;
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};

#[derive(Parser)]
#[command(name = "cosigner", about = "Policy-gated Bitcoin co-signing service")]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    /// Build and validate the wallet's miniscript descriptor.
    Descriptor {
        #[command(subcommand)]
        command: DescriptorCommand,
    },
    /// Run the HTTP API (POST /inspect, /sign_psbt, /veto/{id}, /policy).
    Serve(ServeArgs),
    /// Helpers for the SATOCHIP-authorized runtime policy change flow (`POST /policy`).
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Lift a freeze using direct server access instead of a SATOCHIP signature.
    ///
    /// `POST /unfreeze` needs the hardware; this does not. That's deliberate and it is not a
    /// hole: anyone who can run this already has the server and therefore the SERVER key, so
    /// requiring hardware here would buy nothing while making a freeze permanent in exactly
    /// the case the lost-SATOCHIP recovery path exists for.
    Unfreeze(UnfreezeArgs),
    /// Encrypted, off-machine backup/restore of wallet.toml + the SERVER xprv - protects
    /// against losing the box that runs this service, not against losing any of the three keys.
    RecoveryKit {
        #[command(subcommand)]
        command: RecoveryKitCommand,
    },
}

#[derive(Subcommand)]
enum RecoveryKitCommand {
    /// Encrypt wallet.toml + the SERVER xprv into a single backup blob.
    Export(RecoveryKitExportArgs),
    /// Decrypt a backup blob back into a wallet.toml + a SERVER xprv file.
    Import(RecoveryKitImportArgs),
}

#[derive(Args)]
struct RecoveryKitExportArgs {
    /// Path to the wallet.toml to back up.
    #[arg(long)]
    config: PathBuf,
    /// Path to a file containing the passphrase (its trimmed contents). Never pass a passphrase
    /// directly on the command line - it would end up in shell history and process listings.
    #[arg(long)]
    passphrase_file: PathBuf,
    /// Where to write the ASCII-armored backup blob.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct RecoveryKitImportArgs {
    /// Path to the ASCII-armored backup blob produced by `recovery-kit export`.
    #[arg(long = "in")]
    input: PathBuf,
    /// Path to a file containing the passphrase (its trimmed contents).
    #[arg(long)]
    passphrase_file: PathBuf,
    /// Where to write the restored wallet.toml.
    #[arg(long)]
    out_config: PathBuf,
    /// Where to write the restored SERVER xprv.
    #[arg(long)]
    out_server_key: PathBuf,
    /// Overwrite out_config/out_server_key if they already exist.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct UnfreezeArgs {
    /// Path to the same TOML wallet config `serve` uses (for `server.ledger_db_path`).
    #[arg(long)]
    config: PathBuf,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Prints the exact text a human must sign (via SATOCHIP's "Sign Message" feature) to
    /// authorize a proposed policy change - see `policy_auth.rs`. What's printed here is
    /// exactly what the running service recomputes and verifies the signature against.
    Message(PolicyMessageArgs),
}

#[derive(Args)]
struct PolicyMessageArgs {
    /// JSON file containing the proposed policy, in the same shape as `POST /policy`'s
    /// `"policy"` field (max_tx_sat, max_daily_sat, ..., destination_whitelist).
    #[arg(long)]
    policy_file: PathBuf,
    /// The version this change should target - one more than the server's current policy
    /// version (see `GET /policy`).
    #[arg(long)]
    version: u64,
}

#[derive(Args)]
struct ServeArgs {
    /// Path to the TOML wallet config (keys + timelock + [bitcoind] + [server]).
    #[arg(long)]
    config: PathBuf,
}

#[derive(Subcommand)]
enum DescriptorCommand {
    /// Build the descriptor from a key/timelock config file and validate its invariants.
    Build(BuildArgs),
    /// Validate an existing descriptor's invariants (from a config, a file, or an inline string).
    Check(CheckArgs),
}

#[derive(Args)]
struct BuildArgs {
    /// Path to the TOML wallet config (keys + timelock).
    #[arg(long)]
    config: PathBuf,
    /// Optional path to write the receive/change descriptor strings to (one per line).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct CheckArgs {
    /// Validate the descriptor rebuilt from this TOML wallet config.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Validate this standalone descriptor string instead (requires --timelock-blocks).
    #[arg(long)]
    descriptor: Option<String>,
    /// Validate the descriptor string in this file instead (requires --timelock-blocks).
    #[arg(long)]
    descriptor_file: Option<PathBuf>,
    /// Required recovery timelock (in blocks) when checking a standalone descriptor, since it
    /// can't otherwise be recovered generically from an arbitrary miniscript.
    #[arg(long)]
    timelock_blocks: Option<u16>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        TopCommand::Descriptor { command } => match command {
            DescriptorCommand::Build(args) => cmd_build(args),
            DescriptorCommand::Check(args) => cmd_check(args),
        },
        TopCommand::Serve(args) => cmd_serve(args),
        TopCommand::Policy { command } => match command {
            PolicyCommand::Message(args) => cmd_policy_message(args),
        },
        TopCommand::Unfreeze(args) => cmd_unfreeze(args),
        TopCommand::RecoveryKit { command } => match command {
            RecoveryKitCommand::Export(args) => cmd_recovery_kit_export(args),
            RecoveryKitCommand::Import(args) => cmd_recovery_kit_import(args),
        },
    }
}

fn cmd_recovery_kit_export(args: RecoveryKitExportArgs) -> Result<()> {
    let passphrase = std::fs::read_to_string(&args.passphrase_file)
        .with_context(|| format!("reading {}", args.passphrase_file.display()))?;
    let armored = cosigner::recovery_kit::export(&args.config, passphrase.trim())?;
    std::fs::write(&args.out, &armored)
        .with_context(|| format!("writing {}", args.out.display()))?;
    println!(
        "Wrote encrypted recovery kit to {} ({} bytes armored).",
        args.out.display(),
        armored.len()
    );
    println!(
        "Store this somewhere OTHER than this machine (a second machine, a paper/QR backup, or \
         Nostr relays via `cosigner recovery-kit publish`) - it is useless as a backup for this \
         box's own disk failure if it only ever lives on this disk."
    );
    Ok(())
}

fn cmd_recovery_kit_import(args: RecoveryKitImportArgs) -> Result<()> {
    if !args.force {
        for p in [&args.out_config, &args.out_server_key] {
            if p.exists() {
                bail!("{} already exists - pass --force to overwrite", p.display());
            }
        }
    }
    let passphrase = std::fs::read_to_string(&args.passphrase_file)
        .with_context(|| format!("reading {}", args.passphrase_file.display()))?;
    let armored = std::fs::read_to_string(&args.input)
        .with_context(|| format!("reading {}", args.input.display()))?;
    let restored = cosigner::recovery_kit::import(&armored, passphrase.trim())?;

    std::fs::write(&args.out_config, &restored.wallet_toml)
        .with_context(|| format!("writing {}", args.out_config.display()))?;
    std::fs::write(&args.out_server_key, &restored.server_xprv)
        .with_context(|| format!("writing {}", args.out_server_key.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.out_server_key, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", args.out_server_key.display()))?;
    }

    println!(
        "Restored wallet.toml to {} and the SERVER xprv to {} (backup created at unix time {}).",
        args.out_config.display(),
        args.out_server_key.display(),
        restored.created_at
    );
    println!(
        "If the restored config's [server_signing].xprv_file doesn't already point at {}, update \
         it (or set xprv_env_var instead) before running `cosigner serve`.",
        args.out_server_key.display()
    );
    Ok(())
}

fn cmd_unfreeze(args: UnfreezeArgs) -> Result<()> {
    let cfg = WalletConfig::load(&args.config)?;
    let (_, server_cfg) = cfg.require_server_config()?;
    let path = server_cfg
        .ledger_db_path
        .clone()
        .context("config is missing server.ledger_db_path")?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;
    rt.block_on(async move {
        let ledger = Ledger::connect(&path)
            .await
            .with_context(|| format!("opening ledger at {path}"))?;
        if !ledger.is_frozen().await? {
            println!("Not frozen - nothing to do.");
            return Ok(());
        }
        ledger.set_frozen(false, now_unix(), None).await?;
        println!("Co-signing UNFROZEN. Restart is not required; the running server picks this up.");
        Ok(())
    })
}

fn cmd_policy_message(args: PolicyMessageArgs) -> Result<()> {
    let raw = std::fs::read_to_string(&args.policy_file)
        .with_context(|| format!("reading {}", args.policy_file.display()))?;
    let policy: cosigner::policy::PolicyConfig = serde_json::from_str(&raw).with_context(|| {
        format!(
            "parsing {} as a policy (max_tx_sat, max_daily_sat, ..., destination_whitelist)",
            args.policy_file.display()
        )
    })?;
    print!(
        "{}",
        cosigner::policy_auth::canonical_message(args.version, &policy)
    );
    Ok(())
}

fn cmd_serve(args: ServeArgs) -> Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = WalletConfig::load(&args.config)?;
    let (bitcoind_cfg, server_cfg) = cfg.require_server_config()?;
    let (policy_cfg, signing_cfg) = cfg.require_signing_config()?;
    let notify_cfg = cfg.require_notify_config()?;
    let ledger_db_path = server_cfg
        .ledger_db_path
        .clone()
        .context("config is missing server.ledger_db_path, required for /sign_psbt")?;
    // [policy] only ever matters as the bootstrap default seeded into the ledger's
    // policy_state table the very first time this database is used - see
    // `Ledger::load_or_seed_policy_state`. Serializing it now (before `cfg` moves into the
    // async block below) avoids holding a borrow of `cfg` across that move.
    let policy_bootstrap_json =
        serde_json::to_string(policy_cfg).context("serializing [policy] for bootstrap")?;
    let wallet = descriptor::build_descriptor(&cfg)?;

    let report = run_invariants(&wallet, &cfg)?;
    if !report.all_invariants_hold() {
        bail!("refusing to start: descriptor failed invariant checks");
    }

    let server_key = ServerSigningKey::load(signing_cfg, &cfg.keys.server.xpub, cfg.network)?;
    let notifier: Arc<dyn Notifier> =
        Arc::new(MultiNotifier::from_config(notify_cfg).context("configuring [notify] channels")?);
    let hold_seconds = notify_cfg.hold_seconds;
    let renotify_interval_seconds = notify_cfg.renotify_interval_seconds;
    let sweep_interval = std::time::Duration::from_secs(notify_cfg.sweep_interval_seconds.max(1));

    let client = bitcoind_client(bitcoind_cfg)?;
    let chain: Arc<dyn ChainSource> = Arc::new(BitcoindRpc::new(client));
    let bind_addr = server_cfg.bind_addr.clone();
    let gap_limit = server_cfg.gap_limit;
    let network = cfg.network;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?;
    rt.block_on(async move {
        let ledger = Arc::new(
            Ledger::connect(&ledger_db_path)
                .await
                .with_context(|| format!("opening ledger at {ledger_db_path}"))?,
        );

        let seeded = ledger
            .load_or_seed_policy_state(&policy_bootstrap_json, now_unix())
            .await
            .context("loading/seeding policy_state")?;
        let seeded_policy_cfg: cosigner::policy::PolicyConfig =
            serde_json::from_str(&seeded.policy_json)
                .context("parsing policy_state.policy_json")?;
        let compiled: CompiledPolicy = seeded_policy_cfg
            .compile(network)
            .context("compiling policy from policy_state")?;
        let policy = Arc::new(tokio::sync::RwLock::new(PolicyHandle {
            version: seeded.version,
            compiled,
        }));

        let state = AppState {
            wallet: Arc::new(wallet),
            cfg: Arc::new(cfg.clone()),
            chain: chain.clone(),
            gap_limit,
            server_key: Arc::new(server_key),
            ledger: ledger.clone(),
            policy: policy.clone(),
            notifier,
            hold_seconds,
        };

        spawn_sweeper(
            state.notifier.clone(),
            renotify_interval_seconds,
            state.ledger.clone(),
            state.wallet.clone(),
            state.cfg.clone(),
            state.server_key.clone(),
            policy,
            chain,
            gap_limit,
            sweep_interval,
        );

        let listener = tokio::net::TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("binding {bind_addr}"))?;
        println!(
            "cosigner listening on {bind_addr} (network={:?})",
            cfg.network
        );
        axum::serve(listener, http::router(state))
            .await
            .context("http server")
    })
}

/// Runs `sign::sweep_due` on a fixed interval for as long as the server is up. Each pending
/// spend's outcome is logged, not propagated - a failure processing one row (or even the
/// sweep query itself, e.g. a transient DB hiccup) must never bring down the HTTP server or
/// stop other rows from being retried on the next tick.
#[allow(clippy::too_many_arguments)]
fn spawn_sweeper(
    notifier: Arc<dyn Notifier>,
    renotify_interval_seconds: i64,
    ledger: Arc<Ledger>,
    wallet: Arc<BuiltDescriptor>,
    cfg: Arc<WalletConfig>,
    server_key: Arc<ServerSigningKey>,
    policy: Arc<tokio::sync::RwLock<PolicyHandle>>,
    chain: Arc<dyn ChainSource>,
    gap_limit: u32,
    interval: std::time::Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = now_unix();
            // A cheap snapshot, taken fresh each tick: never hold the policy lock across the
            // `.await`s inside `sweep_due` - picks up any `POST /policy` change immediately.
            let compiled = policy.read().await.compiled.clone();
            let results = sign::sweep_due(
                &ledger,
                &wallet,
                &cfg,
                &server_key,
                &compiled,
                &cfg.recovery_config(),
                &chain,
                gap_limit,
                now,
            )
            .await;
            match sign::renotify_pending(&ledger, notifier.as_ref(), renotify_interval_seconds, now)
                .await
            {
                Ok(0) => {}
                Ok(n) => tracing::info!(count = n, "sent hold reminders"),
                Err(e) => tracing::warn!(error = %e, "re-notification sweep failed"),
            }

            for (txid, outcome) in results {
                match outcome {
                    Ok(outcome) => tracing::info!(txid, ?outcome, "processed pending signature"),
                    Err(err) => {
                        tracing::warn!(txid, error = %err, "failed to process pending signature (will retry)")
                    }
                }
            }
        }
    });
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn bitcoind_client(cfg: &BitcoindConfig) -> Result<bitcoincore_rpc::Client> {
    let auth = if let Some(cookie) = &cfg.rpc_cookie_file {
        bitcoincore_rpc::Auth::CookieFile(PathBuf::from(cookie))
    } else {
        bitcoincore_rpc::Auth::UserPass(
            cfg.rpc_user.clone().context("bitcoind.rpc_user")?,
            cfg.rpc_password.clone().context("bitcoind.rpc_password")?,
        )
    };
    bitcoincore_rpc::Client::new(&cfg.rpc_url, auth)
        .with_context(|| format!("connecting to bitcoind at {}", cfg.rpc_url))
}

fn cmd_build(args: BuildArgs) -> Result<()> {
    let cfg = WalletConfig::load(&args.config)?;
    let built = descriptor::build_descriptor(&cfg)?;

    println!("== Descriptor (receive + change, <0;1> multipath) ==");
    println!("{}", built.multipath);
    println!();
    println!("== External (receive) descriptor ==");
    println!("{}", built.external);
    println!("== Internal (change) descriptor ==");
    println!("{}", built.internal);
    println!();

    for i in 0..3u32 {
        let addr = descriptor::address_at(&built.external, i, cfg.network)?;
        println!("receive[{i}]: {addr}");
    }
    let change0 = descriptor::address_at(&built.internal, 0, cfg.network)?;
    println!("change[0]:  {change0}");
    println!();

    let report = run_invariants(&built, &cfg)?;
    print_report(&report, built.timelock_blocks);

    if let Some(out) = &args.out {
        let contents = format!("{}\n{}\n", built.external, built.internal);
        std::fs::write(out, contents).with_context(|| format!("writing {}", out.display()))?;
        println!("\nwrote external/internal descriptors to {}", out.display());
    }

    if !report.all_invariants_hold() {
        bail!("descriptor built but failed invariant checks - see above");
    }
    Ok(())
}

fn cmd_check(args: CheckArgs) -> Result<()> {
    match (&args.config, &args.descriptor, &args.descriptor_file) {
        (Some(config_path), None, None) => {
            let cfg = WalletConfig::load(config_path)?;
            let built = descriptor::build_descriptor(&cfg)?;
            println!("{}", built.multipath);
            let report = run_invariants(&built, &cfg)?;
            print_report(&report, built.timelock_blocks);
            if !report.all_invariants_hold() {
                bail!("descriptor failed invariant checks - see above");
            }
        }
        (None, desc_str, desc_file) => {
            let timelock_blocks = args
                .timelock_blocks
                .context("--timelock-blocks is required when checking a standalone descriptor")?;
            let raw = match (desc_str, desc_file) {
                (Some(s), None) => s.clone(),
                (None, Some(path)) => std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?,
                _ => bail!("pass exactly one of --config, --descriptor, or --descriptor-file"),
            };
            let desc = descriptor::parse_descriptor(&raw)?;
            println!("{desc}");
            let definite = descriptor::at_index(&desc, 0)?;
            let keys = generic_labeled_keys(&definite);
            let report = invariants::verify_invariants(&definite, &keys, timelock_blocks)?;
            print_report(&report, timelock_blocks);
            if !report.all_invariants_hold() {
                bail!("descriptor failed invariant checks - see above");
            }
        }
        _ => bail!("pass exactly one of --config, --descriptor, or --descriptor-file"),
    }
    Ok(())
}

fn run_invariants(built: &BuiltDescriptor, cfg: &WalletConfig) -> Result<InvariantReport> {
    let definite = descriptor::at_index(&built.external, 0)?;
    let keys = role_labeled_keys(&built.external, cfg)?;
    invariants::verify_invariants(&definite, &keys, built.timelock_blocks)
}

/// Labels the descriptor's keys "satochip" / "server" / "mobile" by matching against the
/// key expressions we built from the config, rather than guessing from position.
fn role_labeled_keys(
    external: &Descriptor<DescriptorPublicKey>,
    cfg: &WalletConfig,
) -> Result<Vec<LabeledKey>> {
    let definite = descriptor::at_index(external, 0)?;
    let keys = descriptor::definite_keys(&definite);

    let roles = [
        ("satochip", &cfg.keys.satochip.xpub),
        ("server", &cfg.keys.server.xpub),
        ("mobile", &cfg.keys.mobile.xpub),
    ];

    let mut labeled = Vec::new();
    for (role, xpub) in roles {
        let key = descriptor::find_role_key(&keys, xpub)
            .with_context(|| format!("could not find key for role {role} in built descriptor"))?;
        labeled.push(LabeledKey {
            label: role.to_string(),
            key,
        });
    }
    Ok(labeled)
}

fn generic_labeled_keys(definite: &Descriptor<DefiniteDescriptorKey>) -> Vec<LabeledKey> {
    let mut found = Vec::new();
    definite.for_each_key(|k| {
        found.push(k.clone());
        true
    });
    found
        .into_iter()
        .enumerate()
        .map(|(i, key)| LabeledKey {
            label: format!("key{}", i + 1),
            key,
        })
        .collect()
}

fn print_report(report: &InvariantReport, timelock_blocks: u16) {
    println!();
    println!("== Invariant report (timelock = {timelock_blocks} blocks) ==");
    println!("keys: {}", report.key_labels.join(", "));
    println!(
        "no single key can spend (alone, or alone after waiting): {}",
        pass(report.no_single_key_can_spend)
    );
    for pair in &report.pairs {
        println!(
            "  {} + {}: immediate={} after_timelock={}",
            pair.labels.0, pair.labels.1, pair.spends_immediately, pair.spends_after_timelock
        );
    }
    println!(
        "exactly one 2-key path spends immediately (HOT): {}",
        pass(report.exactly_one_immediate_path)
    );
    println!(
        "at least one 2-key path spends after the timelock (RECOVERY): {}",
        pass(report.at_least_one_timelocked_path)
    );
    println!(
        "recovery path is blocked exactly one block before the timelock: {}",
        pass(report.timelock_boundary_holds)
    );
    println!(
        "losing any ONE key is survivable (every pair can eventually spend): {}",
        pass(report.every_pair_can_eventually_spend)
    );
    println!(
        "ALL INVARIANTS HOLD: {}",
        pass(report.all_invariants_hold())
    );
}

fn pass(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}
