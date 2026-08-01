use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use cosigner::config::WalletConfig;
use cosigner::descriptor::{self, BuiltDescriptor};
use cosigner::invariants::{self, InvariantReport, LabeledKey};
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
    }
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
    let mut found: Vec<(String, DefiniteDescriptorKey)> = Vec::new();
    definite.for_each_key(|k| {
        found.push((k.to_string(), k.clone()));
        true
    });

    let roles = [
        ("satochip", &cfg.keys.satochip.xpub),
        ("server", &cfg.keys.server.xpub),
        ("mobile", &cfg.keys.mobile.xpub),
    ];

    let mut labeled = Vec::new();
    for (role, xpub) in roles {
        let xpub = xpub.trim();
        let (key_str, key) = found
            .iter()
            .find(|(s, _)| s.contains(xpub))
            .cloned()
            .with_context(|| format!("could not find key for role {role} in built descriptor"))?;
        let _ = key_str;
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
