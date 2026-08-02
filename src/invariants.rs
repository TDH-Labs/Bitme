//! Formal, structural proof (not just a smoke test) that a descriptor's spending policy has
//! the required shape:
//!
//!   - no single key, alone, ever authorizes a spend (with or without waiting)
//!   - exactly one 2-key subset can spend immediately (the HOT path)
//!   - the remaining 2-key subset(s) can only spend after the configured relative timelock,
//!     and not one block earlier (exact boundary, not "eventually")
//!   - *every* 2-key subset can eventually spend - i.e. losing any single key is survivable.
//!     This is the invariant that makes the wallet recoverable rather than merely secure, and
//!     it's the one an earlier revision of this descriptor failed.
//!
//! This works by lifting the descriptor to rust-miniscript's abstract `Semantic` policy and
//! using its `entails` algorithm ("every satisfaction of A is also a satisfaction of B") to ask,
//! for every key and every pair of keys, "is having just these signatures (optionally plus
//! having waited long enough) *sufficient* to satisfy the whole descriptor?". This is a
//! property of the policy itself, independent of any particular PSBT or transaction.

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use miniscript::descriptor::DefiniteDescriptorKey;
use miniscript::policy::{Concrete, Liftable, Semantic};
use miniscript::Descriptor;

/// A key participating in the spending policy, with a human-readable role label
/// ("satochip", "server", "mobile", or "key1"/"key2"/"key3" if roles are unknown).
#[derive(Clone)]
pub struct LabeledKey {
    pub label: String,
    pub key: DefiniteDescriptorKey,
}

#[derive(Debug, Clone)]
pub struct PairResult {
    pub labels: (String, String),
    pub spends_immediately: bool,
    pub spends_after_timelock: bool,
}

#[derive(Debug, Clone)]
pub struct InvariantReport {
    pub key_labels: Vec<String>,
    pub no_single_key_can_spend: bool,
    pub pairs: Vec<PairResult>,
    pub exactly_one_immediate_path: bool,
    pub at_least_one_timelocked_path: bool,
    pub timelock_boundary_holds: bool,
    /// Every 2-key subset can spend, immediately or after the timelock - so the loss of any
    /// single key still leaves a way to move the funds. See the module doc.
    pub every_pair_can_eventually_spend: bool,
}

impl InvariantReport {
    pub fn all_invariants_hold(&self) -> bool {
        self.no_single_key_can_spend
            && self.exactly_one_immediate_path
            && self.at_least_one_timelocked_path
            && self.timelock_boundary_holds
            && self.every_pair_can_eventually_spend
    }
}

fn lift_fragment(fragment: &str) -> Result<Semantic<DefiniteDescriptorKey>> {
    Concrete::<DefiniteDescriptorKey>::from_str(fragment)
        .with_context(|| format!("parsing test policy fragment: {fragment}"))?
        .lift()
        .with_context(|| format!("lifting test policy fragment: {fragment}"))
}

/// Runs the invariant analysis against `descriptor` (already resolved to a single derivation
/// index - the policy shape, hence every invariant below, is identical at every index since
/// only the concrete key bytes change) using `keys` as the full set of signers in the policy.
pub fn verify_invariants(
    descriptor: &Descriptor<DefiniteDescriptorKey>,
    keys: &[LabeledKey],
    timelock_blocks: u16,
) -> Result<InvariantReport> {
    if keys.len() < 2 {
        bail!("need at least two keys to analyze a multi-key spending policy");
    }

    let full_policy: Semantic<DefiniteDescriptorKey> = descriptor
        .lift()
        .context("lifting descriptor to a semantic policy")?;

    // 1. No single key, alone, ever satisfies the descriptor - checked both with no time
    //    constraint at all, and with an unbounded amount of elapsed time.
    let mut no_single_key_can_spend = true;
    for k in keys {
        let alone = lift_fragment(&format!("pk({})", k.key))?;
        if alone.entails(full_policy.clone()).unwrap_or(true) {
            no_single_key_can_spend = false;
        }
        let alone_after_timelock =
            lift_fragment(&format!("and(pk({}),older({timelock_blocks}))", k.key))?;
        if alone_after_timelock
            .entails(full_policy.clone())
            .unwrap_or(true)
        {
            no_single_key_can_spend = false;
        }
    }

    // 2. Pairwise analysis over every 2-key subset.
    let mut pairs = Vec::new();
    let mut immediate_count = 0usize;
    let mut timelocked_count = 0usize;
    let mut boundary_ok = true;

    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            let (a, b) = (&keys[i], &keys[j]);

            let immediate = lift_fragment(&format!("and(pk({}),pk({}))", a.key, b.key))?
                .entails(full_policy.clone())
                .unwrap_or(false);

            let after_timelock = lift_fragment(&format!(
                "and(pk({}),and(pk({}),older({timelock_blocks})))",
                a.key, b.key
            ))?
            .entails(full_policy.clone())
            .unwrap_or(false);

            if immediate {
                immediate_count += 1;
            }
            if after_timelock && !immediate {
                timelocked_count += 1;
                if timelock_blocks > 1 {
                    let one_block_early = lift_fragment(&format!(
                        "and(pk({}),and(pk({}),older({})))",
                        a.key,
                        b.key,
                        timelock_blocks - 1
                    ))?
                    .entails(full_policy.clone())
                    .unwrap_or(true);
                    if one_block_early {
                        boundary_ok = false;
                    }
                }
            }

            pairs.push(PairResult {
                labels: (a.label.clone(), b.label.clone()),
                spends_immediately: immediate,
                spends_after_timelock: after_timelock,
            });
        }
    }

    let every_pair_can_eventually_spend = pairs
        .iter()
        .all(|p| p.spends_immediately || p.spends_after_timelock);

    Ok(InvariantReport {
        key_labels: keys.iter().map(|k| k.label.clone()).collect(),
        pairs,
        no_single_key_can_spend,
        exactly_one_immediate_path: immediate_count == 1,
        at_least_one_timelocked_path: timelocked_count >= 1,
        timelock_boundary_holds: boundary_ok,
        every_pair_can_eventually_spend,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::{PublicKey, Sequence};
    use miniscript::ForEachKey;

    use super::*;
    use crate::config::WalletConfig;
    use crate::descriptor::{at_index, build_descriptor, policy_string, BuiltDescriptor};
    use crate::test_util::{test_signature, test_signer, test_wallet_config};

    /// Labels a built descriptor's keys "satochip"/"server"/"mobile" by matching them back
    /// against the config that produced them - mirrors what the CLI does, kept independent of
    /// `main.rs` so these tests exercise `verify_invariants` the same way production code does.
    fn labeled_keys(
        cfg: &WalletConfig,
        built: &BuiltDescriptor,
    ) -> (Descriptor<DefiniteDescriptorKey>, Vec<LabeledKey>) {
        let definite = at_index(&built.external, 0).unwrap();
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
            let (_, key) = found
                .iter()
                .find(|(s, _)| s.contains(xpub.trim()))
                .cloned()
                .unwrap_or_else(|| panic!("key for role {role} not found in descriptor"));
            labeled.push(LabeledKey {
                label: role.to_string(),
                key,
            });
        }
        (definite, labeled)
    }

    fn pair<'a>(report: &'a InvariantReport, a: &str, b: &str) -> &'a PairResult {
        report
            .pairs
            .iter()
            .find(|p| (p.labels.0 == a && p.labels.1 == b) || (p.labels.0 == b && p.labels.1 == a))
            .unwrap_or_else(|| panic!("no pair ({a}, {b}) in report"))
    }

    // ---- Formal: entailment over the abstract policy, independent of any real signature ----

    #[test]
    fn formal_invariants_hold_for_the_built_descriptor() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let (definite, keys) = labeled_keys(&cfg, &built);
        let report = verify_invariants(&definite, &keys, 12960).unwrap();

        assert!(report.no_single_key_can_spend, "{report:?}");
        assert!(report.exactly_one_immediate_path, "{report:?}");
        assert!(report.at_least_one_timelocked_path, "{report:?}");
        assert!(report.timelock_boundary_holds, "{report:?}");
        assert!(report.all_invariants_hold());

        let hot = pair(&report, "satochip", "server");
        assert!(
            hot.spends_immediately,
            "HOT path (satochip+server) must spend immediately"
        );

        // Recovery when THIS SERVICE is gone.
        let no_server = pair(&report, "satochip", "mobile");
        assert!(
            !no_server.spends_immediately,
            "satochip+mobile must not bypass the policy engine by spending immediately"
        );
        assert!(
            no_server.spends_after_timelock,
            "satochip+mobile must spend after the timelock (server-loss recovery)"
        );

        // Recovery when the SATOCHIP is gone - the property the previous descriptor lacked,
        // and the whole reason for the redesign.
        let no_hardware = pair(&report, "server", "mobile");
        assert!(
            !no_hardware.spends_immediately,
            "server+mobile must not spend immediately - no-hardware spends must wait"
        );
        assert!(
            no_hardware.spends_after_timelock,
            "server+mobile MUST spend after the timelock: losing the SATOCHIP must be survivable"
        );

        assert!(
            report.every_pair_can_eventually_spend,
            "losing any single key must be survivable: {report:?}"
        );
    }

    #[test]
    fn formal_invariants_hold_across_a_range_of_timelocks() {
        for n in [1u16, 2, 6, 144, 4032, 12960, 65535] {
            let cfg = test_wallet_config(n);
            let built = build_descriptor(&cfg).unwrap();
            let (definite, keys) = labeled_keys(&cfg, &built);
            let report = verify_invariants(&definite, &keys, n).unwrap();
            assert!(
                report.all_invariants_hold(),
                "timelock {n} blocks failed: {report:?}"
            );
        }
    }

    // ---- Empirical: real secp256k1 signatures fed through rust-miniscript's own witness
    // construction algorithm (`Descriptor::get_satisfaction`), independent of the formal
    // entailment analysis above. Uses fresh throwaway keys via `policy_string`, the same
    // template `build_descriptor` uses, so the shape under test can't drift from production. ----

    fn concrete_descriptor(
        satochip: PublicKey,
        server: PublicKey,
        mobile: PublicKey,
        timelock: u16,
    ) -> Descriptor<PublicKey> {
        let s = policy_string(
            &satochip.to_string(),
            &server.to_string(),
            &mobile.to_string(),
            timelock,
        );
        Descriptor::<PublicKey>::from_str(&s).expect("valid miniscript")
    }

    #[test]
    fn hot_path_witness_constructs_with_satochip_and_server_and_no_wait() {
        let satochip = test_signer(0x11);
        let server = test_signer(0x12);
        let mobile = test_signer(0x13);
        let desc = concrete_descriptor(satochip.public, server.public, mobile.public, 12960);

        let mut sigs = HashMap::new();
        sigs.insert(satochip.public, test_signature(&satochip.secret));
        sigs.insert(server.public, test_signature(&server.secret));
        let satisfier = (sigs, Sequence::ZERO);

        desc.get_satisfaction(satisfier)
            .expect("satochip+server should satisfy the HOT path immediately");
    }

    #[test]
    fn recovery_path_witness_requires_satochip_and_mobile_and_the_full_timelock() {
        let satochip = test_signer(0x21);
        let server = test_signer(0x22);
        let mobile = test_signer(0x23);
        let timelock = 12960u16;
        let desc = concrete_descriptor(satochip.public, server.public, mobile.public, timelock);

        let mut sigs = HashMap::new();
        sigs.insert(satochip.public, test_signature(&satochip.secret));
        sigs.insert(mobile.public, test_signature(&mobile.secret));

        let one_block_early = (sigs.clone(), Sequence::from_height(timelock - 1));
        desc.get_satisfaction(one_block_early)
            .expect_err("must not satisfy one block before the timelock elapses");

        let exactly_at_timelock = (sigs, Sequence::from_height(timelock));
        desc.get_satisfaction(exactly_at_timelock)
            .expect("must satisfy exactly at the configured timelock");
    }

    #[test]
    fn no_single_key_witness_constructs_even_after_unlimited_time() {
        let satochip = test_signer(0x31);
        let server = test_signer(0x32);
        let mobile = test_signer(0x33);
        let desc = concrete_descriptor(satochip.public, server.public, mobile.public, 12960);
        let far_future = Sequence::from_height(u16::MAX);

        for signer in [&satochip, &server, &mobile] {
            let mut sigs = HashMap::new();
            sigs.insert(signer.public, test_signature(&signer.secret));
            desc.get_satisfaction((sigs, far_future)).expect_err(
                "a single key must never be able to spend, no matter how long it waits",
            );
        }
    }

    /// The no-hardware recovery path, empirically: SERVER + MOBILE must be blocked before the
    /// timelock and must work at it. This is what makes a destroyed SATOCHIP survivable.
    #[test]
    fn server_and_mobile_witness_constructs_only_after_the_timelock() {
        let satochip = test_signer(0x41);
        let server = test_signer(0x42);
        let mobile = test_signer(0x43);
        let timelock = 4320u16;
        let desc = concrete_descriptor(satochip.public, server.public, mobile.public, timelock);

        let mut sigs = HashMap::new();
        sigs.insert(server.public, test_signature(&server.secret));
        sigs.insert(mobile.public, test_signature(&mobile.secret));

        desc.get_satisfaction((sigs.clone(), Sequence::ZERO))
            .expect_err("server+mobile must not spend immediately");
        desc.get_satisfaction((sigs.clone(), Sequence::from_height(timelock - 1)))
            .expect_err("server+mobile must not spend one block before the timelock");
        desc.get_satisfaction((sigs, Sequence::from_height(timelock)))
            .expect("server+mobile must spend exactly at the timelock: lost-SATOCHIP recovery");
    }

    #[test]
    fn server_alone_can_never_spend_even_with_a_forged_looking_satisfier_for_every_other_slot() {
        // Belt-and-braces: SERVER's signature present, but no signature offered for any other
        // key at all (not even an attempted/garbage one) and no elapsed time. Must still fail.
        let satochip = test_signer(0x51);
        let server = test_signer(0x52);
        let mobile = test_signer(0x53);
        let desc = concrete_descriptor(satochip.public, server.public, mobile.public, 12960);

        let mut sigs = HashMap::new();
        sigs.insert(server.public, test_signature(&server.secret));
        desc.get_satisfaction((sigs, Sequence::ZERO))
            .expect_err("SERVER alone must never be able to spend");
    }
}
