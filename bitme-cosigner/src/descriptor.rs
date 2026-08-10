//! Constructs and parses the wallet's miniscript descriptor.
//!
//! Policy: **any two of the three keys can spend, but any spend involving the MOBILE key waits
//! `N` blocks.**
//!
//!   wsh(thresh(2,pk(HARDWARE),s:pk(SERVER),snj:and_v(v:pk(MOBILE),older(N))))
//!
//! Which gives exactly three spending combinations:
//!
//!   - HARDWARE + SERVER, immediately - the "HOT" path, and the only one this service
//!     co-signs on demand, subject to the policy engine.
//!   - HARDWARE + MOBILE, after `N` blocks - recovery when *this service* is gone.
//!   - MOBILE + SERVER, after `N` blocks - recovery when the *HARDWARE* is gone.
//!
//! That third combination is the reason for this shape. An earlier revision made HARDWARE
//! mandatory in both branches
//! (`and_v(v:pk(HARDWARE),or_d(pk(SERVER),and_v(v:pk(MOBILE),older(N))))`), which meant losing
//! the HARDWARE seed lost the funds outright - a single point of catastrophic failure with no
//! recourse. Every single-device loss is now survivable, which is the property Bitkey's 2-of-3
//! has and that one lacked.
//!
//! The timelock on the MOBILE branch is what keeps this service meaningful: the *only* way to
//! spend without waiting `N` blocks is HARDWARE + SERVER, so the policy engine cannot be
//! side-stepped for day-to-day spending. And unlike Bitkey - whose "Delay & Notify" waiting
//! period is enforced by their server and therefore evaporates if that server is compromised or
//! shut down - this delay is a consensus rule. It holds even if this service is rooted, seized,
//! or deleted.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use bitcoin::Address;
use miniscript::descriptor::{DefiniteDescriptorKey, DescriptorType};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey, ToPublicKey};

use crate::config::{ChainNetwork, KeySpec, WalletConfig};

/// A fully constructed wallet descriptor, split into its receive (external) and change
/// (internal) halves per BIP389 multipath convention `<0;1>`.
#[derive(Debug, Clone)]
pub struct BuiltDescriptor {
    /// The single descriptor string containing both paths via `<0;1>`, as configured.
    pub multipath: Descriptor<DescriptorPublicKey>,
    /// Receive addresses (multipath index 0).
    pub external: Descriptor<DescriptorPublicKey>,
    /// Change addresses (multipath index 1).
    pub internal: Descriptor<DescriptorPublicKey>,
    pub timelock_blocks: u16,
    /// Lazily-built `scriptPubkey -> (chain, index)` map, so ownership is a hash lookup rather
    /// than a linear scan. See [`find_owner`].
    ///
    /// `Arc<Mutex<..>>` rather than `OnceLock`: clones of a `BuiltDescriptor` (the signing path
    /// clones one into `spawn_blocking` on every request) must share the work rather than each
    /// redo it, and the cache has to be invalidated when `gap_limit` changes - which only
    /// happens in tests, but silently returning results for the wrong gap limit would be a
    /// nasty way to find that out.
    spk_index: Arc<Mutex<Option<ScriptIndex>>>,
}

/// Every scriptPubkey this wallet can produce up to a gap limit, and where it sits.
#[derive(Debug)]
struct ScriptIndex {
    gap_limit: u32,
    by_script: HashMap<bitcoin::ScriptBuf, Owned>,
}

fn key_expr(key: &KeySpec) -> Result<String> {
    let fp = key.master_fingerprint.trim().to_lowercase();
    let path = bitcoin::bip32::DerivationPath::from_str(key.derivation_path.trim())
        .context("invalid derivation path")?;
    let xpub = key.xpub.trim();
    if path.is_empty() {
        Ok(format!("[{fp}]{xpub}/<0;1>/*"))
    } else {
        Ok(format!("[{fp}/{path}]{xpub}/<0;1>/*"))
    }
}

/// Builds the raw descriptor string
/// `wsh(thresh(2,pk(A),s:pk(B),snj:and_v(v:pk(C),older(N))))` from three already-formatted key
/// expressions. Shared by the production builder and by tests, so the policy shape used in
/// tests can never drift from the one actually deployed.
///
/// The `s:`/`snj:` wrappers are miniscript type-system coercions (`thresh` needs every branch
/// to leave a 0-or-1 on the stack); this exact form is what rust-miniscript's own policy
/// compiler emits for `thresh(2,pk(A),pk(B),and(pk(C),older(N)))`, kept literal here so the
/// deployed script is deterministic rather than dependent on a compiler's cost heuristics.
pub fn policy_string(
    hardware_expr: &str,
    server_expr: &str,
    mobile_expr: &str,
    timelock_blocks: u16,
) -> String {
    format!(
        "wsh(thresh(2,pk({hardware_expr}),s:pk({server_expr}),snj:and_v(v:pk({mobile_expr}),older({timelock_blocks}))))"
    )
}

pub fn build_descriptor(cfg: &WalletConfig) -> Result<BuiltDescriptor> {
    cfg.validate()?;

    let hardware_expr = key_expr(&cfg.keys.hardware).context("keys.hardware")?;
    let server_expr = key_expr(&cfg.keys.server).context("keys.server")?;
    let mobile_expr = key_expr(&cfg.keys.mobile).context("keys.mobile")?;

    let desc_str = policy_string(
        &hardware_expr,
        &server_expr,
        &mobile_expr,
        cfg.timelock_blocks,
    );

    let multipath = Descriptor::<DescriptorPublicKey>::from_str(&desc_str)
        .with_context(|| format!("parsing generated descriptor: {desc_str}"))?;

    if multipath.desc_type() != DescriptorType::Wsh {
        bail!(
            "expected a wsh() descriptor, got {:?}",
            multipath.desc_type()
        );
    }
    multipath
        .sanity_check()
        .context("generated descriptor failed miniscript sanity check")?;

    let mut singles = multipath
        .clone()
        .into_single_descriptors()
        .context("splitting multipath descriptor into external/internal")?;
    if singles.len() != 2 {
        bail!(
            "expected exactly 2 derivation paths (external, internal) from <0;1>, got {}",
            singles.len()
        );
    }
    let internal = singles.pop().unwrap();
    let external = singles.pop().unwrap();
    external
        .sanity_check()
        .context("external descriptor failed sanity check")?;
    internal
        .sanity_check()
        .context("internal descriptor failed sanity check")?;

    Ok(BuiltDescriptor {
        multipath,
        external,
        internal,
        timelock_blocks: cfg.timelock_blocks,
        spk_index: Arc::new(Mutex::new(None)),
    })
}

/// Derives the address at `index` for a single-path (non-multipath) descriptor.
pub fn address_at(
    desc: &Descriptor<DescriptorPublicKey>,
    index: u32,
    network: ChainNetwork,
) -> Result<Address> {
    let definite = desc
        .at_derivation_index(index)
        .with_context(|| format!("deriving index {index}"))?;
    definite
        .address(network.to_bitcoin_network())
        .with_context(|| format!("computing address at index {index}"))
}

/// Resolves a single-path descriptor to its fully concrete (non-wildcard) form at `index`,
/// for invariant analysis and satisfaction.
pub fn at_index(
    desc: &Descriptor<DescriptorPublicKey>,
    index: u32,
) -> Result<Descriptor<DefiniteDescriptorKey>> {
    desc.at_derivation_index(index)
        .with_context(|| format!("deriving index {index}"))
}

/// Which chain (receive/external or change/internal) a derived scriptPubkey was found on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    External,
    Internal,
}

/// Where in the wallet a scriptPubkey was found, from [`find_owner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owned {
    pub chain: Chain,
    pub index: u32,
}

/// Searches both the external and internal chains of `wallet` for `target`, up to
/// `gap_limit` indices on each. Checks external first: an address a caller is *spending
/// from* is at least as likely to be a receive address as a change one, and either way both
/// chains resolve to the same policy, so the order only affects which `Chain` gets reported
/// when (pathologically) both happened to match.
///
/// Backed by a cache built once per `(wallet, gap_limit)`.
///
/// **Invariant: ownership lookup is O(1) in the gap limit.** This is called once per PSBT input,
/// with a default gap limit of 1000, so deriving a key and hashing a script for every index on
/// both chains per call would make the work per request scale with both the gap limit and the
/// input count. Building the map once turns each subsequent lookup into a hash probe. Do not put
/// the scan back.
pub fn find_owner(
    wallet: &BuiltDescriptor,
    target: &bitcoin::ScriptBuf,
    gap_limit: u32,
) -> Result<Option<Owned>> {
    let mut guard = wallet
        .spk_index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Rebuild when the gap limit differs from what the cache was built for. In production that
    // never happens - it comes from config and does not change while the process runs - but
    // answering from a map built for a *different* gap limit would silently report a script as
    // foreign (or as ours) depending on call order, which is precisely the kind of bug that only
    // shows up once real coins are involved.
    let needs_build = match guard.as_ref() {
        Some(index) => index.gap_limit != gap_limit,
        None => true,
    };
    if needs_build {
        *guard = Some(build_script_index(wallet, gap_limit)?);
    }

    Ok(guard
        .as_ref()
        .expect("just built")
        .by_script
        .get(target)
        .copied())
}

fn build_script_index(wallet: &BuiltDescriptor, gap_limit: u32) -> Result<ScriptIndex> {
    let mut by_script = HashMap::with_capacity(gap_limit as usize * 2);
    // Internal first, then external, so that external wins on the (pathological) collision -
    // preserving the ordering the linear scan had.
    for (chain, desc) in [
        (Chain::Internal, &wallet.internal),
        (Chain::External, &wallet.external),
    ] {
        for index in 0..gap_limit {
            let definite = at_index(desc, index)?;
            by_script.insert(definite.script_pubkey(), Owned { chain, index });
        }
    }
    Ok(ScriptIndex {
        gap_limit,
        by_script,
    })
}

/// Every key in a fully-derived (non-wildcard) descriptor, paired with its own key
/// expression string - used to pick a specific role's key back out by matching against the
/// xpub that role was configured with (the only stable identifier we have for "which key is
/// HARDWARE" once everything's been derived down to raw public keys).
pub fn definite_keys(
    desc: &Descriptor<DefiniteDescriptorKey>,
) -> Vec<(String, DefiniteDescriptorKey)> {
    let mut found = Vec::new();
    desc.for_each_key(|k| {
        found.push((k.to_string(), k.clone()));
        true
    });
    found
}

/// Picks the key belonging to `xpub` out of `keys` (as produced by [`definite_keys`]).
///
/// Matches on the key expression's parsed extended key rather than by substring. Substring
/// matching happened to work - real xpubs are fixed-length base58 and one is not a substring of
/// another - but this function decides *which key is the SERVER key* immediately before signing
/// with it, and "happens to work" is the wrong standard for that. An exact comparison cannot be
/// fooled by a prefix relationship that a future key format might permit.
pub fn find_role_key(
    keys: &[(String, DefiniteDescriptorKey)],
    xpub: &str,
) -> Result<DefiniteDescriptorKey> {
    let xpub = xpub.trim();
    let wanted: bitcoin::bip32::Xpub = xpub
        .parse()
        .with_context(|| format!("role xpub {xpub} is not a valid extended public key"))?;

    keys.iter()
        .find(|(expr, _)| key_expr_xpub(expr).is_some_and(|found| found == wanted))
        .map(|(_, k)| k.clone())
        .with_context(|| format!("key for xpub {xpub} not found in descriptor"))
}

/// Extracts the extended key from a descriptor key expression - `[origin]xpub/0/5` and friends.
/// Returns `None` for anything that isn't an xpub-derived expression (e.g. a raw public key),
/// which simply means it can never match a role.
fn key_expr_xpub(expr: &str) -> Option<bitcoin::bip32::Xpub> {
    let after_origin = match expr.split_once(']') {
        Some((_, rest)) => rest,
        None => expr,
    };
    after_origin.split('/').next()?.parse().ok()
}

/// The three role keys (as concrete, spendable public keys - not descriptor key
/// expressions) at one derivation index, for matching against a PSBT's `partial_sigs`.
pub struct RoleKeys {
    pub hardware: bitcoin::PublicKey,
    pub server: bitcoin::PublicKey,
    pub mobile: bitcoin::PublicKey,
}

pub fn role_keys_at(
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    chain: Chain,
    index: u32,
) -> Result<RoleKeys> {
    let desc = match chain {
        Chain::External => &wallet.external,
        Chain::Internal => &wallet.internal,
    };
    let definite = at_index(desc, index)?;
    let keys = definite_keys(&definite);
    Ok(RoleKeys {
        hardware: find_role_key(&keys, &cfg.keys.hardware.xpub)?.to_public_key(),
        server: find_role_key(&keys, &cfg.keys.server.xpub)?.to_public_key(),
        mobile: find_role_key(&keys, &cfg.keys.mobile.xpub)?.to_public_key(),
    })
}

/// Parses a standalone descriptor string (e.g. loaded from a file, or produced by another
/// tool) for `descriptor check`. Does not require key role information.
///
/// If the descriptor is a `<0;1>` multipath descriptor, returns its external (index 0) half -
/// `at_derivation_index` cannot resolve a multipath key on its own, and the invariant analysis
/// depends only on the miniscript's key/timelock structure, which is identical on both paths.
pub fn parse_descriptor(s: &str) -> Result<Descriptor<DescriptorPublicKey>> {
    let desc = Descriptor::<DescriptorPublicKey>::from_str(s.trim())
        .with_context(|| "parsing descriptor")?;
    desc.sanity_check()
        .context("descriptor failed miniscript sanity check")?;

    if desc.is_multipath() {
        let mut singles = desc
            .into_single_descriptors()
            .context("splitting multipath descriptor")?;
        if singles.is_empty() {
            bail!("multipath descriptor split into zero single-path descriptors");
        }
        let external = singles.remove(0);
        external
            .sanity_check()
            .context("external descriptor failed sanity check")?;
        Ok(external)
    } else {
        Ok(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_wallet_config;

    #[test]
    fn builds_expected_wsh_shape() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).expect("should build");

        assert_eq!(built.multipath.desc_type(), DescriptorType::Wsh);
        let s = built.multipath.to_string();
        assert!(s.starts_with("wsh(thresh(2,pk("), "got: {s}");
        assert!(s.contains(",s:pk("), "got: {s}");
        assert!(s.contains(",snj:and_v(v:pk("), "got: {s}");
        assert!(s.contains(",older(12960))))"), "got: {s}");
        assert!(s.contains("<0;1>/*"), "got: {s}");

        // Round-trips through the parser byte-for-byte (proves it's a valid, canonical
        // descriptor string, not just something we happened to construct).
        let reparsed = Descriptor::<DescriptorPublicKey>::from_str(&s).unwrap();
        assert_eq!(reparsed.to_string(), s);
    }

    #[test]
    fn splits_into_distinct_external_and_internal_descriptors() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        assert_ne!(built.external.to_string(), built.internal.to_string());
        assert!(!built.external.is_multipath());
        assert!(!built.internal.is_multipath());

        let receive0 = address_at(&built.external, 0, cfg.network).unwrap();
        let change0 = address_at(&built.internal, 0, cfg.network).unwrap();
        assert_ne!(receive0, change0);
    }

    #[test]
    fn address_derivation_is_deterministic() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let a = address_at(&built.external, 5, cfg.network).unwrap();
        let b = address_at(&built.external, 5, cfg.network).unwrap();
        assert_eq!(a, b);
        let c = address_at(&built.external, 6, cfg.network).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn rejects_config_that_fails_validation() {
        let mut cfg = test_wallet_config(0);
        cfg.timelock_blocks = 0;
        assert!(build_descriptor(&cfg).is_err());
    }

    #[test]
    fn parse_descriptor_accepts_a_multipath_string_and_splits_it() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let parsed = parse_descriptor(&built.multipath.to_string()).unwrap();
        assert_eq!(parsed.to_string(), built.external.to_string());
    }

    #[test]
    fn parse_descriptor_rejects_garbage() {
        assert!(parse_descriptor("not a descriptor").is_err());
    }

    #[test]
    fn parse_descriptor_rejects_wrong_checksum() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let mut s = built.external.to_string();
        s.push('x'); // corrupt the checksum
        assert!(parse_descriptor(&s).is_err());
    }

    #[test]
    fn find_owner_locates_external_and_internal_scripts() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();

        let receive3 = at_index(&built.external, 3).unwrap().script_pubkey();
        let owned = find_owner(&built, &receive3, 10)
            .unwrap()
            .expect("should find it");
        assert_eq!(
            owned,
            Owned {
                chain: Chain::External,
                index: 3
            }
        );

        let change7 = at_index(&built.internal, 7).unwrap().script_pubkey();
        let owned = find_owner(&built, &change7, 10)
            .unwrap()
            .expect("should find it");
        assert_eq!(
            owned,
            Owned {
                chain: Chain::Internal,
                index: 7
            }
        );
    }

    #[test]
    fn find_owner_respects_the_gap_limit() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let receive50 = at_index(&built.external, 50).unwrap().script_pubkey();
        assert!(find_owner(&built, &receive50, 10).unwrap().is_none());
        assert!(find_owner(&built, &receive50, 51).unwrap().is_some());
    }

    /// The hazard the cache introduces: answering from a map built for a *different* gap limit.
    /// A script beyond the current limit must read as foreign even if a previous call with a
    /// larger limit put it in the map, and vice versa - otherwise ownership would depend on call
    /// order, which is the sort of bug that only surfaces once real coins are involved.
    #[test]
    fn changing_the_gap_limit_invalidates_the_cache_in_both_directions() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let far = at_index(&built.external, 40).unwrap().script_pubkey();

        // Wide first, so index 40 is cached as ours...
        assert!(find_owner(&built, &far, 50).unwrap().is_some());
        // ...then narrow: it must stop being ours.
        assert!(
            find_owner(&built, &far, 10).unwrap().is_none(),
            "a narrower gap limit must not answer from a wider cache"
        );
        // ...and widening again must find it once more.
        assert!(
            find_owner(&built, &far, 50).unwrap().is_some(),
            "a wider gap limit must rebuild rather than answer from the narrow cache"
        );
    }

    /// Clones share the cache rather than each rebuilding it - the signing path clones a
    /// `BuiltDescriptor` into `spawn_blocking` on every request, so per-clone rebuilds would put
    /// the cost straight back.
    #[test]
    fn a_clone_shares_the_built_index() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        let script = at_index(&built.external, 3).unwrap().script_pubkey();

        find_owner(&built, &script, 25).unwrap();
        let clone = built.clone();
        assert!(
            clone.spk_index.lock().unwrap().is_some(),
            "the clone must see the already-built index, not an empty one"
        );
        assert_eq!(
            find_owner(&clone, &script, 25).unwrap(),
            Some(Owned {
                chain: Chain::External,
                index: 3
            })
        );
    }

    #[test]
    fn find_owner_returns_none_for_a_foreign_script() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        // A well-formed P2WSH scriptPubkey (OP_0 <32-byte hash>) that isn't ours.
        let foreign = bitcoin::ScriptBuf::from(vec![0u8; 34]);
        assert!(find_owner(&built, &foreign, 25).unwrap().is_none());
    }
}
