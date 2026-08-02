//! Constructs and parses the wallet's miniscript descriptor.
//!
//! Policy (see README for the derivation): SATOCHIP is required for every spend. It is paired
//! either with SERVER for an immediate ("HOT") spend, or with MOBILE after a relative timelock
//! for the ("RECOVERY") spend that lets the user move funds even if this service is gone:
//!
//!   wsh(and_v(v:pk(SATOCHIP),or_d(pk(SERVER),and_v(v:pk(MOBILE),older(N)))))
//!
//! This mirrors the two-of-three structure described in LedgerHQ/resigner's README
//! (`and_v(v:pk(user),or_d(pk(service),older(N)))`), extended so the recovery branch also
//! requires MOBILE rather than SATOCHIP alone - our recovery path is 2-of-2, not 1-of-1.

use std::str::FromStr;

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

/// Builds the raw descriptor string `wsh(and_v(v:pk(A),or_d(pk(B),and_v(v:pk(C),older(N)))))`
/// from three already-formatted key expressions. Shared by the production builder and by
/// tests, so the policy shape used in tests can never drift from the one actually deployed.
pub fn policy_string(
    satochip_expr: &str,
    server_expr: &str,
    mobile_expr: &str,
    timelock_blocks: u16,
) -> String {
    format!(
        "wsh(and_v(v:pk({satochip_expr}),or_d(pk({server_expr}),and_v(v:pk({mobile_expr}),older({timelock_blocks})))))"
    )
}

pub fn build_descriptor(cfg: &WalletConfig) -> Result<BuiltDescriptor> {
    cfg.validate()?;

    let satochip_expr = key_expr(&cfg.keys.satochip).context("keys.satochip")?;
    let server_expr = key_expr(&cfg.keys.server).context("keys.server")?;
    let mobile_expr = key_expr(&cfg.keys.mobile).context("keys.mobile")?;

    let desc_str = policy_string(
        &satochip_expr,
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

/// Searches `desc` at indices `0..gap_limit` for one whose scriptPubkey equals `target`.
///
/// This is the only trustworthy way to answer "is this scriptPubkey ours": PSBT metadata
/// (bip32_derivation, the "this is change" convention some wallets use) is supplied by
/// whoever built the PSBT and must never be taken on faith - see `inspect.rs`.
fn find_on_chain(
    desc: &Descriptor<DescriptorPublicKey>,
    target: &bitcoin::ScriptBuf,
    gap_limit: u32,
) -> Result<Option<u32>> {
    for index in 0..gap_limit {
        let definite = at_index(desc, index)?;
        if &definite.script_pubkey() == target {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Searches both the external and internal chains of `wallet` for `target`, up to
/// `gap_limit` indices on each. Checks external first: an address a caller is *spending
/// from* is at least as likely to be a receive address as a change one, and either way both
/// chains resolve to the same policy, so the order only affects which `Chain` gets reported
/// when (pathologically) both happened to match.
pub fn find_owner(
    wallet: &BuiltDescriptor,
    target: &bitcoin::ScriptBuf,
    gap_limit: u32,
) -> Result<Option<Owned>> {
    if let Some(index) = find_on_chain(&wallet.external, target, gap_limit)? {
        return Ok(Some(Owned {
            chain: Chain::External,
            index,
        }));
    }
    if let Some(index) = find_on_chain(&wallet.internal, target, gap_limit)? {
        return Ok(Some(Owned {
            chain: Chain::Internal,
            index,
        }));
    }
    Ok(None)
}

/// Every key in a fully-derived (non-wildcard) descriptor, paired with its own key
/// expression string - used to pick a specific role's key back out by matching against the
/// xpub that role was configured with (the only stable identifier we have for "which key is
/// SATOCHIP" once everything's been derived down to raw public keys).
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
pub fn find_role_key(
    keys: &[(String, DefiniteDescriptorKey)],
    xpub: &str,
) -> Result<DefiniteDescriptorKey> {
    let xpub = xpub.trim();
    keys.iter()
        .find(|(s, _)| s.contains(xpub))
        .map(|(_, k)| k.clone())
        .with_context(|| format!("key for xpub {xpub} not found in descriptor"))
}

/// The three role keys (as concrete, spendable public keys - not descriptor key
/// expressions) at one derivation index, for matching against a PSBT's `partial_sigs`.
pub struct RoleKeys {
    pub satochip: bitcoin::PublicKey,
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
        satochip: find_role_key(&keys, &cfg.keys.satochip.xpub)?.to_public_key(),
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
        assert!(s.starts_with("wsh(and_v(v:pk("), "got: {s}");
        assert!(s.contains(",or_d(pk("), "got: {s}");
        assert!(s.contains(",older(12960)))))"), "got: {s}");
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

    #[test]
    fn find_owner_returns_none_for_a_foreign_script() {
        let cfg = test_wallet_config(12960);
        let built = build_descriptor(&cfg).unwrap();
        // A well-formed P2WSH scriptPubkey (OP_0 <32-byte hash>) that isn't ours.
        let foreign = bitcoin::ScriptBuf::from(vec![0u8; 34]);
        assert!(find_owner(&built, &foreign, 25).unwrap().is_none());
    }
}
