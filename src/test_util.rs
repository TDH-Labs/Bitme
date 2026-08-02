//! Test-only fixtures. Not compiled into the shipped binary: no key material here is ever
//! loaded by the running service, and none of it should be treated as real key material.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Network, NetworkKind, PrivateKey, PublicKey};

use crate::config::{ChainNetwork, KeySpec, KeysConfig, WalletConfig};

pub const TEST_PATH: &str = "48h/1h/0h/2h";

/// Deterministically derives a (fingerprint, path, xpub) key spec plus the matching
/// account-level xprv from a single seed byte. Deterministic on purpose: tests must be
/// reproducible.
pub fn test_key_spec_with_xpriv(seed_byte: u8) -> (KeySpec, Xpriv) {
    let secp = Secp256k1::new();
    let seed = [seed_byte; 32];
    let master = Xpriv::new_master(NetworkKind::Test, &seed).expect("valid seed");
    let fingerprint = master.fingerprint(&secp);
    let path = DerivationPath::from_str(TEST_PATH).expect("valid path");
    let derived = master
        .derive_priv(&secp, &path)
        .expect("derivation succeeds");
    let xpub = Xpub::from_priv(&secp, &derived);
    let spec = KeySpec {
        master_fingerprint: fingerprint.to_string(),
        derivation_path: TEST_PATH.to_string(),
        xpub: xpub.to_string(),
    };
    (spec, derived)
}

pub fn test_key_spec(seed_byte: u8) -> KeySpec {
    test_key_spec_with_xpriv(seed_byte).0
}

/// The account-level xprv for the `server` role in [`test_wallet_config`] (seed `0x03`) -
/// use this to build a matching `ServerSigningKey` in signing tests.
pub fn test_server_xpriv() -> Xpriv {
    test_key_spec_with_xpriv(0x03).1
}

pub fn test_wallet_config(timelock_blocks: u16) -> WalletConfig {
    WalletConfig {
        network: ChainNetwork::Signet,
        i_understand_this_is_mainnet: false,
        timelock_blocks,
        keys: KeysConfig {
            satochip: test_key_spec(0x01),
            mobile: test_key_spec(0x02),
            server: test_key_spec(0x03),
        },
        bitcoind: None,
        server: None,
        policy: None,
        server_signing: None,
        notify: None,
    }
}

/// A single fresh secp256k1 keypair, independent of the xpub machinery above, for empirical
/// witness-satisfaction tests that need to actually sign something.
pub struct TestSigner {
    pub secret: SecretKey,
    pub public: PublicKey,
}

pub fn test_signer(seed_byte: u8) -> TestSigner {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed_byte; 32]).expect("valid scalar");
    let private = PrivateKey::new(secret, Network::Signet);
    let public = private.public_key(&secp);
    TestSigner { secret, public }
}

/// A fixed-message ECDSA signature under `secret`, wrapped for use with a miniscript Satisfier.
/// The message content is irrelevant here: satisfaction only checks that *a* signature is
/// present for the right key, not that it verifies against a real sighash.
pub fn test_signature(secret: &SecretKey) -> bitcoin::ecdsa::Signature {
    let secp = Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest([0x42; 32]);
    let sig = secp.sign_ecdsa(&msg, secret);
    bitcoin::ecdsa::Signature::sighash_all(sig)
}
