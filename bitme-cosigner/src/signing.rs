//! Produces the SERVER partial signature for the HOT-path inputs of an already-inspected,
//! already-policy-approved PSBT. Never finalizes or broadcasts - only ever adds one more
//! partial signature to inputs this service already independently verified (in `inspect.rs`)
//! belong to our descriptor.
//!
//! Every input's witness_script and witness_utxo are recomputed from our own descriptor and
//! from the chain-verified `InputReport`, then written into the PSBT before signing -
//! never trusted from whatever the caller's PSBT happened to contain, consistent with the
//! rest of this service's "verify or derive, never trust the PSBT" design.

use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::SighashCache;
use bitcoin::EcdsaSighashType;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{ChainNetwork, ServerSigningConfig, WalletConfig};
use crate::descriptor::{self, BuiltDescriptor, Chain};
use crate::inspect::InputReport;

/// The SERVER account-level extended private key, held for the service's lifetime so it can
/// keep countersigning HOT-path spends.
///
/// Zeroizing here is honest but limited, and the limitation is worth stating plainly: neither
/// `secp256k1` nor `bitcoin` implement `Zeroize` for `SecretKey`/`Xpriv` (verified against
/// their source - no such impl exists), and `Xpriv` is `Copy`, so the compiler is free to have
/// left copies of it elsewhere in memory by the time this drops. What this type actually
/// guarantees: the raw xprv string read from the file/env var is wiped as soon as it's parsed
/// (via `Zeroizing<String>`), and the parsed key's own bytes are best-effort overwritten on
/// drop via `SecretKey::non_secure_erase` - real mitigation, not a provable guarantee.
pub struct ServerSigningKey {
    xprv: Xpriv,
}

impl Drop for ServerSigningKey {
    fn drop(&mut self) {
        self.xprv.private_key.non_secure_erase();
    }
}

impl ServerSigningKey {
    /// Loads the xprv from the configured file or env var, and verifies it derives the exact
    /// xpub registered as `[keys.server]` - refusing to start with a key that doesn't match
    /// the wallet this service was built for.
    pub fn load(
        cfg: &ServerSigningConfig,
        expected_server_xpub: &str,
        network: ChainNetwork,
    ) -> Result<Self> {
        let raw: Zeroizing<String> = if let Some(path) = &cfg.xprv_file {
            Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading server_signing.xprv_file {path}"))?
                    .trim()
                    .to_string(),
            )
        } else if let Some(var) = &cfg.xprv_env_var {
            Zeroizing::new(
                std::env::var(var)
                    .with_context(|| format!("reading server_signing.xprv_env_var {var}"))?,
            )
        } else {
            anyhow::bail!("server_signing: one of xprv_file or xprv_env_var is required");
        };

        let xprv = Xpriv::from_str(raw.trim())
            .context("server_signing key is not a valid extended private key")?;

        let secp = Secp256k1::new();
        let derived_xpub = Xpub::from_priv(&secp, &xprv);
        let expected = Xpub::from_str(expected_server_xpub.trim())
            .context("keys.server.xpub is not a valid extended public key")?;
        if derived_xpub != expected {
            anyhow::bail!(
                "server_signing key does not match the registered keys.server.xpub - wrong key, or wrong \
                 derivation depth (server_signing must be the xprv AT keys.server.derivation_path, not the \
                 master key)"
            );
        }
        if xprv.network != expected.network {
            anyhow::bail!(
                "server_signing key network ({:?}) does not match keys.server.xpub network ({:?})",
                xprv.network,
                expected.network
            );
        }
        let _ = network; // network is already implied by the xpub match above; kept for a clearer error message path if ever needed

        Ok(Self { xprv })
    }

    fn derive_child(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        chain: Chain,
        index: u32,
    ) -> Result<Xpriv> {
        derive_child_xpriv(&self.xprv, secp, chain, index)
    }
}

/// Derives the `<chain>/<index>` child of an account-level xprv - the same unhardened path
/// the descriptor uses for every role's public key (`<0;1>/*`). `pub(crate)` so tests can
/// derive a matching child for a *different* role (e.g. HARDWARE) the same way, to build a
/// fully-satisfying witness alongside the SERVER signature this module produces.
pub(crate) fn derive_child_xpriv(
    account_xpriv: &Xpriv,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    chain: Chain,
    index: u32,
) -> Result<Xpriv> {
    let chain_num = match chain {
        Chain::External => 0,
        Chain::Internal => 1,
    };
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(chain_num).context("chain child number")?,
        ChildNumber::from_normal_idx(index).context("index child number")?,
    ]);
    account_xpriv
        .derive_priv(secp, &path)
        .context("deriving child signing key")
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("input {input_index} requests sighash type {requested:?}, but this service only ever signs SIGHASH_ALL")]
    UnsupportedSighashType {
        input_index: usize,
        requested: EcdsaSighashType,
    },
    #[error("input {input_index}: {source}")]
    Sighash {
        input_index: usize,
        #[source]
        source: bitcoin::psbt::SignError,
    },
    #[error("input {input_index}: derived signing key's public key does not match the expected SERVER role key - refusing to attach a signature that could not possibly be valid")]
    KeyMismatch { input_index: usize },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Signs every input in `inputs` with the SERVER key, in place. All-or-nothing: validates
/// every input's requested sighash type *before* mutating the PSBT, so a rejection never
/// leaves it partially signed.
pub fn sign_hot_inputs(
    psbt: &mut Psbt,
    wallet: &BuiltDescriptor,
    cfg: &WalletConfig,
    server_key: &ServerSigningKey,
    inputs: &[InputReport],
) -> Result<(), SigningError> {
    for (input_index, _) in inputs.iter().enumerate() {
        let requested = psbt.inputs[input_index].ecdsa_hash_ty().map_err(|_| {
            SigningError::UnsupportedSighashType {
                input_index,
                requested: EcdsaSighashType::All,
            }
        })?;
        if requested != EcdsaSighashType::All {
            return Err(SigningError::UnsupportedSighashType {
                input_index,
                requested,
            });
        }
    }

    let secp = Secp256k1::new();

    // `inputs` (an `InspectionReport::inputs`) was built by enumerating this same PSBT's
    // `unsigned_tx.input` in order - and `inspect()` already rejected the whole PSBT if any
    // input wasn't ours - so position `k` here is exactly `psbt.inputs[k]`, no lookup needed.
    for (input_index, input) in inputs.iter().enumerate() {
        let desc = match input.chain {
            Chain::External => &wallet.external,
            Chain::Internal => &wallet.internal,
        };
        let definite = descriptor::at_index(desc, input.index).map_err(SigningError::Other)?;
        let witness_script = definite
            .explicit_script()
            .map_err(|e| SigningError::Other(e.into()))?;
        let script_pubkey = definite.script_pubkey();

        psbt.inputs[input_index].witness_script = Some(witness_script.clone());
        psbt.inputs[input_index].witness_utxo = Some(bitcoin::TxOut {
            value: input.amount,
            script_pubkey,
        });

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let (msg, sighash_type) =
            psbt.sighash_ecdsa(input_index, &mut cache)
                .map_err(|source| SigningError::Sighash {
                    input_index,
                    source,
                })?;
        debug_assert_eq!(sighash_type, EcdsaSighashType::All, "checked above");

        let child = server_key
            .derive_child(&secp, input.chain, input.index)
            .map_err(SigningError::Other)?;
        let server_pubkey = bitcoin::PublicKey::new(child.private_key.public_key(&secp));

        let role_keys = descriptor::role_keys_at(wallet, cfg, input.chain, input.index)
            .map_err(SigningError::Other)?;
        if server_pubkey != role_keys.server {
            return Err(SigningError::KeyMismatch { input_index });
        }

        let raw_sig = secp.sign_ecdsa(&msg, &child.private_key);
        let sig = bitcoin::ecdsa::Signature {
            signature: raw_sig,
            sighash_type,
        };
        psbt.inputs[input_index]
            .partial_sigs
            .insert(server_pubkey, sig);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Txid, Witness,
    };

    use super::*;
    use crate::config::ServerSigningConfig;
    use crate::descriptor::build_descriptor;
    use crate::test_util::{test_key_spec_with_xpriv, test_server_xpriv, test_wallet_config};

    fn fake_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn foreign_script() -> ScriptBuf {
        let mut bytes = vec![0x00, 0x20];
        bytes.extend_from_slice(&[0xAB; 32]);
        ScriptBuf::from(bytes)
    }

    fn load_server_key(cfg: &WalletConfig, env_var: &str) -> ServerSigningKey {
        let xprv = test_server_xpriv();
        // SAFETY: test-only; each test uses a distinct env var name to avoid cross-test races.
        unsafe { std::env::set_var(env_var, xprv.to_string()) };
        let signing_cfg = ServerSigningConfig {
            xprv_file: None,
            xprv_env_var: Some(env_var.to_string()),
        };
        ServerSigningKey::load(&signing_cfg, &cfg.keys.server.xpub, cfg.network).unwrap()
    }

    fn unsigned_psbt_spending_index0(
        our_spk: ScriptBuf,
        amount: Amount,
        sequence: Sequence,
    ) -> (Psbt, OutPoint) {
        let outpoint = OutPoint::new(fake_txid(1), 0);
        let dest = TxOut {
            value: Amount::from_sat(amount.to_sat() - 10_000),
            script_pubkey: foreign_script(),
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![dest],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: amount,
            script_pubkey: our_spk,
        });
        (psbt, outpoint)
    }

    #[test]
    fn server_signature_is_cryptographically_valid_and_completes_a_satisfiable_witness() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let server_key = load_server_key(&cfg, "COSIGNER_TEST_XPRV_VALID_SIG");

        let our_spk = descriptor::at_index(&wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let amount = Amount::from_sat(100_000);
        let (mut psbt, outpoint) =
            unsigned_psbt_spending_index0(our_spk, amount, Sequence::ENABLE_RBF_NO_LOCKTIME);
        let inputs = vec![InputReport {
            outpoint,
            amount,
            confirmations: 6,
            chain: Chain::External,
            index: 0,
        }];

        sign_hot_inputs(&mut psbt, &wallet, &cfg, &server_key, &inputs).unwrap();

        let role_keys = descriptor::role_keys_at(&wallet, &cfg, Chain::External, 0).unwrap();
        let server_sig = *psbt.inputs[0]
            .partial_sigs
            .get(&role_keys.server)
            .expect("server signature must be present");

        // Independently re-derive the sighash message (via the same library API a correct
        // implementation must use) and verify the signature against it with a
        // verification-only context - proves this is a real, valid ECDSA signature over the
        // exact spend, not just "some signature got attached".
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let (msg, sighash_type) = psbt.sighash_ecdsa(0, &mut cache).unwrap();
        assert_eq!(sighash_type, EcdsaSighashType::All);
        Secp256k1::verification_only()
            .verify_ecdsa(&msg, &server_sig.signature, &role_keys.server.inner)
            .expect("server signature must verify against the real sighash");

        // Complete the witness with a matching HARDWARE signature (we hold that test key too)
        // and prove the *whole* HOT-path witness is satisfiable - not just that a signature
        // was attached, but that it's the correct one for this exact descriptor and input.
        let secp = Secp256k1::new();
        let (_, hardware_account_xprv) = test_key_spec_with_xpriv(0x01);
        let hardware_child =
            derive_child_xpriv(&hardware_account_xprv, &secp, Chain::External, 0).unwrap();
        let hardware_pubkey = bitcoin::PublicKey::new(hardware_child.private_key.public_key(&secp));
        assert_eq!(
            hardware_pubkey, role_keys.hardware,
            "test fixture derived the wrong hardware key"
        );
        let hardware_raw_sig = secp.sign_ecdsa(&msg, &hardware_child.private_key);
        let hardware_sig = bitcoin::ecdsa::Signature {
            signature: hardware_raw_sig,
            sighash_type,
        };

        // `get_satisfaction` needs a satisfier keyed by this descriptor's own key type
        // (`DefiniteDescriptorKey`, not the plain `bitcoin::PublicKey` used above for the
        // standalone signature-verification check), so look those up by role too.
        let definite = descriptor::at_index(&wallet.external, 0).unwrap();
        let definite_keys = descriptor::definite_keys(&definite);
        let hardware_definite_key =
            descriptor::find_role_key(&definite_keys, &cfg.keys.hardware.xpub).unwrap();
        let server_definite_key =
            descriptor::find_role_key(&definite_keys, &cfg.keys.server.xpub).unwrap();

        let mut sigs = HashMap::new();
        sigs.insert(hardware_definite_key, hardware_sig);
        sigs.insert(server_definite_key, server_sig);
        let satisfier = (sigs, Sequence::ZERO);

        definite
            .get_satisfaction(satisfier)
            .expect("hardware + server signatures must satisfy the HOT path");
    }

    #[test]
    fn rejects_a_non_all_sighash_type_without_mutating_the_psbt() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let server_key = load_server_key(&cfg, "COSIGNER_TEST_XPRV_BAD_SIGHASH");

        let our_spk = descriptor::at_index(&wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let amount = Amount::from_sat(100_000);
        let (mut psbt, outpoint) =
            unsigned_psbt_spending_index0(our_spk, amount, Sequence::ENABLE_RBF_NO_LOCKTIME);
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::None.into());
        let inputs = vec![InputReport {
            outpoint,
            amount,
            confirmations: 6,
            chain: Chain::External,
            index: 0,
        }];

        let err = sign_hot_inputs(&mut psbt, &wallet, &cfg, &server_key, &inputs).unwrap_err();
        assert!(matches!(
            err,
            SigningError::UnsupportedSighashType { input_index: 0, .. }
        ));
        assert!(
            psbt.inputs[0].witness_script.is_none(),
            "must not mutate the psbt when rejecting"
        );
        assert!(psbt.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn signing_is_deterministic_across_repeated_calls() {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let server_key = load_server_key(&cfg, "COSIGNER_TEST_XPRV_DETERMINISTIC");

        let our_spk = descriptor::at_index(&wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let amount = Amount::from_sat(100_000);
        let (mut psbt_a, outpoint) = unsigned_psbt_spending_index0(
            our_spk.clone(),
            amount,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        );
        let (mut psbt_b, _) =
            unsigned_psbt_spending_index0(our_spk, amount, Sequence::ENABLE_RBF_NO_LOCKTIME);
        let inputs = vec![InputReport {
            outpoint,
            amount,
            confirmations: 6,
            chain: Chain::External,
            index: 0,
        }];

        sign_hot_inputs(&mut psbt_a, &wallet, &cfg, &server_key, &inputs).unwrap();
        sign_hot_inputs(&mut psbt_b, &wallet, &cfg, &server_key, &inputs).unwrap();

        let role_keys = descriptor::role_keys_at(&wallet, &cfg, Chain::External, 0).unwrap();
        assert_eq!(
            psbt_a.inputs[0].partial_sigs.get(&role_keys.server),
            psbt_b.inputs[0].partial_sigs.get(&role_keys.server),
            "re-signing the same input must produce a byte-identical signature (RFC6979)"
        );
    }
}
