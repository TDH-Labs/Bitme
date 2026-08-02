//! Shared setup for the regtest integration tests. Not itself a test binary - Cargo's
//! `tests/<name>.rs` convention treats `tests/common/mod.rs` specially (unlike `tests/*.rs` at
//! the top level, it's never compiled as its own test target), which is exactly what makes it
//! safe to `mod common;` from more than one integration test file without duplicating setup.
//!
//! Not every test binary that pulls this module in uses every helper in it - that's expected
//! for a shared fixture module, not a sign of dead code in the crate itself.
#![allow(dead_code)]

use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    transaction, Address, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use cosigner::config::{ChainNetwork, KeySpec, KeysConfig, ServerSigningConfig, WalletConfig};
use cosigner::ledger::Ledger;
use cosigner::policy::PolicyConfig;
use cosigner::signing::ServerSigningKey;

pub const GAP_LIMIT: u32 = 20;
pub const TIMELOCK_BLOCKS: u16 = 6;
pub const SATOCHIP_SEED: u8 = 0xA1;
pub const MOBILE_SEED: u8 = 0xA2;
pub const SERVER_SEED: u8 = 0xA3;
pub const KEY_PATH: &str = "48h/1h/0h/2h";

/// Reads the three `COSIGNER_REGTEST_RPC_*` env vars, or returns `None` (meaning: skip). Every
/// test in both regtest integration files starts with
/// `let Some(node) = common::regtest_client() else { ...skip... };` so `cargo test` stays green
/// with no node available, while still running for real wherever one is.
pub fn regtest_client() -> Option<Client> {
    let url = std::env::var("COSIGNER_REGTEST_RPC_URL").ok()?;
    let user = std::env::var("COSIGNER_REGTEST_RPC_USER").unwrap_or_else(|_| "cosigner".into());
    let password =
        std::env::var("COSIGNER_REGTEST_RPC_PASSWORD").unwrap_or_else(|_| "cosigner".into());
    Some(
        Client::new(&url, Auth::UserPass(user, password))
            .expect("constructing bitcoind RPC client"),
    )
}

/// A second RPC client scoped to a fresh node-wallet named `name` (bitcoind's "no wallet
/// loaded by default" mode needs an explicit wallet for `sendtoaddress`/`getnewaddress`).
pub fn node_wallet_client(node: &Client, name: &str) -> Client {
    let _ = node.create_wallet(name, None, None, None, None);
    let rpc_url = std::env::var("COSIGNER_REGTEST_RPC_URL").unwrap();
    Client::new(
        &format!("{rpc_url}/wallet/{name}"),
        Auth::UserPass(
            std::env::var("COSIGNER_REGTEST_RPC_USER").unwrap_or_else(|_| "cosigner".into()),
            std::env::var("COSIGNER_REGTEST_RPC_PASSWORD").unwrap_or_else(|_| "cosigner".into()),
        ),
    )
    .unwrap()
}

pub fn key_spec_with_xpriv(seed_byte: u8, path: &str) -> (KeySpec, Xpriv) {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Test, &[seed_byte; 32]).unwrap();
    let fingerprint = master.fingerprint(&secp);
    let derivation_path = DerivationPath::from_str(path).unwrap();
    let derived = master.derive_priv(&secp, &derivation_path).unwrap();
    let xpub = Xpub::from_priv(&secp, &derived);
    let spec = KeySpec {
        master_fingerprint: fingerprint.to_string(),
        derivation_path: path.to_string(),
        xpub: xpub.to_string(),
    };
    (spec, derived)
}

pub fn key_spec(seed_byte: u8, path: &str) -> KeySpec {
    key_spec_with_xpriv(seed_byte, path).0
}

pub fn regtest_wallet_config() -> WalletConfig {
    WalletConfig {
        network: ChainNetwork::Regtest,
        i_understand_this_is_mainnet: false,
        timelock_blocks: TIMELOCK_BLOCKS,
        keys: KeysConfig {
            satochip: key_spec(SATOCHIP_SEED, KEY_PATH),
            mobile: key_spec(MOBILE_SEED, KEY_PATH),
            server: key_spec(SERVER_SEED, KEY_PATH),
        },
        bitcoind: None,
        server: None,
        policy: None,
        server_signing: None,
        notify: None,
        recovery: None,
    }
}

/// Derives the `<chain>/<index>` child xprv of an account-level xprv - the same unhardened
/// path every role's descriptor key uses (`<0;1>/*`). A test-only re-implementation of
/// `signing::derive_child_xpriv` (that one's `pub(crate)`, not reachable from an integration
/// test crate) so SATOCHIP signatures can be produced here the same way the server produces
/// SERVER ones.
pub fn derive_child_xpriv(account_xpriv: &Xpriv, chain: u32, index: u32) -> Xpriv {
    let secp = Secp256k1::new();
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(chain).unwrap(),
        ChildNumber::from_normal_idx(index).unwrap(),
    ]);
    account_xpriv.derive_priv(&secp, &path).unwrap()
}

/// Loads a `ServerSigningKey` matching `regtest_wallet_config()`'s server role, plus an
/// in-memory ledger (with `policy_cfg` seeded as version 1) and the resulting compiled policy -
/// the `/sign_psbt`-only pieces of `AppState` every regtest test has to provide.
pub async fn signing_test_fixtures(
    cfg: &WalletConfig,
    policy_cfg: PolicyConfig,
) -> (
    ServerSigningKey,
    Ledger,
    u64,
    cosigner::policy::CompiledPolicy,
) {
    let (_, xprv) = key_spec_with_xpriv(SERVER_SEED, KEY_PATH);
    let env_var = format!(
        "COSIGNER_TEST_SERVER_XPRV_{}_{}",
        std::process::id(),
        // Distinct per call within one process too, so tests run with `--test-threads=1` but
        // multiple fixtures per process (as the full-flow test does) never collide.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // SAFETY: test-only; env_var name is unique per call (see above).
    unsafe { std::env::set_var(&env_var, xprv.to_string()) };
    let signing_cfg = ServerSigningConfig {
        xprv_file: None,
        xprv_env_var: Some(env_var),
    };
    let server_key =
        ServerSigningKey::load(&signing_cfg, &cfg.keys.server.xpub, cfg.network).unwrap();

    let ledger = Ledger::connect_in_memory().await.unwrap();
    let policy = policy_cfg.compile(cfg.network).unwrap();
    let seeded = ledger
        .load_or_seed_policy_state(&serde_json::to_string(&policy_cfg).unwrap(), 0)
        .await
        .unwrap();

    (server_key, ledger, seeded.version, policy)
}

pub fn permissive_policy() -> PolicyConfig {
    PolicyConfig {
        max_tx_sat: u64::MAX,
        max_daily_sat: u64::MAX,
        max_weekly_sat: u64::MAX,
        max_monthly_sat: u64::MAX,
        max_fee_sat: u64::MAX,
        max_fee_rate_sat_per_vb: f64::MAX,
        destination_whitelist: None,
    }
}

/// Mines 101 blocks to a fresh node-wallet address (to mature coinbase funds), so the node
/// wallet has spendable BTC.
pub fn fund_node_wallet(node: &Client, wallet: &Client) {
    let mining_address = wallet.get_new_address(None, None).unwrap().assume_checked();
    node.generate_to_address(101, &mining_address).unwrap();
}

/// Sends `amount` from the node's wallet to `dest`, mines it into a block, and returns the
/// resulting outpoint plus the exact `TxOut` bitcoind now reports for it.
pub fn fund_address(
    node: &Client,
    wallet: &Client,
    dest: &Address,
    amount: Amount,
) -> (OutPoint, TxOut) {
    let txid = wallet
        .send_to_address(dest, amount, None, None, None, None, None, None)
        .unwrap();
    let mining_address = wallet.get_new_address(None, None).unwrap().assume_checked();
    node.generate_to_address(1, &mining_address).unwrap();

    let raw = node.get_raw_transaction_info(&txid, None).unwrap();
    let vout = raw
        .vout
        .iter()
        .find(|v| v.script_pub_key.script().ok().as_ref() == Some(&dest.script_pubkey()))
        .expect("funding output not found in its own transaction");

    let outpoint = OutPoint::new(txid, vout.n);
    let utxo = node
        .get_tx_out(&txid, vout.n, Some(true))
        .unwrap()
        .expect("just-mined utxo should exist");
    let txout = TxOut {
        value: utxo.value,
        script_pubkey: ScriptBuf::from(utxo.script_pub_key.hex),
    };
    (outpoint, txout)
}

/// Mines `n` empty blocks - used to advance past the RECOVERY path's relative timelock.
pub fn mine_blocks(node: &Client, wallet: &Client, n: u64) {
    let mining_address = wallet.get_new_address(None, None).unwrap().assume_checked();
    node.generate_to_address(n, &mining_address).unwrap();
}

pub fn unsigned_spend_psbt(
    outpoint: OutPoint,
    prevout: &TxOut,
    dest: &Address,
    send_amount: Amount,
    sequence: Sequence,
) -> Psbt {
    let txin = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    };
    let txout = TxOut {
        value: send_amount,
        script_pubkey: dest.script_pubkey(),
    };
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(prevout.clone());
    psbt
}
