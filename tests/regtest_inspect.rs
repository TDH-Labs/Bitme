//! Integration test for `POST /inspect` against a *real* `bitcoind` regtest node.
//!
//! This sandbox has no network path to bitcoincore.org (outbound HTTPS to it is blocked by
//! this environment's egress policy), no `bitcoind` apt package, and no working Docker
//! daemon, so this file could not actually be run or verified during development - the unit
//! tests in `src/inspect.rs` (43 of them, using an in-memory mock chain source) exercise the
//! same logic exhaustively, but this is the only test that goes through the real HTTP router
//! and a real node. Please run it once you have a node and report back if anything needs
//! adjusting.
//!
//! ## Running
//!
//! Start a regtest node (a fallback fee is required, or `sendtoaddress` below will fail with
//! "Fee estimation failed" - regtest has no fee market to estimate from):
//!
//! ```sh
//! bitcoind -regtest -daemon -fallbackfee=0.0001 \
//!   -rpcuser=cosigner -rpcpassword=cosigner -rpcport=18443
//! ```
//!
//! Then run:
//!
//! ```sh
//! COSIGNER_REGTEST_RPC_URL=http://127.0.0.1:18443 \
//! COSIGNER_REGTEST_RPC_USER=cosigner \
//! COSIGNER_REGTEST_RPC_PASSWORD=cosigner \
//! cargo test --test regtest_inspect -- --test-threads=1
//! ```
//!
//! Without `COSIGNER_REGTEST_RPC_URL` set, both tests print a message and pass trivially -
//! this is deliberate, so `cargo test` stays green in environments without a node, while
//! still running for real wherever one is available (e.g. your machine, or CI with a
//! bitcoind service container).

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    transaction, Address, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use cosigner::chain::BitcoindRpc;
use cosigner::config::{ChainNetwork, KeySpec, KeysConfig, ServerSigningConfig, WalletConfig};
use cosigner::descriptor;
use cosigner::http::{self, AppState};
use cosigner::ledger::Ledger;
use cosigner::notify::NoopNotifier;
use cosigner::policy::PolicyConfig;
use cosigner::signing::ServerSigningKey;
use http_body_util::BodyExt;
use tower::ServiceExt;

const GAP_LIMIT: u32 = 20;
const TIMELOCK_BLOCKS: u16 = 6;

/// Reads the three `COSIGNER_REGTEST_RPC_*` env vars, or returns `None` (meaning: skip).
fn regtest_client() -> Option<Client> {
    let url = std::env::var("COSIGNER_REGTEST_RPC_URL").ok()?;
    let user = std::env::var("COSIGNER_REGTEST_RPC_USER").unwrap_or_else(|_| "cosigner".into());
    let password =
        std::env::var("COSIGNER_REGTEST_RPC_PASSWORD").unwrap_or_else(|_| "cosigner".into());
    Some(
        Client::new(&url, Auth::UserPass(user, password))
            .expect("constructing bitcoind RPC client"),
    )
}

const SERVER_SEED: u8 = 0xA3;
const KEY_PATH: &str = "48h/1h/0h/2h";

fn key_spec_with_xpriv(seed_byte: u8, path: &str) -> (KeySpec, Xpriv) {
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

fn key_spec(seed_byte: u8, path: &str) -> KeySpec {
    key_spec_with_xpriv(seed_byte, path).0
}

fn regtest_wallet_config() -> WalletConfig {
    WalletConfig {
        network: ChainNetwork::Regtest,
        i_understand_this_is_mainnet: false,
        timelock_blocks: TIMELOCK_BLOCKS,
        keys: KeysConfig {
            satochip: key_spec(0xA1, KEY_PATH),
            mobile: key_spec(0xA2, KEY_PATH),
            server: key_spec(SERVER_SEED, KEY_PATH),
        },
        bitcoind: None,
        server: None,
        policy: None,
        server_signing: None,
        notify: None,
    }
}

/// Loads a `ServerSigningKey` matching `regtest_wallet_config()`'s server role, plus an
/// in-memory ledger and a permissive compiled policy - the `/sign_psbt`-only pieces of
/// `AppState` that `/inspect`-only tests still have to provide but don't exercise.
async fn signing_test_fixtures(
    cfg: &WalletConfig,
) -> (ServerSigningKey, Ledger, cosigner::policy::CompiledPolicy) {
    let (_, xprv) = key_spec_with_xpriv(SERVER_SEED, KEY_PATH);
    let env_var = format!("COSIGNER_TEST_SERVER_XPRV_{}", std::process::id());
    // SAFETY: test-only, single-threaded-per-process env var scoped to this process id.
    unsafe { std::env::set_var(&env_var, xprv.to_string()) };
    let signing_cfg = ServerSigningConfig {
        xprv_file: None,
        xprv_env_var: Some(env_var),
    };
    let server_key =
        ServerSigningKey::load(&signing_cfg, &cfg.keys.server.xpub, cfg.network).unwrap();

    let ledger = Ledger::connect_in_memory().await.unwrap();

    let policy_cfg = PolicyConfig {
        max_tx_sat: u64::MAX,
        max_daily_sat: u64::MAX,
        max_weekly_sat: u64::MAX,
        max_monthly_sat: u64::MAX,
        max_fee_sat: u64::MAX,
        max_fee_rate_sat_per_vb: f64::MAX,
        destination_whitelist: None,
    };
    let policy = policy_cfg.compile(cfg.network).unwrap();

    (server_key, ledger, policy)
}

/// Mines 101 blocks to a fresh node-wallet address (to mature coinbase funds), so the node
/// wallet has spendable BTC.
fn fund_node_wallet(node: &Client, wallet: &Client) {
    let mining_address = wallet.get_new_address(None, None).unwrap().assume_checked();
    node.generate_to_address(101, &mining_address).unwrap();
}

/// Sends `amount` from the node's wallet to `dest`, mines it into a block, and returns the
/// resulting outpoint plus the exact `TxOut` bitcoind now reports for it.
fn fund_address(
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

fn unsigned_spend_psbt(
    outpoint: OutPoint,
    prevout: &TxOut,
    dest: &Address,
    send_amount: Amount,
) -> Psbt {
    let txin = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
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

#[tokio::test]
async fn inspect_recognizes_a_real_utxo_and_computes_fee_over_regtest() {
    let Some(node) = regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();

    let wallet_name = "cosigner-test-hot";
    let _ = node.create_wallet(wallet_name, None, None, None, None);
    let rpc_url = std::env::var("COSIGNER_REGTEST_RPC_URL").unwrap();
    let node_wallet = Client::new(
        &format!("{rpc_url}/wallet/{wallet_name}"),
        Auth::UserPass(
            std::env::var("COSIGNER_REGTEST_RPC_USER").unwrap_or_else(|_| "cosigner".into()),
            std::env::var("COSIGNER_REGTEST_RPC_PASSWORD").unwrap_or_else(|_| "cosigner".into()),
        ),
    )
    .unwrap();
    fund_node_wallet(&node, &node_wallet);

    let our_address = descriptor::address_at(&wallet.external, 0, cfg.network).unwrap();
    let (outpoint, prevout) = fund_address(
        &node,
        &node_wallet,
        &our_address,
        Amount::from_sat(1_000_000),
    );

    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let psbt = unsigned_spend_psbt(outpoint, &prevout, &dest_address, Amount::from_sat(900_000));

    let (server_key, ledger, policy) = signing_test_fixtures(&cfg).await;
    let chain = std::sync::Arc::new(BitcoindRpc::new(node));
    let state = AppState {
        wallet: std::sync::Arc::new(wallet),
        cfg: std::sync::Arc::new(cfg),
        chain,
        gap_limit: GAP_LIMIT,
        server_key: std::sync::Arc::new(server_key),
        ledger: std::sync::Arc::new(ledger),
        policy: std::sync::Arc::new(policy),
        notifier: std::sync::Arc::new(NoopNotifier),
        hold_seconds: 0,
    };
    let app = http::router(state);

    let body = serde_json::json!({ "psbt": psbt.to_string() }).to_string();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/inspect")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "expected 200 OK from /inspect"
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["inputs"].as_array().unwrap().len(), 1);
    assert_eq!(json["inputs"][0]["chain"], "external");
    assert_eq!(json["inputs"][0]["index"], 0);
    assert_eq!(json["total_in_sat"], 1_000_000);
    assert_eq!(json["total_out_sat"], 900_000);
    assert_eq!(json["fee_sat"], 100_000);
    assert_eq!(json["spending_path"], "hot");
    assert_eq!(json["outputs"][0]["kind"], "destination");
}

#[tokio::test]
async fn inspect_rejects_an_input_not_derived_from_our_descriptor_over_regtest() {
    let Some(node) = regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();

    let wallet_name = "cosigner-test-foreign";
    let _ = node.create_wallet(wallet_name, None, None, None, None);
    let rpc_url = std::env::var("COSIGNER_REGTEST_RPC_URL").unwrap();
    let node_wallet = Client::new(
        &format!("{rpc_url}/wallet/{wallet_name}"),
        Auth::UserPass(
            std::env::var("COSIGNER_REGTEST_RPC_USER").unwrap_or_else(|_| "cosigner".into()),
            std::env::var("COSIGNER_REGTEST_RPC_PASSWORD").unwrap_or_else(|_| "cosigner".into()),
        ),
    )
    .unwrap();
    fund_node_wallet(&node, &node_wallet);

    // Fund an address that is NOT ours at all - just the node wallet's own.
    let foreign_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let (outpoint, prevout) = fund_address(
        &node,
        &node_wallet,
        &foreign_address,
        Amount::from_sat(1_000_000),
    );

    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let psbt = unsigned_spend_psbt(outpoint, &prevout, &dest_address, Amount::from_sat(900_000));

    let (server_key, ledger, policy) = signing_test_fixtures(&cfg).await;
    let chain = std::sync::Arc::new(BitcoindRpc::new(node));
    let state = AppState {
        wallet: std::sync::Arc::new(wallet),
        cfg: std::sync::Arc::new(cfg),
        chain,
        gap_limit: GAP_LIMIT,
        server_key: std::sync::Arc::new(server_key),
        ledger: std::sync::Arc::new(ledger),
        policy: std::sync::Arc::new(policy),
        notifier: std::sync::Arc::new(NoopNotifier),
        hold_seconds: 0,
    };
    let app = http::router(state);

    let body = serde_json::json!({ "psbt": psbt.to_string() }).to_string();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/inspect")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "foreign_input");
}
