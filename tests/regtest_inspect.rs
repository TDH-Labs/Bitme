//! Integration test for `POST /inspect` against a *real* `bitcoind` regtest node.
//!
//! See `tests/common/mod.rs` for the shared setup, and `tests/regtest_full_flow.rs` for the
//! fuller sign/hold/veto/policy-change flow against the same kind of node.
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
//! Then run this file together with `regtest_full_flow.rs` in one invocation, so they never
//! run as concurrent processes against the same node/mempool:
//!
//! ```sh
//! COSIGNER_REGTEST_RPC_URL=http://127.0.0.1:18443 \
//! COSIGNER_REGTEST_RPC_USER=cosigner \
//! COSIGNER_REGTEST_RPC_PASSWORD=cosigner \
//! cargo test --test regtest_inspect --test regtest_full_flow -- --test-threads=1
//! ```
//!
//! Without `COSIGNER_REGTEST_RPC_URL` set, every test in both files prints a message and passes
//! trivially - this is deliberate, so `cargo test` stays green in environments without a node,
//! while still running for real wherever one is available (e.g. your machine, or CI with a
//! bitcoind service container).

mod common;

use bitcoin::{Amount, Sequence};
use bitcoincore_rpc::RpcApi;
use cosigner::chain::BitcoindRpc;
use cosigner::descriptor;
use cosigner::http::{self, AppState};
use cosigner::notify::NoopNotifier;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn inspect_recognizes_a_real_utxo_and_computes_fee_over_regtest() {
    let Some(node) = common::regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = common::regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();

    let node_wallet = common::node_wallet_client(&node, "cosigner-test-hot");
    common::fund_node_wallet(&node, &node_wallet);

    let our_address = descriptor::address_at(&wallet.external, 0, cfg.network).unwrap();
    let (outpoint, prevout) = common::fund_address(
        &node,
        &node_wallet,
        &our_address,
        Amount::from_sat(1_000_000),
    );

    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let psbt = common::unsigned_spend_psbt(
        outpoint,
        &prevout,
        &dest_address,
        Amount::from_sat(900_000),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );

    let (server_key, ledger, policy_version, policy) =
        common::signing_test_fixtures(&cfg, common::permissive_policy()).await;
    let chain = std::sync::Arc::new(BitcoindRpc::new(node));
    let state = AppState {
        wallet: std::sync::Arc::new(wallet),
        cfg: std::sync::Arc::new(cfg),
        chain,
        gap_limit: common::GAP_LIMIT,
        server_key: std::sync::Arc::new(server_key),
        ledger: std::sync::Arc::new(ledger),
        policy: std::sync::Arc::new(tokio::sync::RwLock::new(http::PolicyHandle {
            version: policy_version,
            compiled: policy,
        })),
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
    let Some(node) = common::regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = common::regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();

    let node_wallet = common::node_wallet_client(&node, "cosigner-test-foreign");
    common::fund_node_wallet(&node, &node_wallet);

    // Fund an address that is NOT ours at all - just the node wallet's own.
    let foreign_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let (outpoint, prevout) = common::fund_address(
        &node,
        &node_wallet,
        &foreign_address,
        Amount::from_sat(1_000_000),
    );

    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let psbt = common::unsigned_spend_psbt(
        outpoint,
        &prevout,
        &dest_address,
        Amount::from_sat(900_000),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );

    let (server_key, ledger, policy_version, policy) =
        common::signing_test_fixtures(&cfg, common::permissive_policy()).await;
    let chain = std::sync::Arc::new(BitcoindRpc::new(node));
    let state = AppState {
        wallet: std::sync::Arc::new(wallet),
        cfg: std::sync::Arc::new(cfg),
        chain,
        gap_limit: common::GAP_LIMIT,
        server_key: std::sync::Arc::new(server_key),
        ledger: std::sync::Arc::new(ledger),
        policy: std::sync::Arc::new(tokio::sync::RwLock::new(http::PolicyHandle {
            version: policy_version,
            compiled: policy,
        })),
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
