//! The live end-to-end flow against a *real* `bitcoind` regtest node: fund a UTXO, submit a
//! PSBT through the real HTTP router, let it queue, sweep it once its hold elapses, and prove
//! the resulting witness is genuinely satisfiable - not just that an HTTP call returned 200.
//! Also covers `POST /veto/{id}` blocking a live spend, and a HARDWARE-authorized `POST
//! /policy` change actually being enforced by a subsequent `/sign_psbt` call.
//!
//! This exists specifically to close the two gaps a prior verification pass left open ("needs
//! a signet faucet" / "needs signature scripting"): regtest needs no faucet at all (mine blocks
//! to yourself), and the signature-scripting here reuses the exact techniques already proven in
//! `src/signing.rs`'s and `src/policy_auth.rs`'s own unit tests - re-implemented here rather
//! than imported, since those helpers are `pub(crate)`/test-only and not reachable from an
//! external integration test crate.
//!
//! See `tests/common/mod.rs` for shared setup, and `tests/regtest_inspect.rs`'s doc comment for
//! how to start a node. Run both regtest files in the same invocation so they never run as
//! concurrent processes against the same node/mempool:
//!
//! ```sh
//! COSIGNER_REGTEST_RPC_URL=http://127.0.0.1:18443 \
//! COSIGNER_REGTEST_RPC_USER=cosigner \
//! COSIGNER_REGTEST_RPC_PASSWORD=cosigner \
//! cargo test --test regtest_inspect --test regtest_full_flow -- --test-threads=1
//! ```

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::SighashCache;
use bitcoin::{Amount, Sequence};
use bitcoincore_rpc::RpcApi;
use cosigner::chain::{BitcoindRpc, ChainSource};
use cosigner::descriptor::{self, BuiltDescriptor, Chain};
use cosigner::http::{self, AppState, PolicyHandle};
use cosigner::notify::NoopNotifier;
use cosigner::policy::PolicyConfig;
use cosigner::sign;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Attaches a real HARDWARE partial signature to `psbt`'s single input, computed the same way
/// `signing::sign_hot_inputs` computes SERVER's - independent proof that this input's sighash
/// is something a real key can sign over correctly, not just something cosigner claims.
fn attach_hardware_signature(
    psbt: &mut bitcoin::psbt::Psbt,
    wallet: &BuiltDescriptor,
    hardware_account_xprv: &Xpriv,
    index: u32,
) {
    let secp = Secp256k1::new();
    let definite = descriptor::at_index(&wallet.external, index).unwrap();
    let witness_script = definite.explicit_script().unwrap();
    psbt.inputs[0].witness_script = Some(witness_script);

    let hardware_child = common::derive_child_xpriv(hardware_account_xprv, 0, index);
    let hardware_pubkey = bitcoin::PublicKey::new(hardware_child.private_key.public_key(&secp));

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let (msg, sighash_type) = psbt.sighash_ecdsa(0, &mut cache).unwrap();
    let raw_sig = secp.sign_ecdsa(&msg, &hardware_child.private_key);
    psbt.inputs[0].partial_sigs.insert(
        hardware_pubkey,
        bitcoin::ecdsa::Signature {
            signature: raw_sig,
            sighash_type,
        },
    );
}

/// Proves the fully-signed PSBT (HARDWARE + SERVER partial sigs) actually satisfies the HOT
/// branch of the real miniscript - the strongest live proof available short of broadcasting:
/// not "the API returned 200", but "this witness is genuinely valid for this descriptor".
fn assert_hot_witness_is_satisfiable(
    signed_psbt: &bitcoin::psbt::Psbt,
    wallet: &BuiltDescriptor,
    cfg: &cosigner::config::WalletConfig,
    index: u32,
) {
    let definite = descriptor::at_index(&wallet.external, index).unwrap();
    let keys = descriptor::definite_keys(&definite);
    let hardware_key = descriptor::find_role_key(&keys, &cfg.keys.hardware.xpub).unwrap();
    let server_key = descriptor::find_role_key(&keys, &cfg.keys.server.xpub).unwrap();

    let hardware_pk = descriptor::role_keys_at(wallet, cfg, Chain::External, index)
        .unwrap()
        .hardware;
    let server_pk = descriptor::role_keys_at(wallet, cfg, Chain::External, index)
        .unwrap()
        .server;

    let hardware_sig = *signed_psbt.inputs[0]
        .partial_sigs
        .get(&hardware_pk)
        .expect("hardware signature must be present");
    let server_sig = *signed_psbt.inputs[0]
        .partial_sigs
        .get(&server_pk)
        .expect("server signature must be present - cosigner did not sign this input");

    let mut sigs = HashMap::new();
    sigs.insert(hardware_key, hardware_sig);
    sigs.insert(server_key, server_sig);
    let satisfier = (sigs, Sequence::ZERO);

    definite
        .get_satisfaction(satisfier)
        .expect("hardware + server signatures must satisfy the HOT path for real");
}

async fn build_state(
    node: bitcoincore_rpc::Client,
    cfg: &cosigner::config::WalletConfig,
    wallet: &BuiltDescriptor,
    policy_cfg: PolicyConfig,
    hold_seconds: i64,
) -> (AppState, Arc<dyn ChainSource>, u64) {
    let (server_key, ledger, policy_version, policy) =
        common::signing_test_fixtures(cfg, policy_cfg).await;
    let chain: Arc<dyn ChainSource> = Arc::new(BitcoindRpc::new(node));
    let state = AppState {
        wallet: Arc::new(wallet.clone()),
        cfg: Arc::new(cfg.clone()),
        chain: chain.clone(),
        gap_limit: common::GAP_LIMIT,
        server_key: Arc::new(server_key),
        ledger: Arc::new(ledger),
        policy: Arc::new(tokio::sync::RwLock::new(PolicyHandle {
            version: policy_version,
            compiled: policy,
        })),
        auth_keys: Arc::new(
            cosigner::policy_auth::HardwareAuthKeys::from_config(cfg, common::GAP_LIMIT)
                .expect("precomputing hardware authorization keys"),
        ),
        api_token: None,
        recovery_contacts: None,
        notifier: Arc::new(NoopNotifier),
        hold_seconds,
    };
    (state, chain, policy_version)
}

async fn post_json(
    app: axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            axum::body::Body::from(b.to_string())
        }
        None => axum::body::Body::empty(),
    };
    let response = app.oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

#[tokio::test]
async fn full_hot_spend_is_queued_held_and_then_signed_with_a_real_satisfiable_witness() {
    let Some(node) = common::regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = common::regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();
    let (_, hardware_xprv) = common::key_spec_with_xpriv(common::HARDWARE_SEED, common::KEY_PATH);

    let node_wallet = common::node_wallet_client(&node, "cosigner-full-flow-hot");
    common::fund_node_wallet(&node, &node_wallet);

    let our_address = descriptor::address_at(&wallet.external, 0, cfg.network).unwrap();
    let (outpoint, prevout) =
        common::fund_address(&node, &node_wallet, &our_address, Amount::from_sat(200_000));
    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let mut psbt = common::unsigned_spend_psbt(
        outpoint,
        &prevout,
        &dest_address,
        Amount::from_sat(199_000),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );
    attach_hardware_signature(&mut psbt, &wallet, &hardware_xprv, 0);

    let submitted_at = now_unix();
    let (state, chain, _) =
        build_state(node, &cfg, &wallet, common::permissive_policy(), 3_600).await;
    let ledger = state.ledger.clone();
    let server_key = state.server_key.clone();
    let policy_snapshot = state.policy.read().await.compiled.clone();

    let (status, body) = post_json(
        http::router(state.clone()),
        "POST",
        "/sign_psbt",
        Some(serde_json::json!({ "psbt": psbt.to_string() })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::ACCEPTED,
        "expected 202 Queued, got: {body}"
    );
    assert_eq!(body["status"], "pending");
    let id = body["id"].as_str().unwrap().to_string();
    assert!(body["hold_until"].as_i64().unwrap() >= submitted_at + 3_600);

    // Not due yet: a sweep "now" (real time) must not touch it.
    let results = sign::sweep_due(
        &ledger,
        &wallet,
        &cfg,
        &server_key,
        &policy_snapshot,
        &cosigner::config::RecoveryConfig::default(),
        &chain,
        common::GAP_LIMIT,
        now_unix(),
    )
    .await;
    assert!(
        results.is_empty(),
        "must not fire before the hold elapses: {results:?}"
    );
    let (status, body) = post_json(
        http::router(state.clone()),
        "GET",
        &format!("/sign_psbt/{id}"),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "got: {body}");
    assert_eq!(body["status"], "pending");

    // Force it due (synthetic future "now" - no real sleeping) and sweep for real.
    let far_future = submitted_at + 3_600 + 1;
    let results = sign::sweep_due(
        &ledger,
        &wallet,
        &cfg,
        &server_key,
        &policy_snapshot,
        &cosigner::config::RecoveryConfig::default(),
        &chain,
        common::GAP_LIMIT,
        far_future,
    )
    .await;
    assert_eq!(results.len(), 1);
    assert!(
        matches!(results[0].1, Ok(sign::PendingOutcome::Signed(_))),
        "expected Signed, got: {:?}",
        results[0].1
    );

    let (status, body) = post_json(
        http::router(state.clone()),
        "GET",
        &format!("/sign_psbt/{id}"),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "got: {body}");
    assert_eq!(body["status"], "signed");
    let signed_psbt: bitcoin::psbt::Psbt = body["psbt"].as_str().unwrap().parse().unwrap();

    assert_hot_witness_is_satisfiable(&signed_psbt, &wallet, &cfg, 0);

    let totals = ledger.rolling_totals(far_future).await.unwrap();
    assert_eq!(
        totals.day_sat, 199_000,
        "the ledger must reflect the real signed spend"
    );
}

#[tokio::test]
async fn veto_blocks_a_live_spend_before_it_can_be_swept() {
    let Some(node) = common::regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = common::regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();

    let node_wallet = common::node_wallet_client(&node, "cosigner-full-flow-veto");
    common::fund_node_wallet(&node, &node_wallet);

    let our_address = descriptor::address_at(&wallet.external, 1, cfg.network).unwrap();
    let (outpoint, prevout) =
        common::fund_address(&node, &node_wallet, &our_address, Amount::from_sat(150_000));
    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let psbt = common::unsigned_spend_psbt(
        outpoint,
        &prevout,
        &dest_address,
        Amount::from_sat(149_000),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );

    let submitted_at = now_unix();
    let (state, chain, _) = build_state(node, &cfg, &wallet, common::permissive_policy(), 0).await;
    let ledger = state.ledger.clone();
    let server_key = state.server_key.clone();
    let policy_snapshot = state.policy.read().await.compiled.clone();

    let (status, body) = post_json(
        http::router(state.clone()),
        "POST",
        "/sign_psbt",
        Some(serde_json::json!({ "psbt": psbt.to_string() })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "got: {body}");
    let id = body["id"].as_str().unwrap().to_string();

    let (status, body) = post_json(
        http::router(state.clone()),
        "POST",
        &format!("/veto/{id}"),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "got: {body}");
    assert_eq!(body["status"], "vetoed");

    let results = sign::sweep_due(
        &ledger,
        &wallet,
        &cfg,
        &server_key,
        &policy_snapshot,
        &cosigner::config::RecoveryConfig::default(),
        &chain,
        common::GAP_LIMIT,
        submitted_at + 10,
    )
    .await;
    assert!(
        results.is_empty(),
        "a vetoed spend must never be swept: {results:?}"
    );

    let (status, body) = post_json(
        http::router(state.clone()),
        "GET",
        &format!("/sign_psbt/{id}"),
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "got: {body}");
    assert_eq!(body["status"], "vetoed");
}

#[tokio::test]
async fn hardware_authorized_policy_change_is_enforced_by_a_live_spend() {
    let Some(node) = common::regtest_client() else {
        eprintln!("COSIGNER_REGTEST_RPC_URL not set - skipping regtest integration test");
        return;
    };

    let cfg = common::regtest_wallet_config();
    let wallet = descriptor::build_descriptor(&cfg).unwrap();
    let (_, hardware_xprv) = common::key_spec_with_xpriv(common::HARDWARE_SEED, common::KEY_PATH);

    let node_wallet = common::node_wallet_client(&node, "cosigner-full-flow-policy");
    common::fund_node_wallet(&node, &node_wallet);

    // Fund two separate UTXOs up front - everything after this point talks to bitcoind only
    // through cosigner's own AppState, not this test's own `node` client.
    let addr_a = descriptor::address_at(&wallet.external, 2, cfg.network).unwrap();
    let (outpoint_a, prevout_a) =
        common::fund_address(&node, &node_wallet, &addr_a, Amount::from_sat(500_000));
    let addr_b = descriptor::address_at(&wallet.external, 3, cfg.network).unwrap();
    let (outpoint_b, prevout_b) =
        common::fund_address(&node, &node_wallet, &addr_b, Amount::from_sat(500_000));
    let dest_address = node_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    // A tight cap: this spend (490_000) is over it, so it must be denied at submission.
    let tight_policy = PolicyConfig {
        max_tx_sat: 100_000,
        ..common::permissive_policy()
    };
    let (state, _chain, initial_version) = build_state(node, &cfg, &wallet, tight_policy, 0).await;

    let over_cap_psbt = common::unsigned_spend_psbt(
        outpoint_a,
        &prevout_a,
        &dest_address,
        Amount::from_sat(490_000),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );
    let (status, body) = post_json(
        http::router(state.clone()),
        "POST",
        "/sign_psbt",
        Some(serde_json::json!({ "psbt": over_cap_psbt.to_string() })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "500k cap of 100k must deny a 490k spend before any change: {body}"
    );
    assert_eq!(body["error"], "policy_denied");

    // Authorize a higher cap, signed by HARDWARE over the exact canonical text the server will
    // recompute and verify against - the real live path, not a unit test mock.
    let raised_cap_policy = PolicyConfig {
        max_tx_sat: 1_000_000,
        ..common::permissive_policy()
    };
    let next_version = initial_version + 1;
    let message = cosigner::policy_auth::canonical_message(next_version, &raised_cap_policy);
    let msg_hash = bitcoin::sign_message::signed_msg_hash(&message);
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa_recoverable(
        &bitcoin::secp256k1::Message::from_digest(msg_hash.to_byte_array()),
        &hardware_xprv.private_key,
    );
    let signature_base64 = bitcoin::sign_message::MessageSignature::new(sig, true).to_base64();

    let (status, body) = post_json(
        http::router(state.clone()),
        "POST",
        "/policy",
        Some(serde_json::json!({
            "policy": {
                "max_tx_sat": raised_cap_policy.max_tx_sat,
                "max_daily_sat": raised_cap_policy.max_daily_sat,
                "max_weekly_sat": raised_cap_policy.max_weekly_sat,
                "max_monthly_sat": raised_cap_policy.max_monthly_sat,
                "max_fee_sat": raised_cap_policy.max_fee_sat,
                "max_fee_rate_sat_per_vb": raised_cap_policy.max_fee_rate_sat_per_vb,
                "destination_whitelist": null,
            },
            "version": next_version,
            "signature": signature_base64,
        })),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "got: {body}");
    assert_eq!(body["version"], next_version);
    assert_eq!(body["max_tx_sat"], 1_000_000);

    // The same shape of spend that was denied a moment ago must now be accepted live.
    let now_allowed_psbt = common::unsigned_spend_psbt(
        outpoint_b,
        &prevout_b,
        &dest_address,
        Amount::from_sat(490_000),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );
    let (status, body) = post_json(
        http::router(state),
        "POST",
        "/sign_psbt",
        Some(serde_json::json!({ "psbt": now_allowed_psbt.to_string() })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::ACCEPTED,
        "the raised cap must be enforced immediately, no restart: {body}"
    );
    assert_eq!(body["status"], "pending");
}
