//! Alternate front door for the exact same HTTP API (`http.rs`), delivered over Nostr NIP-17
//! private messages instead of an open port.
//!
//! Deliberately reuses the real `axum::Router` rather than re-implementing request handling: an
//! inbound message is `{"method", "path", "body"}`, translated into a synthetic
//! `axum::http::Request` and dispatched through `router.oneshot(..)` - the exact mechanism the
//! regtest integration tests already use to drive the HTTP API in-process. This means the two
//! transports can never drift out of sync with each other; every policy/signing/freeze rule the
//! HTTP API enforces applies identically here, because it's literally the same code path.
//!
//! Authentication is NIP-59 Gift Wrap (<https://github.com/nostr-protocol/nips/blob/master/59.md>),
//! which underlies NIP-17 private messages: unwrapping a gift wrap cryptographically verifies
//! the sender (`UnwrappedGift::sender`) *before* this module ever looks at the message content.
//! `allowed_npubs` in config is then a plain allowlist check against that already-verified
//! sender - not what makes a sender authentic, only what makes them authorized. Removing an
//! npub from the list is how a lost or stolen device is cut off: its messages are still
//! genuinely from it (the crypto doesn't lie), they're just ignored from then on.
//!
//! Outbound-only: this only ever opens connections *to* relays. No inbound port, no domain, no
//! certificate.

use std::collections::HashSet;
use std::str::FromStr;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use crate::config::NostrTransportConfig;
use crate::http::{self, AppState};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct InboundEnvelope {
    method: String,
    path: String,
    #[serde(default)]
    body: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct OutboundEnvelope {
    status: u16,
    body: serde_json::Value,
}

/// Reads this service's Nostr secret key from the configured file or env var. Accepts either
/// bech32 (`nsec1...`) or raw hex, the same "don't force a format on operators" latitude
/// `ServerSigningKey::load` already gives xprvs.
fn read_nsec(cfg: &NostrTransportConfig) -> Result<SecretKey> {
    let raw = if let Some(path) = &cfg.nsec_file {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading nostr_transport.nsec_file {path}"))?
    } else if let Some(var) = &cfg.nsec_env_var {
        std::env::var(var).with_context(|| format!("reading nostr_transport.nsec_env_var {var}"))?
    } else {
        anyhow::bail!("nostr_transport: one of nsec_file or nsec_env_var is required");
    };
    let trimmed = raw.trim();
    SecretKey::from_bech32(trimmed)
        .or_else(|_| SecretKey::from_str(trimmed))
        .context("nostr_transport nsec is not a valid Nostr secret key (bech32 nsec or hex)")
}

/// Translates one inbound envelope into a synthetic HTTP request against `router`, and the
/// response back into an outbound envelope. Never panics or propagates a transport-layer error
/// upward - every failure mode (bad JSON, unsupported method, a handler error) becomes a
/// structured `OutboundEnvelope` reply instead, since the only way the sender finds out what
/// went wrong is this reply.
async fn dispatch(router: axum::Router, env: InboundEnvelope) -> OutboundEnvelope {
    let method = match env.method.to_uppercase().as_str() {
        "GET" => axum::http::Method::GET,
        "POST" => axum::http::Method::POST,
        other => {
            return OutboundEnvelope {
                status: 400,
                body: serde_json::json!({
                    "error": "unsupported_method",
                    "message": format!("{other} is not supported over the Nostr transport"),
                }),
            };
        }
    };

    let body_bytes = match &env.body {
        Some(v) => match serde_json::to_vec(v) {
            Ok(b) => b,
            Err(e) => {
                return OutboundEnvelope {
                    status: 400,
                    body: serde_json::json!({"error": "bad_request", "message": e.to_string()}),
                };
            }
        },
        None => Vec::new(),
    };

    let mut builder = Request::builder().method(method).uri(&env.path);
    if env.body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let request = match builder.body(Body::from(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            return OutboundEnvelope {
                status: 400,
                body: serde_json::json!({"error": "bad_request", "message": e.to_string()}),
            };
        }
    };

    let response = match router.oneshot(request).await {
        Ok(r) => r,
        Err(e) => {
            return OutboundEnvelope {
                status: 500,
                body: serde_json::json!({"error": "internal", "message": e.to_string()}),
            };
        }
    };
    let status = response.status().as_u16();
    let bytes = match response.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return OutboundEnvelope {
                status: 500,
                body: serde_json::json!({"error": "internal", "message": e.to_string()}),
            };
        }
    };
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    OutboundEnvelope { status, body }
}

async fn handle_gift_wrap(
    client: &Client,
    router: &axum::Router,
    allowed: &HashSet<PublicKey>,
    event: Event,
) -> Result<()> {
    let unwrapped = client
        .unwrap_gift_wrap(&event)
        .await
        .context("unwrapping gift wrap")?;

    if !allowed.contains(&unwrapped.sender) {
        tracing::warn!(
            sender = %unwrapped.sender.to_bech32().unwrap_or_default(),
            "ignoring a message from an npub not on the allowlist"
        );
        return Ok(());
    }

    let env: InboundEnvelope = match serde_json::from_str(&unwrapped.rumor.content) {
        Ok(e) => e,
        Err(parse_err) => {
            let reply = OutboundEnvelope {
                status: 400,
                body: serde_json::json!({
                    "error": "bad_request",
                    "message": format!("not a valid request envelope: {parse_err}"),
                }),
            };
            let reply_json = serde_json::to_string(&reply).context("serializing reply")?;
            client
                .send_private_msg(unwrapped.sender, reply_json, [])
                .await
                .context("sending error reply")?;
            return Ok(());
        }
    };

    let reply = dispatch(router.clone(), env).await;
    let reply_json = serde_json::to_string(&reply).context("serializing reply")?;
    client
        .send_private_msg(unwrapped.sender, reply_json, [])
        .await
        .context("sending reply")?;
    Ok(())
}

/// Runs the Nostr transport for as long as the process lives: connects outbound to every
/// configured relay, subscribes to gift wraps addressed to this service's own identity, and
/// answers each one by dispatching into `state`'s router. Intended to be spawned as a background
/// task alongside the HTTP server, not run standalone - see `cmd_serve` in `main.rs`.
pub async fn run(cfg: &NostrTransportConfig, state: AppState) -> Result<()> {
    let secret_key = read_nsec(cfg)?;
    let keys = Keys::new(secret_key);
    let allowed: HashSet<PublicKey> = cfg.compiled_allowlist()?.into_iter().collect();

    let client = Client::new(keys.clone());
    for url in &cfg.relays {
        client
            .add_relay(url.as_str())
            .await
            .with_context(|| format!("adding relay {url}"))?;
    }
    client.connect().await;

    let our_pubkey = keys.public_key();
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(our_pubkey);
    client
        .subscribe(filter, None)
        .await
        .context("subscribing to gift wraps")?;

    let router = http::router(state);

    tracing::info!(
        npub = %our_pubkey.to_bech32().unwrap_or_default(),
        relays = cfg.relays.len(),
        allowed = allowed.len(),
        "nostr transport listening"
    );

    client
        .handle_notifications(|notification| {
            let client = client.clone();
            let router = router.clone();
            let allowed = allowed.clone();
            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::GiftWrap {
                        if let Err(e) = handle_gift_wrap(&client, &router, &allowed, *event).await {
                            tracing::warn!(error = %e, "failed to handle an inbound nostr message");
                        }
                    }
                }
                Ok(false) // never exit the loop on our own
            }
        })
        .await
        .context("nostr notification loop ended")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use tokio::sync::RwLock;

    use super::*;
    use crate::chain::mock::MockChainSource;
    use crate::chain::Utxo;
    use crate::config::ServerSigningConfig;
    use crate::descriptor::{self, build_descriptor, BuiltDescriptor};
    use crate::http::PolicyHandle;
    use crate::ledger::Ledger;
    use crate::notify::mock::RecordingNotifier;
    use crate::policy::{CompiledPolicy, PolicyConfig};
    use crate::signing::ServerSigningKey;
    use crate::test_util::{test_server_xpriv, test_wallet_config};

    async fn test_state() -> (AppState, Arc<MockChainSource>, BuiltDescriptor) {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = Arc::new(MockChainSource::new());

        let xprv = test_server_xpriv();
        let env_var = "COSIGNER_TEST_NOSTR_TRANSPORT_XPRV".to_string();
        // SAFETY: single-threaded within this test's own process env namespace; no other test
        // in this module reads this variable name.
        unsafe { std::env::set_var(&env_var, xprv.to_string()) };
        let server_key = ServerSigningKey::load(
            &ServerSigningConfig {
                xprv_file: None,
                xprv_env_var: Some(env_var),
            },
            &cfg.keys.server.xpub,
            cfg.network,
        )
        .unwrap();

        let policy_cfg = PolicyConfig {
            max_tx_sat: u64::MAX,
            max_daily_sat: u64::MAX,
            max_weekly_sat: u64::MAX,
            max_monthly_sat: u64::MAX,
            max_fee_sat: u64::MAX,
            max_fee_rate_sat_per_vb: f64::MAX,
            destination_whitelist: None,
        };
        let policy: CompiledPolicy = policy_cfg.compile(cfg.network).unwrap();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        let seeded = ledger
            .load_or_seed_policy_state(&serde_json::to_string(&policy_cfg).unwrap(), 0)
            .await
            .unwrap();

        let state = AppState {
            wallet: Arc::new(wallet.clone()),
            cfg: Arc::new(cfg),
            chain: chain.clone(),
            gap_limit: 50,
            server_key: Arc::new(server_key),
            ledger: Arc::new(ledger),
            policy: Arc::new(RwLock::new(PolicyHandle {
                version: seeded.version,
                compiled: policy,
            })),
            notifier: Arc::new(RecordingNotifier::new()),
            hold_seconds: 0,
        };
        (state, chain, wallet)
    }

    fn fake_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    #[tokio::test]
    async fn dispatch_routes_get_health_with_no_body() {
        let (state, _chain, _wallet) = test_state().await;
        let router = http::router(state);
        let reply = dispatch(
            router,
            InboundEnvelope {
                method: "GET".to_string(),
                path: "/health".to_string(),
                body: None,
            },
        )
        .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["service"], "cosigner");
    }

    #[tokio::test]
    async fn dispatch_routes_post_inspect_with_a_body_and_mirrors_http_status() {
        let (state, chain, wallet) = test_state().await;
        let script_pubkey = descriptor::at_index(&wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let outpoint = OutPoint::new(fake_txid(0x11), 0);
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey,
                },
                confirmations: 6,
            },
        );
        let dest_script = ScriptBuf::from(vec![0x00, 0x14, 0xaa]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: dest_script,
            }],
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();

        let router = http::router(state);
        let reply = dispatch(
            router,
            InboundEnvelope {
                method: "POST".to_string(),
                path: "/inspect".to_string(),
                body: Some(serde_json::json!({ "psbt": psbt.to_string() })),
            },
        )
        .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["spending_path"], "hot");
        assert_eq!(reply.body["fee_sat"], 10_000);
    }

    #[tokio::test]
    async fn dispatch_rejects_an_unsupported_method_without_touching_the_router() {
        let (state, _chain, _wallet) = test_state().await;
        let router = http::router(state);
        let reply = dispatch(
            router,
            InboundEnvelope {
                method: "DELETE".to_string(),
                path: "/health".to_string(),
                body: None,
            },
        )
        .await;
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body["error"], "unsupported_method");
    }

    #[tokio::test]
    async fn dispatch_returns_404_for_an_unknown_path_rather_than_panicking() {
        let (state, _chain, _wallet) = test_state().await;
        let router = http::router(state);
        let reply = dispatch(
            router,
            InboundEnvelope {
                method: "GET".to_string(),
                path: "/not-a-real-endpoint".to_string(),
                body: None,
            },
        )
        .await;
        assert_eq!(reply.status, 404);
    }

    #[test]
    fn nsec_can_be_read_from_bech32_or_hex() {
        let dir = std::env::temp_dir().join(format!(
            "cosigner-test-nostr-transport-{}-nsec",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let keys = Keys::generate();
        let hex = keys.secret_key().to_secret_hex();
        let bech32 = keys.secret_key().to_bech32().unwrap();

        let hex_path = dir.join("hex.nsec");
        std::fs::write(&hex_path, &hex).unwrap();
        let bech32_path = dir.join("bech32.nsec");
        std::fs::write(&bech32_path, &bech32).unwrap();

        let cfg_hex = NostrTransportConfig {
            nsec_file: Some(hex_path.to_string_lossy().to_string()),
            nsec_env_var: None,
            relays: vec!["wss://example.invalid".to_string()],
            allowed_npubs: vec![],
        };
        let cfg_bech32 = NostrTransportConfig {
            nsec_file: Some(bech32_path.to_string_lossy().to_string()),
            nsec_env_var: None,
            relays: vec!["wss://example.invalid".to_string()],
            allowed_npubs: vec![],
        };

        assert_eq!(read_nsec(&cfg_hex).unwrap(), *keys.secret_key());
        assert_eq!(read_nsec(&cfg_bech32).unwrap(), *keys.secret_key());
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let env = InboundEnvelope {
            method: "POST".to_string(),
            path: "/sign_psbt".to_string(),
            body: Some(serde_json::json!({"psbt": "cHNidP8..."})),
        };
        let text = serde_json::to_string(&env).unwrap();
        let parsed: InboundEnvelope = serde_json::from_str(&text).unwrap();
        assert_eq!(env, parsed);
    }
}
