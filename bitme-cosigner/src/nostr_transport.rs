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
//!
//! Every dispatched event's ID is recorded in the ledger (`Ledger::mark_nostr_event_seen`) and
//! checked before processing (`Ledger::has_seen_nostr_event`), because relays don't guarantee
//! at-most-once delivery and - the case that actually matters - every process restart opens a
//! fresh subscription with no lower time bound, which replays this identity's *entire*
//! gift-wrap history from each relay. Without this, an old captured request sitting on a public
//! relay (e.g. a superseded `/unfreeze`) would silently re-fire on every restart, with no
//! attacker needed at all.

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
use crate::ledger::Ledger;

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
/// `api_token`, if the deployment has one, is attached to the synthetic request.
///
/// That is not a bypass. The token exists to answer "is this caller allowed to consume budget",
/// and on this transport that question was already answered - and answered more strongly - by
/// NIP-59 unwrapping plus the npub allowlist, both of which have happened before anything reaches
/// here. Requiring the token as well would mean shipping it to every device *in addition* to
/// their npub being allowlisted, for no additional guarantee. Attaching it here keeps one router
/// with one set of rules rather than forking the route table per transport.
async fn dispatch(
    router: axum::Router,
    api_token: Option<&str>,
    env: InboundEnvelope,
) -> OutboundEnvelope {
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
    if let Some(token) = api_token {
        builder = builder.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
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
    ledger: &Ledger,
    api_token: Option<&str>,
    event: Event,
) -> Result<()> {
    // Relays don't guarantee at-most-once delivery, and - critically - every process restart
    // creates a fresh subscription with no `since` bound, which replays this identity's *entire*
    // gift-wrap history from every relay, not just what's new. Without this check, a historical
    // request sitting on a relay (e.g. an old /unfreeze) would silently re-fire on every
    // restart, with no attacker involved at all. Dedup on the outer gift-wrap event's own ID,
    // before unwrapping - cheaper, and the ID is stable/known before any decryption happens.
    let event_id = event.id.to_hex();
    // Cheap read first: a genuine replay exits here without decrypting anything.
    if ledger
        .has_seen_nostr_event(&event_id)
        .await
        .context("checking nostr_seen_events")?
    {
        return Ok(());
    }

    let unwrapped = client
        .unwrap_gift_wrap(&event)
        .await
        .context("unwrapping gift wrap")?;

    // **Invariant: nothing durable is written for a sender who is not on the allowlist.**
    //
    // This service's npub is public, so anyone at all can address a gift wrap to it, and the
    // volume of inbound messages is therefore not something the operator controls. Persisting one
    // row per message would make an unbounded table out of that, and each write takes the ledger's
    // single connection - the same one `POST /veto/{id}` needs. Rejecting first costs an unwrap
    // for a non-contact but leaves no trace and takes no write lock. Keep this check above the
    // write.
    if !allowed.contains(&unwrapped.sender) {
        tracing::warn!(
            sender = %unwrapped.sender.to_bech32().unwrap_or_default(),
            "ignoring a message from an npub not on the allowlist"
        );
        return Ok(());
    }

    // Marked *before* dispatching, not after: a crash mid-dispatch must not risk replaying the
    // same request on the next restart. If the sender never got a reply, that's on them to
    // resend as a new event (new ID) - normal request/response retry, not a replay concern.
    ledger
        .mark_nostr_event_seen(&event_id, now_unix())
        .await
        .context("recording nostr_seen_events")?;

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

    let reply = dispatch(router.clone(), api_token, env).await;
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
    let ledger = state.ledger.clone();

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

    let api_token = state.api_token.clone();
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
            let ledger = ledger.clone();
            let api_token = api_token.clone();
            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::GiftWrap {
                        if let Err(e) = handle_gift_wrap(
                            &client,
                            &router,
                            &allowed,
                            &ledger,
                            api_token.as_deref(),
                            *event,
                        )
                        .await
                        {
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
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

        let auth_keys = crate::policy_auth::HardwareAuthKeys::from_config(&cfg, 50).unwrap();
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
            auth_keys: Arc::new(auth_keys),
            api_token: None,
            recovery_contacts: None,
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
            None,
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
            None,
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
            None,
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
            None,
            InboundEnvelope {
                method: "GET".to_string(),
                path: "/not-a-real-endpoint".to_string(),
                body: None,
            },
        )
        .await;
        assert_eq!(reply.status, 404);
    }

    /// A syntactically-real, signed `Kind::GiftWrap` event - but with plain-text (not NIP-59
    /// sealed/encrypted) content, so `unwrap_gift_wrap` is guaranteed to fail on it. That's
    /// deliberate: these tests are about the dedup check that runs *before* unwrapping, not
    /// about a full real gift-wrap round trip (covered structurally by `dispatch`'s tests and
    /// left for live-relay verification, same as `nostr_kit.rs`).
    fn fake_gift_wrap_event(keys: &Keys) -> Event {
        EventBuilder::new(Kind::GiftWrap, "not a real NIP-59 seal")
            .sign_with_keys(keys)
            .unwrap()
    }

    /// A genuine NIP-59 gift wrap from `sender` to `receiver`, carrying `envelope` as its rumor.
    /// Needed for any test that has to get past `unwrap_gift_wrap` - which is now everything
    /// that touches the allowlist or the replay table, since authorization happens before
    /// anything durable is written.
    async fn real_gift_wrap(sender: &Keys, receiver: &Keys, envelope: &InboundEnvelope) -> Event {
        let rumor = EventBuilder::private_msg_rumor(
            receiver.public_key(),
            serde_json::to_string(envelope).unwrap(),
        )
        .build(sender.public_key());
        EventBuilder::gift_wrap(sender, &receiver.public_key(), rumor, [])
            .await
            .expect("building a real gift wrap")
    }

    #[tokio::test]
    async fn handle_gift_wrap_skips_an_event_already_marked_seen() {
        let (state, _chain, _wallet) = test_state().await;
        let ledger = state.ledger.clone();
        let router = http::router(state);
        let allowed: HashSet<PublicKey> = HashSet::new();

        let service_keys = Keys::generate();
        let client = Client::new(service_keys.clone()); // no relays added
        let event = fake_gift_wrap_event(&service_keys);

        ledger
            .mark_nostr_event_seen(&event.id.to_hex(), 0)
            .await
            .unwrap();

        // If the dedup check didn't short-circuit, this would fail downstream (bad unwrap, then
        // a reply attempt with no relay configured) instead of returning Ok(()) immediately.
        let result = handle_gift_wrap(&client, &router, &allowed, &ledger, None, event).await;
        assert!(
            result.is_ok(),
            "an already-seen event must be skipped cleanly: {result:?}"
        );
    }

    /// An authorized request is recorded in the replay table *before* it is dispatched, so a
    /// crash between the two cannot cause it to run twice on the next restart.
    #[tokio::test]
    async fn an_allowlisted_event_is_marked_seen_before_dispatch() {
        let (state, _chain, _wallet) = test_state().await;
        let ledger = state.ledger.clone();
        let router = http::router(state);

        let service_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let allowed: HashSet<PublicKey> = [sender_keys.public_key()].into_iter().collect();
        let client = Client::new(service_keys.clone());

        let envelope = InboundEnvelope {
            method: "GET".to_string(),
            path: "/health".to_string(),
            body: None,
        };
        let event = real_gift_wrap(&sender_keys, &service_keys, &envelope).await;
        let event_id = event.id.to_hex();
        assert!(!ledger.has_seen_nostr_event(&event_id).await.unwrap());

        // Dispatch succeeds but the *reply* fails - no relays are configured on this client - so
        // this returns Err. That's the point: the marking must already have happened by then.
        let _ = handle_gift_wrap(&client, &router, &allowed, &ledger, None, event).await;
        assert!(
            ledger.has_seen_nostr_event(&event_id).await.unwrap(),
            "an authorized event must be recorded before dispatch, so a crash can't replay it"
        );
    }

    #[tokio::test]
    async fn a_relay_redelivering_the_same_event_only_ever_dispatches_it_once() {
        // The actual scenario this bug produced: a fresh subscription (every restart) replays
        // history, so the SAME event can arrive for processing more than once in a row.
        let (state, _chain, _wallet) = test_state().await;
        let ledger = state.ledger.clone();
        let router = http::router(state);

        let service_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let allowed: HashSet<PublicKey> = [sender_keys.public_key()].into_iter().collect();
        let client = Client::new(service_keys.clone());

        let envelope = InboundEnvelope {
            method: "GET".to_string(),
            path: "/health".to_string(),
            body: None,
        };
        let event = real_gift_wrap(&sender_keys, &service_keys, &envelope).await;

        // First delivery gets all the way to the reply, which fails (no relays on this client).
        let _ = handle_gift_wrap(&client, &router, &allowed, &ledger, None, event.clone()).await;

        let second = handle_gift_wrap(&client, &router, &allowed, &ledger, None, event).await;
        assert!(
            second.is_ok(),
            "redelivery of the exact same event must be a clean no-op, not reprocessed: {second:?}"
        );
    }

    /// A message from an npub that isn't on the allowlist must leave **no durable trace**.
    ///
    /// This service's npub is public, so the volume of inbound messages is not something the
    /// operator controls. Persisting one row per message would make `nostr_seen_events` unbounded
    /// and would take a write lock on the ledger's single connection each time - the same
    /// connection `POST /veto/{id}` needs.
    #[tokio::test]
    async fn an_unauthorized_sender_is_never_recorded() {
        let (state, _chain, _wallet) = test_state().await;
        let ledger = state.ledger.clone();
        let router = http::router(state);

        let service_keys = Keys::generate();
        let stranger_keys = Keys::generate();
        // Allowlist contains somebody else entirely.
        let allowed: HashSet<PublicKey> = [Keys::generate().public_key()].into_iter().collect();
        let client = Client::new(service_keys.clone());

        let envelope = InboundEnvelope {
            method: "POST".to_string(),
            path: "/freeze".to_string(),
            body: None,
        };
        let event = real_gift_wrap(&stranger_keys, &service_keys, &envelope).await;
        let event_id = event.id.to_hex();

        let result = handle_gift_wrap(&client, &router, &allowed, &ledger, None, event).await;
        assert!(result.is_ok(), "rejection is a clean no-op, not an error");
        assert!(
            !ledger.has_seen_nostr_event(&event_id).await.unwrap(),
            "a non-contact's message must not be persisted - that would make this table's size \
             depend on inbound volume rather than on anything the operator controls"
        );
    }

    /// Replay records don't accumulate forever: anything older than the retention window is
    /// dropped, which is what keeps the table bounded now that it is no longer written for
    /// unauthorized senders.
    #[tokio::test]
    async fn expired_replay_records_are_pruned() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .mark_nostr_event_seen("old-event", 1_000)
            .await
            .unwrap();
        ledger
            .mark_nostr_event_seen("recent-event", 9_000)
            .await
            .unwrap();

        let pruned = ledger.prune_nostr_seen_events(5_000).await.unwrap();
        assert_eq!(pruned, 1);
        assert!(!ledger.has_seen_nostr_event("old-event").await.unwrap());
        assert!(ledger.has_seen_nostr_event("recent-event").await.unwrap());
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
