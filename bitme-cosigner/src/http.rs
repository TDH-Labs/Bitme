//! The HTTP API. Thin: every handler just deserializes the request, hands off to the pure
//! logic in `inspect.rs` (running blocking chain-RPC calls off the async runtime), and
//! serializes the result. No policy or signing logic lives here.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::psbt::Psbt;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::chain::ChainSource;
use crate::config::WalletConfig;
use crate::descriptor::{BuiltDescriptor, Chain};
use crate::inspect::{self, InspectError, InspectionReport, OutputKind, SpendingPath};
use crate::ledger::{Ledger, PendingStatus};
use crate::notify::Notifier;
use crate::policy::{CompiledPolicy, PolicyConfig};
use crate::policy_auth::{self, PolicyAuthError};
use crate::recovery_contacts;
use crate::sign::{self, LedgerOutcome, SignPsbtError, SubmitError, SubmitOutcome};
use crate::signing::{ServerSigningKey, SigningError};

/// The currently-effective policy plus the version it was authorized as - see `policy_auth.rs`.
/// Held behind a lock in `AppState` so `POST /policy` can hot-swap it without a restart; every
/// other handler takes a cheap read-locked snapshot (`CompiledPolicy` is `Clone`) rather than
/// holding the lock across any `await`.
pub struct PolicyHandle {
    pub version: u64,
    pub compiled: CompiledPolicy,
}

#[derive(Clone)]
pub struct AppState {
    pub wallet: Arc<BuiltDescriptor>,
    pub cfg: Arc<WalletConfig>,
    pub chain: Arc<dyn ChainSource>,
    pub gap_limit: u32,
    /// Only used by `/sign_psbt`.
    pub server_key: Arc<ServerSigningKey>,
    /// Only used by `/sign_psbt`, `GET /sign_psbt/{id}`, `/veto/{id}` and `/policy`.
    pub ledger: Arc<Ledger>,
    /// Only used by `/sign_psbt` and `/policy`.
    pub policy: Arc<RwLock<PolicyHandle>>,
    /// The hardware key's authorized signing keys, derived once at startup. Used by
    /// `POST /policy` and `POST /unfreeze` - see `policy_auth::HardwareAuthKeys` for why this is
    /// precomputed rather than derived per request.
    pub auth_keys: Arc<policy_auth::HardwareAuthKeys>,
    /// Bearer token required by `/inspect` and `/sign_psbt`, if one is configured. `None`
    /// disables the check entirely - see `config::ServerConfig::api_token_file`.
    pub api_token: Option<Arc<str>>,
    /// Recovery contacts and the quorum size, if configured. `None` means social recovery is off
    /// and `POST /recovery/approve/{id}` refuses everything.
    pub recovery_contacts: Option<Arc<(std::collections::HashSet<nostr_sdk::PublicKey>, usize)>>,
    /// Only used by `/sign_psbt`.
    pub notifier: Arc<dyn Notifier>,
    /// Only used by `/sign_psbt`. How long an approved spend is held (and vetoable) before the
    /// background sweeper actually signs it.
    pub hold_seconds: i64,
}

/// Rejects a request to a token-protected route unless it carries the configured bearer token.
///
/// Only ever applied to `/inspect` and `/sign_psbt` - see [`crate::config::ServerConfig`] for why
/// the stop-things-happening endpoints are deliberately left open. Comparison is
/// constant-time-ish by construction: tokens are compared as whole byte slices via `ct_eq`-style
/// folding rather than `==` short-circuiting on the first differing byte.
async fn require_token(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(expected) = state.api_token.as_deref() else {
        return next.run(request).await;
    };

    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        next.run(request).await
    } else {
        ApiError {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            message: "this endpoint requires an Authorization: Bearer <token> header".to_string(),
        }
        .into_response()
    }
}

/// Length-independent equality. Not a defence against a serious timing attack over a LAN - the
/// noise floor is far above the signal - but comparing secrets with `==` is the kind of thing
/// that is free to get right and awkward to explain later.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn router(state: AppState) -> Router {
    // Split deliberately. The endpoints that *consume* something - budget, notifications,
    // unbounded per-input chain work - sit behind the token. The endpoints that only ever *stop*
    // something happening stay open, because the worst they can do is deny service and they have
    // to work from whatever device is to hand during an emergency.
    let guarded = Router::new()
        .route("/inspect", post(inspect_handler))
        .route("/sign_psbt", post(sign_psbt_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_token,
        ));

    Router::new()
        // `/` had no route at all, so opening the app from Umbrel's dashboard after setup
        // returned a bare 404. It also gives the wallet descriptor a permanent home: the setup
        // wizard showed it once and then vanished on the first restart.
        .route("/", get(status_page_handler))
        .route("/health", get(health_handler))
        .route("/sign_psbt/{id}", get(get_sign_psbt_handler))
        .route("/veto/{id}", post(veto_handler))
        .route("/policy", get(get_policy_handler).post(post_policy_handler))
        .route("/freeze", get(get_freeze_handler).post(post_freeze_handler))
        .route("/unfreeze", post(post_unfreeze_handler))
        .route("/recovery/approve/{id}", post(recovery_approve_handler))
        .merge(guarded)
        .with_state(state)
}

/// The human-facing landing page for a configured service. Everything else here is API.
async fn status_page_handler(State(state): State<AppState>) -> axum::response::Html<String> {
    let policy_version = state.policy.read().await.version;
    axum::response::Html(crate::status_page::render(
        &state.wallet,
        &state.cfg,
        policy_version,
    ))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    service: &'static str,
    version: &'static str,
    network: &'static str,
    policy_version: u64,
}

/// Deliberately minimal and non-sensitive: no key material, no ledger contents, nothing that
/// would matter if scraped by a monitoring tool or shown by a reverse proxy's health check -
/// just enough to confirm the service is up and pointed at the network you expect.
async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let network = match state.cfg.network {
        crate::config::ChainNetwork::Mainnet => "mainnet",
        crate::config::ChainNetwork::Testnet => "testnet",
        crate::config::ChainNetwork::Signet => "signet",
        crate::config::ChainNetwork::Regtest => "regtest",
    };
    let policy_version = state.policy.read().await.version;
    Json(HealthResponse {
        service: "cosigner",
        version: env!("CARGO_PKG_VERSION"),
        network,
        policy_version,
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

#[derive(Debug, Deserialize)]
struct PsbtRequest {
    /// Base64-encoded PSBT, per BIP174.
    psbt: String,
}

#[derive(Debug, Serialize)]
struct InspectResponse {
    inputs: Vec<InputJson>,
    outputs: Vec<OutputJson>,
    total_in_sat: u64,
    total_out_sat: u64,
    fee_sat: u64,
    estimated_vsize: u64,
    fee_rate_sat_per_vb: f64,
    spending_path: &'static str,
}

#[derive(Debug, Serialize)]
struct InputJson {
    outpoint: String,
    amount_sat: u64,
    confirmations: u32,
    chain: &'static str,
    index: u32,
}

#[derive(Debug, Serialize)]
struct OutputJson {
    script_pubkey_hex: String,
    address: Option<String>,
    amount_sat: u64,
    kind: &'static str,
}

impl From<InspectionReport> for InspectResponse {
    fn from(r: InspectionReport) -> Self {
        InspectResponse {
            inputs: r
                .inputs
                .into_iter()
                .map(|i| InputJson {
                    outpoint: i.outpoint.to_string(),
                    amount_sat: i.amount.to_sat(),
                    confirmations: i.confirmations,
                    chain: match i.chain {
                        Chain::External => "external",
                        Chain::Internal => "internal",
                    },
                    index: i.index,
                })
                .collect(),
            outputs: r
                .outputs
                .into_iter()
                .map(|o| OutputJson {
                    script_pubkey_hex: o.script_pubkey.to_hex_string(),
                    address: o.address.map(|a| a.to_string()),
                    amount_sat: o.amount.to_sat(),
                    kind: match o.kind {
                        OutputKind::Change => "change",
                        OutputKind::OwnReceive => "own_receive",
                        OutputKind::Destination => "destination",
                    },
                })
                .collect(),
            total_in_sat: r.total_in.to_sat(),
            total_out_sat: r.total_out.to_sat(),
            fee_sat: r.fee.to_sat(),
            estimated_vsize: r.estimated_vsize,
            fee_rate_sat_per_vb: r.fee_rate_sat_per_vb,
            spending_path: match r.spending_path {
                SpendingPath::Hot => "hot",
                SpendingPath::Recovery => "recovery",
                SpendingPath::Ambiguous => "ambiguous",
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorJson {
    error: &'static str,
    message: String,
}

struct ApiError {
    status: StatusCode,
    error: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorJson {
                error: self.error,
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl From<InspectError> for ApiError {
    fn from(e: InspectError) -> Self {
        let status = match &e {
            InspectError::InvalidTransaction(_) => StatusCode::BAD_REQUEST,
            InspectError::UnknownUtxo { .. }
            | InspectError::TamperedUtxo { .. }
            | InspectError::ForeignInput { .. }
            | InspectError::SpoofedChange { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            InspectError::Chain(_) => StatusCode::BAD_GATEWAY,
        };
        ApiError {
            status,
            error: e.code(),
            message: e.to_string(),
        }
    }
}

async fn inspect_handler(
    State(state): State<AppState>,
    Json(req): Json<PsbtRequest>,
) -> Result<Json<InspectResponse>, ApiError> {
    let psbt = Psbt::from_str(req.psbt.trim()).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        error: "invalid_psbt",
        message: format!("failed to parse psbt: {e}"),
    })?;

    let wallet = state.wallet.clone();
    let cfg = state.cfg.clone();
    let chain = state.chain.clone();
    let gap_limit = state.gap_limit;

    // bitcoincore_rpc is a blocking client; keep it off the async executor.
    let report = tokio::task::spawn_blocking(move || {
        inspect::inspect(&psbt, &wallet, &cfg, chain.as_ref(), gap_limit)
    })
    .await
    .map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "internal",
        message: e.to_string(),
    })??;

    Ok(Json(report.into()))
}

#[derive(Debug, Serialize)]
struct SignResponse {
    /// Base64-encoded PSBT, with this service's SERVER signature added - never finalized,
    /// never broadcast.
    psbt: String,
    /// "recorded" for a newly-approved spend, "already_recorded" for an idempotent replay of
    /// a transaction this service already signed before (no new ledger entry was written).
    ledger: &'static str,
    #[serde(flatten)]
    inspection: InspectResponse,
}

#[derive(Debug, Serialize)]
struct QueuedResponse {
    /// Also the unsigned transaction's txid - `GET /sign_psbt/{id}` and `POST /veto/{id}` both
    /// take this back.
    id: String,
    status: &'static str,
    /// Unix time the background sweeper will actually sign this, unless vetoed first.
    hold_until: i64,
}

fn pending_status_str(status: PendingStatus) -> &'static str {
    match status {
        PendingStatus::Pending => "pending",
        PendingStatus::Vetoed => "vetoed",
        PendingStatus::Signed => "signed",
        PendingStatus::Denied => "denied",
        PendingStatus::Failed => "failed",
    }
}

impl From<SigningError> for ApiError {
    fn from(e: SigningError) -> Self {
        let status = match &e {
            SigningError::UnsupportedSighashType { .. } => StatusCode::BAD_REQUEST,
            SigningError::Sighash { .. } => StatusCode::BAD_REQUEST,
            SigningError::KeyMismatch { .. } | SigningError::Other(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        ApiError {
            status,
            error: "signing_failed",
            message: e.to_string(),
        }
    }
}

impl From<SignPsbtError> for ApiError {
    fn from(e: SignPsbtError) -> Self {
        match e {
            SignPsbtError::NotHotPath => ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                error: "not_hot_path",
                message: e.to_string(),
            },
            SignPsbtError::Signing(signing_err) => signing_err.into(),
            SignPsbtError::Denied(violations) => ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                error: "policy_denied",
                message: violations
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            },
            SignPsbtError::Internal(err) => ApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: "internal",
                message: err.to_string(),
            },
        }
    }
}

impl From<SubmitError> for ApiError {
    fn from(e: SubmitError) -> Self {
        let status = match &e {
            SubmitError::NotHotPath | SubmitError::Denied(_) | SubmitError::RecoveryDisabled => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            // 503: the service is deliberately refusing right now, but this is a temporary,
            // operator-controlled state - not a permanent judgement about this transaction.
            SubmitError::Frozen(_) => StatusCode::SERVICE_UNAVAILABLE,
            SubmitError::Vetoed
            | SubmitError::PreviouslyDenied(_)
            | SubmitError::PreviouslyFailed(_) => StatusCode::CONFLICT,
            SubmitError::NotifyFailed(_) => StatusCode::BAD_GATEWAY,
            SubmitError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let error = match &e {
            SubmitError::NotHotPath => "not_hot_path",
            SubmitError::RecoveryDisabled => "recovery_disabled",
            SubmitError::Frozen(_) => "frozen",
            SubmitError::Denied(_) => "policy_denied",
            SubmitError::Vetoed => "vetoed",
            SubmitError::PreviouslyDenied(_) => "previously_denied",
            SubmitError::PreviouslyFailed(_) => "previously_failed",
            SubmitError::NotifyFailed(_) => "notify_failed",
            SubmitError::Internal(_) => "internal",
        };
        ApiError {
            status,
            error,
            message: e.to_string(),
        }
    }
}

/// Inspects and, if policy allows, queues `req.psbt` for signing: notifies out-of-band and
/// holds for `hold_seconds` before the background sweeper actually signs it - see `sign.rs`
/// for why nothing is ever signed synchronously here. The one exception is a replay of a PSBT
/// this service already fully signed before, which resolves immediately (200) exactly as it
/// did before M5; everything else newly approved returns 202 with an id to poll or veto.
async fn sign_psbt_handler(
    State(state): State<AppState>,
    Json(req): Json<PsbtRequest>,
) -> Result<Response, ApiError> {
    let psbt = Psbt::from_str(req.psbt.trim()).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        error: "invalid_psbt",
        message: format!("failed to parse psbt: {e}"),
    })?;

    let wallet = state.wallet.clone();
    let cfg = state.cfg.clone();
    let chain = state.chain.clone();
    let gap_limit = state.gap_limit;

    // Inspection does blocking bitcoind RPC I/O; keep it off the async executor, exactly as
    // /inspect does. Everything after this (the ledger transaction(s), signing, notifying) is
    // either async I/O or fast pure computation, so it runs directly on this task.
    let (psbt, report) = tokio::task::spawn_blocking(move || {
        let report = inspect::inspect(&psbt, &wallet, &cfg, chain.as_ref(), gap_limit);
        (psbt, report)
    })
    .await
    .map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "internal",
        message: e.to_string(),
    })?;
    let report: InspectionReport = report.map_err(ApiError::from)?;

    // A cheap snapshot: never hold the policy lock across the `.await`s below.
    let policy = state.policy.read().await.compiled.clone();
    let outcome = sign::submit_for_signing(
        psbt,
        report,
        &state.wallet,
        &state.cfg,
        &state.server_key,
        &state.ledger,
        &policy,
        &state.cfg.recovery_config(),
        state.notifier.as_ref(),
        state.hold_seconds,
        now_unix(),
    )
    .await
    .map_err(ApiError::from)?;

    Ok(match outcome {
        SubmitOutcome::AlreadySigned(result) => {
            let ledger = match result.ledger {
                LedgerOutcome::Recorded => "recorded",
                LedgerOutcome::AlreadyRecorded => "already_recorded",
            };
            Json(SignResponse {
                psbt: result.psbt.to_string(),
                ledger,
                inspection: result.report.into(),
            })
            .into_response()
        }
        SubmitOutcome::Queued { txid, hold_until } => (
            StatusCode::ACCEPTED,
            Json(QueuedResponse {
                id: txid,
                status: "pending",
                hold_until,
            }),
        )
            .into_response(),
    })
}

#[derive(Debug, Serialize)]
struct PendingStatusResponse {
    id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hold_until: Option<i64>,
    /// Present once `status` is `"signed"`: the base64 PSBT with this service's signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    psbt: Option<String>,
    /// Present once `status` is `"denied"` or `"failed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Polls the status of a spend queued by `POST /sign_psbt` - `id` is the unsigned txid
/// returned there.
async fn get_sign_psbt_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let row = state.ledger.get_pending(&id).await.map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "internal",
        message: e.to_string(),
    })?;
    let Some(row) = row else {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            message: format!("no signing request with id {id}"),
        });
    };

    let http_status = match row.status {
        PendingStatus::Pending => StatusCode::ACCEPTED,
        PendingStatus::Signed => StatusCode::OK,
        PendingStatus::Vetoed => StatusCode::CONFLICT,
        PendingStatus::Denied => StatusCode::UNPROCESSABLE_ENTITY,
        PendingStatus::Failed => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Ok((
        http_status,
        Json(PendingStatusResponse {
            id: row.txid,
            status: pending_status_str(row.status),
            hold_until: matches!(row.status, PendingStatus::Pending).then_some(row.hold_until),
            psbt: row.signed_psbt_base64,
            message: row.message,
        }),
    )
        .into_response())
}

#[derive(Debug, Serialize)]
struct VetoResponse {
    id: String,
    status: &'static str,
}

/// Cancels a still-pending spend before its hold elapses - `id` is the unsigned txid returned
/// by `POST /sign_psbt`. Idempotent: vetoing an already-vetoed (or already-denied/failed) spend
/// just reports its current status; vetoing one that's already signed is a 409, since by then
/// it's too late.
async fn veto_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let outcome = state.ledger.veto_pending(&id).await.map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "internal",
        message: e.to_string(),
    })?;
    let Some(status) = outcome else {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            message: format!("no pending signing request with id {id}"),
        });
    };

    if status == PendingStatus::Signed {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            error: "already_signed",
            message: "too late to veto - this spend was already signed".to_string(),
        });
    }

    Ok(Json(VetoResponse {
        id,
        status: pending_status_str(status),
    })
    .into_response())
}

#[derive(Debug, Serialize)]
struct PolicyResponse {
    version: u64,
    #[serde(flatten)]
    policy: PolicyConfig,
}

/// Re-expresses a compiled (network-checked) policy back in the plain `PolicyConfig` shape
/// used by `GET`/`POST /policy` - the inverse of [`PolicyConfig::compile`].
fn policy_response(version: u64, compiled: &CompiledPolicy) -> PolicyResponse {
    PolicyResponse {
        version,
        policy: PolicyConfig {
            max_tx_sat: compiled.max_tx_sat,
            max_daily_sat: compiled.max_daily_sat,
            max_weekly_sat: compiled.max_weekly_sat,
            max_monthly_sat: compiled.max_monthly_sat,
            max_fee_sat: compiled.max_fee_sat,
            max_fee_rate_sat_per_vb: compiled.max_fee_rate_sat_per_vb,
            destination_whitelist: compiled
                .destination_whitelist
                .as_ref()
                .map(|addrs| addrs.iter().map(|a| a.to_string()).collect()),
        },
    }
}

impl From<PolicyAuthError> for ApiError {
    fn from(e: PolicyAuthError) -> Self {
        let status = match &e {
            PolicyAuthError::VersionMismatch { .. } => StatusCode::CONFLICT,
            PolicyAuthError::InvalidPolicy(_) => StatusCode::UNPROCESSABLE_ENTITY,
            PolicyAuthError::MalformedSignature(_) => StatusCode::BAD_REQUEST,
            // The request is well-formed but its signature doesn't authorize the action.
            PolicyAuthError::UnauthorizedSigner => StatusCode::FORBIDDEN,
            PolicyAuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let error = match &e {
            PolicyAuthError::VersionMismatch { .. } => "version_mismatch",
            PolicyAuthError::InvalidPolicy(_) => "invalid_policy",
            PolicyAuthError::MalformedSignature(_) => "malformed_signature",
            PolicyAuthError::UnauthorizedSigner => "unauthorized_signer",
            PolicyAuthError::Internal(_) => "internal",
        };
        ApiError {
            status,
            error,
            message: e.to_string(),
        }
    }
}

/// The current policy and the version it's authorized as - the version a `POST /policy`
/// request must target next (`version + 1`).
async fn get_policy_handler(State(state): State<AppState>) -> Json<PolicyResponse> {
    let handle = state.policy.read().await;
    Json(policy_response(handle.version, &handle.compiled))
}

#[derive(Debug, Deserialize)]
struct PolicyChangeRequestJson {
    policy: PolicyConfig,
    version: u64,
    /// Base64-encoded standard Bitcoin signed message, produced by HARDWARE, over the exact
    /// text `policy_auth::canonical_message(version, &policy)` renders - see that function's
    /// docs for the format a human needs to actually sign.
    signature: String,
}

/// Applies a HARDWARE-authorized policy change - see `policy_auth.rs`. On success, hot-swaps
/// the policy every other handler reads, with no restart required.
async fn post_policy_handler(
    State(state): State<AppState>,
    Json(req): Json<PolicyChangeRequestJson>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let outcome = policy_auth::apply_policy_change(
        &state.ledger,
        &state.cfg,
        &state.auth_keys,
        policy_auth::PolicyChangeRequest {
            policy: req.policy,
            version: req.version,
            signature_base64: req.signature,
        },
        now_unix(),
    )
    .await
    .map_err(ApiError::from)?;

    let response = policy_response(outcome.version, &outcome.compiled);
    *state.policy.write().await = PolicyHandle {
        version: outcome.version,
        compiled: outcome.compiled,
    };
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Txid, Witness,
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::chain::mock::MockChainSource;
    use crate::chain::Utxo;
    use crate::config::ServerSigningConfig;
    use crate::descriptor::{self, build_descriptor};
    use crate::ledger::Ledger;
    use crate::notify::mock::RecordingNotifier;
    use crate::policy::PolicyConfig;
    use crate::test_util::{test_key_spec_with_xpriv, test_server_xpriv, test_wallet_config};

    static ENV_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn fake_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn foreign_script(fill: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x20];
        bytes.extend_from_slice(&[fill; 32]);
        ScriptBuf::from(bytes)
    }

    async fn test_state(hold_seconds: i64) -> (AppState, Arc<MockChainSource>) {
        let cfg = test_wallet_config(12960);
        let wallet = build_descriptor(&cfg).unwrap();
        let chain = Arc::new(MockChainSource::new());

        let xprv = test_server_xpriv();
        // SAFETY: test-only; a counter keeps each call's env var name distinct so concurrent
        // tests in this process never race on the same variable.
        let env_var = format!(
            "COSIGNER_TEST_HTTP_XPRV_{}",
            ENV_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
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
            max_tx_sat: 100_000,
            max_daily_sat: u64::MAX,
            max_weekly_sat: u64::MAX,
            max_monthly_sat: u64::MAX,
            max_fee_sat: u64::MAX,
            max_fee_rate_sat_per_vb: f64::MAX,
            destination_whitelist: None,
        };
        let policy = policy_cfg.compile(cfg.network).unwrap();

        let ledger = Ledger::connect_in_memory().await.unwrap();
        let seeded = ledger
            .load_or_seed_policy_state(&serde_json::to_string(&policy_cfg).unwrap(), 0)
            .await
            .unwrap();

        let auth_keys = policy_auth::HardwareAuthKeys::from_config(&cfg, 50).unwrap();
        let state = AppState {
            wallet: Arc::new(wallet),
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
            hold_seconds,
        };
        (state, chain)
    }

    /// An unsigned HOT-path PSBT spending a fresh UTXO funded into `chain` at `wallet`'s
    /// external chain index 0.
    fn hot_psbt(chain: &MockChainSource, wallet: &BuiltDescriptor, txid_byte: u8) -> Psbt {
        let script_pubkey = descriptor::at_index(&wallet.external, 0)
            .unwrap()
            .script_pubkey();
        let outpoint = OutPoint::new(fake_txid(txid_byte), 0);
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script_pubkey.clone(),
                },
                confirmations: 6,
            },
        );
        let dest = TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: foreign_script(txid_byte),
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
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
            value: Amount::from_sat(50_000),
            script_pubkey,
        });
        psbt
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        let body = match body {
            Some(b) => {
                builder = builder.header("content-type", "application/json");
                axum::body::Body::from(b.to_string())
            }
            None => axum::body::Body::empty(),
        };
        let request = builder.body(body).unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }

    /// As `call`, but presenting a bearer token.
    async fn call_with_token(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
        token: &str,
    ) -> (StatusCode, Value) {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
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
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }

    /// The token gates what *consumes* something - rolling budget, notifications, unbounded
    /// per-input chain work - and deliberately does not gate what only ever *stops* things
    /// happening.
    #[tokio::test]
    async fn the_token_guards_submission_but_never_the_panic_buttons() {
        let (mut state, chain) = test_state(1_000_000).await;
        state.api_token = Some(Arc::from("s3cret-token"));
        let psbt = hot_psbt(&chain, &state.wallet, 0x71);
        let body = serde_json::json!({ "psbt": psbt.to_string() });

        for uri in ["/sign_psbt", "/inspect"] {
            let (status, json) = call(router(state.clone()), "POST", uri, Some(body.clone())).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{uri} must require a token"
            );
            assert_eq!(json["error"], "unauthorized");
        }

        let (status, _) = call_with_token(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(body.clone()),
            "not-the-token",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a wrong token is refused");

        let (status, json) = call_with_token(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(body),
            "s3cret-token",
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "got: {json}");

        // Unguarded on purpose: these must work in a hurry, from whatever device is to hand, and
        // the worst an unauthenticated caller achieves with them is denial of service.
        let (status, _) = call(router(state.clone()), "POST", "/freeze", None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(router(state.clone()), "GET", "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        // 404 (unknown id), not 401 - proof it was never behind the token.
        let (status, _) = call(router(state), "POST", "/veto/never-seen", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A quorum releases the hold, and *only* the hold. Everything else about the row is
    /// untouched, and policy is still re-evaluated when it fires - which is the entire security
    /// argument for letting other people influence this service at all.
    #[tokio::test]
    async fn a_recovery_quorum_releases_the_hold_and_nothing_else() {
        use nostr_sdk::prelude::*;

        let (mut state, chain) = test_state(1_000_000).await;
        let (a, b, stranger) = (Keys::generate(), Keys::generate(), Keys::generate());
        state.recovery_contacts = Some(Arc::new((
            [a.public_key(), b.public_key()].into_iter().collect(),
            2,
        )));

        let psbt = hot_psbt(&chain, &state.wallet, 0x81);
        let (status, body) = call(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "got: {body}");
        let id = body["id"].as_str().unwrap().to_string();

        let before = state.ledger.get_pending(&id).await.unwrap().unwrap();
        assert!(state
            .ledger
            .due_pending(now_unix())
            .await
            .unwrap()
            .is_empty());

        let sign = |k: &Keys, msg: &str| {
            EventBuilder::text_note(msg)
                .sign_with_keys(k)
                .unwrap()
                .as_json()
        };
        let msg = recovery_contacts::canonical_approval_message(&id);

        // One contact is not a quorum.
        let (status, _) = call(
            router(state.clone()),
            "POST",
            &format!("/recovery/approve/{id}"),
            Some(serde_json::json!({ "approvals": [sign(&a, &msg)] })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Neither is one contact plus somebody who isn't on the list.
        let (status, _) = call(
            router(state.clone()),
            "POST",
            &format!("/recovery/approve/{id}"),
            Some(serde_json::json!({ "approvals": [sign(&a, &msg), sign(&stranger, &msg)] })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            state
                .ledger
                .due_pending(now_unix())
                .await
                .unwrap()
                .is_empty(),
            "a failed quorum must not have moved anything"
        );

        // Two distinct contacts is.
        let (status, body) = call(
            router(state.clone()),
            "POST",
            &format!("/recovery/approve/{id}"),
            Some(serde_json::json!({ "approvals": [sign(&a, &msg), sign(&b, &msg)] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["approvals"], 2);
        assert_eq!(body["released"], true);

        let after = state.ledger.get_pending(&id).await.unwrap().unwrap();
        assert_eq!(
            state.ledger.due_pending(now_unix()).await.unwrap(),
            vec![id.clone()],
            "the spend is now due"
        );

        // ...and that is genuinely all that changed. If a quorum could alter any of these, it
        // would be able to influence what gets signed rather than merely when.
        assert_eq!(after.status, before.status);
        assert_eq!(after.psbt_base64, before.psbt_base64);
        assert_eq!(after.spend_amount_sat, before.spend_amount_sat);
        assert_eq!(after.fee_sat, before.fee_sat);
        assert!(after.hold_until < before.hold_until);
    }

    /// A quorum cannot resurrect a spend the owner already vetoed. The veto is the owner's
    /// override and must outrank anybody else's opinion.
    #[tokio::test]
    async fn a_quorum_cannot_revive_a_vetoed_spend() {
        use nostr_sdk::prelude::*;

        let (mut state, chain) = test_state(1_000_000).await;
        let (a, b) = (Keys::generate(), Keys::generate());
        state.recovery_contacts = Some(Arc::new((
            [a.public_key(), b.public_key()].into_iter().collect(),
            2,
        )));

        let psbt = hot_psbt(&chain, &state.wallet, 0x82);
        let (_, body) = call(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        let (status, _) = call(router(state.clone()), "POST", &format!("/veto/{id}"), None).await;
        assert_eq!(status, StatusCode::OK);

        let msg = recovery_contacts::canonical_approval_message(&id);
        let sign = |k: &Keys| {
            EventBuilder::text_note(msg.clone())
                .sign_with_keys(k)
                .unwrap()
                .as_json()
        };
        let (status, json) = call(
            router(state.clone()),
            "POST",
            &format!("/recovery/approve/{id}"),
            Some(serde_json::json!({ "approvals": [sign(&a), sign(&b)] })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "got: {json}");
        assert!(state
            .ledger
            .due_pending(now_unix())
            .await
            .unwrap()
            .is_empty());
    }

    /// Social recovery off is the default, and off must mean refused rather than ignored.
    #[tokio::test]
    async fn recovery_approval_is_refused_when_no_contacts_are_configured() {
        let (state, chain) = test_state(1_000_000).await;
        assert!(state.recovery_contacts.is_none());
        let psbt = hot_psbt(&chain, &state.wallet, 0x83);
        let (_, body) = call(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        let (status, _) = call(
            router(state),
            "POST",
            &format!("/recovery/approve/{id}"),
            Some(serde_json::json!({ "approvals": [] })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    /// With no token configured the API behaves exactly as before - an existing install must not
    /// stop answering its own coordinator on upgrade.
    #[tokio::test]
    async fn no_configured_token_means_no_authentication() {
        let (state, chain) = test_state(1_000_000).await;
        assert!(state.api_token.is_none());
        let psbt = hot_psbt(&chain, &state.wallet, 0x72);

        let (status, _) = call(
            router(state),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn full_queue_and_veto_flow_via_http() {
        let (state, chain) = test_state(1_000_000).await;
        let psbt = hot_psbt(&chain, &state.wallet, 1);

        let (status, body) = call(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "got: {body}");
        assert_eq!(body["status"], "pending");
        let id = body["id"].as_str().unwrap().to_string();
        assert!(body["hold_until"].as_i64().unwrap() > 0);

        let (status, body) = call(
            router(state.clone()),
            "GET",
            &format!("/sign_psbt/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "got: {body}");
        assert_eq!(body["status"], "pending");

        let (status, body) =
            call(router(state.clone()), "POST", &format!("/veto/{id}"), None).await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["status"], "vetoed");

        let (status, body) = call(
            router(state.clone()),
            "GET",
            &format!("/sign_psbt/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "got: {body}");
        assert_eq!(body["status"], "vetoed");

        // Idempotent: vetoing an already-vetoed request just reports its status again.
        let (status, body) =
            call(router(state.clone()), "POST", &format!("/veto/{id}"), None).await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["status"], "vetoed");

        let (status, _) = call(router(state), "GET", "/sign_psbt/never-seen", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn veto_of_unknown_id_is_404() {
        let (state, _chain) = test_state(1_000_000).await;
        let (status, body) = call(router(state), "POST", "/veto/never-seen", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "got: {body}");
    }

    #[tokio::test]
    async fn over_cap_spend_is_denied_immediately_and_never_queued() {
        let (state, chain) = test_state(1_000_000).await;
        // policy.max_tx_sat is 100_000 in test_state(); this destination amount (49_000) is
        // fine on its own, so make a second, larger spend that trips the per-tx cap instead.
        let script_pubkey = descriptor::at_index(&state.wallet.external, 1)
            .unwrap()
            .script_pubkey();
        let outpoint = OutPoint::new(fake_txid(9), 0);
        chain.insert(
            outpoint,
            Utxo {
                txout: TxOut {
                    value: Amount::from_sat(200_000),
                    script_pubkey: script_pubkey.clone(),
                },
                confirmations: 6,
            },
        );
        let dest = TxOut {
            value: Amount::from_sat(150_000),
            script_pubkey: foreign_script(9),
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
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
            value: Amount::from_sat(200_000),
            script_pubkey,
        });
        let id = psbt.unsigned_tx.compute_txid().to_string();

        let (status, body) = call(
            router(state.clone()),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "got: {body}");
        assert_eq!(body["error"], "policy_denied");

        let (status, _) = call(router(state), "GET", &format!("/sign_psbt/{id}"), None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a denied-at-submission spend must never be queued"
        );
    }

    // ---- M6: GET/POST /policy ----

    fn sign_hardware_message(message: &str) -> String {
        use bitcoin::secp256k1::{Message, Secp256k1};

        let (_, hardware_xprv) = test_key_spec_with_xpriv(0x01);
        let secp = Secp256k1::new();
        let msg_hash = bitcoin::sign_message::signed_msg_hash(message);
        let msg = Message::from_digest(msg_hash.to_byte_array());
        let sig = secp.sign_ecdsa_recoverable(&msg, &hardware_xprv.private_key);
        bitcoin::sign_message::MessageSignature::new(sig, true).to_base64()
    }

    #[tokio::test]
    async fn get_policy_reports_the_seeded_version_and_values() {
        let (state, _chain) = test_state(1_000_000).await;
        let (status, body) = call(router(state), "GET", "/policy", None).await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["version"], 1);
        assert_eq!(body["max_tx_sat"], 100_000);
    }

    #[tokio::test]
    async fn health_reports_service_network_and_policy_version() {
        let (state, _chain) = test_state(1_000_000).await;
        let (status, body) = call(router(state), "GET", "/health", None).await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["service"], "cosigner");
        assert_eq!(body["network"], "signet");
        assert_eq!(body["policy_version"], 1);
    }

    #[tokio::test]
    async fn post_policy_with_a_valid_hardware_signature_hot_swaps_the_running_policy() {
        let (state, chain) = test_state(1_000_000).await;

        let new_policy = serde_json::json!({
            "max_tx_sat": 5,
            "max_daily_sat": u64::MAX,
            "max_weekly_sat": u64::MAX,
            "max_monthly_sat": u64::MAX,
            "max_fee_sat": u64::MAX,
            "max_fee_rate_sat_per_vb": f64::MAX,
            "destination_whitelist": null,
        });
        let message = crate::policy_auth::canonical_message(
            2,
            &serde_json::from_value(new_policy.clone()).unwrap(),
        );
        let signature = sign_hardware_message(&message);

        let (status, body) = call(
            router(state.clone()),
            "POST",
            "/policy",
            Some(serde_json::json!({
                "policy": new_policy,
                "version": 2,
                "signature": signature,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["version"], 2);
        assert_eq!(body["max_tx_sat"], 5);

        let (status, body) = call(router(state.clone()), "GET", "/policy", None).await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert_eq!(body["version"], 2);

        // The new (much lower) cap must actually be enforced by /sign_psbt now, without a
        // restart - proves the hot-swap, not just that the DB row changed.
        let psbt = hot_psbt(&chain, &state.wallet, 42);
        let (status, body) = call(
            router(state),
            "POST",
            "/sign_psbt",
            Some(serde_json::json!({ "psbt": psbt.to_string() })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "got: {body}");
        assert_eq!(body["error"], "policy_denied");
    }

    #[tokio::test]
    async fn post_policy_rejects_a_signature_from_a_non_hardware_key() {
        let (state, _chain) = test_state(1_000_000).await;

        let new_policy = serde_json::json!({
            "max_tx_sat": 5,
            "max_daily_sat": u64::MAX,
            "max_weekly_sat": u64::MAX,
            "max_monthly_sat": u64::MAX,
            "max_fee_sat": u64::MAX,
            "max_fee_rate_sat_per_vb": f64::MAX,
            "destination_whitelist": null,
        });
        // Signed with SERVER's own key instead of HARDWARE's.
        let message = crate::policy_auth::canonical_message(
            2,
            &serde_json::from_value(new_policy.clone()).unwrap(),
        );
        let msg_hash = bitcoin::sign_message::signed_msg_hash(&message);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let server_xprv = test_server_xpriv();
        let sig = secp.sign_ecdsa_recoverable(
            &bitcoin::secp256k1::Message::from_digest(msg_hash.to_byte_array()),
            &server_xprv.private_key,
        );
        let signature = bitcoin::sign_message::MessageSignature::new(sig, true).to_base64();

        let (status, body) = call(
            router(state),
            "POST",
            "/policy",
            Some(serde_json::json!({
                "policy": new_policy,
                "version": 2,
                "signature": signature,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "got: {body}");
        assert_eq!(body["error"], "unauthorized_signer");
    }

    #[tokio::test]
    async fn post_policy_rejects_a_wrong_version() {
        let (state, _chain) = test_state(1_000_000).await;

        let new_policy = serde_json::json!({
            "max_tx_sat": 5,
            "max_daily_sat": u64::MAX,
            "max_weekly_sat": u64::MAX,
            "max_monthly_sat": u64::MAX,
            "max_fee_sat": u64::MAX,
            "max_fee_rate_sat_per_vb": f64::MAX,
            "destination_whitelist": null,
        });
        let message = crate::policy_auth::canonical_message(
            99,
            &serde_json::from_value(new_policy.clone()).unwrap(),
        );
        let signature = sign_hardware_message(&message);

        let (status, body) = call(
            router(state),
            "POST",
            "/policy",
            Some(serde_json::json!({
                "policy": new_policy,
                "version": 99,
                "signature": signature,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "got: {body}");
        assert_eq!(body["error"], "version_mismatch");
    }
}

#[derive(Debug, Serialize)]
struct FreezeResponse {
    frozen: bool,
    /// The current freeze generation - what an unfreeze authorization must be signed for (see
    /// `policy_auth::canonical_unfreeze_message`). 0 if this service has never been frozen.
    generation: u64,
}

#[derive(Debug, Deserialize)]
struct FreezeRequest {
    #[serde(default)]
    reason: Option<String>,
}

async fn get_freeze_handler(
    State(state): State<AppState>,
) -> Result<Json<FreezeResponse>, ApiError> {
    let frozen = state.ledger.is_frozen().await.map_err(internal)?;
    let generation = state.ledger.freeze_generation().await.map_err(internal)?;
    Ok(Json(FreezeResponse { frozen, generation }))
}

/// Halts all co-signing until explicitly unfrozen. **Deliberately unauthenticated.**
///
/// This is the "my phone was just stolen" button, and it needs to work from whatever device is
/// to hand, in a hurry, possibly without your hardware key. Freezing is fail-safe: the worst an
/// attacker achieves by calling it is denial of service, which is strictly better than the
/// theft it exists to prevent. *Unfreezing* is the privileged direction, and that one requires
/// a HARDWARE signature - see [`post_unfreeze_handler`].
///
/// A freeze survives restarts (it's a ledger row), so "turn it off and on again" will not
/// silently disarm it.
async fn post_freeze_handler(
    State(state): State<AppState>,
    body: Option<Json<FreezeRequest>>,
) -> Result<Json<FreezeResponse>, ApiError> {
    let reason = body.and_then(|Json(b)| b.reason);
    state
        .ledger
        .set_frozen(true, now_unix(), reason.as_deref())
        .await
        .map_err(internal)?;
    let generation = state.ledger.freeze_generation().await.map_err(internal)?;
    tracing::warn!(reason = ?reason, generation, "co-signing FROZEN");
    Ok(Json(FreezeResponse {
        frozen: true,
        generation,
    }))
}

/// Resumes co-signing. Requires a HARDWARE-signed message over the exact text
/// `policy_auth::canonical_unfreeze_message(generation)`, where `generation` is the *current
/// freeze generation* (see `GET /freeze`) - which both proves hardware possession and stops an
/// old unfreeze authorization from being replayed to lift a later, unrelated freeze. Generation,
/// not policy version: freezing and policy changes are unrelated events, and binding to the
/// latter would let one captured signature re-unfreeze indefinitely.
///
/// If you've lost the HARDWARE itself, use the `cosigner unfreeze` CLI on the server instead:
/// requiring the hardware here would make a freeze unrecoverable in exactly the scenario the
/// recovery path exists for.
async fn post_unfreeze_handler(
    State(state): State<AppState>,
    Json(req): Json<UnfreezeRequest>,
) -> Result<Json<FreezeResponse>, ApiError> {
    let generation = state.ledger.freeze_generation().await.map_err(internal)?;
    policy_auth::verify_unfreeze_authorization(&state.auth_keys, generation, &req.signature)
        .map_err(ApiError::from)?;
    state
        .ledger
        .set_frozen(false, now_unix(), None)
        .await
        .map_err(internal)?;
    tracing::warn!(generation, "co-signing UNFROZEN by HARDWARE authorization");
    Ok(Json(FreezeResponse {
        frozen: false,
        generation,
    }))
}

#[derive(Debug, Deserialize)]
struct UnfreezeRequest {
    signature: String,
}

#[derive(Debug, Deserialize)]
struct RecoveryApprovalRequest {
    /// Signed Nostr events, one per contact, each with
    /// `recovery_contacts::canonical_approval_message(txid)` as its content.
    approvals: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RecoveryApprovalResponse {
    id: String,
    approvals: usize,
    threshold: usize,
    released: bool,
}

/// Releases a queued spend's remaining hold on the say-so of a quorum of recovery contacts.
///
/// **Deliberately the only thing a quorum can do.** It brings `hold_until` forward and nothing
/// else: the spend was already approved by policy when it was queued, policy is re-evaluated from
/// scratch when it actually fires, and every consensus rule is untouched. A quorum cannot create
/// a spend, raise a cap, redirect a destination or revive a vetoed row - see
/// `recovery_contacts.rs` for why that boundary is the whole design.
///
/// Unauthenticated in the bearer-token sense, like `/veto` and `/freeze`: the signatures *are*
/// the authentication, and requiring the API token as well would mean a contact helping you
/// recover needed a secret from the box you have lost access to.
async fn recovery_approve_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RecoveryApprovalRequest>,
) -> Result<Json<RecoveryApprovalResponse>, ApiError> {
    let Some(contacts) = state.recovery_contacts.as_ref() else {
        return Err(ApiError {
            status: StatusCode::NOT_IMPLEMENTED,
            error: "recovery_contacts_not_configured",
            message: "no recovery contacts are configured on this service".to_string(),
        });
    };
    let (allowed, threshold) = (&contacts.0, contacts.1);

    // Refuse before counting votes if there is nothing to release: a quorum spent on a spend that
    // is already signed, vetoed or gone tells the contacts something useful.
    match state.ledger.get_pending(&id).await.map_err(internal)? {
        Some(row) if row.status == PendingStatus::Pending => {}
        _ => {
            return Err(ApiError {
                status: StatusCode::NOT_FOUND,
                error: "not_pending",
                message: format!("no spend with id {id} is currently pending"),
            })
        }
    }

    let voters = recovery_contacts::count_distinct_approvals(&id, &req.approvals, allowed)
        .map_err(|e| ApiError {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_approval",
            message: e.to_string(),
        })?;

    if voters.len() < threshold {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            error: "short_of_quorum",
            message: format!(
                "only {} of {threshold} required contacts have approved",
                voters.len()
            ),
        });
    }

    let released = state
        .ledger
        .release_hold(&id, now_unix())
        .await
        .map_err(internal)?;
    tracing::warn!(
        txid = %id,
        approvals = voters.len(),
        threshold,
        "hold RELEASED early by recovery-contact quorum"
    );

    Ok(Json(RecoveryApprovalResponse {
        id,
        approvals: voters.len(),
        threshold,
        released,
    }))
}

fn internal(e: anyhow::Error) -> ApiError {
    ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "internal",
        message: e.to_string(),
    }
}
