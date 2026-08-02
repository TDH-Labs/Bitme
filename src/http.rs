//! The HTTP API. Thin: every handler just deserializes the request, hands off to the pure
//! logic in `inspect.rs` (running blocking chain-RPC calls off the async runtime), and
//! serializes the result. No policy or signing logic lives here.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use bitcoin::psbt::Psbt;
use serde::{Deserialize, Serialize};

use crate::chain::ChainSource;
use crate::config::WalletConfig;
use crate::descriptor::{BuiltDescriptor, Chain};
use crate::inspect::{self, InspectError, InspectionReport, OutputKind, SpendingPath};
use crate::ledger::Ledger;
use crate::policy::CompiledPolicy;
use crate::sign::{self, LedgerOutcome, SignPsbtError};
use crate::signing::{ServerSigningKey, SigningError};

#[derive(Clone)]
pub struct AppState {
    pub wallet: Arc<BuiltDescriptor>,
    pub cfg: Arc<WalletConfig>,
    pub chain: Arc<dyn ChainSource>,
    pub gap_limit: u32,
    /// Only used by `/sign_psbt`.
    pub server_key: Arc<ServerSigningKey>,
    /// Only used by `/sign_psbt`.
    pub ledger: Arc<Ledger>,
    /// Only used by `/sign_psbt`.
    pub policy: Arc<CompiledPolicy>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/inspect", post(inspect_handler))
        .route("/sign_psbt", post(sign_psbt_handler))
        .with_state(state)
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

async fn sign_psbt_handler(
    State(state): State<AppState>,
    Json(req): Json<PsbtRequest>,
) -> Result<Json<SignResponse>, ApiError> {
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
    // /inspect does. Everything after this (the ledger transaction, signing) is either async
    // I/O or fast pure computation, so it runs directly on this task.
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

    let result = sign::sign_psbt(
        psbt,
        report,
        &state.wallet,
        &state.cfg,
        &state.server_key,
        &state.ledger,
        &state.policy,
        now_unix(),
    )
    .await?;

    let ledger = match result.ledger {
        LedgerOutcome::Recorded => "recorded",
        LedgerOutcome::AlreadyRecorded => "already_recorded",
    };
    Ok(Json(SignResponse {
        psbt: result.psbt.to_string(),
        ledger,
        inspection: result.report.into(),
    }))
}
