//! Browser-based first-run setup, served in place of the API when no `wallet.toml` exists yet.
//!
//! Before this existed, standing the service up meant hand-writing ~30 TOML fields, generating
//! a BIP32 key by hand with an external tool, and getting three xpubs and their derivation
//! paths exactly right with no feedback until `serve` failed. On Umbrel - which has no
//! per-app file editor and no secret-entry UI - that meant SSHing into the box. This module
//! replaces that with a wizard on the app's own port.
//!
//! It deliberately reuses `wizard.rs` rather than duplicating it: the same [`WizardAnswers`]
//! struct, the same field validators, and the same `render_user_toml` renderer that
//! `cosigner init` uses. The web layer here is only collection and IO, so the CLI and the
//! browser can't drift into producing different configs.
//!
//! # Lifecycle
//!
//! `docker-entrypoint.sh` runs `cosigner setup` when `config/wallet.toml` is absent, and
//! `cosigner serve` when it's present. Finishing the wizard writes the config and then, on an
//! explicit click, shuts this server down; Docker's `restart: unless-stopped` brings the
//! container back, the entrypoint now finds a config, and the real API starts. There is no
//! in-process transition from setup mode to serving mode - a restart is the only path, so a
//! half-configured process can never end up holding a signing key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};
use zeroize::Zeroizing;

use crate::config::{ChainNetwork, WalletConfig};
use crate::descriptor;
use crate::wizard::{
    self, BitcoindAuthAnswer, KeyAnswer, NotifyAnswer, PolicyAnswer, ServerSigningAnswer,
    WizardAnswers,
};

/// Where the generated SERVER key is written, relative to the config directory. Referenced by
/// `[server_signing].xprv_file` in the config this module writes.
const SERVER_XPRV_FILENAME: &str = "server.xprv";
const WALLET_TOML_FILENAME: &str = "wallet.toml";

/// Deployment facts the wizard doesn't ask about because the container already knows them.
/// These come from the same environment variables `docker-entrypoint.sh` reads, so the two
/// always agree about what the deployment looks like.
#[derive(Clone, Debug)]
pub struct Deployment {
    pub network: ChainNetwork,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub bind_addr: String,
    pub bitcoind_rpc_url: String,
}

/// A freshly generated SERVER key, held in memory between "generate" and "finish".
///
/// Only the account-level xprv is retained. The master key it was derived from is dropped
/// immediately after derivation and never persisted: every key the descriptor actually uses
/// hangs off unhardened `<0;1>/*` children of this account key, so the master buys nothing
/// operationally while being strictly more dangerous to keep.
struct GeneratedServerKey {
    /// Fingerprint of the *master* key - this is what goes in the descriptor's key origin.
    master_fingerprint: String,
    derivation_path: String,
    xpub: String,
    /// The account-level xprv, wiped on drop.
    account_xprv: Zeroizing<String>,
}

pub struct SetupState {
    deployment: Deployment,
    generated: Mutex<Option<GeneratedServerKey>>,
    /// Fires once, when the user clicks "start the cosigner" on the final screen.
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}

impl SetupState {
    pub fn new(deployment: Deployment, shutdown: oneshot::Sender<()>) -> Self {
        Self {
            deployment,
            generated: Mutex::new(None),
            shutdown: Mutex::new(Some(shutdown)),
        }
    }

    fn wallet_toml_path(&self) -> PathBuf {
        self.deployment.config_dir.join(WALLET_TOML_FILENAME)
    }

    fn server_xprv_path(&self) -> PathBuf {
        self.deployment.config_dir.join(SERVER_XPRV_FILENAME)
    }
}

pub fn router(state: Arc<SetupState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/api/state", get(state_handler))
        .route("/api/validate-key", post(validate_key_handler))
        .route("/api/server-key", post(server_key_handler))
        .route("/api/decode-qr", post(decode_qr_handler))
        .route("/api/finish", post(finish_handler))
        .route("/api/start", post(start_handler))
        // Axum's default request body cap is 2 MB; a phone photo of a QR is routinely larger.
        .layer(axum::extract::DefaultBodyLimit::max(12 * 1024 * 1024))
        .with_state(state)
}

// --- error plumbing ---------------------------------------------------------------------------

/// Every failure here is something the person at the keyboard needs to read and act on, so the
/// message is the payload rather than being swallowed into a generic 500.
struct SetupError(StatusCode, String);

impl IntoResponse for SetupError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl SetupError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
}

// --- handlers ---------------------------------------------------------------------------------

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("setup.html"))
}

#[derive(Serialize)]
struct SetupHealth {
    service: &'static str,
    version: &'static str,
    status: &'static str,
    network: &'static str,
}

/// Answers on the same path the real API uses, so Umbrel's `app_proxy` port-wait and the
/// container HEALTHCHECK both succeed while the box is still waiting to be configured. The
/// `status` field is what distinguishes this from a configured, serving instance.
async fn health_handler(State(state): State<Arc<SetupState>>) -> Json<SetupHealth> {
    Json(SetupHealth {
        service: "cosigner",
        version: env!("CARGO_PKG_VERSION"),
        status: "awaiting-setup",
        network: wizard::network_str(state.deployment.network),
    })
}

#[derive(Serialize)]
struct StateResponse {
    network: &'static str,
    /// True once wallet.toml exists - the UI uses this to jump straight to the final screen if
    /// the page is reloaded after finishing.
    configured: bool,
    default_derivation_path: String,
    default_timelock_blocks: u16,
    bitcoind_rpc_url: String,
}

async fn state_handler(State(state): State<Arc<SetupState>>) -> Json<StateResponse> {
    Json(StateResponse {
        network: wizard::network_str(state.deployment.network),
        configured: state.wallet_toml_path().exists(),
        default_derivation_path: default_derivation_path(state.deployment.network),
        default_timelock_blocks: 12960,
        bitcoind_rpc_url: state.deployment.bitcoind_rpc_url.clone(),
    })
}

#[derive(Deserialize)]
struct ValidateKeyRequest {
    fingerprint: String,
    derivation_path: String,
    xpub: String,
}

#[derive(Serialize)]
struct ValidateKeyResponse {
    ok: bool,
}

/// Validates one key as it's typed, using the exact validators `cosigner init` uses - so the
/// browser rejects the same inputs the CLI would, with the same wording.
async fn validate_key_handler(
    State(state): State<Arc<SetupState>>,
    Json(req): Json<ValidateKeyRequest>,
) -> Result<Json<ValidateKeyResponse>, SetupError> {
    validate_key(state.deployment.network, &req)?;
    Ok(Json(ValidateKeyResponse { ok: true }))
}

fn validate_key(network: ChainNetwork, req: &ValidateKeyRequest) -> Result<KeyAnswer, SetupError> {
    let fingerprint = req.fingerprint.trim().to_lowercase();
    let derivation_path = req.derivation_path.trim().to_string();
    let xpub = req.xpub.trim().to_string();

    wizard::validate_fingerprint(&fingerprint).map_err(SetupError::bad_request)?;
    wizard::validate_derivation_path(&derivation_path).map_err(SetupError::bad_request)?;
    wizard::validate_xpub_for(network, &derivation_path)(&xpub).map_err(SetupError::bad_request)?;

    Ok(KeyAnswer {
        fingerprint,
        derivation_path,
        xpub,
    })
}

#[derive(Serialize)]
struct ServerKeyResponse {
    master_fingerprint: String,
    derivation_path: String,
    xpub: String,
    /// `[fingerprint/path]xpub` - what another wallet needs to register this as a co-signer.
    key_expression: String,
    /// The same key expression as a scannable QR, for adding this key to a phone wallet without
    /// retyping it.
    key_expression_qr_svg: Option<String>,
    /// Coldcard's generic export shape, which a lot of wallets accept as a key-import file even
    /// when they don't parse a raw key expression. Offered as a fallback, not a preference.
    import_json: String,
}

/// Generates the SERVER key on the box, from the operating system's CSPRNG.
///
/// Entropy source: `bitcoin::secp256k1::rand::rngs::OsRng`, which on Linux is the
/// `getrandom(2)` syscall - the same kernel CSPRNG that seeds `/dev/urandom`, drawn directly
/// rather than through a file descriptor (so it cannot be affected by a missing or replaced
/// `/dev/urandom` node inside the container) and blocking until the pool is initialised. No
/// userspace PRNG is interposed, nothing is seeded from a timestamp, process id, or any other
/// low-entropy source, and no new dependency was added to reach it: secp256k1 already pulls
/// `rand` in this build.
///
/// 256 bits are drawn and used directly as BIP32 master seed material.
async fn server_key_handler(
    State(state): State<Arc<SetupState>>,
) -> Result<Json<ServerKeyResponse>, SetupError> {
    let network = state.deployment.network;
    let path_str = default_derivation_path(network);

    let generated = generate_server_key(network, &path_str)
        .map_err(|e| SetupError::internal(format!("generating the SERVER key failed: {e}")))?;

    let expr = key_expression(
        &generated.master_fingerprint,
        &generated.derivation_path,
        &generated.xpub,
    );
    let response = ServerKeyResponse {
        key_expression_qr_svg: qr_svg(&expr),
        import_json: serde_json::json!({
            "xfp": generated.master_fingerprint.to_uppercase(),
            "p2wsh": {
                "xpub": generated.xpub,
                "deriv": format!("m/{}", generated.derivation_path.replace('h', "'")),
                "_pub": generated.xpub,
            },
        })
        .to_string(),
        key_expression: expr,
        master_fingerprint: generated.master_fingerprint.clone(),
        derivation_path: generated.derivation_path.clone(),
        xpub: generated.xpub.clone(),
    };
    *state.generated.lock().await = Some(generated);
    Ok(Json(response))
}

fn generate_server_key(network: ChainNetwork, path_str: &str) -> Result<GeneratedServerKey> {
    let secp = Secp256k1::new();
    let path: DerivationPath = path_str.parse().context("parsing the default derivation path")?;

    let mut seed = Zeroizing::new([0u8; 32]);
    bitcoin::secp256k1::rand::rngs::OsRng.fill_bytes(seed.as_mut());

    let master = Xpriv::new_master(network.xpub_network_kind(), seed.as_ref())
        .context("deriving a BIP32 master key from fresh entropy")?;
    let master_fingerprint = master.fingerprint(&secp).to_string().to_lowercase();

    let account = master
        .derive_priv(&secp, &path)
        .context("deriving the account key")?;
    let xpub = Xpub::from_priv(&secp, &account).to_string();

    Ok(GeneratedServerKey {
        master_fingerprint,
        derivation_path: path_str.to_string(),
        xpub,
        account_xprv: Zeroizing::new(account.to_string()),
    })
}

#[derive(Deserialize)]
struct FinishRequest {
    timelock_blocks: u16,
    satochip: ValidateKeyRequest,
    mobile: ValidateKeyRequest,
    policy: PolicyRequest,
    hold_seconds: i64,
    recovery_hold_seconds: i64,
    #[serde(default)]
    ntfy_url: Option<String>,
    /// Alternative to ntfy. The config has always supported both; only the browser wizard was
    /// ntfy-only, which forced anyone unwilling to use a third-party push service to give up
    /// on the wizard entirely.
    #[serde(default)]
    smtp: Option<SmtpRequest>,
}

#[derive(Deserialize)]
struct SmtpRequest {
    host: String,
    port: u16,
    username: String,
    password: String,
    from: String,
    to: String,
}

#[derive(Deserialize)]
struct PolicyRequest {
    max_tx_sat: u64,
    max_daily_sat: u64,
    max_weekly_sat: u64,
    max_monthly_sat: u64,
    max_fee_sat: u64,
    max_fee_rate_sat_per_vb: f64,
}

#[derive(Serialize)]
struct FinishResponse {
    descriptor: String,
    receive_descriptor: String,
    change_descriptor: String,
    first_address: String,
    server_fingerprint: String,
    config_path: String,
    /// The multipath descriptor as an inline SVG QR, for carrying to a phone without retyping
    /// it. `None` if the descriptor is too long to encode - the copy/download paths in the UI
    /// always work, so this is a convenience that's allowed to be absent rather than an error.
    descriptor_qr_svg: Option<String>,
    /// The same wallet as a single-path receive descriptor. BIP389 multipath (`<0;1>`) is the
    /// compact form and what this service prefers, but plenty of wallets - Bitcoin Keeper among
    /// them, on the version this was tested against - reject it outright as an unrecognised
    /// format. Offering both turns "your descriptor is broken" into "try the other one".
    receive_qr_svg: Option<String>,
    change_qr_svg: Option<String>,
}

/// Renders `data` as an inline SVG QR, or `None` if it's too long to encode. Callers always
/// show the same payload as selectable text too, so a missing QR degrades to "type it" rather
/// than blocking anything.
pub(crate) fn qr_svg(data: &str) -> Option<String> {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    // Low EC deliberately: these are long strings, the screen showing them is inches away from
    // the camera, and a failed scan is retried for free - whereas overflowing the version cap
    // means no QR at all.
    QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .ok()
        .map(|code| {
            code.render()
                .min_dimensions(240, 240)
                .dark_color(svg::Color("#000000"))
                .light_color(svg::Color("#ffffff"))
                .build()
        })
}

/// A descriptor key expression: `[fingerprint/derivation]xpub`. This is the standard way to
/// hand a co-signer key to another wallet - a bare xpub loses the key origin, and without it a
/// coordinator cannot build a PSBT this service will recognise as its own.
///
/// The hardened marker is normalised to an apostrophe rather than passed through as written.
/// BIP380 permits both `'` and `h`, but `'` is what is actually accepted everywhere, and it's
/// what `descriptor.rs` emits for the finished wallet descriptor - so emitting `48h/0h/0h/2h`
/// here meant this service handed out the same key in two different notations depending on
/// which screen you were looking at. Parsing and re-displaying via [`DerivationPath`] gets the
/// canonical form for free instead of doing string surgery on whatever was typed in.
fn key_expression(fingerprint: &str, derivation_path: &str, xpub: &str) -> String {
    let fp = fingerprint.trim().to_lowercase();
    let raw = derivation_path
        .trim()
        .trim_start_matches(['m', 'M'])
        .trim_start_matches('/');
    if raw.is_empty() {
        return format!("[{fp}]{}", xpub.trim());
    }
    let path = match raw.parse::<DerivationPath>() {
        Ok(p) => p.to_string(),
        // Unparseable paths can't reach here - every path is validated before a key is
        // accepted - but falling back to the input beats panicking on a display string.
        Err(_) => raw.to_string(),
    };
    format!("[{fp}/{path}]{}", xpub.trim())
}

/// Writes the config. This is the only handler that touches disk, and it is all-or-nothing:
/// the rendered TOML is parsed and validated, and the descriptor is built from it, before
/// anything is written. A config that would fail on `serve` is rejected here instead, while
/// the person who can fix it is still looking at the form.
async fn finish_handler(
    State(state): State<Arc<SetupState>>,
    Json(req): Json<FinishRequest>,
) -> Result<Json<FinishResponse>, SetupError> {
    if state.wallet_toml_path().exists() {
        return Err(SetupError::bad_request(
            "this cosigner is already configured; refusing to overwrite wallet.toml",
        ));
    }

    let network = state.deployment.network;
    let satochip = validate_key(network, &req.satochip)?;
    let mobile = validate_key(network, &req.mobile)?;

    let mut guard = state.generated.lock().await;
    let generated = guard.as_ref().ok_or_else(|| {
        SetupError::bad_request("no SERVER key has been generated yet - go back and generate one")
    })?;

    if req.timelock_blocks == 0 {
        return Err(SetupError::bad_request(
            "the recovery timelock must be at least 1 block",
        ));
    }
    // `WalletConfig::validate` enforces this too, but only after the whole form has been
    // filled in. Rejecting it here, with the reason, beats a late failure on a field the UI
    // could plausibly have presented as optional.
    let has_ntfy = req
        .ntfy_url
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_smtp = req
        .smtp
        .as_ref()
        .is_some_and(|s| !s.host.trim().is_empty() && !s.to.trim().is_empty());
    if !has_ntfy && !has_smtp {
        return Err(SetupError::bad_request(
            "a notification channel is required - either an ntfy URL or SMTP email. A hold \
             window with no notification channel would wait silently and then sign, with nobody \
             in a position to veto it",
        ));
    }
    // Two distinct keys are the whole point of a multisig; identical xpubs would compile into a
    // descriptor that looks like 2-of-3 but is really 1-of-2.
    if satochip.xpub == mobile.xpub {
        return Err(SetupError::bad_request(
            "the SATOCHIP and Bitcoin Keeper keys are the same xpub - each key must be a \
             different device",
        ));
    }
    if satochip.xpub == generated.xpub || mobile.xpub == generated.xpub {
        return Err(SetupError::bad_request(
            "one of the keys you entered is the SERVER key this box just generated",
        ));
    }

    let answers = build_answers(&state.deployment, &req, satochip, mobile, generated);
    let toml_text = wizard::render_user_toml(&answers);

    // Parse and validate exactly the bytes about to be written - not the in-memory answers -
    // so a rendering bug surfaces here rather than as a confusing failure on the next start.
    let cfg: WalletConfig = toml::from_str(&toml_text)
        .map_err(|e| SetupError::internal(format!("generated config failed to parse: {e}")))?;
    cfg.validate()
        .map_err(|e| SetupError::bad_request(format!("{e}")))?;

    let built = descriptor::build_descriptor(&cfg)
        .map_err(|e| SetupError::bad_request(format!("these keys don't form a valid wallet: {e}")))?;
    // Receive index 0, from the external chain - the address the UI tells the operator to
    // cross-check against what Bitcoin Keeper shows after importing the descriptor. A mismatch
    // there is the cheapest possible way to catch a mistyped xpub before any coins move.
    let first_address = descriptor::address_at(&built.external, 0, cfg.network)
        .map_err(|e| SetupError::internal(format!("deriving the first address failed: {e}")))?
        .to_string();

    write_private(&state.server_xprv_path(), generated.account_xprv.as_bytes())
        .map_err(|e| SetupError::internal(format!("writing the SERVER key failed: {e}")))?;
    // wallet.toml last: its presence is what the entrypoint keys off, so it must never exist
    // without the key file it points at.
    if let Err(e) = write_private(&state.wallet_toml_path(), toml_text.as_bytes()) {
        let _ = std::fs::remove_file(state.server_xprv_path());
        return Err(SetupError::internal(format!(
            "writing wallet.toml failed: {e}"
        )));
    }

    let multipath = built.multipath.to_string();
    let receive = built.external.to_string();
    let change = built.internal.to_string();
    let response = FinishResponse {
        descriptor_qr_svg: qr_svg(&multipath),
        receive_qr_svg: qr_svg(&receive),
        change_qr_svg: qr_svg(&change),
        descriptor: multipath,
        receive_descriptor: receive,
        change_descriptor: change,
        first_address,
        server_fingerprint: generated.master_fingerprint.clone(),
        config_path: state.wallet_toml_path().display().to_string(),
    };
    // The key is on disk now; drop the in-memory copy.
    *guard = None;
    Ok(Json(response))
}

fn build_answers(
    deployment: &Deployment,
    req: &FinishRequest,
    satochip: KeyAnswer,
    mobile: KeyAnswer,
    generated: &GeneratedServerKey,
) -> WizardAnswers {
    WizardAnswers {
        network: deployment.network,
        timelock_blocks: req.timelock_blocks,
        satochip,
        mobile,
        server: KeyAnswer {
            fingerprint: generated.master_fingerprint.clone(),
            derivation_path: generated.derivation_path.clone(),
            xpub: generated.xpub.clone(),
        },
        server_signing: ServerSigningAnswer::File(
            deployment
                .config_dir
                .join(SERVER_XPRV_FILENAME)
                .display()
                .to_string(),
        ),
        // The four fields below are part of [bitcoind]/[server], which `render_user_toml`
        // omits - docker-entrypoint.sh regenerates both sections from the environment on every
        // start. They're populated with the real values anyway so that `WizardAnswers` always
        // describes the actual deployment, rather than carrying placeholders that would be
        // wrong if this struct were ever rendered in full.
        bitcoind_rpc_url: deployment.bitcoind_rpc_url.clone(),
        bitcoind_auth: BitcoindAuthAnswer::UserPass(String::new(), String::new()),
        bind_addr: deployment.bind_addr.clone(),
        gap_limit: 1000,
        ledger_db_path: deployment
            .data_dir
            .join("ledger.sqlite3")
            .display()
            .to_string(),
        policy: PolicyAnswer {
            max_tx_sat: req.policy.max_tx_sat,
            max_daily_sat: req.policy.max_daily_sat,
            max_weekly_sat: req.policy.max_weekly_sat,
            max_monthly_sat: req.policy.max_monthly_sat,
            max_fee_sat: req.policy.max_fee_sat,
            max_fee_rate_sat_per_vb: req.policy.max_fee_rate_sat_per_vb,
            destination_whitelist: None,
        },
        notify: NotifyAnswer {
            hold_seconds: req.hold_seconds,
            sweep_interval_seconds: 30,
            renotify_interval_seconds: 3600,
            ntfy_url: req
                .ntfy_url
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            ntfy_auth_token: None,
            smtp: req.smtp.as_ref().map(|s| crate::wizard::SmtpAnswer {
                host: s.host.trim().to_string(),
                port: s.port,
                username: s.username.trim().to_string(),
                password: s.password.clone(),
                from: s.from.trim().to_string(),
                to: s.to.trim().to_string(),
            }),
        },
        recovery_hold_seconds: req.recovery_hold_seconds,
        recovery_destination_whitelist: None,
        nostr_transport: None,
    }
}

/// Writes owner-read/write only, and creates with those permissions rather than relaxing them
/// afterwards - so the file is never briefly world-readable, even for an instant.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("flushing {} to disk", path.display()))?;
    Ok(())
}

#[derive(Serialize)]
struct DecodeQrResponse {
    /// Every distinct payload found in the image, in the order the decoder returned them.
    payloads: Vec<String>,
    /// Best-effort interpretation of the first payload as a key, so the UI can fill all three
    /// fields from one scan instead of making the operator split it up by hand.
    key: Option<ScannedKey>,
}

#[derive(Serialize)]
struct ScannedKey {
    fingerprint: Option<String>,
    derivation_path: Option<String>,
    xpub: String,
}

/// Decodes a QR from an uploaded image.
///
/// This exists because the browser can't do it here. Both `getUserMedia` (camera) and
/// `BarcodeDetector` require a secure context, and this app is served over plain HTTP on a LAN
/// hostname, so live camera scanning is unavailable in every mainstream browser. Photographing
/// the QR with the phone's normal camera app and uploading the picture works regardless of
/// browser, transport, or platform - and it's the difference between scanning a 111-character
/// xpub and retyping it.
async fn decode_qr_handler(body: axum::body::Bytes) -> Result<Json<DecodeQrResponse>, SetupError> {
    // Generous but bounded: modern phone photos are a few MB, and decoding is CPU-bound on a
    // box that may be busy.
    const MAX_IMAGE_BYTES: usize = 12 * 1024 * 1024;
    if body.is_empty() {
        return Err(SetupError::bad_request("no image was uploaded"));
    }
    if body.len() > MAX_IMAGE_BYTES {
        return Err(SetupError::bad_request(
            "that image is larger than 12 MB - try a screenshot, or a lower-resolution photo",
        ));
    }

    let payloads = tokio::task::spawn_blocking(move || decode_qr_bytes(&body))
        .await
        .map_err(|e| SetupError::internal(format!("decoding panicked: {e}")))?
        .map_err(|e| SetupError::bad_request(format!("{e}")))?;

    if payloads.is_empty() {
        return Err(SetupError::bad_request(
            "no QR code found in that image - make sure the whole code is in frame and in focus",
        ));
    }
    let key = payloads.first().and_then(|p| parse_scanned_key(p));
    Ok(Json(DecodeQrResponse { payloads, key }))
}

fn decode_qr_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let img = image::load_from_memory(bytes)
        .context("that file doesn't look like a PNG, JPEG or WebP image")?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if !content.is_empty() && !out.contains(&content) {
                out.push(content);
            }
        }
    }
    Ok(out)
}

/// Pulls a key out of whatever a wallet happened to put in its QR. Handles the three shapes
/// seen in practice: a descriptor key expression with origin, a bare xpub, and a JSON export
/// (Coldcard's shape and the variations on it). Returns `None` rather than guessing wildly -
/// the operator can always fall back to typing, and a wrong auto-fill is worse than none.
fn parse_scanned_key(payload: &str) -> Option<ScannedKey> {
    let s = payload.trim();

    // 1. `[fingerprint/derivation]xpub...` - possibly with a trailing `/<0;1>/*` from a full
    //    descriptor fragment, which is not part of the account xpub.
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((origin, tail)) = rest.split_once(']') {
            let (fp, path) = match origin.split_once('/') {
                Some((fp, path)) => (fp, Some(path.to_string())),
                None => (origin, None),
            };
            let xpub = tail.split('/').next().unwrap_or(tail).trim().to_string();
            if !xpub.is_empty() {
                return Some(ScannedKey {
                    fingerprint: Some(fp.trim().to_lowercase()),
                    derivation_path: path,
                    xpub,
                });
            }
        }
    }

    // 2. A JSON export. Look for an xpub and an origin wherever they happen to live, rather
    //    than committing to one vendor's exact schema.
    if s.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let fp = ["xfp", "master_fingerprint", "fingerprint"]
                .iter()
                .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
                .map(|f| f.trim().to_lowercase());
            // Prefer the P2WSH-multisig account, which is what this wallet uses.
            let section = ["p2wsh", "bip48_2", "p2wsh_multisig"]
                .iter()
                .find_map(|k| v.get(*k))
                .unwrap_or(&v);
            let xpub = ["xpub", "_pub", "Zpub", "zpub"]
                .iter()
                .find_map(|k| section.get(*k).and_then(|x| x.as_str()))?;
            let deriv = ["deriv", "derivation", "path", "derivation_path"]
                .iter()
                .find_map(|k| section.get(*k).and_then(|x| x.as_str()))
                .map(|d| {
                    d.trim()
                        .trim_start_matches(['m', 'M'])
                        .trim_start_matches('/')
                        .to_string()
                });
            return Some(ScannedKey {
                fingerprint: fp,
                derivation_path: deriv,
                xpub: xpub.trim().to_string(),
            });
        }
    }

    // 3. A bare extended key, with nothing else in the payload.
    let bare = s.split_whitespace().next().unwrap_or(s);
    if bare.len() > 100
        && bare.chars().all(|c| c.is_ascii_alphanumeric())
        && ["xpub", "tpub", "ypub", "zpub", "Vpub", "Zpub", "upub", "vpub"]
            .iter()
            .any(|p| bare.starts_with(p))
    {
        return Some(ScannedKey {
            fingerprint: None,
            derivation_path: None,
            xpub: bare.to_string(),
        });
    }

    None
}

/// Shuts the setup server down so the container restarts into `cosigner serve`.
async fn start_handler(State(state): State<Arc<SetupState>>) -> Result<StatusCode, SetupError> {
    if !state.wallet_toml_path().exists() {
        return Err(SetupError::bad_request(
            "setup hasn't been completed yet - there's no config to start with",
        ));
    }
    if let Some(tx) = state.shutdown.lock().await.take() {
        let _ = tx.send(());
    }
    Ok(StatusCode::ACCEPTED)
}

/// BIP48 script-type-2 (P2WSH multisig) account path, with the network's registered SLIP44
/// coin type: 0' on mainnet, 1' on every test chain.
fn default_derivation_path(network: ChainNetwork) -> String {
    let coin_type = match network {
        ChainNetwork::Mainnet => "0h",
        ChainNetwork::Testnet | ChainNetwork::Signet | ChainNetwork::Regtest => "1h",
    };
    format!("48h/{coin_type}/0h/2h")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(network: ChainNetwork) -> Deployment {
        Deployment {
            network,
            config_dir: PathBuf::from("/data/config"),
            data_dir: PathBuf::from("/data"),
            bind_addr: "0.0.0.0:8080".to_string(),
            bitcoind_rpc_url: "http://10.21.21.8:8332".to_string(),
        }
    }

    #[test]
    fn default_path_uses_the_registered_coin_type_per_network() {
        assert_eq!(default_derivation_path(ChainNetwork::Mainnet), "48h/0h/0h/2h");
        assert_eq!(default_derivation_path(ChainNetwork::Signet), "48h/1h/0h/2h");
        assert_eq!(default_derivation_path(ChainNetwork::Regtest), "48h/1h/0h/2h");
        assert_eq!(default_derivation_path(ChainNetwork::Testnet), "48h/1h/0h/2h");
    }

    #[test]
    fn generated_server_key_matches_its_own_xpub_and_path() {
        let network = ChainNetwork::Signet;
        let path = default_derivation_path(network);
        let g = generate_server_key(network, &path).expect("generation should succeed");

        // The xprv written to disk must be the account key the config's xpub names - this is
        // exactly the equality `ServerSigningKey::load` refuses to start without.
        let secp = Secp256k1::new();
        let account: Xpriv = g.account_xprv.parse().expect("account xprv should parse");
        let derived = Xpub::from_priv(&secp, &account).to_string();
        assert_eq!(derived, g.xpub);

        // And the xpub must sit at the declared depth, or `KeySpec::validate` rejects it.
        let xpub: Xpub = g.xpub.parse().expect("xpub should parse");
        let depth = path.parse::<DerivationPath>().expect("path parses").len();
        assert_eq!(xpub.depth as usize, depth);
    }

    /// The key handed out on the setup screen and the key inside the finished descriptor must
    /// be byte-identical, notation included. They were not: `key_expression` passed the
    /// configured path through verbatim (`48h/1h/0h/2h`) while `descriptor.rs` emits the
    /// canonical apostrophe form, so this service advertised the same key two different ways.
    #[test]
    fn key_expression_notation_matches_the_descriptor() {
        let expr = key_expression("AB12CD34", "48h/1h/0h/2h", "tpubEXAMPLE");
        assert_eq!(expr, "[ab12cd34/48'/1'/0'/2']tpubEXAMPLE");
        assert!(!expr.contains('h'), "hardened marker must be an apostrophe: {expr}");

        // Already-canonical input is left alone, and `m/` prefixes are stripped.
        assert_eq!(
            key_expression("ab12cd34", "48'/1'/0'/2'", "tpubEXAMPLE"),
            "[ab12cd34/48'/1'/0'/2']tpubEXAMPLE"
        );
        assert_eq!(
            key_expression("ab12cd34", "m/48h/1h/0h/2h", "tpubEXAMPLE"),
            "[ab12cd34/48'/1'/0'/2']tpubEXAMPLE"
        );
    }

    /// End to end: the origin the wizard shows for the SERVER key has to be exactly the origin
    /// that ends up in the descriptor a coordinator imports, or the coordinator builds PSBTs
    /// this service won't recognise as its own.
    #[test]
    fn advertised_server_key_appears_verbatim_in_the_built_descriptor() {
        let network = ChainNetwork::Signet;
        let path = default_derivation_path(network);
        let g = generate_server_key(network, &path).expect("generation");
        let advertised = key_expression(&g.master_fingerprint, &g.derivation_path, &g.xpub);

        let (satochip, _) = crate::test_util::test_key_spec_with_xpriv(1);
        let (mobile, _) = crate::test_util::test_key_spec_with_xpriv(2);
        let mut cfg = crate::test_util::test_wallet_config(144);
        cfg.network = network;
        cfg.keys.satochip = satochip;
        cfg.keys.mobile = mobile;
        cfg.keys.server = crate::config::KeySpec {
            master_fingerprint: g.master_fingerprint.clone(),
            derivation_path: g.derivation_path.clone(),
            xpub: g.xpub.clone(),
        };

        let built = descriptor::build_descriptor(&cfg).expect("descriptor should build");
        let desc = built.multipath.to_string();
        let origin = advertised.split(']').next().expect("has an origin");
        assert!(
            desc.contains(origin),
            "descriptor does not contain the advertised origin\n  advertised: {origin}]\n  descriptor: {desc}"
        );
    }

    #[test]
    fn two_generated_keys_are_never_the_same() {
        let path = default_derivation_path(ChainNetwork::Signet);
        let a = generate_server_key(ChainNetwork::Signet, &path).expect("first");
        let b = generate_server_key(ChainNetwork::Signet, &path).expect("second");
        assert_ne!(a.xpub, b.xpub);
        assert_ne!(a.master_fingerprint, b.master_fingerprint);
    }

    #[test]
    fn generated_key_is_on_the_requested_network() {
        for network in [
            ChainNetwork::Mainnet,
            ChainNetwork::Signet,
            ChainNetwork::Regtest,
        ] {
            let path = default_derivation_path(network);
            let g = generate_server_key(network, &path).expect("generation should succeed");
            let xpub: Xpub = g.xpub.parse().expect("xpub parses");
            assert_eq!(xpub.network, network.xpub_network_kind());
        }
    }

    /// The web wizard must not emit `[bitcoind]`/`[server]`: docker-entrypoint.sh appends its
    /// own copies of both on every start, and TOML rejects a duplicated table, so emitting
    /// them here would make the container fail to start immediately after setup.
    #[test]
    fn rendered_config_omits_the_sections_the_entrypoint_generates() {
        let network = ChainNetwork::Signet;
        let (satochip, _) = crate::test_util::test_key_spec_with_xpriv(1);
        let (mobile, _) = crate::test_util::test_key_spec_with_xpriv(2);
        let path = default_derivation_path(network);
        let generated = generate_server_key(network, &path).expect("generation");

        let req = FinishRequest {
            timelock_blocks: 12960,
            satochip: ValidateKeyRequest {
                fingerprint: satochip.master_fingerprint.clone(),
                derivation_path: satochip.derivation_path.clone(),
                xpub: satochip.xpub.clone(),
            },
            mobile: ValidateKeyRequest {
                fingerprint: mobile.master_fingerprint.clone(),
                derivation_path: mobile.derivation_path.clone(),
                xpub: mobile.xpub.clone(),
            },
            policy: PolicyRequest {
                max_tx_sat: 100_000,
                max_daily_sat: 200_000,
                max_weekly_sat: 500_000,
                max_monthly_sat: 1_000_000,
                max_fee_sat: 10_000,
                max_fee_rate_sat_per_vb: 50.0,
            },
            hold_seconds: 3600,
            recovery_hold_seconds: 86400,
            ntfy_url: Some("https://ntfy.sh/bitme-test-topic".to_string()),
            smtp: None,
        };

        let answers = build_answers(
            &deployment(network),
            &req,
            KeyAnswer {
                fingerprint: satochip.master_fingerprint.clone(),
                derivation_path: satochip.derivation_path.clone(),
                xpub: satochip.xpub.clone(),
            },
            KeyAnswer {
                fingerprint: mobile.master_fingerprint.clone(),
                derivation_path: mobile.derivation_path.clone(),
                xpub: mobile.xpub.clone(),
            },
            &generated,
        );
        let text = wizard::render_user_toml(&answers);
        assert!(!text.contains("[bitcoind]"), "rendered:\n{text}");
        assert!(!text.contains("[server]"), "rendered:\n{text}");
        assert!(text.contains("[server_signing]"), "rendered:\n{text}");

        // ...and what it does emit has to be a config the service would accept.
        let cfg: WalletConfig = toml::from_str(&text).expect("should parse");
        cfg.validate().expect("should validate");
        descriptor::build_descriptor(&cfg).expect("should build a descriptor");
    }
}
