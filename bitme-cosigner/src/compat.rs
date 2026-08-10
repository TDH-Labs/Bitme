//! Device and coordinator compatibility: which combinations of hardware signer, coordinator app
//! and mobile-key holder can actually use this wallet.
//!
//! See `docs/COMPATIBILITY.md` for the reasoning. The short version: this wallet's descriptor is
//! miniscript with a relative timelock, which is a standard P2WSH output but is *not*
//! `sortedmulti()`. Two independent things must be true before a given pairing works - some app
//! has to import and track a `thresh`/`older` descriptor, and something has to drive the hardware
//! device to sign for it - and the intersection of software that does both is small. A user can
//! pick two well-supported products and end up with a wallet they cannot spend from.
//!
//! # Why roles, not pairs
//!
//! The obvious model is a matrix of `(hardware x coordinator)`. It is the wrong one: O(n*m),
//! never complete, and it produces false negatives by rejecting setups where two apps split the
//! work between them. This models the three *roles* in a spend and lets [`resolve`] compose
//! them, so a combination nobody has explicitly tested still gets a correct answer.
//!
//! # Why data, not code
//!
//! The matrix is deserialized from TOML shipped alongside the binary and overridable by the
//! operator. Firmware and app releases move faster than this project does, and a hardcoded
//! matrix that blocks a combination which *started* working is worse than having no matrix at
//! all. For the same reason [`Verdict::Blocked`] is overridable by the operator rather than
//! fatal - see [`Resolution::acknowledgement`].

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The bundled matrix, compiled in so the wizard always has something to work with even if no
/// operator-supplied file exists.
const BUNDLED: &str = include_str!("compatibility.toml");

/// How far a claim in the matrix can be trusted. Not decoration: `Unverified` renders as a
/// warning in the wizard regardless of what the flags say, because an optimistic guess about
/// somebody's coins is worse than an admission of ignorance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    /// Someone ran the full flow on signet with this exact combination. The only value that
    /// should be treated as authoritative.
    SignetTested,
    /// Claimed by vendor documentation.
    VendorDocs,
    /// Claimed in a release announcement.
    ReleaseNotes,
    /// Inferred from an issue tracker.
    IssueTracker,
    /// Assumed. Always surfaces as a caveat.
    Unverified,
}

impl Provenance {
    pub fn is_authoritative(self) -> bool {
        matches!(self, Provenance::SignetTested)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Provenance::SignetTested => "verified end to end on signet",
            Provenance::VendorDocs => "from vendor documentation, not tested here",
            Provenance::ReleaseNotes => "from a release announcement, not tested here",
            Provenance::IssueTracker => "inferred from an issue tracker, not tested here",
            Provenance::Unverified => "UNVERIFIED - nobody has confirmed this",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HardwareEntry {
    pub id: String,
    pub label: String,
    /// Will produce a signature for a witness script that is not `multi`/`sortedmulti`. For
    /// devices that sign whatever hash they are handed this is `true` - the constraint lives in
    /// the coordinator, not here.
    pub signs_miniscript: bool,
    /// Accepts a branch guarded by a relative timelock. Some devices support miniscript but
    /// restrict which fragments they will handle.
    pub signs_older: bool,
    /// Bitcoin signed-message support, as consumed by `policy_auth::HardwareAuthKeys::verify`.
    /// A device can be perfectly fine for spending and still fail this, which leaves the
    /// operator unable to run `POST /policy` or `POST /unfreeze` without shell access.
    pub signs_message: bool,
    pub verified: Provenance,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoordinatorEntry {
    pub id: String,
    pub label: String,
    /// Will import and track a `thresh`/`older` descriptor as a watch-only wallet. **This is the
    /// field that eliminates most software.**
    pub registers_miniscript: bool,
    /// Hardware ids this app can drive. Not transitive: being able to import a descriptor says
    /// nothing about which devices an app can talk to, and vice versa.
    #[serde(default)]
    pub drives: Vec<String>,
    /// Can itself hold the MOBILE key.
    #[serde(default)]
    pub holds_mobile_key: bool,
    pub verified: Provenance,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Matrix {
    pub schema_version: u32,
    /// Surfaced in the wizard so an operator can judge how stale their data is.
    pub revision: String,
    #[serde(default, rename = "hardware")]
    pub hardware: Vec<HardwareEntry>,
    #[serde(default, rename = "coordinator")]
    pub coordinators: Vec<CoordinatorEntry>,
}

impl Matrix {
    /// The matrix compiled into this binary.
    pub fn bundled() -> Result<Self> {
        toml::from_str(BUNDLED).context("parsing the bundled compatibility matrix")
    }

    /// Loads an operator-supplied matrix, falling back to the bundled one if the path doesn't
    /// exist. A *malformed* file is an error rather than a silent fallback: someone who wrote
    /// one meant it, and quietly ignoring it would hide exactly the customisation they were
    /// trying to make.
    pub fn load_or_bundled(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            return Self::bundled();
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading compatibility matrix {}", path.display()))?;
        let matrix: Self = toml::from_str(&text)
            .with_context(|| format!("parsing compatibility matrix {}", path.display()))?;
        matrix.validate()?;
        Ok(matrix)
    }

    fn validate(&self) -> Result<()> {
        let ids: std::collections::HashSet<&str> =
            self.hardware.iter().map(|h| h.id.as_str()).collect();
        if ids.len() != self.hardware.len() {
            anyhow::bail!("compatibility matrix has duplicate hardware ids");
        }
        // A `drives` entry naming a device that isn't in the matrix is a typo, and a silent one:
        // it would make that pairing resolve as "cannot drive" for a reason nobody could see.
        for c in &self.coordinators {
            for driven in &c.drives {
                if !ids.contains(driven.as_str()) {
                    anyhow::bail!(
                        "coordinator {:?} claims to drive unknown hardware id {driven:?}",
                        c.id
                    );
                }
            }
        }
        Ok(())
    }

    pub fn hardware(&self, id: &str) -> Option<&HardwareEntry> {
        self.hardware.iter().find(|h| h.id == id)
    }

    pub fn coordinator(&self, id: &str) -> Option<&CoordinatorEntry> {
        self.coordinators.iter().find(|c| c.id == id)
    }
}

/// The spending paths this wallet has. Each needs a different combination of roles, which is what
/// makes the whole model tractable - see the table in `docs/COMPATIBILITY.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Path {
    /// HARDWARE + SERVER, immediately. The only path used day to day.
    DailySpend,
    /// A hardware-key signed message. `POST /policy`, and `POST /unfreeze`.
    PolicyChange,
    /// HARDWARE + MOBILE, after the timelock. Used when this service is gone.
    RecoveryServerGone,
    /// MOBILE + SERVER, after the timelock. Used when the hardware key is gone.
    RecoveryHardwareGone,
}

impl Path {
    pub const ALL: [Path; 4] = [
        Path::DailySpend,
        Path::PolicyChange,
        Path::RecoveryServerGone,
        Path::RecoveryHardwareGone,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Path::DailySpend => "Everyday spending",
            Path::PolicyChange => "Changing spending limits, and unfreezing",
            Path::RecoveryServerGone => "Recovery if this server is lost",
            Path::RecoveryHardwareGone => "Recovery if the hardware key is lost",
        }
    }

    fn needs_miniscript_registration(self) -> bool {
        !matches!(self, Path::PolicyChange)
    }

    fn needs_hardware_driving(self) -> bool {
        matches!(
            self,
            Path::DailySpend | Path::PolicyChange | Path::RecoveryServerGone
        )
    }

    fn needs_hardware_signing(self) -> bool {
        matches!(self, Path::DailySpend | Path::RecoveryServerGone)
    }

    fn needs_message_signing(self) -> bool {
        matches!(self, Path::PolicyChange)
    }

    /// Whether a CLI on the box can substitute for the missing capability. Only true for policy
    /// changes, where `cosigner policy` / `cosigner unfreeze` already exist as a fallback.
    fn has_cli_fallback(self) -> bool {
        matches!(self, Path::PolicyChange)
    }
}

/// Why a path can't be served by the chosen combination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Gap {
    /// The chosen coordinator can't import this wallet's descriptor.
    CannotRegisterDescriptor { alternatives: Vec<String> },
    /// The chosen coordinator can't talk to the chosen hardware device.
    CannotDriveHardware { alternatives: Vec<String> },
    /// The device itself can't sign for this script shape.
    HardwareCannotSign,
    /// The device can't produce a Bitcoin signed message.
    HardwareCannotSignMessages,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// One app covers this path end to end.
    Ok,
    /// Works, but needs a second app (or the CLI). A concrete alternative exists.
    NeedsAnotherApp,
    /// No known combination of listed software covers this path.
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathResult {
    pub path: Path,
    pub label: &'static str,
    pub verdict: Verdict,
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolution {
    pub hardware: String,
    pub coordinator: String,
    pub paths: Vec<PathResult>,
    /// The worst verdict across every path - what the wizard gates on.
    pub overall: Verdict,
    /// True if any entry involved is less than authoritative, so the UI can say so even when
    /// every flag says yes.
    pub any_unverified: bool,
    pub caveats: Vec<String>,
}

impl Resolution {
    pub fn is_blocked(&self) -> bool {
        self.overall == Verdict::Blocked
    }

    /// The text the operator must acknowledge before proceeding, or `None` if nothing needs
    /// acknowledging.
    ///
    /// Generated from which check failed rather than written per device pair. That is what makes
    /// this scale to devices nobody has thought of yet, and it is also what keeps the wording
    /// honest: there is no opportunity to soften a specific case.
    pub fn acknowledgement(&self) -> Option<String> {
        if self.overall == Verdict::Ok && !self.any_unverified {
            return None;
        }
        let mut out = String::new();

        for p in self.paths.iter().filter(|p| p.verdict != Verdict::Ok) {
            out.push_str(&format!("{}: ", p.label));
            let mut clauses = Vec::new();
            for gap in &p.gaps {
                clauses.push(match gap {
                    Gap::CannotRegisterDescriptor { alternatives } if alternatives.is_empty() => {
                        "no listed app can track this wallet's descriptor".to_string()
                    }
                    Gap::CannotRegisterDescriptor { alternatives } => format!(
                        "your coordinator cannot track this wallet's descriptor - you would need {}",
                        alternatives.join(" or ")
                    ),
                    Gap::CannotDriveHardware { alternatives } if alternatives.is_empty() => {
                        "no listed app can both track this descriptor and sign with this device"
                            .to_string()
                    }
                    Gap::CannotDriveHardware { alternatives } => format!(
                        "your coordinator cannot sign with this device - EVERY transaction on \
                         this path would need {}",
                        alternatives.join(" or ")
                    ),
                    Gap::HardwareCannotSign => {
                        "this device cannot sign for this wallet's script".to_string()
                    }
                    Gap::HardwareCannotSignMessages => {
                        "this device cannot sign messages, so you would need shell access to the \
                         box and the `cosigner` CLI"
                            .to_string()
                    }
                });
            }
            out.push_str(&clauses.join("; "));
            out.push('\n');
        }

        for caveat in &self.caveats {
            out.push_str(caveat);
            out.push('\n');
        }

        if self.overall == Verdict::Blocked {
            out.push_str(
                "\nIf you fund this wallet you may be unable to spend from it until software \
                 support changes.",
            );
        }
        Some(out)
    }
}

/// Resolves one `(hardware, coordinator)` choice into a verdict per spending path.
///
/// `mobile_holder` is the coordinator id holding the MOBILE key; it may be the same app. Unknown
/// ids are an error rather than a permissive default - a typo must not silently resolve to "all
/// clear".
pub fn resolve(
    matrix: &Matrix,
    hardware_id: &str,
    coordinator_id: &str,
    mobile_holder_id: &str,
) -> Result<Resolution> {
    let hw = matrix
        .hardware(hardware_id)
        .with_context(|| format!("unknown hardware id {hardware_id:?}"))?;
    let coord = matrix
        .coordinator(coordinator_id)
        .with_context(|| format!("unknown coordinator id {coordinator_id:?}"))?;
    let mobile = matrix
        .coordinator(mobile_holder_id)
        .with_context(|| format!("unknown mobile-key holder id {mobile_holder_id:?}"))?;

    // Apps that could stand in for a missing capability. Computed once rather than per path.
    let can_register: Vec<String> = matrix
        .coordinators
        .iter()
        .filter(|c| c.registers_miniscript && c.id != coord.id)
        .map(|c| c.label.clone())
        .collect();
    let can_register_and_drive: Vec<String> = matrix
        .coordinators
        .iter()
        .filter(|c| {
            c.registers_miniscript && c.drives.iter().any(|d| d == hardware_id) && c.id != coord.id
        })
        .map(|c| c.label.clone())
        .collect();

    let drives_hardware = coord.drives.iter().any(|d| d == hardware_id);

    let mut paths = Vec::with_capacity(Path::ALL.len());
    for path in Path::ALL {
        let mut gaps = Vec::new();

        if path.needs_miniscript_registration() {
            // The mobile-only recovery path is tracked by whichever app holds the mobile key,
            // which need not be the day-to-day coordinator.
            let registrar = if path == Path::RecoveryHardwareGone {
                mobile
            } else {
                coord
            };
            if !registrar.registers_miniscript {
                gaps.push(Gap::CannotRegisterDescriptor {
                    alternatives: can_register.clone(),
                });
            }
        }

        if path.needs_hardware_driving() && !drives_hardware {
            gaps.push(Gap::CannotDriveHardware {
                alternatives: can_register_and_drive.clone(),
            });
        }

        if path.needs_hardware_signing() && !(hw.signs_miniscript && hw.signs_older) {
            gaps.push(Gap::HardwareCannotSign);
        }

        if path.needs_message_signing() && !hw.signs_message {
            gaps.push(Gap::HardwareCannotSignMessages);
        }

        let verdict = if gaps.is_empty() {
            Verdict::Ok
        } else if path.has_cli_fallback()
            || gaps.iter().all(|g| match g {
                Gap::CannotRegisterDescriptor { alternatives }
                | Gap::CannotDriveHardware { alternatives } => !alternatives.is_empty(),
                // Nothing substitutes for a device that cannot produce the signature.
                Gap::HardwareCannotSign => false,
                Gap::HardwareCannotSignMessages => true,
            })
        {
            Verdict::NeedsAnotherApp
        } else {
            Verdict::Blocked
        };

        paths.push(PathResult {
            path,
            label: path.label(),
            verdict,
            gaps,
        });
    }

    let overall = paths.iter().map(|p| p.verdict).max().unwrap_or(Verdict::Ok);

    let mut caveats = Vec::new();
    for (what, prov) in [
        (hw.label.as_str(), hw.verified),
        (coord.label.as_str(), coord.verified),
    ] {
        if !prov.is_authoritative() {
            caveats.push(format!("{what}: {}", prov.describe()));
        }
    }
    let any_unverified = !caveats.is_empty();

    Ok(Resolution {
        hardware: hw.label.clone(),
        coordinator: coord.label.clone(),
        paths,
        overall,
        any_unverified,
        caveats,
    })
}

/// Every hardware option, pre-resolved against one coordinator, so the wizard can render the full
/// list with each entry's verdict inline rather than hiding the incompatible ones.
///
/// Showing a greyed-out option with no explanation generates support questions; showing it with
/// the reason attached teaches the constraint. Nothing is ever filtered out of this list.
pub fn options_for_coordinator(
    matrix: &Matrix,
    coordinator_id: &str,
    mobile_holder_id: &str,
) -> Result<Vec<(HardwareEntry, Resolution)>> {
    let mut out = Vec::with_capacity(matrix.hardware.len());
    for hw in &matrix.hardware {
        let resolution = resolve(matrix, &hw.id, coordinator_id, mobile_holder_id)?;
        out.push((hw.clone(), resolution));
    }
    // Best first, then alphabetically, so the workable choices are what the eye lands on.
    out.sort_by(|a, b| {
        a.1.overall
            .cmp(&b.1.overall)
            .then_with(|| a.0.label.cmp(&b.0.label))
    });
    Ok(out)
}

/// A compact `path -> verdict` map, for callers that want the summary without the reasons.
pub fn verdict_map(resolution: &Resolution) -> HashMap<Path, Verdict> {
    resolution
        .paths
        .iter()
        .map(|p| (p.path, p.verdict))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix() -> Matrix {
        Matrix::bundled().expect("the bundled matrix must always parse")
    }

    #[test]
    fn the_bundled_matrix_parses_and_is_internally_consistent() {
        let m = matrix();
        assert_eq!(m.schema_version, 1);
        assert!(!m.hardware.is_empty());
        assert!(!m.coordinators.is_empty());
        m.validate().expect("bundled matrix must validate");
    }

    /// The combination this project was built around, and the reason any of this exists.
    /// Bitcoin Keeper registers miniscript but will not drive a Satochip; Sparrow drives a
    /// Satochip but does not implement miniscript. Neither does both.
    #[test]
    fn satochip_plus_keeper_is_blocked_for_spending_but_not_for_mobile_recovery() {
        let m = matrix();
        let r = resolve(&m, "satochip", "bitcoin-keeper", "bitcoin-keeper").unwrap();

        let by_path = verdict_map(&r);
        assert_eq!(
            by_path[&Path::DailySpend],
            Verdict::Blocked,
            "no listed app both registers miniscript and drives a Satochip"
        );
        assert_eq!(by_path[&Path::RecoveryServerGone], Verdict::Blocked);
        assert_eq!(
            by_path[&Path::RecoveryHardwareGone],
            Verdict::Ok,
            "MOBILE + SERVER needs neither the hardware nor an app that can drive it"
        );
        assert!(r.is_blocked());

        let ack = r
            .acknowledgement()
            .expect("a blocked combination must warn");
        assert!(
            ack.contains("may be unable to spend"),
            "the warning must state the real consequence: {ack}"
        );
    }

    /// The wording rule from docs/COMPATIBILITY.md: when a coordinator cannot drive the device,
    /// the consequence is *every* transaction, not just ones over a limit. Getting this wrong
    /// would have someone tick a box thinking they had accepted an edge case.
    #[test]
    fn a_coordinator_that_cannot_drive_says_every_transaction() {
        let m = matrix();
        // Keeper registers miniscript but cannot drive a SeedSigner.
        let r = resolve(&m, "seedsigner", "bitcoin-keeper", "bitcoin-keeper").unwrap();
        let ack = r.acknowledgement().expect("must warn");
        assert!(
            ack.contains("EVERY transaction") || ack.contains("cannot sign for this wallet"),
            "must not understate the consequence: {ack}"
        );
        assert!(!ack.contains("daily limit"), "must not imply a cap: {ack}");
    }

    #[test]
    fn a_fully_supported_pairing_resolves_clean() {
        let m = matrix();
        let r = resolve(&m, "coldcard", "bitcoin-keeper", "bitcoin-keeper").unwrap();
        assert_eq!(r.overall, Verdict::Ok, "{r:#?}");
        assert!(!r.is_blocked());
        for p in &r.paths {
            assert_eq!(p.verdict, Verdict::Ok, "{} should be clear", p.label);
        }
    }

    /// Message signing is a separate axis: a device can be perfectly fine for spending and still
    /// leave the operator unable to change limits without shell access. That must surface as its
    /// own warning, and must not block spending.
    #[test]
    fn a_device_that_cannot_sign_messages_only_affects_policy_changes() {
        let mut m = matrix();
        let hw = m
            .hardware
            .iter_mut()
            .find(|h| h.id == "coldcard")
            .expect("coldcard is in the bundled matrix");
        hw.signs_message = false;

        let r = resolve(&m, "coldcard", "bitcoin-keeper", "bitcoin-keeper").unwrap();
        let by_path = verdict_map(&r);
        assert_eq!(by_path[&Path::DailySpend], Verdict::Ok);
        assert_eq!(by_path[&Path::PolicyChange], Verdict::NeedsAnotherApp);
        assert!(!r.is_blocked(), "this must not block funding the wallet");

        let ack = r.acknowledgement().unwrap();
        assert!(ack.contains("cosigner` CLI"), "{ack}");
    }

    /// Every device is offered, including unusable ones, each carrying its own reason. Filtering
    /// them out silently is what produces "why isn't my device listed" support questions.
    #[test]
    fn options_lists_every_device_best_first() {
        let m = matrix();
        let options = options_for_coordinator(&m, "bitcoin-keeper", "bitcoin-keeper").unwrap();
        assert_eq!(options.len(), m.hardware.len(), "nothing may be hidden");

        let verdicts: Vec<Verdict> = options.iter().map(|(_, r)| r.overall).collect();
        let mut sorted = verdicts.clone();
        sorted.sort();
        assert_eq!(verdicts, sorted, "workable options must come first");
    }

    #[test]
    fn unknown_ids_are_errors_not_permissive_defaults() {
        let m = matrix();
        assert!(resolve(&m, "no-such-device", "bitcoin-keeper", "bitcoin-keeper").is_err());
        assert!(resolve(&m, "coldcard", "no-such-app", "bitcoin-keeper").is_err());
        assert!(resolve(&m, "coldcard", "bitcoin-keeper", "no-such-app").is_err());
    }

    /// An unverified entry must produce a caveat even when every capability flag says yes -
    /// "we think this works" and "we checked" are different claims.
    #[test]
    fn unverified_entries_caveat_even_when_everything_resolves_ok() {
        let mut m = matrix();
        m.hardware
            .iter_mut()
            .find(|h| h.id == "coldcard")
            .unwrap()
            .verified = Provenance::Unverified;

        let r = resolve(&m, "coldcard", "bitcoin-keeper", "bitcoin-keeper").unwrap();
        assert_eq!(r.overall, Verdict::Ok);
        assert!(r.any_unverified);
        assert!(
            r.acknowledgement().is_some(),
            "an unverified claim must still be acknowledged"
        );
    }

    #[test]
    fn a_drives_entry_naming_an_unknown_device_is_rejected() {
        let mut m = matrix();
        m.coordinators[0].drives.push("ghost-device".to_string());
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("ghost-device"), "{err}");
    }
}
