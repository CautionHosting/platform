// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! One-time notice about potentially unsafe build and run environments.
//!
//! `caution verify` reproduces enclave measurements locally, so both the machine
//! that built this binary and the machine running it are trusted. Findings are
//! explained once per CLI build and findings set, then stay silent until either
//! changes.

use crate::{output, prompt};
use caution_environment_heuristics::{self as heuristics, Heuristic};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

pub(crate) const BUILD_ID: &str = env!("CAUTION_CLI_BUILD_ID");
const DOCS_URL: &str =
    "https://docs.caution.co/concepts/security-assumptions/#verifier-environment";
const ACK_FILE: &str = "environment-ack.json";
const ACCEPT_ENV_VAR: &str = "CAUTION_ACCEPT_ENV_RISK";

struct Findings {
    build: Vec<Heuristic>,
    run: Vec<Heuristic>,
}

impl Findings {
    fn current() -> Self {
        let build: Vec<Heuristic> =
            serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/heuristics.json")))
                .expect("should have valid constant build heuristics");
        Self::new(build, heuristics::heuristics())
    }

    fn new(mut build: Vec<Heuristic>, mut run: Vec<Heuristic>) -> Self {
        heuristics::collapse_heuristics(&mut build);
        heuristics::collapse_heuristics(&mut run);
        Self { build, run }
    }

    fn is_empty(&self) -> bool {
        self.build.is_empty() && self.run.is_empty()
    }

    fn fingerprint(&self) -> String {
        let serialized = serde_json::to_vec(&(&self.build, &self.run))
            .expect("heuristics should always serialize");
        hex::encode(Sha256::digest(serialized))
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Ack {
    build_id: String,
    fingerprint: String,
    acknowledged_at: String,
}

impl Ack {
    fn matches(&self, build_id: &str, fingerprint: &str) -> bool {
        self.build_id == build_id && self.fingerprint == fingerprint
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum AckFileErrorKind {
    Read,
    Parse,
    Serialize,
    Write,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("environment acknowledgement file '{path}' ({kind:?}) [{location}]")]
pub(crate) struct AckFileError {
    kind: AckFileErrorKind,
    #[context(borrow = Path)]
    path: PathBuf,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn load_ack(path: &Path) -> Result<Option<Ack>, AckFileError> {
    use AckFileErrorCtx as Ctx;

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(Ctx::new(AckFileErrorKind::Read, path)),
    };
    serde_json::from_str(&contents)
        .map(Some)
        .with_context(Ctx::new(AckFileErrorKind::Parse, path))
}

fn save_ack(path: &Path, ack: &Ack) -> Result<(), AckFileError> {
    use AckFileErrorCtx as Ctx;

    let contents =
        serde_json::to_vec_pretty(ack).with_context(Ctx::new(AckFileErrorKind::Serialize, path))?;
    std::fs::write(path, contents).with_context(Ctx::new(AckFileErrorKind::Write, path))
}

fn ack_path(verbose: bool) -> Option<PathBuf> {
    match crate::config_dir() {
        Ok(dir) => Some(dir.join(ACK_FILE)),
        Err(e) => {
            output::verbose(verbose, format!("Environment notice: {e}"));
            None
        }
    }
}

fn current_ack(path: Option<&Path>, verbose: bool) -> Option<Ack> {
    load_ack(path?).unwrap_or_else(|e| {
        output::verbose(verbose, format!("Environment notice: {e}"));
        None
    })
}

fn record_ack(path: Option<&Path>, fingerprint: &str, verbose: bool) {
    let Some(path) = path else { return };
    let ack = Ack {
        build_id: BUILD_ID.to_string(),
        fingerprint: fingerprint.to_string(),
        acknowledged_at: chrono::Utc::now().to_rfc3339(),
    };
    if let Err(e) = save_ack(path, &ack) {
        output::verbose(verbose, format!("Environment notice: {e}"));
    }
}

fn print_notice(findings: &Findings) {
    output::warning("Potentially unsafe environment");
    output::warning(
        "  `caution verify` reproduces enclave measurements on this machine. If this machine,",
    );
    output::warning(
        "  or the machine that built this CLI, is compromised, verification results can be forged.",
    );
    output::warning("");
    for heuristic in &findings.build {
        output::warning(format!("  [BUILD] {heuristic}"));
    }
    for heuristic in &findings.run {
        output::warning(format!("    [RUN] {heuristic}"));
    }
    output::warning("");
    output::warning(
        "  Recommended: for verification you rely on, use a StageX-built CLI on a dedicated,",
    );
    output::warning("  minimal machine with no package managers and no LD_PRELOAD.");
    output::warning(format!("  Details: {DOCS_URL}"));
}

/// Explain environment findings once per CLI build and findings set.
///
/// Interactive sessions acknowledge with Enter. Non-interactive sessions see the
/// notice without blocking, and `CAUTION_ACCEPT_ENV_RISK=1` acknowledges it
/// silently. Acknowledgement storage failures never fail the command.
pub(crate) fn gate(verbose: bool) {
    let findings = Findings::current();
    if findings.is_empty() {
        return;
    }

    let fingerprint = findings.fingerprint();
    let path = ack_path(verbose);
    if current_ack(path.as_deref(), verbose).is_some_and(|ack| ack.matches(BUILD_ID, &fingerprint))
    {
        return;
    }

    if std::env::var(ACCEPT_ENV_VAR).is_ok_and(|value| value == "1") {
        record_ack(path.as_deref(), &fingerprint, verbose);
        return;
    }

    print_notice(&findings);
    output::warning("  Shown once per CLI build; review it again with `caution environment`.");

    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        output::warning("");
        return;
    }

    match prompt::acknowledge("\nPress Enter to acknowledge and continue... ") {
        Ok(()) => record_ack(path.as_deref(), &fingerprint, verbose),
        Err(e) => output::verbose(verbose, format!("Environment notice not acknowledged: {e}")),
    }
}

/// Print the full environment report for `caution environment`.
pub(crate) fn print_report(verbose: bool) {
    let findings = Findings::current();
    output::status(format!("CLI build: {BUILD_ID}"));
    if findings.is_empty() {
        output::success("No environment findings.");
        return;
    }

    output::status("");
    print_notice(&findings);
    output::status("");

    let fingerprint = findings.fingerprint();
    match current_ack(ack_path(verbose).as_deref(), verbose) {
        Some(ack) if ack.matches(BUILD_ID, &fingerprint) => {
            output::status(format!("Acknowledged at {}", ack.acknowledged_at))
        }
        _ => output::status("Not yet acknowledged for this build and findings."),
    }
}

/// One-line reminder printed after a successful `caution verify`.
pub(crate) fn verify_reminder() {
    if Findings::current().is_empty() {
        return;
    }
    output::warning(format!(
        "Note: verified from a potentially unsafe environment. Run `caution environment` or see {DOCS_URL}"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str) -> Heuristic {
        Heuristic::PackageManager(name.to_string())
    }

    #[test]
    fn fingerprint_ignores_finding_order() {
        let os = Heuristic::UnknownOs(Some("macos".to_string()));
        let a = Findings::new(vec![pkg("npm"), pkg("brew")], vec![os.clone(), pkg("brew")]);
        let b = Findings::new(vec![pkg("brew"), pkg("npm")], vec![pkg("brew"), os]);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_findings() {
        let base = Findings::new(vec![pkg("brew")], vec![pkg("brew")]);
        let preload = Findings::new(
            vec![pkg("brew")],
            vec![pkg("brew"), Heuristic::LD_PRELOAD("/tmp/x.so".into())],
        );
        let moved = Findings::new(vec![], vec![pkg("brew"), pkg("brew")]);
        assert_ne!(base.fingerprint(), preload.fingerprint());
        assert_ne!(base.fingerprint(), moved.fingerprint());
    }

    #[test]
    fn ack_matches_only_same_build_and_fingerprint() {
        let ack = Ack {
            build_id: "0.1.0+aaaaaaaaaaaa".to_string(),
            fingerprint: "f1".to_string(),
            acknowledged_at: "2026-10-06T00:00:00Z".to_string(),
        };
        assert!(ack.matches("0.1.0+aaaaaaaaaaaa", "f1"));
        assert!(!ack.matches("0.1.0+bbbbbbbbbbbb", "f1"));
        assert!(!ack.matches("0.1.0+aaaaaaaaaaaa", "f2"));
    }

    #[test]
    fn ack_roundtrips_and_missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ACK_FILE);
        assert_eq!(load_ack(&path).unwrap(), None);

        let ack = Ack {
            build_id: BUILD_ID.to_string(),
            fingerprint: "f1".to_string(),
            acknowledged_at: "2026-10-06T00:00:00Z".to_string(),
        };
        save_ack(&path, &ack).unwrap();
        assert_eq!(load_ack(&path).unwrap(), Some(ack));
    }

    #[test]
    fn corrupt_ack_file_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ACK_FILE);
        std::fs::write(&path, "not json").unwrap();
        let err = load_ack(&path).unwrap_err();
        assert_eq!(err.kind, AckFileErrorKind::Parse);
    }

    #[test]
    fn build_id_includes_version() {
        assert!(BUILD_ID.starts_with(concat!(env!("CARGO_PKG_VERSION"), "+")));
    }
}
