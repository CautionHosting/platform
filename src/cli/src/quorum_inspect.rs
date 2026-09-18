// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::{
    ApiClient, output,
    quorum_init::{self, InitError, InitErrorCtx as Ctx},
    share_release::{self, HolderNames, terminal_label},
};
use dterror::ResultExt;
use keymaker_models::generate_quorum::{
    GenerateQuorumBundle, GenerateQuorumResponse, deterministic_bundle_hash, v1::Key,
};
use sequoia_openpgp::{Cert, parse::Parse};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::SystemTime};

#[derive(clap::Args, Debug)]
pub(crate) struct Options {
    /// Saved proofed V1 quorum bundle to inspect.
    #[arg(long, default_value = ".caution/quorum-bundle.json")]
    bundle: PathBuf,
    /// Trusted Keymaker PCR policy (otherwise environment or .caution default).
    #[arg(long, conflicts_with = "unverified")]
    keymaker_pcr_policy: Option<PathBuf>,
    /// Show unauthenticated contents without proof verification or Platform lookup.
    #[arg(long)]
    unverified: bool,
}

fn load(
    text: &str,
    options: &Options,
) -> Result<(GenerateQuorumBundle, Option<SystemTime>), InitError> {
    let response: GenerateQuorumResponse = serde_json::from_str(text)
        .with_context(Ctx::new("invalid proofed V1 quorum bundle JSON"))?;
    if options.unverified {
        return Ok((response.data, None));
    }
    let policy = quorum_init::load_policy(&quorum_init::policy_path(
        options.keymaker_pcr_policy.as_deref(),
    ))?;
    locksmith::bundle::load_response_with_timestamp(response, &policy)
        .with_context(Ctx::new("unable to verify proofed V1 quorum bundle"))
}

fn summary(
    bundle: &GenerateQuorumBundle,
    generation_time: Option<SystemTime>,
    names: &HolderNames,
    options: &Options,
    verbose: bool,
    platform: Option<&str>,
) -> Result<String, InitError> {
    let GenerateQuorumBundle::V1(data) = bundle;
    if data.threshold == 0 || data.threshold > data.max || usize::from(data.max) != data.keyring.len() {
        return Err(InitError::invalid("invalid bundle threshold or holder count"));
    }
    let id = uuid::Uuid::from_bytes(data.bundle_id).to_string();
    let title = data.label.get("name").filter(|name| !name.is_empty())
        .map(|name| format!("{} · {}", terminal_label(name), &id[..8]))
        .unwrap_or_else(|| format!("Bundle {}", &id[..8]));
    let status = if options.unverified {
        "UNVERIFIED — bundle contents have not been authenticated."
    } else if generation_time.is_some() {
        "Proof verified — historical Keymaker evidence matches the configured policy."
    } else {
        "TEST ONLY — synthetic proof accepted; no authenticated generation time."
    };
    let mut lines = vec![format!("{title}\n{status}\n")];
    let pgp = data.keyring.iter().filter(|key| matches!(key, Key::OpenPGP { .. })).count();
    let custody = [(pgp, "External PGP"), (data.keyring.len() - pgp, "Passkey")]
        .into_iter().filter(|(count, _)| *count > 0).map(|(count, kind)| format!("{count} {kind}")).collect::<Vec<_>>().join(" · ");
    lines.push(format!("Quorum       {} of {} holders · {custody}", data.threshold, data.max));
    if !options.unverified {
        if let Some(at) = generation_time {
            let at: chrono::DateTime<chrono::Utc> = at.into();
            lines.push(format!("Generated    {} (authenticated)", at.format("%d %b %Y, %H:%M:%S UTC")));
        }
        if let Some(platform) = platform { lines.push(format!("Platform     {} (metadata source)", terminal_label(platform))); }
    }
    let mut labels: Vec<_> = data.label.iter().filter(|(key, _)| key.as_str() != "name").collect();
    labels.sort_by_key(|(key, _)| *key);
    for (key, value) in labels { lines.push(format!("Label        {} = {}", terminal_label(key), terminal_label(value))); }
    let mut rows = Vec::new();
    for (index, key) in data.keyring.iter().enumerate() {
        let (cert, custody, credentials) = match key {
            Key::OpenPGP { cert } => (cert, "External PGP", None),
            Key::WebAuthn { cert, credential } => (cert, "Passkey", Some(credential.len())),
        };
        let fingerprint = Cert::from_bytes(cert.as_bytes()).with_context(Ctx::new("invalid holder certificate"))?.fingerprint().to_string();
        let name = names.get(&fingerprint).filter(|name| names.values().filter(|other| *other == *name).count() == 1)
            .map(|name| terminal_label(name)).unwrap_or_else(|| format!("Holder {}", index + 1));
        let certificate = if verbose { fingerprint } else { share_release::short_fingerprint(&fingerprint) };
        rows.push((name, custody, certificate, credentials));
    }
    let width = rows.iter().map(|row| row.0.chars().count()).max().unwrap_or(0).max(6);
    let passkeys = rows.iter().any(|row| row.3.is_some());
    lines.push(format!("\n{:<width$}  {:<12}  {:<17}{}", "HOLDER", "CUSTODY", "CERTIFICATE", if passkeys { "  PASSKEYS" } else { "" }));
    for (name, custody, certificate, credentials) in rows {
        let count = if passkeys { format!("  {}", credentials.map(|n| n.to_string()).unwrap_or_else(|| "—".into())) } else { String::new() };
        lines.push(format!("{name:<width$}  {custody:<12}  {certificate:<17}{count}"));
    }
    if passkeys { lines.push("Multiple included passkeys still contribute one share per holder.".into()); }
    if !names.is_empty() { lines.push("\nNames reflect current Platform registrations, not authorization evidence.".into()); }
    if verbose {
        lines.push("\nIdentifiers & verification".into());
        lines.push(format!("Bundle ID: {id}"));
        lines.push(format!("Bundle hash: {}", hex::encode(deterministic_bundle_hash(bundle).with_context(Ctx::new("hash bundle"))?)));
        // Match Dashboard hashing of the exact UTF-8 public-key text.
        lines.push(format!("Public key SHA-256: {}", hex::encode(Sha256::digest(data.public_key.as_bytes()))));
        if !options.unverified { lines.push(format!("Verification policy: {}", terminal_label(&quorum_init::policy_path(options.keymaker_pcr_policy.as_deref()).display().to_string()))); }
    }
    Ok(lines.join("\n"))
}

pub(crate) async fn run(client: &ApiClient, options: Options) -> Result<(), InitError> {
    let text =
        std::fs::read_to_string(&options.bundle).with_context(Ctx::new("read quorum bundle"))?;
    let (bundle, at) = load(&text, &options)?;
    let names = if options.unverified {
        HolderNames::new()
    } else {
        let envelope =
            serde_json::from_str(&text).with_context(Ctx::new("invalid quorum bundle JSON"))?;
        share_release::holder_names_for(client, &envelope, "inspect").await
    };
    output::status(summary(&bundle, at, &names, &options, client.verbose, Some(&client.base_url))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use keymaker_models::generate_quorum::v1;
    use sequoia_openpgp::{cert::CertBuilder, serialize::SerializeInto};

    fn fixture() -> GenerateQuorumBundle {
        let (cert, _) = CertBuilder::new()
            .add_userid("test")
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let cert = String::from_utf8(cert.armored().to_vec().unwrap()).unwrap();
        GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
            bundle_id: [1; 16],
            label: [("name".into(), "test\x1b[31m\nspoof".into())].into(),
            keyring: vec![
                Key::OpenPGP { cert: cert.clone() },
                Key::WebAuthn {
                    cert,
                    credential: vec!["private snapshot".into(); 2],
                },
            ],
            threshold: 2,
            max: 2,
            shardfile: "encrypted shares".into(),
            public_key: "abc".into(),
        })
    }
    fn options() -> Options {
        Options {
            bundle: "bundle.json".into(),
            keymaker_pcr_policy: None,
            unverified: true,
        }
    }
    fn envelope(bundle: &GenerateQuorumBundle) -> String {
        serde_json::json!({"data": bundle, "necroproof": []}).to_string()
    }

    #[test]
    fn summary_covers_custody_counts_hashes_and_sanitization() {
        let mut bundle = fixture();
        for kind in ["mixed", "pgp", "passkey"] {
            let GenerateQuorumBundle::V1(data) = &mut bundle;
            if kind == "pgp" {
                data.keyring.remove(1);
                data.max = 1;
                data.threshold = 1;
            }
            if kind == "passkey" {
                let Key::OpenPGP { cert } = &data.keyring[0] else {
                    unreachable!()
                };
                data.keyring[0] = Key::WebAuthn {
                    cert: cert.clone(),
                    credential: vec!["snapshot".into(); 2],
                };
            }
            let text = summary(&bundle, None, &HolderNames::new(), &options(), false, None).unwrap();
            assert!(text.contains("UNVERIFIED"));
            assert!(text.contains("01010101"));
            assert!(!text.contains("0 External PGP") && !text.contains("0 Passkey"));
            assert!(text.contains("Holder 1"));
            assert!(
                !text.contains("Public key SHA-256")
            );
            assert!(!text.contains('\x1b'));
            assert!(!text.contains("\nspoof"));
            assert!(!text.contains("snapshot"));
            assert!(!text.contains("BEGIN PGP"));
            assert!(!text.contains("encrypted shares"));
            assert!(!text.contains("Bundle hash:"));
            if kind != "pgp" {
                assert!(text.contains("PASSKEYS") && text.contains("one share per holder"));
            }
        }
    }

    #[test]
    fn verbose_and_verified_timestamp_are_explicit() {
        let bundle = fixture();
        let GenerateQuorumBundle::V1(data) = &bundle;
        let Key::OpenPGP { cert } = &data.keyring[0] else {
            unreachable!()
        };
        let fingerprint = Cert::from_bytes(cert.as_bytes())
            .unwrap()
            .fingerprint()
            .to_string();
        let names = [(fingerprint.clone(), "alice".into())].into();
        let mut opts = options();
        opts.unverified = false;
        opts.keymaker_pcr_policy = Some("trusted.json".into());
        let text = summary(&bundle, Some(SystemTime::UNIX_EPOCH), &names, &opts, true, Some("https://platform.test")).unwrap();
        assert!(text.contains("Proof verified — historical"));
        assert!(text.contains("01 Jan 1970, 00:00:00 UTC (authenticated)"));
        assert!(text.contains(&fingerprint));
        assert!(text.contains("alice   Passkey"));
        assert!(text.contains("alice   External PGP"));
        assert!(text.contains("https://platform.test (metadata source)"));
        assert!(text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert!(text.contains("not authorization evidence"));
        assert!(text.contains("Verification policy: trusted.json"));
        assert!(text.contains("Bundle hash:"));
        assert!(
            summary(&bundle, None, &names, &opts, false, None)
                .unwrap()
                .contains("TEST ONLY")
        );
        let unverified = summary(
            &bundle,
            Some(SystemTime::UNIX_EPOCH),
            &HolderNames::new(),
            &options(),
            true,
            None,
        )
        .unwrap();
        assert!(!unverified.contains("(authenticated)"));
        assert!(!unverified.contains("Verification policy"));
    }

    #[test]
    fn unverified_skips_policy_but_rejects_malformed_contents() {
        let bundle = fixture();
        assert_eq!(
            load(&envelope(&bundle), &options()).unwrap(),
            (bundle, None)
        );
        assert!(load("{}", &options()).is_err());
        assert!(load("not json", &options()).is_err());
        let mut bundle = fixture();
        let GenerateQuorumBundle::V1(data) = &mut bundle;
        data.threshold = 0;
        assert!(summary(&bundle, None, &HolderNames::new(), &options(), false, None).is_err());
    }

    #[test]
    fn verification_never_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let opts = Options {
            keymaker_pcr_policy: Some(path.clone()),
            unverified: false,
            ..options()
        };
        let text = envelope(&fixture());
        assert!(load(&text, &opts).is_err());
        std::fs::write(&path, "{}").unwrap();
        assert!(load(&text, &opts).is_err());
        std::fs::write(&path, serde_json::json!({"sets":[{"pcrs":{"0":"11".repeat(48),"1":"11".repeat(48),"2":"11".repeat(48)}}]}).to_string()).unwrap();
        assert!(load(&text, &opts).is_err());
    }

    #[test]
    fn inspect_arguments_and_conflict() {
        assert!(crate::Cli::try_parse_from(["caution", "secret", "inspect"]).is_ok());
        assert!(
            crate::Cli::try_parse_from(["caution", "secret", "inspect", "--unverified"]).is_ok()
        );
        assert!(
            crate::Cli::try_parse_from([
                "caution",
                "secret",
                "inspect",
                "--unverified",
                "--keymaker-pcr-policy",
                "policy.json"
            ])
            .is_err()
        );
    }
}
