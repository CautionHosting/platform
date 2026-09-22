// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
use crate::{
    ApiClient, output,
    quorum_init::{self, InitError, InitErrorCtx as Ctx},
    share_release,
};
use dterror::ResultExt;
use locksmith::{
    bundle::{LoadedBundle, RecoverySource},
    legacy,
};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(clap::Args, Debug)]
pub(crate) struct Options {
    /// Original, unversioned V0 bundle. The source is never rewritten.
    #[arg(long)]
    bundle: PathBuf,
    /// Private OpenPGP keyring; omit to use a selected OpenPGP smartcard.
    #[arg(long)]
    keyring: Option<PathBuf>,
    /// Full holder fingerprint; required when selection is ambiguous in noninteractive use.
    #[arg(long)]
    holder: Option<String>,
    #[arg(long, default_value = ".caution/quorum-bundle.json")]
    output: PathBuf,
    /// Upload the imported artifact using the existing signed Platform operation.
    #[arg(long)]
    upload: bool,
}

pub(crate) fn load(
    text: &str,
    allow_legacy: bool,
    policy_path: Option<&Path>,
) -> Result<(LoadedBundle, Option<SystemTime>), InitError> {
    let legacy = legacy::is_imported_json(text).with_context(Ctx::new("invalid bundle format"))?;
    let policy = if legacy {
        None
    } else {
        serde_json::from_str::<keymaker_models::generate_quorum::GenerateQuorumResponse>(text)
            .with_context(Ctx::new(
                "expected proofed V1 or ImportedV0; raw V0 requires secret import-legacy",
            ))?;
        Some(quorum_init::load_policy(&quorum_init::policy_path(
            policy_path,
        ))?)
    };
    locksmith::bundle::load_recovery_json(text, policy.as_ref(), allow_legacy)
        .with_context(Ctx::new("unable to load quorum bundle"))
}

pub(crate) async fn run(client: &ApiClient, options: Options) -> Result<(), InitError> {
    // Fail before a passphrase/PIN prompt, and check again atomically when publishing the output.
    if options.output.exists() {
        return Err(InitError::invalid(
            "output already exists; choose another --output path",
        ));
    }
    let text =
        fs::read_to_string(&options.bundle).with_context(Ctx::new("read original V0 bundle"))?;
    let candidates =
        legacy::import_candidates(&text).with_context(Ctx::new("invalid original V0 bundle"))?;
    let (holder, _) = share_release::select_holder(
        &candidates,
        options.holder.as_deref(),
        options.keyring.as_deref(),
        &BTreeMap::new(),
    )?;
    output::status("Importing legacy metadata only. No Keymaker generation proof is available.");
    let imported = legacy::import_with_default_prompt(&text, options.keyring.as_deref(), &holder)
        .with_context(Ctx::new("legacy metadata import failed"))?;
    let hash = imported
        .content_hash()
        .with_context(Ctx::new("hash imported artifact"))?;
    let view = imported.recovery();
    output::status(format!(
        "Legacy V0 — no Keymaker generation proof\nQuorum: {} of {} holders\nContent hash: {hash}",
        view.threshold, view.max
    ));
    let json = serde_json::to_vec_pretty(&imported)
        .with_context(Ctx::new("serialize imported artifact"))?;
    save(&options.output, &json)?;
    output::success(format!(
        "Saved {}. Package this file in the rebuilt enclave; encryption and release require --allow-legacy.",
        options.output.display()
    ));
    if options.upload {
        let config = client.ensure_authenticated().await.with_context(Ctx::new(
            "bundle saved locally; authenticate before uploading",
        ))?;
        let body = serde_json::to_vec(&serde_json::json!({"data": imported, "allow_legacy": true}))
            .with_context(Ctx::new("serialize legacy upload"))?;
        output::status(format!(
            "Authorize legacy upload: {hash}. The signature covers the artifact and explicit legacy acceptance."
        ));
        let response = client
            .signed_request(
                &config.session_id,
                "/api/quorum-bundles",
                reqwest::Method::POST,
                body,
            )
            .await
            .with_context(Ctx::new("bundle saved locally; Platform upload failed"))?;
        response.error_for_status().with_context(Ctx::new(
            "bundle saved locally; Platform rejected legacy upload",
        ))?;
        output::success("Legacy bundle uploaded to Platform.");
    }
    Ok(())
}

fn save(output: &Path, json: &[u8]) -> Result<(), InitError> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(Ctx::new("create output directory"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(Ctx::new("create temporary output"))?;
    temp.write_all(json)
        .with_context(Ctx::new("write imported artifact"))?;
    temp.persist_noclobber(output).with_context(Ctx::new(
        "output exists or cannot be saved; source bundle is unchanged",
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_use_is_explicit_without_a_keymaker_policy() {
        let text = include_str!("../../../tests/fixtures/imported-v0.json");
        assert!(load(text, false, None).is_err());
        let (bundle, at) = load(text, true, None).unwrap();
        assert!(bundle.recovery().legacy);
        assert!(bundle.bundle_id().is_none());
        assert!(at.is_none());
        assert!(load(r#"{"data":{"version":"V1"},"necroproof":[]}"#, true, None).is_err());
    }
    #[test]
    fn output_is_not_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("bundle.json");
        save(&output, b"original").unwrap();
        assert!(save(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original");
    }
}
