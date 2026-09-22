// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
//! Fail before provisioning when the application image lacks Locksmith's required inputs.
use dterror::{BoxError, CtxError, Location, ResultExt};
use std::{collections::HashSet, io::Read, path::Path};
#[derive(Debug, thiserror::Error, CtxError)]
#[error("Locksmith artifact preflight failed: {message} [{location:?}]")]
pub(crate) struct Error {
    message: &'static str,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}
impl Error {
    #[track_caller]
    fn missing(message: &'static str) -> Self {
        Self {
            message,
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}
pub(crate) fn check(root: &Path) -> Result<(), Error> {
    let mut files = HashSet::new();
    let mut requires_policy = false;
    if root.is_file()
        && root
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"))
    {
        let file = std::fs::File::open(root).with_context(ErrorCtx::new("open application tar"))?;
        let mut archive = tar::Archive::new(file);
        for entry in archive
            .entries()
            .with_context(ErrorCtx::new("read application tar"))?
        {
            let mut entry = entry.with_context(ErrorCtx::new("read artifact entry"))?;
            if !entry.header().entry_type().is_file() || entry.size() == 0 {
                continue;
            }
            let path = entry
                .path()
                .with_context(ErrorCtx::new("read artifact path"))?;
            let path = path.strip_prefix("./").unwrap_or(&path).to_path_buf();
            if path == Path::new("etc/caution/bundle.json") {
                requires_policy |= requires_keymaker_policy(&mut entry)?;
            }
            files.insert(path);
        }
    } else {
        let directory = root.join("etc/caution");
        for name in ["bundle.json", "keymaker-pcr-policy.json"] {
            let path = directory.join(name);
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.len() > 0) {
                if name == "bundle.json" {
                    let file = std::fs::File::open(&path)
                        .with_context(ErrorCtx::new("open quorum bundle"))?;
                    requires_policy = requires_keymaker_policy(file)?;
                }
                files.insert(std::path::PathBuf::from("etc/caution").join(name));
            }
        }
        if let Ok(entries) = std::fs::read_dir(directory.join("secrets")) {
            for entry in entries {
                let entry = entry.with_context(ErrorCtx::new("read encrypted secret artifact"))?;
                if entry
                    .file_type()
                    .with_context(ErrorCtx::new("read artifact type"))?
                    .is_file()
                    && entry
                        .metadata()
                        .with_context(ErrorCtx::new("read artifact size"))?
                        .len()
                        > 0
                {
                    files.insert(
                        std::path::PathBuf::from("etc/caution/secrets").join(entry.file_name()),
                    );
                }
            }
        }
    }
    if !files.contains(Path::new("etc/caution/bundle.json")) {
        return Err(Error::missing(
            "include non-empty /etc/caution/bundle.json in the application image",
        ));
    }
    if requires_policy && !files.contains(Path::new("etc/caution/keymaker-pcr-policy.json")) {
        return Err(Error::missing(
            "include non-empty /etc/caution/keymaker-pcr-policy.json in the application image",
        ));
    }
    if !files.iter().any(|p| {
        p.parent() == Some(Path::new("etc/caution/secrets"))
            && p.extension().is_some_and(|ext| ext == "asc")
    }) {
        return Err(Error::missing(
            "include an encrypted /etc/caution/secrets/*.asc artifact in the application image",
        ));
    }
    Ok(())
}

fn requires_keymaker_policy(bundle: impl Read) -> Result<bool, Error> {
    let bundle: serde_json::Value =
        serde_json::from_reader(bundle).with_context(ErrorCtx::new("parse quorum bundle JSON"))?;
    // This is an artifact-presence check, not bundle validation. Locksmith validates
    // ImportedV0 metadata or verifies the V1 proof and policy at runtime.
    Ok(bundle.get("format").and_then(serde_json::Value::as_str) != Some("ImportedV0"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMPORTED_V0: &str = include_str!("../../../tests/fixtures/imported-v0.json");
    // Only the format matters to preflight; V1 proof verification stays in Locksmith.
    const V1: &str = r#"{"data":{"version":"V1"},"necroproof":[]}"#;

    fn assert_directory_and_tar(root: &Path, expected_error: Option<&str>) {
        let tar = tempfile::NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(tar.reopen().unwrap());
        builder.append_dir_all(".", root).unwrap();
        builder.finish().unwrap();
        for path in [root, tar.path()] {
            match expected_error {
                Some(message) => assert_eq!(check(path).unwrap_err().message, message),
                None => check(path).unwrap(),
            }
        }
    }

    #[test]
    fn v1_requires_policy_in_directory_and_tar() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/caution/secrets")).unwrap();
        std::fs::write(dir.path().join("etc/caution/bundle.json"), V1).unwrap();
        std::fs::write(
            dir.path().join("etc/caution/secrets/TEST.asc"),
            b"encrypted",
        )
        .unwrap();
        let policy = dir.path().join("etc/caution/keymaker-pcr-policy.json");
        for contents in [None, Some("")] {
            if let Some(contents) = contents {
                std::fs::write(&policy, contents).unwrap();
            }
            assert_directory_and_tar(
                dir.path(),
                Some("include non-empty /etc/caution/keymaker-pcr-policy.json in the application image"),
            );
        }
        std::fs::write(&policy, b"policy").unwrap();
        assert_directory_and_tar(dir.path(), None);
    }

    #[test]
    fn imported_v0_requires_bundle_and_ciphertext_but_no_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/caution/secrets")).unwrap();
        let bundle = dir.path().join("etc/caution/bundle.json");
        for contents in [None, Some("")] {
            if let Some(contents) = contents {
                std::fs::write(&bundle, contents).unwrap();
            }
            assert_directory_and_tar(
                dir.path(),
                Some("include non-empty /etc/caution/bundle.json in the application image"),
            );
        }
        std::fs::write(&bundle, IMPORTED_V0).unwrap();
        let ciphertext = dir.path().join("etc/caution/secrets/TEST.asc");
        for contents in [None, Some("")] {
            if let Some(contents) = contents {
                std::fs::write(&ciphertext, contents).unwrap();
            }
            assert_directory_and_tar(
                dir.path(),
                Some("include an encrypted /etc/caution/secrets/*.asc artifact in the application image"),
            );
        }
        std::fs::write(&ciphertext, b"encrypted").unwrap();
        assert_directory_and_tar(dir.path(), None);
    }

    #[test]
    fn invalid_or_other_formats_do_not_gain_legacy_exemption() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/caution/secrets")).unwrap();
        std::fs::write(
            dir.path().join("etc/caution/secrets/TEST.asc"),
            b"encrypted",
        )
        .unwrap();
        let bundle = dir.path().join("etc/caution/bundle.json");
        std::fs::write(&bundle, "{invalid").unwrap();
        assert_directory_and_tar(dir.path(), Some("parse quorum bundle JSON"));
        let imported: serde_json::Value = serde_json::from_str(IMPORTED_V0).unwrap();
        for text in [
            V1.to_owned(),
            serde_json::to_string(&imported["original"]).unwrap(),
            r#"{"format":"ImportedV1"}"#.to_owned(),
        ] {
            std::fs::write(&bundle, text).unwrap();
            assert_directory_and_tar(
                dir.path(),
                Some("include non-empty /etc/caution/keymaker-pcr-policy.json in the application image"),
            );
        }
    }
}
