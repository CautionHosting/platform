// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
//! Fail before provisioning when the application image lacks Locksmith's required inputs.
use dterror::{BoxError, CtxError, Location, ResultExt};
use std::{collections::HashSet, path::Path};
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
            let entry = entry.with_context(ErrorCtx::new("read artifact entry"))?;
            if !entry.header().entry_type().is_file() || entry.size() == 0 {
                continue;
            }
            let path = entry
                .path()
                .with_context(ErrorCtx::new("read artifact path"))?;
            let path = path.strip_prefix("./").unwrap_or(&path).to_path_buf();
            files.insert(path);
        }
    } else {
        let directory = root.join("etc/caution");
        for name in ["bundle.json", "keymaker-pcr-policy.json"] {
            let path = directory.join(name);
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.len() > 0) {
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
    if !files.contains(Path::new("etc/caution/keymaker-pcr-policy.json")) {
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_and_tar_require_all_three_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/caution/secrets")).unwrap();
        for path in [
            "etc/caution/bundle.json",
            "etc/caution/keymaker-pcr-policy.json",
            "etc/caution/secrets/TEST.asc",
        ] {
            assert!(check(dir.path()).is_err());
            std::fs::write(dir.path().join(path), b"fixture").unwrap();
        }
        assert!(check(dir.path()).is_ok());
        let tar = tempfile::NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(tar.reopen().unwrap());
        builder.append_dir_all(".", dir.path()).unwrap();
        builder.finish().unwrap();
        assert!(check(tar.path()).is_ok());
    }
}
