// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use dterror::ResultExt;
use std::path::{Path, PathBuf};

/// Failure to stage or export the frame-preserving tunnel helper.
#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("could not copy tunnel artifact '{path}' [{location}]")]
pub struct ArtifactError {
    #[context(borrow = Path)]
    path: PathBuf,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

/// Stage the helper from the selected framework's templates, not the current CLI.
#[tracing::instrument(skip_all, err)]
pub async fn stage_sources(
    templates: &Path,
    stage: &Path,
    containerfile: &str,
) -> Result<(), ArtifactError> {
    use ArtifactErrorCtx as Ctx;
    if !containerfile.contains("COPY tap-framer/") {
        return Ok(());
    }
    let destination = stage.join("tap-framer");
    tokio::fs::create_dir_all(destination.join("src"))
        .await
        .with_context(Ctx::new(&destination))?;
    for name in ["Cargo.toml", "Cargo.lock", "src/main.rs", "src/vsock.rs"] {
        let source = templates.join("tap-framer").join(name);
        tokio::fs::copy(&source, destination.join(name))
            .await
            .with_context(Ctx::new(&source))?;
    }
    Ok(())
}

/// Export the very same executable packaged into the EIF for its host endpoint.
#[tracing::instrument(skip_all, err)]
pub async fn export_binary(work_dir: &Path, output_eif: &Path) -> Result<(), ArtifactError> {
    use ArtifactErrorCtx as Ctx;
    let recipe = work_dir.join("eif-stage/Containerfile.eif");
    let containerfile = tokio::fs::read_to_string(&recipe)
        .await
        .with_context(Ctx::new(&recipe))?;
    let sidecar = output_eif.with_extension("tap-framer");
    if !containerfile.contains("COPY tap-framer/") {
        return match tokio::fs::remove_file(&sidecar).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(Ctx::new(&sidecar)),
        };
    }
    let source = work_dir.join("eif-stage/output/tap-framer");
    tokio::fs::copy(&source, &sidecar)
        .await
        .with_context(Ctx::new(&source))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn historical_templates_need_no_helper() {
        let dir = tempfile::tempdir().unwrap();
        stage_sources(
            &dir.path().join("absent"),
            dir.path(),
            "FROM scratch AS output",
        )
        .await
        .unwrap();
        assert!(!dir.path().join("tap-framer").exists());
    }

    #[tokio::test]
    async fn new_templates_require_each_helper_source() {
        let names = ["Cargo.toml", "Cargo.lock", "src/main.rs", "src/vsock.rs"];
        for missing in names {
            let dir = tempfile::tempdir().unwrap();
            let templates = dir.path().join("templates");
            for name in names {
                if name != missing {
                    let source = templates.join("tap-framer").join(name);
                    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
                    std::fs::write(source, name).unwrap();
                }
            }
            let error = stage_sources(
                &templates,
                &dir.path().join("stage"),
                "COPY tap-framer/ /build/",
            )
            .await
            .expect_err("every helper source is required");
            assert_eq!(error.path, templates.join("tap-framer").join(missing));
            assert_eq!(
                error
                    .source
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
        }
    }

    #[tokio::test]
    async fn historical_build_does_not_export_stale_helper() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("eif-stage/output")).unwrap();
        std::fs::write(
            dir.path().join("eif-stage/Containerfile.eif"),
            "FROM scratch AS output",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("eif-stage/output/tap-framer"),
            b"stale helper",
        )
        .unwrap();
        std::fs::write(dir.path().join("enclave.tap-framer"), b"previous export").unwrap();
        export_binary(dir.path(), &dir.path().join("enclave.eif"))
            .await
            .unwrap();
        assert!(!dir.path().join("enclave.tap-framer").exists());
    }

    #[tokio::test]
    async fn exports_built_helper_beside_eif() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("eif-stage/output/tap-framer");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(
            dir.path().join("eif-stage/Containerfile.eif"),
            "COPY tap-framer/ /build/",
        )
        .unwrap();
        std::fs::write(source, b"built helper").unwrap();
        export_binary(dir.path(), &dir.path().join("enclave.eif"))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("enclave.tap-framer")).unwrap(),
            b"built helper"
        );
    }

    #[tokio::test]
    async fn missing_built_helper_fails_export() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("eif-stage")).unwrap();
        std::fs::write(
            dir.path().join("eif-stage/Containerfile.eif"),
            "COPY tap-framer/ /build/",
        )
        .unwrap();
        assert!(export_binary(dir.path(), &dir.path().join("enclave.eif"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stages_selected_framework_helper() {
        let dir = tempfile::tempdir().unwrap();
        let templates = dir.path().join("historical-templates");
        let stage = dir.path().join("stage");
        for name in ["Cargo.toml", "Cargo.lock", "src/main.rs", "src/vsock.rs"] {
            let source = templates.join("tap-framer").join(name);
            std::fs::create_dir_all(source.parent().unwrap()).unwrap();
            std::fs::write(source, format!("selected-framework:{name}")).unwrap();
        }
        stage_sources(&templates, &stage, "COPY tap-framer/ /build-tap-framer/\n")
            .await
            .unwrap();
        assert!(
            stage.join("tap-framer/src/main.rs").is_file(),
            "the selected helper must be staged"
        );
        for name in ["Cargo.toml", "Cargo.lock", "src/main.rs", "src/vsock.rs"] {
            assert_eq!(
                std::fs::read_to_string(stage.join("tap-framer").join(name)).unwrap(),
                format!("selected-framework:{name}")
            );
        }
    }
}
