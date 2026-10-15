// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
use super::*;
use std::fs;

const OLD_LOCKSMITH: &str = "2db332a5315242ae84385571b2af9e2b499a369c";

fn historical_manifest() -> EnclaveManifest {
    let mut manifest = EnclaveManifest::new(
        None,
        EnclaveSource::Local { path: ".".into() },
        FrameworkSource::GitArchive {
            url: "https://example.invalid/historical.tar.gz".into(),
            commit: Some("historical-framework".into()),
        },
        None,
        Some("/app/server".into()),
        None,
    );
    manifest.locksmith = true;
    manifest.locksmith_commit = Some(OLD_LOCKSMITH.into());
    manifest.enclaveos_commit = Some("historical-enclaveos".into());
    manifest.bootproof_commit = Some("historical-bootproof".into());
    manifest
}

fn raw_v0_image(root: &Path) -> Vec<u8> {
    let imported: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/imported-v0.json")).unwrap();
    let raw = serde_json::to_vec_pretty(&imported["original"]).unwrap();
    fs::create_dir_all(root.join("etc/caution/secrets")).unwrap();
    fs::write(root.join("etc/caution/bundle.json"), &raw).unwrap();
    fs::write(root.join("etc/caution/secrets/TEST.asc"), b"ciphertext").unwrap();
    raw
}

#[tokio::test]
async fn remote_deployment_manifest_does_not_bypass_artifact_preflight() {
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("image");
    raw_v0_image(&image);
    let builder = EnclaveBuilder::new("unused", "local", "unused", root.path()).unwrap();
    assert_eq!(builder.cache_type, CacheType::Build);
    // Exercise the actual filesystem build entrypoint. Preflight must fail
    // before attempting source downloads, even with a supplied remote manifest.
    for manifest in [None, Some(historical_manifest())] {
        let error = builder
            .build_enclave_from_filesystem(
                image.clone(),
                None,
                None,
                None,
                None,
                None,
                manifest,
                &[],
                None,
                false,
                "disabled",
                "X25519",
                false,
                None,
                "http",
                true,
                None,
                false,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, BuildEnclaveError::CheckArtifacts { .. }));
    }
}

#[tokio::test]
async fn uncached_manifest_reproduction_preserves_raw_v0_directory_and_tar() {
    for archived in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("image");
        let raw = raw_v0_image(&image);
        let user_fs = if archived {
            let path = root.path().join("image.tar");
            let mut archive = tar::Builder::new(fs::File::create(&path).unwrap());
            archive.append_dir_all(".", &image).unwrap();
            archive.finish().unwrap();
            path
        } else {
            image.clone()
        };
        let builder = EnclaveBuilder::new_with_cache(
            "unused",
            "local",
            "unused",
            "test",
            "historical",
            CacheType::Reproduction,
            true,
            root.path(),
        )
        .unwrap();
        assert!(builder.get_cached_eif().is_none());
        // A reproduction cache alone is insufficient: manifestless builds
        // still select current defaults and must pass current preflight.
        assert!(matches!(
            builder.check_locksmith_artifacts(&user_fs, true, None),
            Err(BuildEnclaveError::CheckArtifacts { .. })
        ));
        let manifest = historical_manifest();
        builder
            .check_locksmith_artifacts(&user_fs, true, Some(&manifest))
            .unwrap();

        let enclave = root.path().join("enclave");
        let templates = root.path().join("historical-templates");
        fs::create_dir(&enclave).unwrap();
        fs::create_dir(&templates).unwrap();
        fs::write(
            templates.join("run.sh.template"),
            "#!/bin/sh\n# historical template\n{{USER_CMD}}\n",
        )
        .unwrap();
        fs::write(
            templates.join("Containerfile.eif"),
            "# historical template\nRUN checkout {{LOCKSMITH_COMMIT}}\n",
        )
        .unwrap();
        let stage = build::stage_eif_components(
            &user_fs,
            &enclave,
            &builder.work_dir,
            manifest.run_command.clone(),
            Some(manifest.clone()),
            &[],
            None,
            false,
            "disabled",
            "X25519",
            false,
            None,
            "http",
            true,
            None,
            false,
            Some(&templates),
        )
        .await
        .unwrap();
        let staged_manifest = EnclaveManifest::read_from_file(&stage.join("manifest.json"))
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(staged_manifest).unwrap(),
            serde_json::to_value(manifest).unwrap()
        );
        let containerfile = fs::read_to_string(stage.join("Containerfile.eif")).unwrap();
        assert!(containerfile.contains("# historical template"));
        assert!(containerfile.contains(OLD_LOCKSMITH));
        if archived {
            assert_eq!(
                fs::read(stage.join(build::APP_PAYLOAD_TAR)).unwrap(),
                fs::read(&user_fs).unwrap()
            );
        } else {
            assert_eq!(
                fs::read(stage.join("app/etc/caution/bundle.json")).unwrap(),
                raw
            );
            assert_eq!(
                fs::read(stage.join("app/etc/caution/secrets/TEST.asc")).unwrap(),
                b"ciphertext"
            );
            assert!(!stage
                .join("app/etc/caution/keymaker-pcr-policy.json")
                .exists());
        }
    }
}
