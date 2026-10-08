// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Real compiler/EIF integration. Run only on a disposable Docker build host:
//! COMPONENT_E2E_ROOT=/path/to/fixture cargo test -p enclave-builder
//!   --test prebuilt_components -- --ignored --nocapture
//! Fixture: framework/, enclave/, selected.lock.json, downloads/ containing the
//! selected real ELF outputs. No application service or enclave is started.
//! Network routing assistance, if needed, must retain original/effective recipes
//! externally and must not be represented as canonical-production build proof.

use enclave_builder::{
    build,
    components::{self, Component, ComponentSet},
    EnclaveManifest, EnclaveSource, FrameworkSource,
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

#[tokio::test]
#[ignore = "real Docker compiler and EIF builds; requires an explicit disposable fixture"]
async fn source_and_prebuilt_use_production_composition() {
    let root =
        PathBuf::from(std::env::var_os("COMPONENT_E2E_ROOT").expect("explicit fixture root"));
    let set: ComponentSet =
        serde_json::from_slice(&fs::read(root.join("selected.lock.json")).unwrap()).unwrap();
    set.validate().unwrap();
    for component in Component::ALL {
        for (name, descriptor) in set.get(component).expect("complete set").files() {
            let bytes = fs::read(root.join("downloads").join(name)).unwrap();
            descriptor.verify(&bytes).unwrap();
            assert!(bytes.starts_with(b"\x7fELF"), "{name} must be a real ELF");
        }
    }
    let pin = |component| {
        set.get(component)
            .unwrap()
            .spec()
            .source_commit()
            .to_owned()
    };
    let enclave_pin = pin(Component::Init);
    let framework_pin = pin(Component::TapFramer);
    let mut manifest = EnclaveManifest::new(
        None,
        EnclaveSource::GitArchive {
            urls: vec![enclave_builder::enclave_source_url(&enclave_pin)],
            commit: Some(enclave_pin.clone()),
        },
        FrameworkSource::GitArchive {
            url: format!("https://codeberg.org/caution/platform/archive/{framework_pin}.tar.gz"),
            commit: Some(framework_pin),
        },
        None,
        Some("/bin/sleep 3600".into()),
        Some("SYNTHETIC TEST APPLICATION: compiler/EIF equality, not runtime attestation".into()),
    );
    manifest.enclaveos_commit = Some(enclave_pin);
    manifest.bootproof_commit = Some(pin(Component::Bootproof));
    manifest.steve_commit = Some(pin(Component::Steve));
    manifest.locksmith_commit = Some(pin(Component::Locksmith));
    manifest.component_set = Some(set.clone());
    let app = root.join("synthetic-app");
    fs::create_dir_all(&app).unwrap();
    fs::write(
        app.join("TEST-ONLY.txt"),
        "Synthetic tiny rootfs; no production deployment.\n",
    )
    .unwrap();
    let templates = root.join("framework/src/enclave-builder/templates");
    let downloads = root.join("downloads");
    for mode in ["source", "prebuilt"] {
        let work = root.join(format!("eif-{mode}"));
        fs::create_dir_all(&work).unwrap();
        let prebuilt = (mode == "prebuilt").then_some(downloads.as_path());
        eprintln!("PRODUCTION_BUILD_START mode={mode}");
        build::build_eif_from_filesystems(
            &app,
            &app,
            &app,
            &root.join("enclave"),
            root.join(format!("{mode}.eif")),
            &work,
            Some("/bin/sleep 3600".into()),
            Some(manifest.clone()),
            &[8080],
            Some(8080),
            false,
            true,
            "http",
            build::DEFAULT_KEY_EXCHANGE,
            false,
            None,
            "http",
            true,
            None,
            true,
            Some(&templates),
            prebuilt,
        )
        .await
        .unwrap();
        let staged = work.join("eif-stage");
        assert_eq!(staged.join("prebuilt").exists(), mode == "prebuilt");
        if mode == "prebuilt" {
            for artifact in set.components().values() {
                for name in artifact.files().keys() {
                    assert_eq!(
                        fs::metadata(staged.join("prebuilt").join(name))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o755
                    );
                }
            }
        }
        eprintln!("PRODUCTION_BUILD_PASS mode={mode}");
    }
    for extension in ["eif", "pcrs", "tap-framer"] {
        let source = fs::read(root.join(format!("source.{extension}"))).unwrap();
        let prebuilt = fs::read(root.join(format!("prebuilt.{extension}"))).unwrap();
        assert!(!source.is_empty());
        assert_eq!(source, prebuilt, "source/prebuilt {extension} bytes");
        println!("EQUAL {extension} sha256={}", components::sha256(&source));
    }
    for name in ["manifest.json", "output/rootfs.cpio.gz"] {
        assert_eq!(
            fs::read(root.join("eif-source/eif-stage").join(name)).unwrap(),
            fs::read(root.join("eif-prebuilt/eif-stage").join(name)).unwrap(),
            "same measured {name}"
        );
    }
    let tap = fs::read(root.join("source.tap-framer")).unwrap();
    set.get(Component::TapFramer).unwrap().files()["tap-framer"]
        .verify(&tap)
        .unwrap();
    println!("PRODUCTION_ENTRYPOINT_EIF_PCR_MANIFEST_AND_HOST_TAP_EQUALITY_PASS");
}
