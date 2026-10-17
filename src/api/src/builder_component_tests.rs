// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use enclave_builder::components::{
    ArtifactFile, Component, ComponentArtifact, ComponentSet, ComponentSpec,
};
use std::collections::BTreeMap;

fn request() -> BuildRequest {
    let mut request = super::tests::make_test_build_request_with_egress(true);
    request.enclaveos_commit = enclave_builder::build::resolve_enclaveos_commit();
    request.steve_commit = enclave_builder::build::resolve_steve_commit();
    request.framework_commit = "a".repeat(40);
    request.e2e = true;
    request.e2e_mode = "steve".into();
    request.locksmith = true;
    let mut artifacts = BTreeMap::new();
    for (component, commit) in [
        (Component::Init, request.enclaveos_commit.clone()),
        (
            Component::Bootproof,
            enclave_builder::build::resolve_bootproof_commit(),
        ),
        (Component::Steve, request.steve_commit.clone()),
        (
            Component::Locksmith,
            enclave_builder::build::resolve_locksmith_commit(),
        ),
        (Component::TapFramer, request.framework_commit.clone()),
    ] {
        let spec = ComponentSpec::new(
            component,
            commit,
            "b".repeat(64),
            component.source_subdir().map(|_| "c".repeat(64)),
        )
        .unwrap();
        let files = component
            .filenames()
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    ArtifactFile::from_bytes(name.as_bytes()).unwrap(),
                )
            })
            .collect();
        artifacts.insert(component, ComponentArtifact::new(spec, files).unwrap());
    }
    request.component_set = Some(ComponentSet::new(artifacts).unwrap());
    request
}

fn config() -> BuilderConfig {
    BuilderConfig {
        ami_id: "ami-test".into(),
        security_group_id: "sg-test".into(),
        subnet_id: "subnet-test".into(),
        instance_profile: "profile-test".into(),
        region: "us-west-2".into(),
        timeout_secs: 1200,
        eif_s3_bucket: "test-bucket".into(),
        git_hostname: "git.example.com".into(),
        additional_instance_tags: Vec::new(),
    }
}

fn script(request: &BuildRequest) -> Result<String, GenerateBuilderUserdataError> {
    generate_builder_userdata(
        Uuid::nil(),
        &config(),
        request,
        "eifs/test.eif",
        "builds/test/helper",
        &"d".repeat(64),
    )
}

#[test]
fn pinned_userdata_fits_ec2_and_downloads_only_from_its_own_bucket() {
    let request = request();
    let script = script(&request).unwrap();
    assert!(
        script.len() < 16_384,
        "pinned userdata size {} exceeds EC2 limit",
        script.len()
    );
    assert!(script.contains("s3://$S3_BUCKET/components/v1/blobs/sha256/$digest/$name"));
    assert!(script.contains("CAUTION_COMPONENTS_PATH=\"$PREBUILT_COMPONENTS\""));
    let manifest = script
        .split_once("<< 'MANIFEST_EOF'\n")
        .unwrap()
        .1
        .split_once("\nMANIFEST_EOF")
        .unwrap()
        .0;
    let manifest: enclave_builder::manifest::EnclaveManifest =
        serde_json::from_str(manifest).unwrap();
    assert_eq!(manifest.component_set, request.component_set);
}

#[test]
fn builder_rejects_source_pin_drift_before_generating_userdata() {
    let mut request = request();
    request.framework_commit = "f".repeat(40);
    assert!(script(&request).is_err());
    let mut request = self::request();
    request.steve_commit = "f".repeat(40);
    assert!(script(&request).is_err());
}

#[test]
fn download_script_checks_hash_and_size_before_helper_execution() {
    for (steve, locksmith, egress, fault) in [
        (false, false, false, "none"),
        (true, true, false, "none"),
        (false, false, true, "none"),
        (true, false, true, "none"),
        (false, true, true, "none"),
        (true, true, true, "none"),
        (true, true, true, "corrupt"),
        (true, true, true, "size"),
    ] {
        let mut request = request();
        request.e2e = steve;
        request.locksmith = locksmith;
        request.egress = egress;
        if fault == "size" {
            let mut set = serde_json::to_value(request.component_set.as_ref().unwrap()).unwrap();
            set["components"]["tap-framer"]["files"]["tap-framer"]["size"] =
                serde_json::json!(b"tap-framer".len() + 1);
            request.component_set = Some(serde_json::from_value(set).unwrap());
        }
        let rendered = script(&request).unwrap();
        let manifest = rendered
            .split_once("<< 'MANIFEST_EOF'\n")
            .unwrap()
            .1
            .split_once("\nMANIFEST_EOF")
            .unwrap()
            .0;
        let fragment = rendered
            .split_once("PREBUILT_COMPONENTS=\"\"")
            .unwrap()
            .1
            .split_once("set_phase \"building-enclave\"")
            .unwrap()
            .0;
        let environment = rendered
            .lines()
            .filter(|line| {
                line.starts_with("S3_BUCKET=")
                    || line.starts_with("E2E=")
                    || line.starts_with("LOCKSMITH=")
                    || line.starts_with("EGRESS=")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let dir = tempfile::tempdir().unwrap();
        let blobs = dir.path().join("blobs");
        for component in Component::ALL {
            for name in component.filenames() {
                let key = format!(
                    "components/v1/blobs/sha256/{}/{name}",
                    enclave_builder::components::sha256(name.as_bytes())
                );
                let path = blobs.join(key);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let mut bytes = name.as_bytes().to_vec();
                if fault == "corrupt" && *name == "tap-framer" {
                    bytes[0] ^= 1;
                }
                std::fs::write(path, bytes).unwrap();
            }
        }
        std::fs::write(dir.path().join("manifest.json"), manifest).unwrap();
        let fragment = fragment.replace("/build/", &format!("{}/", dir.path().display()));
        let requests = dir.path().join("requests");
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                r#"set -e
{environment}
aws() {{
    test "$#" = 4
    test "$1 $2" = "s3 cp"
    test "$4" = "$PREBUILT_COMPONENTS/${{3##*/}}"
    printf '%s\n' "$3" >> "$REQUESTS"
    cp "$BLOBS/${{3#s3://test-bucket/}}" "$4"
}}
{fragment}
touch "$READY"
"#
            ))
            .env("LC_ALL", "C")
            .env("BLOBS", &blobs)
            .env("REQUESTS", &requests)
            .env("READY", dir.path().join("ready"))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(if fault == "none" { 0 } else { 1 }),
            "steve={steve}, locksmith={locksmith}, fault={fault}: {stdout}\n{stderr}"
        );
        assert_eq!(dir.path().join("ready").exists(), fault == "none");
        let mut expected_names = vec!["bootproofd", "init"];
        if egress {
            expected_names.push("tap-framer");
        }
        if steve {
            expected_names.push("steve");
        }
        if locksmith {
            expected_names.extend(["locksmith-oneshot", "locksmithd"]);
        }
        expected_names.sort();
        let mut expected_requests = expected_names
            .iter()
            .map(|name| {
                format!(
                    "s3://test-bucket/components/v1/blobs/sha256/{}/{name}",
                    enclave_builder::components::sha256(name.as_bytes())
                )
            })
            .collect::<Vec<_>>();
        expected_requests.sort();
        let requests = std::fs::read_to_string(requests).unwrap();
        let mut requests = requests.lines().collect::<Vec<_>>();
        requests.sort();
        assert_eq!(requests, expected_requests);
        let mut downloaded = std::fs::read_dir(dir.path().join("prebuilt"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        downloaded.sort();
        assert_eq!(downloaded, expected_names);
        if fault == "none" {
            for name in expected_names {
                assert_eq!(
                    std::fs::read(dir.path().join("prebuilt").join(name)).unwrap(),
                    name.as_bytes()
                );
            }
        } else if fault == "corrupt" {
            assert!(
                stderr.contains("computed checksum did NOT match"),
                "{stderr}"
            );
        } else {
            assert!(stdout.contains("tap-framer: OK"), "{stdout}");
        }
    }
}
