// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn source_builds_pin_the_reviewed_release_on_both_host_paths() {
    let mut request = super::tests::deployment_request("s3://fixture/app.eif", Some("app.eif"));
    request.egress = true;
    let digest = SOURCE_TAP_FRAMER_SHA256.trim();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let managed = tempfile::tempdir().unwrap();
    generate_nitro_deployment_main_tf(managed.path(), &request, "s3://fixture/app.eif")
        .await
        .unwrap();
    let byoc = tempfile::tempdir().unwrap();
    generate_managed_onprem_deployment_tf(byoc.path(), &request, "s3://fixture/app.eif")
        .await
        .unwrap();
    for dir in [&managed, &byoc] {
        let generated = std::fs::read_to_string(dir.path().join("main.tf")).unwrap();
        generated.parse::<hcl::Body>().unwrap();
        assert!(generated.contains(&format!("tap_framer_sha256 = \"{digest}\"")));
    }
}

#[test]
fn host_rejects_corrupt_or_unpinned_helpers_before_installation() {
    let source = include_str!("../../../terraform/modules/aws/nitro-enclave/user-data.sh");
    let fragment = source
        .split_once("# TAP_FRAMER_INSTALL_BEGIN")
        .unwrap()
        .1
        .split_once("# TAP_FRAMER_INSTALL_END")
        .unwrap()
        .0;
    let payload = b"synthetic host installation test fixture";
    let digest = format!("{:x}", Sha256::digest(payload));
    for (valid, expected) in [
        (true, digest.as_str()),
        (false, digest.as_str()),
        (true, ""),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("payload");
        let mut bytes = payload.to_vec();
        if !valid {
            bytes[0] ^= 1;
        }
        std::fs::write(&input, bytes).unwrap();
        let executable = dir.path().join("tap-framer");
        let downloaded = dir.path().join("download");
        let started = dir.path().join("started");
        let requests = dir.path().join("requests");
        let script = fragment
            .replace("${eif_s3_path}", "s3://fixture/app.eif")
            .replace("${tap_framer_sha256}", expected)
            .replace("/usr/local/bin/tap-framer", executable.to_str().unwrap())
            .replace(
                "/opt/nitro/tap-framer.download",
                downloaded.to_str().unwrap(),
            );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                r#"set -e
aws() {{
    printf '%s\n' "$3" >> "$REQUESTS"
    test "$#" = 4
    test "$1 $2" = "s3 cp"
    test "$3" = "s3://fixture/app.eif.tap-framer"
    test "$4" = "$DOWNLOAD"
    cp "$PAYLOAD" "$4"
}}
{script}
touch "$STARTED"
"#
            ))
            .env("LC_ALL", "C")
            .env("PAYLOAD", &input)
            .env("STARTED", &started)
            .env("DOWNLOAD", &downloaded)
            .env("REQUESTS", &requests)
            .output()
            .unwrap();
        let accepted = valid && !expected.is_empty();
        assert_eq!(
            std::fs::read_to_string(requests).unwrap(),
            "s3://fixture/app.eif.tap-framer\n"
        );
        assert_eq!(
            output.status.success(),
            accepted,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(executable.exists(), accepted);
        assert_eq!(started.exists(), accepted);
        if accepted {
            assert_eq!(std::fs::read(&executable).unwrap(), payload);
            assert_eq!(
                std::fs::metadata(&executable).unwrap().permissions().mode() & 0o777,
                0o755
            );
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(if expected.is_empty() {
                    "no properly formatted checksum lines found"
                } else {
                    "computed checksum did NOT match"
                })
            );
        }
    }
}
