// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
#[tokio::test]
async fn both_host_provisioners_pin_the_recorded_digest_and_reject_invalid_digests() {
    let mut request = super::tests::deployment_request("s3://fixture/app.eif", Some("app.eif"));
    let legacy = serde_json::to_value(&request).unwrap();
    assert!(legacy.get("tap_framer_sha256").is_none());
    assert!(
        serde_json::from_value::<NitroDeploymentRequest>(legacy)
            .unwrap()
            .tap_framer_sha256
            .is_none()
    );
    let digest = "a".repeat(64);
    request.tap_framer_sha256 = Some(digest.clone());
    let saved = serde_json::to_vec(&request).unwrap();
    let mut request: NitroDeploymentRequest = serde_json::from_slice(&saved).unwrap();
    assert_eq!(request.tap_framer_sha256.as_deref(), Some(digest.as_str()));
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
    request.tap_framer_sha256 = Some("$(unsafe)".into());
    let rejected = tempfile::tempdir().unwrap();
    assert!(
        generate_nitro_deployment_main_tf(rejected.path(), &request, "s3://fixture/app.eif")
            .await
            .is_err()
    );
    assert!(
        generate_managed_onprem_deployment_tf(rejected.path(), &request, "s3://fixture/app.eif")
            .await
            .is_err()
    );
    assert!(!rejected.path().join("main.tf").exists());
}
