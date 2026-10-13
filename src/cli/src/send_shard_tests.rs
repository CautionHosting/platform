// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use serde_json::json;

#[test]
fn deployment_release_uses_only_the_recorded_bundle() {
    let org = vec![
        json!({"bundle_hash": "aa", "data": {"n": 1}}),
        json!({"bundle_hash": "bb", "data": {"n": 2}}),
    ];
    // The recorded hash picks its organization bundle, never the first one.
    assert_eq!(
        select_deployment_bundle(Some("bb"), None, None, &org).unwrap(),
        ReleaseBundle::Org(json!({"n": 2}))
    );
    // A matching local bundle is used as is; a different one is ignored.
    assert_eq!(
        select_deployment_bundle(Some("bb"), None, Some(Some("bb")), &org).unwrap(),
        ReleaseBundle::Local
    );
    assert_eq!(
        select_deployment_bundle(Some("bb"), None, Some(Some("aa")), &org).unwrap(),
        ReleaseBundle::Org(json!({"n": 2}))
    );
    assert!(matches!(
        select_deployment_bundle(Some("cc"), None, Some(Some("aa")), &org),
        Err(BundleSelection::NotFound { .. })
    ));
    // An explicit bundle must be the one the deployment was built with.
    assert!(matches!(
        select_deployment_bundle(Some("bb"), Some(Some("aa")), None, &org),
        Err(BundleSelection::Mismatch { .. })
    ));
    assert!(matches!(
        select_deployment_bundle(Some("bb"), Some(None), None, &org),
        Err(BundleSelection::Mismatch { .. })
    ));
    assert_eq!(
        select_deployment_bundle(Some("bb"), Some(Some("bb")), None, &org).unwrap(),
        ReleaseBundle::Explicit
    );
    // Nothing recorded: only an explicit bundle is accepted.
    assert!(matches!(
        select_deployment_bundle(None, None, Some(Some("aa")), &org),
        Err(BundleSelection::NotRecorded { .. })
    ));
    assert_eq!(
        select_deployment_bundle(None, Some(None), None, &org).unwrap(),
        ReleaseBundle::Explicit
    );
}

/// The API's `canonical_hash` of the same fixture (`BUNDLE` in the
/// `app_deployments::admission` tests). `bundle_text_hash` is a cross-crate
/// copy, so this literal, taken from the API's output, is the only thing that
/// ties the two together.
const BUNDLE_FIXTURE_HASH: &str =
    "0331123d7171622a4a4440ff3916f9d85e99199a7e146388fac2fe3e5ca79ae3";

#[test]
fn bundle_text_hash_matches_the_api_canonical_hash() {
    let text = r#"{"data":{"version":"V1","bundle_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"label":{"a":"1","b":"2"},"keyring":[],"threshold":1,"max":1,"shardfile":"shares","public_key":"key"},"necroproof":[]}"#;
    assert_eq!(bundle_text_hash(text).as_deref(), Some(BUNDLE_FIXTURE_HASH));
    let reordered = text.replace(
        r#""label":{"a":"1","b":"2"}"#,
        r#""label":{"b":"2","a":"1"}"#,
    );
    assert_eq!(bundle_text_hash(text), bundle_text_hash(&reordered));
    assert_eq!(bundle_text_hash("{}"), None);
}

/// Target, trust and bundle resolution for one deployment, against the mock
/// stack. No enclave connection or share release is attempted.
#[cfg(feature = "e2e-testing-unsafe")]
#[tokio::test]
#[ignore = "run make test-quorum-mock"]
async fn deployment_release_resolves_exact_target_trust_and_bundle() {
    let work = PathBuf::from(std::env::var("QUORUM_RECOVERY_TEST_DIR").unwrap());
    let base_url = std::env::var("PUBLIC_CERTIFICATE_SERVICE_URL").unwrap();
    let config_path = work.join("deployment-release-client.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&json!({
            "session_id": "mock-recovery", "expires_at": "2099-01-01T00:00:00Z", "server_url": base_url,
        }))
        .unwrap(),
    )
    .unwrap();
    let client = ApiClient {
        base_url,
        client: reqwest::Client::new(),
        config_path,
        deployment_path: None,
        verbose: false,
        qr: false,
        workdir: Some(work.clone()),
    };
    let app = uuid::Uuid::new_v4();
    let (live, candidate, gone) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let bundle = work.join("webauthn.json");
    let hash = bundle_text_hash(&fs::read_to_string(&bundle).unwrap()).unwrap();
    let view = |id: uuid::Uuid, role: &str, status: &str, ip: Option<&str>, bundle_hash: &str| {
        json!({
            "id": id, "app_id": app, "role": role, "status": status,
            "commit_sha": "b6e8c92", "public_ip": ip, "bundle_hash": bundle_hash,
            "tls_after_switch": false, "created_at": "2026-10-12T10:00:00Z",
        })
    };
    let fixtures = work.join("mock-resources/api");
    let write = |path: &str, value: serde_json::Value| {
        let file = fixtures.join(format!("{path}.json"));
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, serde_json::to_vec(&value).unwrap()).unwrap();
    };
    let other = "00".repeat(32);
    write(
        &format!("resources/{app}"),
        json!({
            "id": app, "state": "running", "provider_resource_id": "i-live",
            "public_ip": "127.0.0.1", "lifecycle": "deployments", "live_deployment_id": live,
        }),
    );
    write(
        &format!("resources/{app}/deployments"),
        json!([
            view(live, "live", "running", Some("127.0.0.1"), &other),
            view(candidate, "candidate", "running", Some("127.0.0.1"), &hash),
        ]),
    );
    write(
        &format!("deployments/{live}"),
        view(live, "live", "running", Some("127.0.0.1"), &other),
    );
    write(
        &format!("deployments/{candidate}"),
        view(candidate, "candidate", "running", Some("127.0.0.1"), &hash),
    );
    write(
        &format!("deployments/{gone}"),
        view(gone, "candidate", "destroyed", None, &hash),
    );
    // The app-level file holds other (A's) PCRs; B has no trust file of its own yet.
    fs::write(
        work.join(".caution/trusted_hashes.json"),
        serde_json::to_vec(&json!({
            "pcr0": "cd".repeat(48), "pcr1": "cd".repeat(48), "pcr2": "cd".repeat(48),
        }))
        .unwrap(),
    )
    .unwrap();
    let release = |deployment: Option<uuid::Uuid>| {
        send_shard(
            &client,
            Some(app.to_string()),
            deployment.map(|d| d.to_string()),
            Some(bundle.clone()),
            None,
            crate::share_release::Options::default(),
        )
    };

    // B's endpoint and recorded bundle resolve, then its own trust file is read:
    // missing, it fails there and never falls back to the app-level file.
    match release(Some(candidate)).await.unwrap_err() {
        SendShardError::ReadTrustedHashes { path, .. } => assert_eq!(
            path,
            crate::verify::trusted_hashes_path(Some(&candidate.to_string()))
        ),
        error => panic!("expected ReadTrustedHashes, got {error}"),
    }
    // Only B was verified. Now the run stops only at holder selection
    // (non-interactive, no --holder).
    let trust = work.join(format!(".caution/deployments/{candidate}"));
    fs::create_dir_all(&trust).unwrap();
    fs::write(
        trust.join("trusted_hashes.json"),
        serde_json::to_vec(&json!({
            "pcr0": "ab".repeat(48), "pcr1": "ab".repeat(48), "pcr2": "ab".repeat(48),
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        release(Some(candidate)).await.unwrap_err(),
        SendShardError::SelectHolder { .. }
    ));
    // A was built with another bundle: refused before any connection.
    assert!(matches!(
        release(Some(live)).await.unwrap_err(),
        SendShardError::DeploymentBundle { .. }
    ));
    // A destroyed deployment has no endpoint.
    assert!(matches!(
        release(Some(gone)).await.unwrap_err(),
        SendShardError::NoDeploymentEndpoint { .. }
    ));
    // Bare release with two running deployments requires -d.
    assert!(matches!(
        release(None).await.unwrap_err(),
        SendShardError::BareTarget { .. }
    ));
}
