// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::{
    ApiClient, output,
    quorum_init::{InitError, InitErrorCtx as Ctx},
    quorum_legacy,
};
use dterror::ResultExt;
use keymaker_models::generate_quorum::GenerateQuorumResponse;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

const UPLOAD_FAILURE: &str = "upload outcome unknown; local bundle is unchanged; retry secret upload with the same bundle to check Platform before uploading";

#[derive(clap::Args, Debug)]
pub(crate) struct Options {
    /// Saved proofed V1 bundle; the file is never rewritten.
    #[arg(long, default_value = ".caution/quorum-bundle.json")]
    bundle: PathBuf,
    /// Trusted Keymaker policy (otherwise environment, project policy, or saved Platform trust).
    #[arg(long)]
    keymaker_pcr_policy: Option<PathBuf>,
}

fn upload_body(client: &ApiClient, options: &Options) -> Result<Value, InitError> {
    let text =
        fs::read_to_string(&options.bundle).with_context(Ctx::new("read saved V1 bundle"))?;
    let response: GenerateQuorumResponse = serde_json::from_str(&text).with_context(Ctx::new(
        "expected proofed V1 bundle; use import-legacy --upload for raw V0",
    ))?;
    quorum_legacy::load(
        &text,
        false,
        options.keymaker_pcr_policy.as_deref(),
        Some(client),
    )?;
    let bundle = response.data.clone().to_latest();
    eprintln!(
        "Verified bundle {} · {} of {} holders",
        uuid::Uuid::from_bytes(bundle.bundle_id),
        bundle.threshold,
        bundle.max,
    );
    let mut labels = bundle.label;
    let name = labels.remove("name");
    Ok(serde_json::json!({"data": response, "name": name, "labels": labels}))
}

fn already_uploaded(records: &[Value], body: &Value) -> Result<bool, InitError> {
    let mut found = false;
    for record in records {
        if record["data"]["data"]["bundle_id"] != body["data"]["data"]["bundle_id"] {
            continue;
        }
        if record["data"] != body["data"] {
            return Err(InitError::invalid(
                "Platform has different data for this bundle ID; upload refused",
            ));
        }
        found = true;
    }
    Ok(found)
}

pub(crate) async fn run(client: &ApiClient, options: Options) -> Result<(), InitError> {
    // Verify before authentication or any Platform request. Never contact Keymaker.
    let body = upload_body(client, &options)?;
    let config = client.ensure_authenticated().await.with_context(Ctx::new(
        "saved bundle is unchanged; authenticate before uploading",
    ))?;
    upload_verified(client, &config.session_id, &body).await
}

async fn upload_verified(
    client: &ApiClient,
    session_id: &str,
    body: &Value,
) -> Result<(), InitError> {
    let records: Vec<Value> = client
        .get_protected_json(
            session_id,
            "/api/quorum-bundles",
            "check prior bundle upload",
        )
        .await
        .with_context(Ctx::new(
            "unable to check prior upload; no upload attempted",
        ))?;
    if already_uploaded(&records, body)? {
        output::success("Bundle already uploaded to Platform; no upload needed.");
        return Ok(());
    }
    let bytes = serde_json::to_vec(body).with_context(Ctx::new("serialize saved bundle upload"))?;
    output::status("Authorize Platform upload of the saved bundle.");
    eprintln!("Payload SHA-256: {}", hex::encode(Sha256::digest(&bytes)));
    let response = client
        .signed_request(
            session_id,
            "/api/quorum-bundles",
            reqwest::Method::POST,
            bytes,
        )
        .await
        .with_context(Ctx::new(UPLOAD_FAILURE))?;
    if !response.status().is_success() {
        let message = client.api_error_message(response).await;
        return Err(InitError::invalid(
            [
                "Platform upload returned an error: ",
                &message,
                "; ",
                UPLOAD_FAILURE,
            ]
            .concat(),
        ));
    }
    let stored: Value = response
        .json()
        .await
        .with_context(Ctx::new(UPLOAD_FAILURE))?;
    if !already_uploaded(&[stored], body)? {
        return Err(InitError::invalid(UPLOAD_FAILURE));
    }
    output::success("Bundle uploaded to Platform.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        secret: crate::SecretCommands,
    }

    #[test]
    fn upload_parses_saved_bundle_and_policy() {
        let cli = TestCli::try_parse_from([
            "caution",
            "upload",
            "--bundle",
            "saved.json",
            "--keymaker-pcr-policy",
            "trusted.json",
        ])
        .unwrap();
        let crate::SecretCommands::Upload(options) = cli.secret else {
            panic!("wrong command")
        };
        assert_eq!(options.bundle, PathBuf::from("saved.json"));
        assert_eq!(
            options.keymaker_pcr_policy,
            Some(PathBuf::from("trusted.json"))
        );
    }

    #[test]
    fn prior_upload_matches_complete_artifact_and_rejects_id_conflicts() {
        let body = serde_json::json!({"data":{"data":{"bundle_id":[1],"public_key":"key"},"necroproof":[2]}});
        let record = serde_json::json!({"data":body["data"],"name":"renamed","id":"platform-id"});
        assert!(!already_uploaded(&[], &body).unwrap());
        assert!(already_uploaded(&[record.clone()], &body).unwrap());
        let unrelated = serde_json::json!({"data":{"data":{"bundle_id":[3]}}});
        assert!(!already_uploaded(&[unrelated], &body).unwrap());
        let mut conflict = record.clone();
        conflict["data"]["necroproof"] = serde_json::json!([9]);
        assert!(already_uploaded(&[record, conflict], &body).is_err());
    }

    #[tokio::test]
    async fn invalid_bundle_is_rejected_before_authentication_and_kept_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bundle.json");
        let policy = directory.path().join("policy.json");
        fs::write(
            &policy,
            serde_json::json!({"sets":[{"pcrs":{
                "0":"ab".repeat(48), "1":"ab".repeat(48), "2":"ab".repeat(48),
            }}]})
            .to_string(),
        )
        .unwrap();
        let client = ApiClient {
            base_url: "http://127.0.0.1:1".into(),
            client: reqwest::Client::new(),
            config_path: directory.path().join("no-auth.json"),
            deployment_path: None,
            verbose: false,
            qr: false,
            workdir: None,
        };
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/v1-contract.json")).unwrap();
        let missing_proof =
            serde_json::json!({"data":fixture["quorum"]["data"],"necroproof":[]}).to_string();
        for (text, expected) in [
            ("{}", "expected proofed V1 bundle"),
            (
                include_str!("../../../tests/fixtures/imported-v0.json"),
                "expected proofed V1 bundle",
            ),
            (missing_proof.as_str(), "unable to load quorum bundle"),
        ] {
            fs::write(&path, text).unwrap();
            let error = run(
                &client,
                Options {
                    bundle: path.clone(),
                    keymaker_pcr_policy: Some(policy.clone()),
                },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(fs::read_to_string(&path).unwrap(), text);
            assert!(!client.config_path.exists());
        }
    }

    #[tokio::test]
    async fn successful_or_uncertain_upload_is_reconciled_without_a_second_post() {
        use axum::{
            Json, Router,
            http::{HeaderMap, StatusCode},
            routing::{get, post},
        };
        use std::sync::{Arc, Mutex};

        for lost_success in [false, true] {
            let records = Arc::new(Mutex::new(Vec::<Value>::new()));
            let calls = Arc::new(Mutex::new(Vec::new()));
            let list_records = records.clone();
            let list_calls = calls.clone();
            let post_records = records.clone();
            let post_calls = calls.clone();
            let begin_calls = calls.clone();
            let app = Router::new()
                .route("/api/quorum-bundles", get(move || {
                    let records = list_records.clone();
                    list_calls.lock().unwrap().push("list");
                    async move { Json(records.lock().unwrap().clone()) }
                }).post(move |headers: HeaderMap, Json(body): Json<Value>| {
                    let records = post_records.clone();
                    post_calls.lock().unwrap().push("upload");
                    async move {
                        assert_eq!(headers["X-Fido2-Challenge-Id"], "test-challenge");
                        assert_eq!(headers["X-Fido2-Response"], "test-assertion");
                        let record = serde_json::json!({"data":body["data"],"id":"record"});
                        records.lock().unwrap().push(record.clone());
                        if lost_success { (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"response lost after storage"}))) }
                        else { (StatusCode::OK, Json(record)) }
                    }
                }))
                .route("/auth/qr-sign/begin", post(move |Json(body): Json<Value>| {
                    begin_calls.lock().unwrap().push("sign");
                    async move {
                        assert_eq!(body["method"], "POST");
                        assert_eq!(body["path"], "/quorum-bundles");
                        let payload = body["body"].as_str().unwrap();
                        assert_eq!(body["body_hash"], hex::encode(Sha256::digest(payload.as_bytes())));
                        Json(serde_json::json!({"challenge_id":"test-challenge","token":"test-token","url":"http://localhost/test-only","expires_at":"2099-01-01T00:00:00Z"}))
                    }
                }))
                .route("/auth/qr-sign/status", get(|| async {
                    Json(serde_json::json!({"status":"completed","fido2_response":"test-assertion","challenge_id":"test-challenge"}))
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = ApiClient {
                base_url: ["http://", &listener.local_addr().unwrap().to_string()].concat(),
                client: reqwest::Client::new(),
                config_path: PathBuf::new(),
                deployment_path: None,
                verbose: false,
                qr: true,
                workdir: None,
            };
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            // Upload orchestration only: mock QR approval, no proof/authentication bypass in run().
            let body = serde_json::json!({"data":{"data":{"bundle_id":[1],"public_key":"key"},"necroproof":[2]}});
            let original = body.clone();
            let result = upload_verified(&client, "test-session", &body).await;
            if lost_success {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("upload outcome unknown")
                );
            } else {
                result.unwrap();
            }
            upload_verified(&client, "test-session", &body)
                .await
                .unwrap();
            assert_eq!(body, original);
            assert_eq!(records.lock().unwrap().len(), 1);
            assert_eq!(*calls.lock().unwrap(), ["list", "sign", "upload", "list"]);
            server.abort();
            let _ = server.await;
        }
    }
}
