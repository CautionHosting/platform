// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{Json, Router, extract::Request, http::StatusCode};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;

const APP: &str = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_APP: &str = "550e8400-e29b-41d4-a716-446655440001";
const GIT_URL: &str = "ssh://git@push.example.test:2222/550e8400-e29b-41d4-a716-446655440000.git";

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn app() -> Value {
    json!({"id": APP, "resource_name": "existing-app", "state": "running",
        "provider_resource_id": "i-test", "git_url": GIT_URL})
}

async fn serve(dir: &Path, status: StatusCode, body: Value) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let router = Router::new().fallback(move |request: Request| {
        observed.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.method(), "GET");
        assert_eq!(request.uri().path(), format!("/api/resources/{APP}"));
        assert_eq!(request.headers()["X-Session-ID"], "synthetic-session");
        let body = body.clone();
        async move { (status, Json(body)) }
    });
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let config = dir.join("config/caution-cli");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("config.json"), json!({
        "session_id": "synthetic-session", "expires_at": "2099-01-01T00:00:00Z", "server_url": url,
    }).to_string()).unwrap();
    (url, requests)
}

async fn run(dir: &Path, url: &str, args: &[&str]) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_caution"));
    command
        .current_dir(dir.join("repo"))
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["--url", url, "apps", "sync"])
        .args(args)
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn sync_creates_and_repairs_the_link_without_touching_other_local_data() {
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(
        &repo,
        &["remote", "add", "origin", "https://example.test/source.git"],
    );
    fs::write(repo.join("caution.hcl"), "local configuration\n").unwrap();
    assert!(!repo.join(".caution").exists());
    let (url, requests) = serve(dir.path(), StatusCode::OK, app()).await;

    for attempt in 0..3 {
        if attempt == 1 {
            fs::write(repo.join(".caution/deployment.json"), "broken old metadata").unwrap();
            fs::write(repo.join(".caution/trusted_hashes.json"), "local trust\n").unwrap();
            fs::write(repo.join(".caution/quorum.json"), "local quorum\n").unwrap();
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "caution",
                    "git@old.example.test:old.git",
                ],
            );
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "--add",
                    "caution",
                    "git@other.example.test:old.git",
                ],
            );
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "--push",
                    "caution",
                    "git@old.example.test:wrong.git",
                ],
            );
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "--add",
                    "--push",
                    "caution",
                    "git@other.example.test:wrong.git",
                ],
            );
        }
        let output = run(dir.path(), &url, &["--app-id", APP]).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(
                &fs::read(repo.join(".caution/deployment.json")).unwrap()
            )
            .unwrap(),
            json!({"resource_id": APP})
        );
        assert_eq!(
            git(&repo, &["remote", "get-url", "--all", "caution"]),
            GIT_URL
        );
        assert_eq!(
            git(&repo, &["remote", "get-url", "--push", "--all", "caution"]),
            GIT_URL
        );
        assert_eq!(
            git(&repo, &["remote", "get-url", "origin"]),
            "https://example.test/source.git"
        );
        assert_eq!(
            fs::read_to_string(repo.join("caution.hcl")).unwrap(),
            "local configuration\n"
        );
        if attempt > 0 {
            assert_eq!(
                fs::read_to_string(repo.join(".caution/trusted_hashes.json")).unwrap(),
                "local trust\n"
            );
            assert_eq!(
                fs::read_to_string(repo.join(".caution/quorum.json")).unwrap(),
                "local quorum\n"
            );
        }
    }
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn sync_rejects_unverified_app_data_without_changing_the_existing_link() {
    let mut wrong_id = app();
    wrong_id["id"] = json!(OTHER_APP);
    let mut missing_url = app();
    missing_url["git_url"] = json!("");
    let mut wrong_url = app();
    wrong_url["git_url"] = json!(format!("git@push.example.test:{OTHER_APP}.git"));
    for (status, body) in [
        (StatusCode::FORBIDDEN, json!({"error": "forbidden"})),
        (StatusCode::NOT_FOUND, json!({"error": "not found"})),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "unavailable"}),
        ),
        (StatusCode::OK, wrong_id),
        (StatusCode::OK, missing_url),
        (StatusCode::OK, wrong_url),
    ] {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".caution")).unwrap();
        fs::write(repo.join(".caution/deployment.json"), "existing metadata").unwrap();
        git(&repo, &["init", "-q"]);
        git(
            &repo,
            &["remote", "add", "caution", "git@old.example.test:old.git"],
        );
        let config = fs::read(repo.join(".git/config")).unwrap();
        let (url, requests) = serve(dir.path(), status, body).await;
        let output = run(dir.path(), &url, &["--app-id", APP]).await;
        assert!(!output.status.success());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read_to_string(repo.join(".caution/deployment.json")).unwrap(),
            "existing metadata"
        );
        assert_eq!(fs::read(repo.join(".git/config")).unwrap(), config);
    }
}

#[tokio::test]
async fn sync_reports_git_failure_without_replacing_local_metadata() {
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir_all(repo.join(".caution")).unwrap();
    fs::write(repo.join(".caution/deployment.json"), "existing metadata").unwrap();
    git(&repo, &["init", "-q"]);
    git(
        &repo,
        &["remote", "add", "caution", "git@old.example.test:old.git"],
    );
    fs::write(repo.join(".git/config.lock"), "existing lock").unwrap();
    let (url, _) = serve(dir.path(), StatusCode::OK, app()).await;
    let output = run(dir.path(), &url, &["--app-id", APP]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("git"));
    assert_eq!(
        fs::read_to_string(repo.join(".caution/deployment.json")).unwrap(),
        "existing metadata"
    );
    assert_eq!(
        git(&repo, &["remote", "get-url", "caution"]),
        "git@old.example.test:old.git"
    );
}

#[tokio::test]
async fn sync_requires_an_explicit_app_uuid_and_a_git_worktree() {
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let (url, requests) = serve(dir.path(), StatusCode::OK, app()).await;
    for (args, expected_error) in [
        (vec![], "--app-id <APP_ID>"),
        (vec!["--app-id"], "a value is required"),
        (vec!["--app-id", "not-an-app-id"], "invalid value"),
        (vec![APP], "unexpected argument"),
    ] {
        let output = run(dir.path(), &url, &args).await;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected_error));
        assert!(!repo.join(".caution/deployment.json").exists());
    }
    let output = run(dir.path(), &url, &["--app-id", APP]).await;
    assert!(!output.status.success());
    assert!(!repo.join(".caution/deployment.json").exists());
    git(&repo, &["init", "--bare", "-q"]);
    let output = run(dir.path(), &url, &["--app-id", APP]).await;
    assert!(!output.status.success());
    assert!(!repo.join(".caution/deployment.json").exists());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}
