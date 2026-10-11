use super::*;
use clap::Parser;

fn client(root: &Path, platform: &str) -> ApiClient {
    ApiClient {
        base_url: platform.into(),
        client: reqwest::Client::new(),
        config_path: root.join("config.json"),
        deployment_path: None,
        verbose: false,
        qr: false,
        workdir: None,
    }
}
fn record(platform: &str, service: Service) -> Record {
    Record {
        version: 1,
        platform: platform_key(platform).unwrap(),
        service,
        endpoint: "https://keys.example.com".into(),
        verified_at: "2026-09-28T12:00:00Z".into(),
        source: serde_json::json!({"app_source":{"commit":"11".repeat(20)}}),
        tls: None,
        policy: serde_json::json!({"sets":[{"pcrs":{"0":"11".repeat(48),"1":"22".repeat(48),"2":"33".repeat(48)}}]}),
    }
}
#[test]
fn service_selector_conflicts_with_application_verification_inputs() {
    assert!(crate::Cli::try_parse_from(["caution", "verify", "--service", "keymaker"]).is_ok());
    assert!(
        crate::Cli::try_parse_from([
            "caution",
            "verify",
            "--service",
            "key-service",
            "--no-cache"
        ])
        .is_ok()
    );
    for (flag, value) in [
        ("--attestation-url", Some("https://example.com")),
        ("--pcrs", Some("pcrs.json")),
        ("--app-source-url", Some("https://example.com/source")),
        ("--from-tarball", Some("source.tar")),
        ("--from-local", None),
        ("--inspect-attestation", None),
    ] {
        let mut args = vec!["caution", "verify", "--service", "keymaker", flag];
        if let Some(value) = value {
            args.push(value);
        }
        assert!(crate::Cli::try_parse_from(args).is_err(), "{flag}");
    }
}
#[test]
fn trust_is_separated_by_platform_and_role_and_validated_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let alpha = client(dir.path(), "https://alpha.example.com/");
    let beta = client(dir.path(), "https://beta.example.com");
    let path = record_path(&alpha, Service::Keymaker).unwrap();
    let mut saved = record(&alpha.base_url, Service::Keymaker);
    save_record(&path, &saved).unwrap();
    assert!(read_record(&alpha, Service::Keymaker).unwrap().is_some());
    assert!(read_record(&beta, Service::Keymaker).unwrap().is_none());
    assert!(read_record(&alpha, Service::KeyService).unwrap().is_none());
    assert_eq!(
        path,
        record_path(
            &client(dir.path(), "https://ALPHA.example.com:443"),
            Service::Keymaker
        )
        .unwrap()
    );
    saved.platform = beta.base_url.clone();
    save_record(&path, &saved).unwrap();
    assert!(read_record(&alpha, Service::Keymaker).is_err());
}
#[test]
fn updates_preserve_previous_record_and_application_measurements() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://alpha.example.com");
    let app = dir.path().join(".caution");
    fs::create_dir(&app).unwrap();
    fs::write(app.join("trusted_hashes.json"), "application baseline").unwrap();
    let path = record_path(&client, Service::KeyService).unwrap();
    let first = record(&client.base_url, Service::KeyService);
    save_record(&path, &first).unwrap();
    let old = fs::read(&path).unwrap();
    let mut next = first;
    next.endpoint = "https://new.example.com".into();
    save_record(&path, &next).unwrap();
    assert_eq!(
        read_record(&client, Service::KeyService)
            .unwrap()
            .unwrap()
            .endpoint,
        next.endpoint
    );
    let backups: Vec<_> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("previous-")
        })
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(&backups[0]).unwrap(), old);
    assert_eq!(
        fs::read_to_string(app.join("trusted_hashes.json")).unwrap(),
        "application baseline"
    );
}
#[test]
fn discovery_requires_unambiguous_machine_identity_and_safe_endpoint() {
    for url in [
        "http://keys.example.com",
        "https://user:password@keys.example.com",
        "https://keys.example.com?q=x",
        "https://keys.example.com/#fragment",
    ] {
        assert!(service_url(url).is_err());
    }
    let parse = |entries| {
        serde_json::from_value::<Snapshot>(serde_json::json!({"pending":false,"entries":entries}))
            .unwrap()
    };
    let entries = serde_json::json!([{"name":"Keymaker","url":"https://wrong.example.com"},{"id":"future-service"},{"id":"keymaker","url":"https://keys.example.com/"}]);
    assert_eq!(
        select_endpoint(parse(entries), Service::Keymaker).unwrap(),
        "https://keys.example.com"
    );
    assert!(
        select_endpoint(
            parse(serde_json::json!([{"name":"Keymaker","url":"https://keys.example.com"}])),
            Service::Keymaker
        )
        .is_err()
    );
    assert!(select_endpoint(parse(serde_json::json!([{"id":"keymaker","url":"https://keys.example.com"},{"id":"keymaker","url":"https://other.example.com"}])), Service::Keymaker).is_err());
}
#[test]
fn saved_policy_rejects_debug_incomplete_extra_pcrs_or_no_current_set() {
    let mut saved = record("https://alpha.example.com", Service::Keymaker);
    assert!(saved.policy_text().is_ok());
    let valid = saved.policy.clone();
    saved.policy["sets"][0]["pcrs"]["0"] = "00".repeat(48).into();
    assert!(saved.policy_text().is_err());
    saved.policy = valid.clone();
    saved.policy["sets"][0]["pcrs"]
        .as_object_mut()
        .unwrap()
        .remove("1");
    assert!(saved.policy_text().is_err());
    saved.policy = valid.clone();
    saved.policy["sets"][0]["pcrs"]["8"] = "11".repeat(48).into();
    assert!(saved.policy_text().is_err());
    saved.policy = valid;
    saved.policy["sets"][0]["expires_at_unix_seconds"] = 123.into();
    assert!(saved.policy_text().is_err());
}
#[tokio::test]
async fn explicit_release_configuration_does_not_read_corrupt_saved_trust() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://alpha.example.com");
    let path = record_path(&client, Service::KeyService).unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "bad json").unwrap();
    let policy = dir.path().join("manual.json");
    fs::write(
        &policy,
        record(&client.base_url, Service::KeyService)
            .policy_text()
            .unwrap(),
    )
    .unwrap();
    let options = crate::share_release::Options {
        recryptor_url: Some("http://explicit.example.com".into()),
        recryptor_pcr_policy: Some(policy),
        ..Default::default()
    };
    assert_eq!(
        release_config_at(&client, &options, dir.path())
            .await
            .unwrap()
            .0,
        "http://explicit.example.com"
    );
}
#[tokio::test]
async fn explicit_endpoint_never_borrows_other_endpoint_trust() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://alpha.example.com");
    save_record(
        &record_path(&client, Service::KeyService).unwrap(),
        &record(&client.base_url, Service::KeyService),
    )
    .unwrap();
    let options = crate::share_release::Options {
        recryptor_url: Some("https://other.example.com".into()),
        ..Default::default()
    };
    assert!(
        release_config_at(&client, &options, dir.path())
            .await
            .is_err()
    );
}
#[test]
fn explicit_keymaker_policy_preserves_historical_rules_and_never_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://alpha.example.com");
    let path = dir.path().join("manual.json");
    save_record(
        &record_path(&client, Service::Keymaker).unwrap(),
        &record(&client.base_url, Service::Keymaker),
    )
    .unwrap();
    assert!(keymaker_policy(&client, Some(&path)).is_err());
    fs::write(&path, "bad json").unwrap();
    assert!(keymaker_policy(&client, Some(&path)).is_err());
    let mut policy = record(&client.base_url, Service::Keymaker).policy;
    policy["sets"][0]["expires_at_unix_seconds"] = 123.into();
    policy["sets"][0]["pcrs"]["8"] = "44".repeat(48).into();
    fs::write(&path, policy.to_string()).unwrap();
    let result: serde_json::Value =
        serde_json::from_str(&keymaker_policy(&client, Some(&path)).unwrap()).unwrap();
    assert_eq!(result, policy);
}

#[test]
fn service_sources_require_immutable_remote_inputs_before_building() {
    let framework_url = [
        "https://codeberg.org/caution/platform/archive/",
        &"bb".repeat(20),
        ".tar.gz",
    ]
    .concat();
    let enclave_url = [
        "https://codeberg.org/caution/enclaveos/archive/",
        &"cc".repeat(20),
        ".tar.gz",
    ]
    .concat();
    let manifest = serde_json::json!({
        "version":"1.0", "powered_by":"https://caution.co",
        "app_source":{"urls":["https://codeberg.org/caution/locksmith"],"commit":"aa".repeat(20)},
        "framework_source":{"type":"git_archive","url":framework_url,"commit":"bb".repeat(20)},
        "enclave_source":{"type":"git_archive","urls":[enclave_url],"commit":"cc".repeat(20)}
    });
    let parsed = serde_json::from_value(manifest.clone()).unwrap();
    assert!(validate_source(Some(&parsed)).is_ok());
    assert!(validate_source(None).is_err());
    for changed in [
        {
            let mut m = manifest.clone();
            m["app_source"]["urls"] =
                serde_json::json!(["https://example.com/repo/archive/main.tar.gz"]);
            m
        },
        {
            let mut m = manifest.clone();
            m["framework_source"]["url"] = "https://example.com/repo/archive/main.tar.gz".into();
            m
        },
        {
            let mut m = manifest.clone();
            m["enclave_source"]["urls"] =
                serde_json::json!(["https://example.com/repo/archive/main.tar.gz"]);
            m
        },
        {
            let mut m = manifest.clone();
            m["app_source"]["commit"] = "HEAD".into();
            m
        },
        {
            let mut m = manifest.clone();
            m["app_source"]["urls"] = serde_json::json!(["file:///local/source"]);
            m
        },
        {
            let mut m = manifest.clone();
            m["framework_source"]["commit"] = serde_json::Value::Null;
            m
        },
        {
            let mut m = manifest.clone();
            m["enclave_source"] = serde_json::json!({"type":"local","path":"/tmp/source"});
            m
        },
    ] {
        let parsed = serde_json::from_value(changed).unwrap();
        assert!(validate_source(Some(&parsed)).is_err());
    }
}

#[tokio::test]
async fn noninteractive_setup_preserves_existing_trust_without_network() {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://unreachable.invalid");
    let path = record_path(&client, Service::Keymaker).unwrap();
    save_record(&path, &record(&client.base_url, Service::Keymaker)).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(run(&client, Service::Keymaker, false).await.is_err());
    assert_eq!(fs::read(path).unwrap(), before);
}

#[tokio::test]
async fn discovery_retries_pending_but_rejects_redirects_and_large_bodies() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn serve(
        responses: Vec<String>,
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let size = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                assert!(request.starts_with("GET /.well-known/caution/build-inputs "));
                assert!(!request.to_ascii_lowercase().contains("authorization:"));
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (format!("http://{address}"), task)
    }
    fn response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
    let pending = r#"{"services":{"pending":true,"entries":[]}}"#;
    let ready = r#"{"services":{"pending":false,"entries":[{"id":"keymaker","url":"https://keys.example.com"}]}}"#;
    let dir = tempfile::tempdir().unwrap();
    let (url, server) = serve(
        vec![response("200 OK", pending), response("200 OK", ready)],
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        discover(&client(dir.path(), &url), Service::Keymaker)
            .await
            .unwrap(),
        "https://keys.example.com"
    );
    server.await.unwrap();
    // A cold API request may wait for five-second probes plus verification.
    let (url, server) = serve(vec![response("200 OK", ready)], Duration::from_secs(6)).await;
    assert_eq!(
        discover(&client(dir.path(), &url), Service::Keymaker)
            .await
            .unwrap(),
        "https://keys.example.com"
    );
    server.await.unwrap();
    for reply in [
        response("302 Found", ready),
        response("200 OK", &"x".repeat(1024 * 1024 + 1)),
        response("200 OK", "{}"),
        response("200 OK", "not json"),
    ] {
        let (url, server) = serve(vec![reply], Duration::ZERO).await;
        assert!(
            discover(&client(dir.path(), &url), Service::Keymaker)
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}

#[path = "service_trust_rollover_tests.rs"]
mod rollover;
