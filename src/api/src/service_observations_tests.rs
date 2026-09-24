use super::*;
use serde_json::json;

// AWS-signed SDK fixture; historical clock only in tests, never production.
const QUOTE: &[u8] = include_bytes!("../tests/fixtures/service-attestation.cbor");
fn fixture() -> Value {
    json!({"document": STANDARD.encode(QUOTE)})
}
fn nonce() -> [u8; 32] {
    hex::decode("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636")
        .unwrap()
        .try_into()
        .unwrap()
}
fn measured() -> HashMap<u8, Vec<u8>> {
    authenticate(&fixture(), &nonce(), Duration::from_secs(1766510416)).unwrap()
}
fn policy_json(pcrs: &HashMap<u8, Vec<u8>>, expiry: Option<u64>) -> String {
    json!({"sets":[{"pcrs":pcrs.iter().map(|(i,v)| (i.to_string(),hex::encode(v))).collect::<BTreeMap<_,_>>(),"expires_at_unix_seconds":expiry}]}).to_string()
}

#[test]
fn authentic_evidence_wrong_nonce_signature_and_expired_chain() {
    assert!(measured().contains_key(&3));
    assert!(authenticate(&fixture(), &[5; 32], Duration::from_secs(1766510416)).is_err());
    let mut bytes = QUOTE.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(
        authenticate(
            &json!({"document":STANDARD.encode(bytes)}),
            &nonce(),
            Duration::from_secs(1766510416)
        )
        .is_err()
    );
    assert!(authenticate(&fixture(), &nonce(), Duration::from_secs(0)).is_err());
}

#[test]
fn policy_matching_expiry_debug_and_distinct_release_constraints() {
    let pcrs = measured();
    let policy = KeymakerPcrPolicy::from_json(&policy_json(&pcrs, None)).unwrap();
    assert_eq!(
        evaluate_policy("test", Some(&policy), false, Some(&pcrs), 100)
            .result
            .status,
        "passed"
    );
    let other = HashMap::from([(0, vec![1; 48]), (1, vec![1; 48]), (2, vec![1; 48])]);
    assert_eq!(
        evaluate_policy("test", Some(&policy), false, Some(&other), 100)
            .result
            .status,
        "failed"
    );
    let expiring = KeymakerPcrPolicy::from_json(&policy_json(&pcrs, Some(101))).unwrap();
    assert_eq!(
        evaluate_policy("test", Some(&expiring), false, Some(&pcrs), 100)
            .result
            .status,
        "passed"
    );
    assert_eq!(
        evaluate_policy("test", Some(&expiring), false, Some(&pcrs), 101)
            .result
            .status,
        "failed"
    );
    assert_eq!(
        evaluate_policy("test", Some(&expiring), true, Some(&pcrs), 100)
            .result
            .status,
        "failed"
    );
    let zero = HashMap::from([(0, vec![0; 48]), (1, vec![0; 48]), (2, vec![0; 48])]);
    assert!(reject_debug(&zero).is_err());
    let debug = KeymakerPcrPolicy::from_json(&policy_json(&zero, None)).unwrap();
    assert_eq!(
        evaluate_policy("test", Some(&debug), false, Some(&zero), 100)
            .result
            .status,
        "failed"
    );
    assert_eq!(
        evaluate_policy("test", Some(&policy), false, None, 100)
            .result
            .status,
        "failed"
    );
}

#[test]
fn additional_authenticated_pcrs_match_without_widening_share_release() {
    let pcrs = measured();
    let mut pinned: HashMap<_, _> = pcrs
        .iter()
        .filter(|(index, _)| **index <= 2)
        .map(|(index, value)| (*index, value.clone()))
        .collect();
    let base_policy = KeymakerPcrPolicy::from_json(&policy_json(&pinned, None)).unwrap();
    assert_eq!(
        evaluate_policy("release", Some(&base_policy), true, Some(&pcrs), 100)
            .result
            .status,
        "passed"
    );
    // PCR3 is supplied by the real signed fixture, not synthetic attestation.
    pinned.insert(3, pcrs[&3].clone());
    let extended = KeymakerPcrPolicy::from_json(&policy_json(&pinned, None)).unwrap();
    for purpose in ["Bundle generation", "Certificate issuance"] {
        assert_eq!(
            evaluate_policy(purpose, Some(&extended), false, Some(&pcrs), 100)
                .result
                .status,
            "passed"
        );
    }
    assert_eq!(
        evaluate_policy("release", Some(&extended), true, Some(&pcrs), 100)
            .result
            .status,
        "failed"
    );
    pinned.get_mut(&3).unwrap()[0] ^= 1;
    let mismatched = KeymakerPcrPolicy::from_json(&policy_json(&pinned, None)).unwrap();
    assert_eq!(
        evaluate_policy("issuance", Some(&mismatched), false, Some(&pcrs), 100)
            .result
            .status,
        "failed"
    );
    let mut missing = pcrs.clone();
    missing.remove(&3);
    assert_eq!(
        evaluate_policy("issuance", Some(&extended), false, Some(&missing), 100)
            .result
            .status,
        "failed"
    );
    let mut unused = pcrs.clone();
    unused.insert(8, vec![0; 48]);
    assert!(reject_debug(&unused).is_ok());
    unused.insert(0, vec![0; 48]);
    assert!(reject_debug(&unused).is_err());
}

#[test]
fn policies_are_reread_and_public_fields_are_explicit() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), policy_json(&measured(), None)).unwrap();
    assert!(load_policy(file.path()).is_some());
    std::fs::write(file.path(), "bad policy").unwrap();
    assert!(load_policy(file.path()).is_none());
    let metadata = json!({"manifest":{"app_source":{"urls":["file:///secret", "https://codeberg.org/caution/locksmith.git"],"commit":"a".repeat(40),"token":"secret"},"path":"/run/config"},"token":"secret"});
    let source = serde_json::to_value(reported_source(&metadata).unwrap()).unwrap();
    assert_eq!(source.as_object().unwrap().len(), 2);
    assert_eq!(
        source["repository"],
        "https://codeberg.org/caution/locksmith.git"
    );
    assert!(!source.to_string().contains("secret"));
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/?token=secret",
        "file:///secret",
    ] {
        assert!(public_url(url).is_none());
    }
}

#[tokio::test]
async fn concurrent_refresh_is_coalesced_and_failures_replace_success() {
    let cache = Arc::new(Mutex::new(Cache::default()));
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = vec![];
    for _ in 0..20 {
        let cache = cache.clone();
        let count = count.clone();
        tasks.push(tokio::spawn(async move {
            cached_snapshot(cache, move || async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                vec![]
            })
            .await
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    let cached = cached_snapshot(cache.clone(), || async {
        panic!("must not refresh within one minute")
    })
    .await;
    assert!(!cached.pending);
    assert!(cached.checked_at.is_some());
    {
        let mut state = cache.lock().await;
        state.snapshot.entries.push(Service {
            name: "old success",
            url: None,
            readiness: Check::success(),
            attestation: Check::success(),
            measurements: BTreeMap::new(),
            policies: vec![],
            service_reported_source: None,
        });
        state.started = Some(Instant::now() - INTERVAL);
    }
    let pending = cached_snapshot(cache.clone(), || async {
        vec![Service {
            name: "latest failure",
            url: None,
            readiness: Check::failure("Unavailable"),
            attestation: Check::failure("Unavailable"),
            measurements: BTreeMap::new(),
            policies: vec![],
            service_reported_source: None,
        }]
    })
    .await;
    assert!(pending.pending);
    assert!(pending.entries.is_empty());
    tokio::task::yield_now().await;
    let state = cache.lock().await;
    assert_eq!(state.snapshot.entries[0].name, "latest failure");
    assert_eq!(state.snapshot.entries[0].readiness.status, "failed");
}

#[tokio::test]
async fn requests_reject_redirects_oversized_bodies_and_timeouts() {
    use axum::{Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/ok",
                    get(|| async { axum::Json(json!({"status":"ready"})) }),
                )
                .route(
                    "/redirect",
                    get(|| async { axum::response::Redirect::temporary("/ok") }),
                )
                .route("/large", get(|| async { "x".repeat(1024) }))
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                        "{}"
                    }),
                ),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap();
    let base = ["http://", &address.to_string()].concat();
    assert!(
        fetch(client.get([&base, "/ok"].concat()), 1024)
            .await
            .is_ok()
    );
    assert!(
        fetch(client.get([&base, "/redirect"].concat()), 1024)
            .await
            .is_err()
    );
    assert_eq!(
        fetch(client.get([&base, "/large"].concat()), 10)
            .await
            .unwrap_err()
            .reason,
        "Response too large"
    );
    assert!(
        fetch(client.get([&base, "/slow"].concat()), 1024)
            .await
            .is_err()
    );
    server.abort();
}
