use super::*;

fn source(url: &str) -> AppSource {
    AppSource {
        urls: vec![url.to_owned()],
        commit: "ab".repeat(20),
        branch: Some("main".into()),
    }
}
#[test]
fn repository_candidates_are_https_and_commit_pinned_without_changing_manifest() {
    for repo in [
        "https://codeberg.org/caution/locksmith",
        "https://forge.example:8443/team/repo.git",
    ] {
        let source = source(repo);
        let before = serde_json::to_value(&source).unwrap();
        let urls = archive_urls(&source).unwrap();
        assert_eq!(urls.len(), 3);
        for url in urls {
            assert_eq!(url.scheme(), "https");
            assert!(url.path().contains(&source.commit));
            assert!(!url.path().contains("main"));
            assert_eq!(url.port(), Url::parse(repo).unwrap().port());
        }
        assert_eq!(serde_json::to_value(&source).unwrap(), before);
    }
}
#[test]
fn mutable_and_mismatched_direct_archives_fail_before_any_download() {
    for url in [
        "https://example.com/repo/archive/main.tar.gz",
        "https://example.com/repo/archive/refs/heads/main.tar.gz",
        "https://example.com/repo/get/main.tar.gz",
        "https://example.com/repo/archive/0000000000000000000000000000000000000000.tar.gz",
        "https://example.com/source.tar.gz",
        "http://example.com/repo",
    ] {
        assert!(archive_urls(&source(url)).is_err(), "{url}");
    }
    let sha = "ab".repeat(20);
    let url = ["https://example.com/repo/archive/", &sha, ".tar.gz"].concat();
    assert_eq!(
        archive_urls(&source(&url)).unwrap(),
        vec![Url::parse(&url).unwrap()]
    );
    assert!(pinned_archive(&url, &"cd".repeat(20)).is_err());
}
#[tokio::test]
async fn actual_hosted_http_client_refuses_plaintext_before_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/archive/commit.tar.gz",
        listener.local_addr().unwrap()
    );
    assert!(http_client().unwrap().get(url).send().await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}
fn archive(content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "repo/Procfile", content)
        .unwrap();
    builder.into_inner().unwrap()
}
#[test]
fn freshly_staged_content_is_isolated_and_cannot_reuse_legacy_build_cache_keys() {
    let first = stage_bytes(&archive(b"build: true\n"), &"ab".repeat(20)).unwrap();
    let second = stage_bytes(&archive(b"build: false\n"), &"ab".repeat(20)).unwrap();
    assert!(first.cache_key.starts_with("hosted-https-v1-"));
    assert_ne!(first.cache_key, second.cache_key);
    assert_ne!(first.path, second.path);
    assert_eq!(
        std::fs::read(first.path.join("Procfile")).unwrap(),
        b"build: true\n"
    );
    let first_path = first.path.clone();
    drop(first);
    assert!(!first_path.exists());
}
