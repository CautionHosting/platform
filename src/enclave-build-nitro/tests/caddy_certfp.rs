use std::{net::TcpListener, path::PathBuf, process::Command};

#[test]
fn publishes_only_trusted_hostname_certificates_and_rotates() {
    let openssl = std::env::var("OPENSSL").unwrap_or_else(|_| "openssl".to_string());
    let s_server_help = Command::new(&openssl)
        .args(["s_server", "-help"])
        .output()
        .expect("openssl must be installed for the Caddy certfp integration test");
    let help = String::from_utf8_lossy(&s_server_help.stderr);
    if !help.contains("-cert_chain") {
        eprintln!("skipping: this OpenSSL lacks s_server -cert_chain");
        return;
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("sh")
        .arg(manifest_dir.join("tests/caddy-certfp-integration.sh"))
        .env("CADDY_TEST_OPENSSL", openssl)
        .env("CADDY_TEST_PORT", port.to_string())
        .env(
            "CADDY_TEST_PUBLISHER",
            manifest_dir.join("templates/caddy-certfp.sh"),
        )
        .status()
        .unwrap();

    assert!(status.success(), "Caddy certfp integration test failed");
}
