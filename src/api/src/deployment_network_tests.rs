//! Local-only validation of the exact bootstrap expression used by both AWS paths.
use super::{bootstrap_locals, tests::deployment_request};
use base64::Engine;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn command_input(command: &mut Command, input: &[u8]) -> Vec<u8> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn enclave_tls_rejects_application_ports_owned_by_its_caddy_listener() {
    for port in [80, 443] {
        for mode in ["disabled", "steve", "tls"] {
            let mut value = serde_json::json!({
                "http": {"port": port, "domain": "app.example.com"},
                "ingress": [{"cidr_ipv4": "0.0.0.0/0", "port": port}],
                "egress": [{"cidr_ipv4": "0.0.0.0/0"}]
            });
            if mode != "disabled" {
                value["http"]["e2e_encryption"] = serde_json::json!({"mode": mode});
            }
            let network: caution_config::NetworkConfig = serde_json::from_value(value).unwrap();
            assert_eq!(
                network.policy().is_err(),
                mode == "tls",
                "mode {mode}, port {port}"
            );
        }
    }
}

#[test]
#[ignore = "requires local terraform, gzip and Caddy; no AWS calls or running-service changes"]
fn terraform_network_policy_bootstrap_renders_and_adapts_without_cloud_access() {
    for (mode, digest) in ["disabled", "steve", "tls"]
        .into_iter()
        .flat_map(|mode| [None, Some("a".repeat(64))].map(|digest| (mode, digest)))
    {
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.tap_framer_sha256 = digest;
        request.domain = Some("policy-test.invalid".into());
        request.egress = true;
        request.e2e = mode != "disabled";
        request.e2e_mode = mode.into();
        let http_port = if mode == "tls" { 8080 } else { 80 };
        request.http_port = Some(http_port);
        let source = if mode == "tls" {
            "0.0.0.0/0"
        } else {
            "198.51.100.0/24"
        };
        let mut network = serde_json::json!({
            "ingress": [
                {"cidr_ipv4": source, "port": http_port},
                {"cidr_ipv4": "203.0.113.1/32", "start_port": 9000, "end_port": 9002}
            ],
            "http": {"port": http_port},
            "egress": [
                {"cidr_ipv4": "192.0.2.8/32", "ip_protocol": "tcp", "port": 443},
                {"cidr_ipv4": "10.0.100.1/32", "ip_protocol": "udp", "port": 53},
                {"cidr_ipv4": "10.0.100.1/32", "ip_protocol": "tcp", "port": 53}
            ]
        });
        if mode != "disabled" {
            network["http"]["e2e_encryption"] = serde_json::json!({"mode": mode});
        }
        request.network = serde_json::from_value(network).unwrap();
        let policy = request.network.policy().unwrap();
        request.ports = policy.ports();
        let directory = tempfile::tempdir().unwrap();
        let body = hcl::Body::builder()
            .add_block(bootstrap_locals(
                &request,
                2,
                "s3://fixture/enclave.eif",
                &policy,
            ))
            .build();
        std::fs::write(
            directory.path().join("main.tf"),
            hcl::to_string(&body).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("user-data.sh"),
            include_str!("../../../terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("network-policy.sh.tftpl"),
            include_str!("../../../terraform/modules/aws/nitro-enclave/network-policy.sh.tftpl"),
        )
        .unwrap();
        let encoded = command_input(
            Command::new("terraform")
                .args(["console", "-no-color"])
                .current_dir(directory.path())
                .env("CHECKPOINT_DISABLE", "1"),
            b"local.enclave_user_data\n",
        );
        let encoded: String = serde_json::from_slice(&encoded).unwrap();
        assert!(
            encoded.len() <= 21844,
            "compressed bootstrap must fit EC2 user-data"
        );
        let compressed = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert!(compressed.len() <= 16384);
        let rendered = command_input(Command::new("gzip").args(["-d", "-c"]), &compressed);
        command_input(Command::new("bash").arg("-n"), &rendered);
        let rendered = String::from_utf8(rendered).unwrap();
        let digest = request
            .tap_framer_sha256
            .as_deref()
            .unwrap_or(super::SOURCE_TAP_FRAMER_SHA256.trim());
        assert!(rendered.contains(&format!("'{digest}' /opt/nitro/tap-framer.download")));
        assert!(
            rendered.contains("-A CAUTION_EGRESS -d 192.0.2.8/32 -p tcp --dport 443:443 -j ACCEPT")
        );
        assert!(
            rendered.contains("-A CAUTION_INPUT -d 10.0.100.1/32 -p udp --dport 53:53 -j ACCEPT")
        );
        assert!(
            rendered.contains(
                "-A CAUTION_INGRESS -s 203.0.113.1/32 -p tcp --dport 9000:9002 -j ACCEPT"
            )
        );
        assert!(rendered.contains("-A CAUTION_INGRESS -p tcp --dport 49500:49600 -j DROP"));
        assert!(rendered.contains("-A CAUTION_INGRESS_GUARD -p tcp --dport 9000:9002 -j DROP"));
        assert!(!rendered.contains(&format!("vsock-proxy-{http_port}.service")));
        for port in 9000..=9002 {
            assert!(rendered.contains(&format!("vsock-proxy-{port}.service")));
        }
        if mode == "disabled" {
            assert!(rendered.contains("TCP-LISTEN:49503,bind=127.0.0.1"));
            assert!(rendered.contains("localhost:49503"));
        } else {
            assert!(!rendered.contains("vsock-proxy-http.service"));
        }
        let caddyfile = rendered
            .split("<<'CADDY_CONFIG'\n")
            .nth(1)
            .unwrap()
            .split("\nCADDY_CONFIG")
            .next()
            .unwrap();
        let path = directory.path().join("Caddyfile");
        std::fs::write(&path, caddyfile).unwrap();
        let binary = std::env::var("CADDY_BINARY").unwrap_or_else(|_| "caddy".into());
        let output = Command::new(binary)
            .args(["adapt", "--adapter", "caddyfile", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let adapted: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(adapted["apps"]["http"]["servers"].is_object());
    }
}
