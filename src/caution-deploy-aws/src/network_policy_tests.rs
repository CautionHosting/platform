use super::*;
use caution_config::NetworkConfig;
use serde_json::{Value, json};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Runs Caddy with its admin API and automatic HTTPS disabled. All listeners and
/// synthetic upstreams use unique loopback-only ports; only this child is killed.
struct LocalCaddy {
    child: Child,
    home: tempfile::TempDir,
    address: SocketAddr,
}

impl Drop for LocalCaddy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn caddy_command(home: &Path) -> Command {
    let mut command = Command::new("/usr/bin/caddy");
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"));
    command
}

/// Only upstream dial addresses are remapped after adapting the production
/// snippet. Management routing/matchers/order are unmodified. This avoids binding
/// production ports 49500/49502 or contacting any preexisting service.
fn remap_test_upstreams(value: &mut Value, steve: SocketAddr, attestation: SocketAddr) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(dial)) = object.get_mut("dial") {
                match dial.as_str() {
                    "localhost:49500" => *dial = steve.to_string(),
                    "localhost:49502" => *dial = attestation.to_string(),
                    _ => {}
                }
            }
            for value in object.values_mut() {
                remap_test_upstreams(value, steve, attestation);
            }
        }
        Value::Array(array) => {
            for value in array {
                remap_test_upstreams(value, steve, attestation);
            }
        }
        _ => {}
    }
}

impl LocalCaddy {
    fn start(render: impl FnOnce(u16) -> String) -> Self {
        let home = tempfile::tempdir().unwrap();
        let ports: Vec<_> = (0..4)
            .map(|_| {
                loop {
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    if !(49500..=49600).contains(&listener.local_addr().unwrap().port()) {
                        break listener;
                    }
                }
            })
            .collect();
        let address = ports[0].local_addr().unwrap();
        let app = ports[1].local_addr().unwrap();
        let attestation = ports[2].local_addr().unwrap();
        let steve = ports[3].local_addr().unwrap();
        let snippet = render(app.port());
        let config = format!(
            "{{\n admin off\n auto_https off\n}}\n\
             http://{address} {{\n bind 127.0.0.1\n{snippet}\n}}\n\
             http://{app} {{\n bind 127.0.0.1\n respond \"APP_UPSTREAM\" 200\n}}\n\
             http://{attestation} {{\n bind 127.0.0.1\n respond \"ATTESTATION_UPSTREAM\" 200\n}}\n\
             http://{steve} {{\n bind 127.0.0.1\n respond \"STEVE_UPSTREAM\" 200\n}}\n"
        );
        let caddyfile = home.path().join("Caddyfile");
        fs::write(&caddyfile, config).unwrap();
        let adapted = caddy_command(home.path())
            .args(["adapt", "--adapter", "caddyfile", "--config"])
            .arg(&caddyfile)
            .output()
            .expect("local Caddy tests require /usr/bin/caddy; never silently skip");
        assert!(
            adapted.status.success(),
            "{}",
            String::from_utf8_lossy(&adapted.stderr)
        );
        let mut adapted: Value = serde_json::from_slice(&adapted.stdout).unwrap();
        assert_eq!(adapted["admin"]["disabled"], true);
        remap_test_upstreams(&mut adapted, steve, attestation);
        let config_path = home.path().join("caddy.json");
        fs::write(&config_path, serde_json::to_vec(&adapted).unwrap()).unwrap();
        let log = fs::File::create(home.path().join("caddy.log")).unwrap();
        drop(ports);
        let child = caddy_command(home.path())
            .args(["run", "--config"])
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            home,
            address,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let exit = server.child.try_wait().unwrap();
            assert!(exit.is_none(), "Caddy exited: {exit:?}\n{}", server.log());
            if server.log().contains("serving initial configuration") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Caddy readiness timeout: {}",
                server.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
        server
    }

    fn log(&self) -> String {
        fs::read_to_string(self.home.path().join("caddy.log")).unwrap()
    }

    fn request(&self, peer: &str, path: &str, headers: &[&str]) -> (u16, String) {
        let mut command = Command::new("curl");
        command.args([
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-time",
            "3",
            "--interface",
            peer,
            "--write-out",
            "\n%{http_code}",
        ]);
        for header in headers {
            command.args(["--header", header]);
        }
        if headers.contains(&"X-E2P-Key: forged") {
            command.args([
                "--request",
                "POST",
                "--data-binary",
                "encrypted-test-payload",
            ]);
        }
        command
            .arg("--dump-header")
            .arg(self.home.path().join("response.headers"));
        let result = command
            .arg(format!("http://{}{path}", self.address))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "curl: {}\nCaddy: {}",
            String::from_utf8_lossy(&result.stderr),
            self.log()
        );
        let response = String::from_utf8(result.stdout).unwrap();
        let (body, status) = response.rsplit_once('\n').unwrap();
        (status.parse().unwrap(), body.into())
    }
}

const FORGED_E2P_HEADERS: &[&str] = &[
    "X-E2P-Key: forged",
    "X-E2P-Original-Method: GET",
    "Content-Type: application/octet-stream",
    "X-Forwarded-For: 127.0.0.2",
    "X-Real-IP: 127.0.0.2",
    "Forwarded: for=127.0.0.2",
];

#[test]
#[ignore = "requires /usr/bin/caddy and curl; run explicitly with --ignored --exact"]
fn local_caddy_enforces_socket_peer_and_management_precedence() {
    for mode in ["disabled", "steve"] {
        let server = LocalCaddy::start(|app_port| {
            let policy = policy(json!({
                "ingress": [{"cidr_ipv4": "127.0.0.2/32", "port": app_port}],
                "http": {"port": app_port}
            }));
            http_routes(&policy, Some(app_port), mode, None)
        });
        let expected_upstream = if mode == "steve" {
            "STEVE_UPSTREAM"
        } else {
            "APP_UPSTREAM"
        };
        for path in ["/", "/application", "/e2p/keys", "/e2p/"] {
            for headers in [&[][..], FORGED_E2P_HEADERS] {
                assert_eq!(
                    server.request("127.0.0.2", path, headers),
                    (200, expected_upstream.into()),
                    "positive control: {mode} {path}"
                );
                assert_eq!(
                    server.request("127.0.0.1", path, headers),
                    (403, "Forbidden".into()),
                    "{mode} {path}"
                );
            }
        }
        for peer in ["127.0.0.1", "127.0.0.2"] {
            assert_eq!(
                server.request(peer, "/.well-known/caution/health", FORGED_E2P_HEADERS),
                (200, "OK".into())
            );
            assert_eq!(
                server.request(peer, "/attestation", FORGED_E2P_HEADERS),
                (200, "ATTESTATION_UPSTREAM".into())
            );
        }
        for path in [
            "/attestation/extra",
            "/attestation/",
            "/.well-known/caution/health/extra",
        ] {
            assert_eq!(
                server.request("127.0.0.1", path, FORGED_E2P_HEADERS).0,
                403,
                "management must be exact: {path}"
            );
        }
    }
}

#[test]
#[ignore = "requires /usr/bin/caddy and curl; run explicitly with --ignored --exact"]
fn local_caddy_tls_redirect_is_peer_scoped_and_preserves_uri() {
    let server = LocalCaddy::start(|app_port| {
        let policy = policy(json!({
            "ingress": [{"cidr_ipv4": "127.0.0.2/32", "port": app_port}],
            "http": {"port": app_port}
        }));
        http_routes(
            &policy,
            Some(app_port),
            "tls",
            Some("application.example.com"),
        )
    });
    assert_eq!(server.request("127.0.0.2", "/hello?x=1&y=2", &[]).0, 308);
    let headers = fs::read_to_string(server.home.path().join("response.headers")).unwrap();
    assert!(
        headers.lines().any(|line| line
            .eq_ignore_ascii_case("Location: https://application.example.com/hello?x=1&y=2")),
        "{headers}"
    );
    assert_eq!(
        server.request("127.0.0.1", "/hello", FORGED_E2P_HEADERS),
        (403, "Forbidden".into())
    );
    assert_eq!(
        server.request("127.0.0.1", "/.well-known/caution/health", &[]),
        (200, "OK".into())
    );
    assert_eq!(
        server.request("127.0.0.1", "/attestation", FORGED_E2P_HEADERS),
        (200, "ATTESTATION_UPSTREAM".into())
    );
}

#[test]
#[ignore = "requires /usr/bin/caddy and curl; run explicitly with --ignored --exact"]
fn local_caddy_no_http_or_unknown_mode_has_no_application_or_e2p_route() {
    for (has_http, mode, domain) in [
        (false, "disabled", None),
        (false, "steve", None),
        (false, "tls", Some("application.example.com")),
        (true, "unknown", None),
        (true, "tls", None),
    ] {
        let server = LocalCaddy::start(|app_port| {
            let mut config = json!({"ingress": [{"cidr_ipv4": "127.0.0.2/32", "port": app_port}]});
            if has_http {
                config["http"] = json!({"port": app_port});
            }
            let snippet = http_routes(&policy(config), has_http.then_some(app_port), mode, domain);
            assert!(!snippet.contains("localhost:49500"));
            assert!(!snippet.contains("@caution_http_sources"));
            assert_eq!(
                snippet.matches("reverse_proxy").count(),
                1,
                "only attestation may proxy"
            );
            snippet
        });
        for peer in ["127.0.0.1", "127.0.0.2"] {
            for path in ["/", "/application", "/e2p/keys", "/e2p/"] {
                assert_eq!(
                    server.request(peer, path, FORGED_E2P_HEADERS),
                    (403, "Forbidden".into()),
                    "{has_http} {mode} {peer} {path}"
                );
            }
            assert_eq!(
                server.request(peer, "/.well-known/caution/health", &[]),
                (200, "OK".into())
            );
            assert_eq!(
                server.request(peer, "/attestation", FORGED_E2P_HEADERS),
                (200, "ATTESTATION_UPSTREAM".into())
            );
        }
    }
}

fn policy(input: Value) -> NetworkPolicy {
    serde_json::from_value::<NetworkConfig>(input)
        .expect("test network config must decode")
        .policy()
        .expect("test policy must validate")
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Ingress {
    low: u16,
    high: u16,
    protocol: String,
    sources: Vec<String>,
}

fn ingress(low: u16, high: u16, source: &str) -> Ingress {
    Ingress {
        low,
        high,
        protocol: "tcp".into(),
        sources: vec![source.into()],
    }
}

fn structural_ingress(blocks: Vec<hcl::Block>) -> Vec<Ingress> {
    blocks
        .into_iter()
        .map(|block| {
            assert_eq!(block.identifier.as_str(), "ingress");
            assert!(block.labels.is_empty());
            let body: Value = hcl::from_body(block.body).unwrap();
            assert!(body.get("ipv6_cidr_blocks").is_none());
            assert!(body.get("security_groups").is_none());
            Ingress {
                low: body["from_port"].as_u64().unwrap().try_into().unwrap(),
                high: body["to_port"].as_u64().unwrap().try_into().unwrap(),
                protocol: body["protocol"].as_str().unwrap().into(),
                sources: serde_json::from_value(body["cidr_blocks"].clone()).unwrap(),
            }
        })
        .collect()
}

#[test]
fn raw_ranges_exclude_all_reserved_ports_without_overflow_or_widening() {
    assert_eq!(
        raw_ranges(1, 65535, Some(8080)),
        vec![
            (1, 21),
            (23, 79),
            (81, 442),
            (444, 8079),
            (8081, 49499),
            (49601, 65535),
        ]
    );
    assert_eq!(
        raw_ranges(8079, 8081, Some(8080)),
        vec![(8079, 8079), (8081, 8081)]
    );
    assert!(raw_ranges(80, 80, Some(80)).is_empty());
    assert!(raw_ranges(443, 443, Some(443)).is_empty());
    assert!(raw_ranges(49500, 49600, None).is_empty());
    assert_eq!(raw_ranges(65534, 65535, Some(65535)), vec![(65534, 65534)]);
    assert_eq!(raw_ranges(1, 2, Some(1)), vec![(2, 2)]);
}

#[test]
fn firewall_forward_rules_have_exact_restore_shape_and_preserve_protocols() {
    let policy = policy(json!({"egress": [
        {"cidr_ipv4": "198.51.100.19/24", "start_port": 8000, "end_port": 8002, "ip_protocol": "tcp"},
        {"cidr_ipv4": "203.0.113.5/32", "port": 53, "ip_protocol": "udp"},
        {"cidr_ipv4": "192.0.2.37/24", "ip_protocol": "all"}
    ]}));
    let mut lines: Vec<_> = egress_forward_rules(&policy)
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    assert_eq!(
        lines,
        [
            "-A CAUTION_EGRESS -d 192.0.2.0/24 -j ACCEPT",
            "-A CAUTION_EGRESS -d 198.51.100.0/24 -p tcp --dport 8000:8002 -j ACCEPT",
            "-A CAUTION_EGRESS -d 203.0.113.5/32 -p udp --dport 53:53 -j ACCEPT",
        ]
    );
    assert!(egress_forward_rules(&policy).ends_with('\n'));
    assert_eq!(egress_forward_rules(&policy_without_http()), "");
}

#[test]
fn firewall_dns_requires_exact_destination_protocol_and_port_permission() {
    for (cidr, protocol, port, expected) in [
        ("10.0.100.1/32", "udp", Some(53), "udp"),
        ("10.0.100.1/32", "tcp", Some(53), "tcp"),
        ("10.0.100.8/24", "udp", Some(53), "udp"),
        ("10.0.100.1/32", "udp", Some(54), ""),
        ("10.0.100.2/32", "udp", Some(53), ""),
        ("10.0.101.0/24", "all", None, ""),
        ("10.0.100.1/32", "all", None, "both"),
        ("0.0.0.0/0", "all", None, "both"),
    ] {
        let mut rule = json!({"cidr_ipv4": cidr, "ip_protocol": protocol});
        if let Some(port) = port {
            rule["port"] = json!(port);
        }
        let policy = policy(json!({"egress": [rule]}));
        let tcp = "-A CAUTION_INPUT -d 10.0.100.1/32 -p tcp --dport 53:53 -j ACCEPT\n";
        let udp = "-A CAUTION_INPUT -d 10.0.100.1/32 -p udp --dport 53:53 -j ACCEPT\n";
        let expected = match expected {
            "tcp" => tcp.into(),
            "udp" => udp.into(),
            "both" => format!("{tcp}{udp}"),
            _ => String::new(),
        };
        assert_eq!(
            egress_dns_rules(&policy),
            expected,
            "{cidr} {protocol} {port:?}"
        );
    }
    let ranged = policy(json!({"egress": [
        {"cidr_ipv4": "10.0.100.0/24", "ip_protocol": "tcp", "start_port": 52, "end_port": 54},
        {"cidr_ipv4": "10.0.100.1/32", "ip_protocol": "tcp", "port": 53}
    ]}));
    assert_eq!(
        egress_dns_rules(&ranged),
        "-A CAUTION_INPUT -d 10.0.100.1/32 -p tcp --dport 53:53 -j ACCEPT\n"
    );
    assert_eq!(egress_dns_rules(&policy_without_http()), "");
}

#[test]
fn sg_transport_and_recovery_are_scoped_to_http_sources_and_feature_gates() {
    let policy = policy(json!({
        "ingress": [
            {"cidr_ipv4": "192.0.2.1/32", "port": 8080},
            {"cidr_ipv4": "198.51.100.0/24", "port": 8080},
            {"cidr_ipv4": "0.0.0.0/0", "port": 9000}
        ],
        "http": {"port": 8080}
    }));
    for mode in ["steve", "disabled", "tls", "unknown"] {
        for locksmith in [true, false] {
            let actual = structural_ingress(ingress_blocks(&policy, Some(8080), mode, locksmith));
            let internal: Vec<_> = actual.iter().filter(|rule| rule.low >= 49500).collect();
            let mut expected = Vec::new();
            for source in ["192.0.2.1/32", "198.51.100.0/24"] {
                if mode == "steve" {
                    expected.push(ingress(49500, 49500, source));
                }
                if locksmith {
                    expected.push(ingress(49504, 49504, source));
                }
            }
            let mut internal: Vec<_> = internal.into_iter().collect();
            internal.sort();
            expected.sort();
            assert_eq!(
                internal,
                expected.iter().collect::<Vec<_>>(),
                "{mode}, locksmith={locksmith}"
            );
        }
    }
    let no_http = policy_without_http();
    for mode in ["steve", "disabled", "tls", "unknown"] {
        assert_eq!(
            structural_ingress(ingress_blocks(&no_http, None, mode, true)),
            vec![ingress(80, 80, "0.0.0.0/0")]
        );
    }
}

fn policy_without_http() -> NetworkPolicy {
    policy(json!({}))
}

#[test]
fn direct_ingress_enforces_the_same_tuples_as_security_groups() {
    let policy = policy(json!({
        "ingress": [
            {"cidr_ipv4": "192.0.2.37/24", "start_port": 8079, "end_port": 8081},
            {"cidr_ipv4": "198.51.100.7/32", "port": 8080}
        ],
        "http": {"port": 8080},
        "recovery_ingress": []
    }));
    for mode in ["disabled", "steve"] {
        for locksmith in [false, true] {
            let expected = structural_ingress(ingress_blocks(&policy, Some(8080), mode, locksmith));
            let (rules, guard) = ingress_input_rules(&policy, Some(8080), mode, locksmith);
            let expected: Vec<_> = expected.iter().filter(|rule| rule.low != 80).collect();
            assert_eq!(
                rules
                    .lines()
                    .filter(|line| line.ends_with("-j ACCEPT"))
                    .count(),
                expected.len()
            );
            for rule in expected {
                assert!(rules.contains(&format!(
                    "-A CAUTION_INGRESS -s {} -p tcp --dport {}:{} -j ACCEPT",
                    rule.sources[0], rule.low, rule.high
                )));
            }
            assert!(!guard.contains("ACCEPT"));
            assert!(guard.contains("--ctstate ESTABLISHED --ctdir REPLY -j RETURN"));
            assert!(guard.contains("--dport 49500:49600 -j DROP"));
            assert!(!rules.contains("--dport 8080:8080"));
            assert!(!rules.contains("--dport 49504:49504 -j ACCEPT"));
        }
    }
    let (rules, _) = ingress_input_rules(&policy_without_http(), None, "steve", true);
    assert!(!rules.contains("ACCEPT"));
    assert!(rules.contains("--dport 443:443 -j DROP"));
}

#[test]
fn sg_preserves_each_source_range_and_hides_private_http_upstream() {
    let policy = policy(json!({
        "ingress": [
            {"cidr_ipv4": "192.0.2.37/24", "start_port": 8079, "end_port": 8081},
            {"cidr_ipv4": "198.51.100.7/32", "port": 8080},
            {"cidr_ipv4": "203.0.113.5/32", "start_port": 9000, "end_port": 9002}
        ],
        "http": {"port": 8080}
    }));
    let mut actual = structural_ingress(ingress_blocks(&policy, Some(8080), "disabled", false));
    let mut expected = vec![
        ingress(80, 80, "0.0.0.0/0"),
        ingress(443, 443, "192.0.2.0/24"),
        ingress(443, 443, "198.51.100.7/32"),
        ingress(8079, 8079, "192.0.2.0/24"),
        ingress(8081, 8081, "192.0.2.0/24"),
        ingress(9000, 9002, "203.0.113.5/32"),
    ];
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}
