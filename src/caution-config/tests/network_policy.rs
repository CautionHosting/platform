use caution_config::{ConfigurationFile, NetworkConfig, TrafficRule};

fn network(input: &str) -> NetworkConfig {
    hcl::from_str(input).expect("network syntax")
}

fn rule(direction: &str, cidr: &str, fields: &str) -> String {
    format!("{direction} {{\ncidr_ipv4 = \"{cidr}\"\n{fields}\n}}\n")
}

#[test]
fn recovery_sources_are_explicit_or_inherit_only_http_sources() {
    let input = rule("ingress", "192.0.2.1/24", "port = 8080")
        + &rule("ingress", "0.0.0.0/0", "port = 9000")
        + "http { port = 8080 }\n";
    let default = network(&input).policy().expect("default recovery");
    assert_eq!(default.http_sources(), ["192.0.2.0/24"]);
    assert_eq!(default.recovery_sources(), ["192.0.2.0/24"]);
    let explicit = network(
        &(input.clone()
            + "recovery_ingress { cidr_ipv4 = \"198.51.100.2/24\" }\n"
            + "recovery_ingress { cidr_ipv4 = \"198.51.100.0/24\" }\n"),
    )
    .policy()
    .expect("explicit recovery");
    assert_eq!(explicit.recovery_sources(), ["198.51.100.0/24"]);
    assert!(
        network(&(input + "recovery_ingress = []"))
            .policy()
            .expect("disabled recovery")
            .recovery_sources()
            .is_empty()
    );
    assert_eq!(
        network("recovery_ingress { cidr_ipv4 = \"192.0.2.1/32\" }")
            .policy()
            .expect("non HTTP recovery")
            .recovery_sources(),
        ["192.0.2.1/32"]
    );
    for fields in ["port = 8080", "ip_protocol = \"tcp\"", "typo = true"] {
        assert!(
            hcl::from_str::<NetworkConfig>(&rule("recovery_ingress", "192.0.2.0/24", fields))
                .is_err()
        );
    }
    assert!(hcl::from_str::<NetworkConfig>("recovery_ingress = null").is_err());
}

#[test]
fn policy_bounds_expansion_and_security_group_rule_count() {
    let too_wide = rule(
        "ingress",
        "192.0.2.0/24",
        "start_port = 10000\nend_port = 65535",
    );
    assert!(network(&too_wide).policy().is_err(), "unbounded expansion");
    let boundary = rule(
        "ingress",
        "192.0.2.0/24",
        "start_port = 10000\nend_port = 10031",
    );
    assert_eq!(
        network(&boundary).policy().expect("32 ports").ports().len(),
        32
    );
    assert!(
        network(&(boundary + &rule("ingress", "198.51.100.0/24", "port = 10032")))
            .policy()
            .is_err()
    );
    let repeated = rule("egress", "192.0.2.0/24", "");
    assert!(network(&repeated.repeat(40)).policy().is_ok());
    assert!(
        network(&repeated.repeat(41)).policy().is_err(),
        "raw rule cap before deduplication"
    );
    let sources: String = (1..=20)
        .map(|host| {
            rule(
                "ingress",
                &format!("192.0.2.{host}/32"),
                "start_port = 8080\nend_port = 8082",
            )
        })
        .collect();
    assert!(
        network(&(sources + "http { port = 8081 }"))
            .policy()
            .is_err(),
        "HTTP/range splitting and recovery SG overhead"
    );
}

#[test]
fn reserved_ports_are_private_http_only_or_rejected() {
    for port in [22, 80, 443, 49500, 49501, 49502, 49503, 49504] {
        let input = rule("ingress", "192.0.2.0/24", &format!("port = {port}"));
        assert!(network(&input).policy().is_err(), "raw {port}");
        let with_http = input + &format!("http {{ port = {port} }}");
        assert_eq!(
            network(&with_http).policy().is_ok(),
            matches!(port, 80 | 443),
            "HTTP {port}"
        );
    }
    assert!(
        network(&rule(
            "ingress",
            "192.0.2.0/24",
            "start_port = 20\nend_port = 23"
        ))
        .policy()
        .is_err()
    );
    assert!(
        network("http { port = 8080 }").policy().is_err(),
        "undeclared HTTP port"
    );
}

#[test]
fn procfile_enforces_network_policy_limits_and_reserved_listeners() {
    for ports in [
        "22".to_string(),
        "80".to_string(),
        "443".to_string(),
        (10000..=10032)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(","),
    ] {
        let input = format!("ports: {ports}\n");
        assert!(
            ConfigurationFile::from_procfile(&input).is_err(),
            "accepted {input}"
        );
    }
    for port in [80, 443] {
        let input = format!("ports: {port}\nhttp_port: {port}\ne2e: false\n");
        assert!(
            ConfigurationFile::from_procfile(&input).is_ok(),
            "private HTTP {port}"
        );
    }
}

#[test]
fn tls_rejects_caddy_listener_collisions_only_in_tls_mode() {
    for port in [80, 443] {
        for (mode, valid) in [("tls", false), ("steve", true), ("disabled", true)] {
            let encryption = if mode == "disabled" {
                "enabled = false".to_string()
            } else {
                format!("mode = \"{mode}\"")
            };
            let input = rule("ingress", "0.0.0.0/0", &format!("port = {port}"))
                + &format!("http {{\nport = {port}\ne2e_encryption {{ {encryption} }}\n}}\n");
            let result = network(&input).policy();
            assert_eq!(result.is_ok(), valid, "{mode} {port}");
            if !valid {
                let error = result.expect_err("TLS listener collision");
                assert!(matches!(
                    error,
                    caution_config::NetworkPolicyError::TlsListenerCollision { .. }
                ));
                assert_eq!(error.client_message(), "Invalid network policy.");
            }
        }
    }
}

#[test]
fn tls_restricted_sources_fail_closed() {
    for (cidr, valid) in [("192.0.2.0/24", false), ("0.0.0.0/0", true)] {
        let input = rule("ingress", cidr, "port = 8080")
            + "http {\nport = 8080\ne2e_encryption { mode = \"tls\" }\n}\n"
            + &rule("egress", "0.0.0.0/0", "");
        assert_eq!(network(&input).policy().is_ok(), valid, "{cidr}");
    }
}

#[test]
fn normalizes_tuples_without_losing_sources_or_protocols() {
    let policy = network(
        r#"
        ingress {
            cidr_ipv4 = "192.0.2.9/24"
            start_port = 8080
            end_port = 8082
        }
        ingress {
            cidr_ipv4 = "192.0.2.0/24"
            start_port = 8080
            end_port = 8082
            ip_protocol = "6"
        }
        ingress {
            cidr_ipv4 = "198.51.100.1/32"
            port = 8081
        }
        egress {
            cidr_ipv4 = "203.0.113.7/24"
            port = 53
            ip_protocol = "udp"
        }
        egress {
            cidr_ipv4 = "203.0.113.0/24"
            port = 53
            ip_protocol = "6"
        }
        egress {
            cidr_ipv4 = "10.42.1.2/8"
            ip_protocol = "all"
        }
        http { port = 8081 }
    "#,
    )
    .policy()
    .expect("valid policy");
    assert_eq!(policy.ports(), [8080, 8081, 8082]);
    assert_eq!(policy.ingress().len(), 2);
    assert_eq!(policy.egress().len(), 3);
    assert_eq!(policy.http_sources(), ["192.0.2.0/24", "198.51.100.1/32"]);
    assert_eq!(policy.recovery_sources(), policy.http_sources());
    assert!(policy.egress_enabled());
    use caution_config::network_policy::Protocol;
    assert!(
        policy
            .egress()
            .iter()
            .any(|rule| rule.cidr_ipv4() == "10.0.0.0/8"
                && rule.protocol() == Protocol::All
                && rule.ports().is_none())
    );
    assert!(
        policy
            .egress()
            .iter()
            .any(|rule| rule.cidr_ipv4() == "203.0.113.0/24"
                && rule.protocol() == Protocol::Udp
                && rule.ports() == Some((53, 53)))
    );
    assert_eq!(serde_json::to_value(&policy).expect("json")["version"], 1);
    assert_eq!(policy.clone(), policy);
    let empty = network("").policy().expect("empty policy");
    assert!(!empty.egress_enabled());
    assert!(empty.recovery_sources().is_empty());
}

#[test]
fn configuration_rejects_invalid_cidr_and_protocol() {
    for cidr in [
        "invalid",
        "::/0",
        "192.0.2.1",
        "192.0.2.1/33",
        "192.0.2.1/-1",
        "192.0.2.1/01",
        "192.0.2.1/+1",
        "192.0.2.1/24/1",
        "192.0.2.1/24\n",
    ] {
        let input = format!(
            "enclave \"main\" {{\nnetwork {{\negress {{\ncidr_ipv4 = {}\n}}\n}}\n}}",
            serde_json::to_string(cidr).expect("string")
        );
        let error = ConfigurationFile::from_str(&input).expect_err("invalid CIDR");
        assert!(
            matches!(error, caution_config::FromStrError::NetworkPolicy { .. }),
            "{error:?}"
        );
    }
    for rule in [
        "ingress {\n cidr_ipv4 = \"192.0.2.0/24\"\n}",
        "ingress {\n cidr_ipv4 = \"192.0.2.0/24\"\nport = 8080\nip_protocol = \"udp\"\n}",
        "ingress {\n cidr_ipv4 = \"192.0.2.0/24\"\nip_protocol = \"all\"\n}",
        "egress {\n cidr_ipv4 = \"192.0.2.0/24\"\nip_protocol = \"tcp\"\n}",
        "egress {\n cidr_ipv4 = \"192.0.2.0/24\"\nip_protocol = \"udp\"\n}",
        "egress {\n cidr_ipv4 = \"192.0.2.0/24\"\nport = 53\nip_protocol = \"-1\"\n}",
        "egress {\n cidr_ipv4 = \"192.0.2.0/24\"\nport = 53\nip_protocol = \"icmp\"\n}",
        "egress {\n cidr_ipv4 = \"192.0.2.0/24\"\nport = 53\nip_protocol = \"tcp; touch /tmp/unsafe\"\n}",
    ] {
        assert!(network(rule).policy().is_err(), "accepted {rule}");
    }
}

#[test]
fn traffic_rule_rejects_unknown_mixed_incomplete_and_invalid_ports() {
    for fields in [
        "ports = 8080",
        "port = 8080\nstart_port = 8080\nend_port = 8081",
        "start_port = 8080",
        "end_port = 8080",
        "start_port = 8081\nend_port = 8080",
        "port = 0",
        "start_port = 0\nend_port = 1",
        "port = null",
        "start_port = null\nend_port = 8080",
        "port = \"8080\"",
        "port = true",
        "port = 8080.5",
        "port = -1",
        "port = 65536",
        "ip_protocol = null",
        "ip_protocol = 6",
        "ip_protocol = [\"tcp\"]",
    ] {
        let input = format!("cidr_ipv4 = \"192.0.2.0/24\"\n{fields}");
        assert!(
            hcl::from_str::<TrafficRule>(&input).is_err(),
            "accepted {input}"
        );
    }
}
