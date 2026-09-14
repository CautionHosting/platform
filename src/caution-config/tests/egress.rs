use caution_config::ConfigurationFile;

fn config_with_network(network: &str) -> String {
    ["enclave \"main\" {\nnetwork {\n", network, "\n}\n}"].concat()
}

#[test]
fn accepts_disabled_and_explicit_unrestricted_egress() {
    for (input, expected_count) in [
        (String::new(), 0),
        ("enclave \"main\" {}".to_owned(), 0),
        (config_with_network(""), 0),
        (config_with_network("egress = []"), 0),
        (
            config_with_network("egress { cidr_ipv4 = \"0.0.0.0/0\" }"),
            1,
        ),
        (
            config_with_network(
                "egress { cidr_ipv4 = \"0.0.0.0/0\" }\negress { cidr_ipv4 = \"0.0.0.0/0\" }",
            ),
            2,
        ),
    ] {
        for config in [
            hcl::from_str::<ConfigurationFile>(&input).unwrap(),
            ConfigurationFile::from_str(&input).unwrap(),
        ] {
            let network = config
                .enclave
                .as_ref()
                .and_then(|enclaves| enclaves.get("main"))
                .and_then(|enclave| enclave.network.as_ref());
            assert_eq!(network.map_or(0, |n| n.egress.len()), expected_count);
            assert_eq!(
                network.is_some_and(|n| n.egress_enabled()),
                expected_count > 0
            );
        }
    }
}

#[test]
fn rejects_every_unsupported_egress_shape() {
    for fields in [
        "cidr_ipv4 = \"192.0.2.1/32\"",
        "cidr_ipv4 = \"10.0.0.0/8\"",
        "cidr_ipv4 = \"::/0\"",
        "cidr_ipv4 = \"invalid\"",
        "cidr_ipv4 = \"0.0.0.0/0\"\nip_protocol = \"tcp\"",
        "cidr_ipv4 = \"0.0.0.0/0\"\nip_protocol = \"udp\"",
        "cidr_ipv4 = \"0.0.0.0/0\"\nip_protocol = \"-1\"",
        "cidr_ipv4 = \"0.0.0.0/0\"\nip_protocol = null",
        "cidr_ipv4 = \"0.0.0.0/0\"\nport = 443",
        "cidr_ipv4 = \"0.0.0.0/0\"\nport = \"bad\"",
        "cidr_ipv4 = \"0.0.0.0/0\"\nport = -1",
        "cidr_ipv4 = \"0.0.0.0/0\"\nport = 65536",
        "cidr_ipv4 = \"0.0.0.0/0\"\nport = null",
        "cidr_ipv4 = \"0.0.0.0/0\"\nstart_port = 80\nend_port = 443",
        "cidr_ipv4 = \"0.0.0.0/0\"\nstart_port = 80",
        "cidr_ipv4 = \"0.0.0.0/0\"\nend_port = 443",
        "cidr_ipv4 = \"0.0.0.0/0\"\nports = 443",
        "",
    ] {
        let rule = ["egress {\n", fields, "\n}"].concat();
        for network in [
            rule.clone(),
            ["egress { cidr_ipv4 = \"0.0.0.0/0\" }\n", &rule].concat(),
            [&rule, "\negress { cidr_ipv4 = \"0.0.0.0/0\" }"].concat(),
        ] {
            let input = config_with_network(&network);
            let error = hcl::from_str::<ConfigurationFile>(&input).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Restricted egress is not supported")
            );
            // The typed parser wraps the HCL error; inspect its source as well.
            let error = ConfigurationFile::from_str(&input).unwrap_err();
            assert!(
                std::error::Error::source(&error)
                    .unwrap()
                    .to_string()
                    .contains("Restricted egress is not supported"),
                "{input}"
            );
        }
    }
}
