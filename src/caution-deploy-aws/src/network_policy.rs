// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Render validated network policy without widening application access.
//! Port 80 management remains public; this is not an all-ports-private policy.

use caution_config::network_policy::{NetworkPolicy, Protocol};
use std::fmt::Write;

/// Explicit ingress tuples. Port 80 is public solely for platform management;
/// the HTTP app upstream is never directly exposed. SSH is owned by its caller.
#[tracing::instrument(skip_all)]
pub fn ingress_blocks(
    policy: &NetworkPolicy,
    http_port: Option<u16>,
    e2e_mode: &str,
    locksmith: bool,
) -> Vec<hcl::Block> {
    ingress_tuples(policy, http_port, e2e_mode, locksmith)
        .into_iter()
        .map(|(low, high, source, description)| ingress_block(low, high, source, description))
        .collect()
}

#[tracing::instrument(skip_all)]
fn ingress_tuples<'a>(
    policy: &'a NetworkPolicy,
    http_port: Option<u16>,
    e2e_mode: &str,
    locksmith: bool,
) -> Vec<(u16, u16, &'a str, &'static str)> {
    let mut rules = vec![(80, 80, "0.0.0.0/0", "Platform HTTP management")];
    for rule in policy.ingress() {
        if let Some((low, high)) = rule.ports() {
            for (low, high) in raw_ranges(low, high, http_port) {
                rules.push((low, high, rule.cidr_ipv4(), "Application TCP ingress"));
            }
        }
    }
    if http_port.is_some() {
        for source in policy.http_sources() {
            rules.push((443, 443, source, "Application HTTPS ingress"));
            if e2e_mode == "steve" {
                rules.push((49500, 49500, source, "Allow STEVE encrypted transport"));
            }
        }
    }
    if locksmith {
        for source in policy.recovery_sources() {
            rules.push((49504, 49504, source, "Allow Locksmith shard receiver"));
        }
    }
    rules
}

/// The same tuples enforced at the host boundary, before TCP-to-VSOCK. AWS
/// security groups are additive, so they cannot be the only source check.
#[tracing::instrument(skip_all)]
pub fn ingress_input_rules(
    policy: &NetworkPolicy,
    http_port: Option<u16>,
    e2e_mode: &str,
    locksmith: bool,
) -> (String, String) {
    // Preserve replies to connections the host initiated, even when its local
    // ephemeral port falls within the reserved listener range. Incoming flows
    // are ORIGINAL direction and must still pass the source allowlist.
    let reply = "-m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n";
    let mut rules = format!("-A CAUTION_INGRESS {reply}");
    let mut guard = format!("-A CAUTION_INGRESS_GUARD {reply}");
    let mut protected = std::collections::BTreeSet::from([(443, 443), (49500, 49600)]);
    for (low, high, source, _) in ingress_tuples(policy, http_port, e2e_mode, locksmith) {
        if low == 80 && high == 80 {
            // Public management/ACME and application requests share port 80;
            // Caddy applies the application's source check after exact routes.
            continue;
        }
        writeln!(
            rules,
            "-A CAUTION_INGRESS -s {source} -p tcp --dport {low}:{high} -j ACCEPT"
        )
        .expect("writing into a String is infallible");
        protected.insert((low, high));
    }
    for (low, high) in protected {
        let deny = format!("-p tcp --dport {low}:{high} -j DROP");
        writeln!(rules, "-A CAUTION_INGRESS {deny}").expect("writing into a String is infallible");
        writeln!(guard, "-A CAUTION_INGRESS_GUARD {deny}")
            .expect("writing into a String is infallible");
    }
    (rules, guard)
}

#[tracing::instrument(skip_all)]
fn ingress_block(low: u16, high: u16, source: &str, description: &str) -> hcl::Block {
    hcl::Block::builder("ingress")
        .add_attribute(("from_port", u64::from(low)))
        .add_attribute(("to_port", u64::from(high)))
        .add_attribute(("protocol", "tcp"))
        .add_attribute((
            "cidr_blocks",
            hcl::Expression::Array(vec![hcl::Expression::String(source.into())]),
        ))
        .add_attribute(("description", description))
        .build()
}

#[tracing::instrument(skip_all)]
fn raw_ranges(low: u16, high: u16, http_port: Option<u16>) -> Vec<(u16, u16)> {
    let mut excluded = vec![(22, 22), (80, 80), (443, 443), (49500, 49600)];
    if let Some(port) = http_port {
        excluded.push((port, port));
    }
    excluded.sort_unstable();
    let mut ranges = Vec::new();
    let mut cursor = u32::from(low);
    let high = u32::from(high);
    for (start, end) in excluded {
        let start = u32::from(start);
        let end = u32::from(end);
        if start > high {
            break;
        }
        if cursor < start {
            ranges.push((cursor as u16, (start - 1) as u16));
        }
        cursor = cursor.max(end + 1);
    }
    if cursor <= high {
        ranges.push((cursor as u16, high as u16));
    }
    ranges
}

/// Canonical restore-format allowlist for guest-forwarded traffic.
#[tracing::instrument(skip_all)]
pub fn egress_forward_rules(policy: &NetworkPolicy) -> String {
    let mut rules = String::new();
    for rule in policy.egress() {
        let protocol = match rule.protocol() {
            Protocol::Tcp => " -p tcp",
            Protocol::Udp => " -p udp",
            Protocol::All => "",
            _ => continue,
        };
        let ports = rule
            .ports()
            .map(|(low, high)| format!(" --dport {low}:{high}"))
            .unwrap_or_default();
        writeln!(
            rules,
            "-A CAUTION_EGRESS -d {}{protocol}{ports} -j ACCEPT",
            rule.cidr_ipv4()
        )
        .expect("writing into a String is infallible");
    }
    rules
}

/// Guest-to-host DNS exceptions, only when explicitly covered by the allowlist.
/// The installer owns the CAUTION_INPUT chain and its terminal drop policy.
#[tracing::instrument(skip_all)]
pub fn egress_dns_rules(policy: &NetworkPolicy) -> String {
    let mut rules = String::new();
    for (protocol, name) in [(Protocol::Tcp, "tcp"), (Protocol::Udp, "udp")] {
        if policy.egress().iter().any(|rule| {
            contains_dns_host(rule.cidr_ipv4())
                && (rule.protocol() == Protocol::All
                    || (rule.protocol() == protocol
                        && rule
                            .ports()
                            .is_some_and(|(low, high)| (low..=high).contains(&53))))
        }) {
            writeln!(
                rules,
                "-A CAUTION_INPUT -d 10.0.100.1/32 -p {name} --dport 53:53 -j ACCEPT"
            )
            .expect("writing into a String is infallible");
        }
    }
    rules
}

#[tracing::instrument(skip_all)]
fn contains_dns_host(cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(prefix)) = (address.parse::<std::net::Ipv4Addr>(), prefix.parse::<u32>())
    else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    let host = u32::from(std::net::Ipv4Addr::new(10, 0, 100, 1));
    (u32::from(address) & mask) == (host & mask)
}

/// Ordered handlers for a Caddy listener body, not a complete configuration.
/// Sources are socket peers (never forwarded headers). Management is public and
/// precedes the app; TLS byte-forwarding and ACME remain outside this snippet.
/// The caller must validate `domain` before rendering.
#[tracing::instrument(skip_all)]
pub fn http_routes(
    policy: &NetworkPolicy,
    http_port: Option<u16>,
    e2e_mode: &str,
    domain: Option<&str>,
) -> String {
    let mut routes = String::from(
        "route {\n\
        handle /.well-known/caution/health {\n\
            respond \"OK\" 200\n\
        }\n\
        handle /attestation {\n\
            reverse_proxy localhost:49502\n\
        }\n",
    );
    if let Some(port) = http_port.filter(|_| !policy.http_sources().is_empty()) {
        let handler = match e2e_mode {
            "steve" => Some(String::from("reverse_proxy localhost:49500")),
            "disabled" => Some(format!("reverse_proxy localhost:{port}")),
            "tls" => domain.map(|domain| format!("redir https://{domain}{{uri}} 308")),
            _ => None,
        };
        if let Some(handler) = handler {
            writeln!(routes, "@caution_http_sources remote_ip {}\nhandle @caution_http_sources {{\n{handler}\n}}", policy.http_sources().join(" "))
                .expect("writing into a String is infallible");
        }
    }
    routes.push_str("handle {\nrespond \"Forbidden\" 403\n}\n}\n");
    routes
}

#[cfg(test)]
#[path = "network_policy_tests.rs"]
mod tests;
