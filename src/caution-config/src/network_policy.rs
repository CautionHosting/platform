//! Validated IPv4 network policies shared by provisioning and build identity.
use crate::{E2eMode, NetworkConfig, PortSpec, TrafficRule};
use dterror::ResultExt;
use serde::Serialize;
use std::{collections::BTreeSet, net::Ipv4Addr};

/// Combined ingress, egress and explicit recovery rule budget, before deduplication.
pub const MAX_RAW_RULES: usize = 40;
/// Distinct ingress port budget, including private HTTP upstream ports.
pub const MAX_INGRESS_PORTS: usize = 32;
/// Conservative generated ingress rule budget: HTTP range splitting, HTTPS, STEVE
/// and recovery are counted even if a service is disabled. Five of the default
/// sixty security-group slots remain available for platform management and SSH.
pub const MAX_SECURITY_GROUP_INGRESS_RULES: usize = 55;

/// Protocols supported by the enforcement layer. No user-controlled protocol text escapes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP with an explicit port interval.
    Tcp,
    /// UDP with an explicit port interval (egress only).
    Udp,
    /// Every IP protocol, without a port interval (egress only).
    All,
}

impl Protocol {
    /// Canonical protocol identifier accepted by security groups and packet filters.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::All => "-1",
        }
    }
}

/// An immutable canonical CIDR/protocol/port tuple.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NetworkRule {
    cidr_ipv4: String,
    protocol: Protocol,
    ports: Option<(u16, u16)>,
}

impl NetworkRule {
    /// Canonical IPv4 network address and prefix length.
    pub fn cidr_ipv4(&self) -> &str {
        &self.cidr_ipv4
    }
    /// The validated protocol.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Inclusive interval, absent only for all-protocol rules.
    pub fn ports(&self) -> Option<(u16, u16)> {
        self.ports
    }
}

/// Versioned, immutable enforcement input. Only normalization can construct it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetworkPolicy {
    version: u8,
    ingress: Vec<NetworkRule>,
    egress: Vec<NetworkRule>,
    http_sources: Vec<String>,
    recovery_sources: Vec<String>,
}

impl NetworkPolicy {
    /// All declared ingress tuples, including private HTTP upstream declarations.
    pub fn ingress(&self) -> &[NetworkRule] {
        &self.ingress
    }
    /// Egress allowlist. An empty list disables the outbound tunnel.
    pub fn egress(&self) -> &[NetworkRule] {
        &self.egress
    }
    /// Sources from ingress rules covering the private HTTP upstream port only.
    pub fn http_sources(&self) -> &[String] {
        &self.http_sources
    }
    /// Recovery endpoint source allowlist.
    pub fn recovery_sources(&self) -> &[String] {
        &self.recovery_sources
    }
    /// Sorted distinct ingress ports, including HTTP upstream ports for build identity.
    pub fn ports(&self) -> Vec<u16> {
        self.ingress
            .iter()
            .filter_map(|rule| rule.ports)
            .flat_map(|(start, end)| start..=end)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    /// Whether the explicit allowlist requires an outbound tunnel.
    pub fn egress_enabled(&self) -> bool {
        !self.egress.is_empty()
    }
}

/// IPv4 CIDR parsing failures. Values are deliberately omitted from diagnostics.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum Ipv4CidrError {
    /// The input is not an address/prefix pair.
    #[error("expected an IPv4 address and decimal prefix length 0-32 [{location}]")]
    Syntax { location: dterror::Location },
    /// Standard-library IPv4 parsing failed.
    #[error("invalid IPv4 address [{location}]")]
    Address {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    /// Decimal prefix parsing failed.
    #[error("invalid IPv4 prefix length [{location}]")]
    Prefix {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Failure to normalize a network allowlist.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError, caution_error::ProviderError)]
pub enum NetworkPolicyError {
    /// The policy exceeds an enforcement resource budget.
    #[error("network policy exceeds {resource} limit {max}")]
    Limit {
        resource: &'static str,
        max: usize,
        #[provide]
        location: dterror::Location,
    },
    /// An application listener conflicts with platform services.
    #[error("ingress port {port} is reserved for platform services")]
    ReservedPort {
        port: u16,
        #[provide]
        location: dterror::Location,
    },
    /// HTTP cannot be exposed without an explicit covering ingress declaration.
    #[error("HTTP port {port} must be present in ingress rules")]
    HttpPortNotInIngress {
        port: u16,
        #[provide]
        location: dterror::Location,
    },
    /// Narrow ACME challenge forwarding is not implemented yet.
    #[error("enclave TLS with restricted HTTP sources is not supported")]
    RestrictedTls {
        #[provide]
        location: dterror::Location,
    },
    /// Enclave Caddy owns the public HTTP and HTTPS listener ports in TLS mode.
    #[error("enclave TLS application port conflicts with the Caddy listener")]
    TlsListenerCollision {
        #[provide]
        location: dterror::Location,
    },
    /// A source/destination CIDR failed validation.
    #[error("invalid {direction} CIDR in rule {index}")]
    InvalidCidr {
        direction: &'static str,
        index: usize,
        #[provide]
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    /// Protocol is unsupported for the rule's direction.
    #[error("unsupported {direction} protocol in rule {index}")]
    InvalidProtocol {
        direction: &'static str,
        index: usize,
        #[provide]
        location: dterror::Location,
    },
    /// Missing/invalid interval or all-protocol rule with an interval.
    #[error("invalid {direction} ports in rule {index}")]
    InvalidPorts {
        direction: &'static str,
        index: usize,
        #[provide]
        location: dterror::Location,
    },
}

impl NetworkPolicyError {
    /// Fixed client-facing description, without input, paths or internal source chains.
    pub fn client_message(&self) -> &'static str {
        "Invalid network policy."
    }
}

#[tracing::instrument(skip_all, err)]
fn canonical_cidr(input: &str) -> Result<String, Ipv4CidrError> {
    use Ipv4CidrErrorCtx as Ctx;
    let (address, prefix) = input.split_once('/').ok_or(Ipv4CidrError::Syntax {
        location: std::panic::Location::caller(),
    })?;
    if prefix.is_empty()
        || prefix.len() > 2
        || !prefix.bytes().all(|b| b.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return Err(Ipv4CidrError::Syntax {
            location: std::panic::Location::caller(),
        });
    }
    let address: Ipv4Addr = address.parse().with_context(Ctx::address())?;
    let prefix: u32 = prefix.parse().with_context(Ctx::prefix())?;
    if prefix > 32 {
        return Err(Ipv4CidrError::Syntax {
            location: std::panic::Location::caller(),
        });
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(format!(
        "{}/{prefix}",
        Ipv4Addr::from(u32::from(address) & mask)
    ))
}

#[tracing::instrument(skip_all, err)]
fn normalize_rules(
    rules: &[TrafficRule],
    direction: &'static str,
) -> Result<Vec<NetworkRule>, NetworkPolicyError> {
    use NetworkPolicyErrorCtx as Ctx;
    let mut normalized = BTreeSet::new();
    for (index, rule) in rules.iter().enumerate() {
        let cidr_ipv4 =
            canonical_cidr(&rule.cidr_ipv4).with_context(Ctx::invalid_cidr(direction, index))?;
        let ports = match rule.port_spec {
            Some(PortSpec::Exact { port }) => Some((port, port)),
            Some(PortSpec::FromTo {
                start_port,
                end_port,
            }) => Some((start_port, end_port)),
            None => None,
        };
        let protocol = match rule.ip_protocol.as_deref() {
            Some("tcp" | "6") => Protocol::Tcp,
            Some("udp" | "17") if direction == "egress" => Protocol::Udp,
            Some("all" | "-1") if direction == "egress" => Protocol::All,
            None if direction == "egress" && ports.is_none() => Protocol::All,
            None => Protocol::Tcp,
            _ => {
                return Err(NetworkPolicyError::InvalidProtocol {
                    direction,
                    index,
                    location: std::panic::Location::caller(),
                });
            }
        };
        let valid_ports = match (protocol, ports) {
            (Protocol::All, None) => true,
            (Protocol::Tcp | Protocol::Udp, Some((start, end))) => start > 0 && start <= end,
            _ => false,
        };
        if !valid_ports {
            return Err(NetworkPolicyError::InvalidPorts {
                direction,
                index,
                location: std::panic::Location::caller(),
            });
        }
        normalized.insert(NetworkRule {
            cidr_ipv4,
            protocol,
            ports,
        });
    }
    Ok(normalized.into_iter().collect())
}

impl NetworkConfig {
    /// Validate and normalize without broadening any declared CIDR/protocol/port tuple.
    pub fn policy(&self) -> Result<NetworkPolicy, NetworkPolicyError> {
        use NetworkPolicyErrorCtx as Ctx;
        if self.ingress.len()
            + self.egress.len()
            + self.recovery_ingress.as_ref().map_or(0, Vec::len)
            > MAX_RAW_RULES
        {
            return Err(NetworkPolicyError::Limit {
                resource: "raw rules",
                max: MAX_RAW_RULES,
                location: std::panic::Location::caller(),
            });
        }
        let ingress = normalize_rules(&self.ingress, "ingress")?;
        let egress = normalize_rules(&self.egress, "egress")?;
        let http_port = self.http.as_ref().map(|http| http.port);
        let mut ports = BTreeSet::new();
        let mut raw_ingress_slots = 0;
        for rule in &ingress {
            if let Some((start, end)) = rule.ports {
                if usize::from(end - start) + 1 > MAX_INGRESS_PORTS {
                    return Err(NetworkPolicyError::Limit {
                        resource: "ingress ports",
                        max: MAX_INGRESS_PORTS,
                        location: std::panic::Location::caller(),
                    });
                }
                for port in start..=end {
                    let private_http = Some(port) == http_port && matches!(port, 80 | 443);
                    if crate::is_reserved(port)
                        || port == 22
                        || (matches!(port, 80 | 443) && !private_http)
                    {
                        return Err(NetworkPolicyError::ReservedPort {
                            port,
                            location: std::panic::Location::caller(),
                        });
                    }
                    ports.insert(port);
                    if ports.len() > MAX_INGRESS_PORTS {
                        return Err(NetworkPolicyError::Limit {
                            resource: "ingress ports",
                            max: MAX_INGRESS_PORTS,
                            location: std::panic::Location::caller(),
                        });
                    }
                }
                raw_ingress_slots += match http_port.filter(|port| (start..=end).contains(port)) {
                    Some(http) => usize::from(start < http) + usize::from(http < end),
                    None => 1,
                };
            }
        }
        if let Some(port) = http_port
            && !ports.contains(&port)
        {
            return Err(NetworkPolicyError::HttpPortNotInIngress {
                port,
                location: std::panic::Location::caller(),
            });
        }
        let http_sources: Vec<String> = self
            .http
            .as_ref()
            .map(|http| {
                ingress
                    .iter()
                    .filter(|rule| {
                        rule.ports
                            .is_some_and(|(start, end)| (start..=end).contains(&http.port))
                    })
                    .map(|rule| rule.cidr_ipv4.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
        let recovery_sources = match &self.recovery_ingress {
            Some(rules) => {
                let mut sources = BTreeSet::new();
                for (index, rule) in rules.iter().enumerate() {
                    sources.insert(
                        canonical_cidr(&rule.cidr_ipv4)
                            .with_context(Ctx::invalid_cidr("recovery_ingress", index))?,
                    );
                }
                sources.into_iter().collect::<Vec<_>>()
            }
            None => http_sources.clone(),
        };
        if raw_ingress_slots + 2 * http_sources.len() + recovery_sources.len()
            > MAX_SECURITY_GROUP_INGRESS_RULES
        {
            return Err(NetworkPolicyError::Limit {
                resource: "security group ingress rules",
                max: MAX_SECURITY_GROUP_INGRESS_RULES,
                location: std::panic::Location::caller(),
            });
        }
        let tls = self
            .http
            .as_ref()
            .and_then(|http| http.e2e_encryption.as_ref())
            .and_then(|e2e| e2e.effective_mode())
            == Some(E2eMode::Tls);
        if tls && matches!(http_port, Some(80 | 443)) {
            return Err(NetworkPolicyError::TlsListenerCollision {
                location: std::panic::Location::caller(),
            });
        }
        if tls && !http_sources.iter().any(|source| source == "0.0.0.0/0") {
            return Err(NetworkPolicyError::RestrictedTls {
                location: std::panic::Location::caller(),
            });
        }
        Ok(NetworkPolicy {
            version: 1,
            ingress,
            egress,
            recovery_sources,
            http_sources,
        })
    }
}
