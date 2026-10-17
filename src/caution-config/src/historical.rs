use crate::*;

/// Failure to decode pinned configuration for historical build reproduction.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum HistoricalConfigError {
    #[error("could not decode historical HCL configuration [{location}]")]
    Hcl {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    #[error("could not decode historical Procfile configuration [{location}]")]
    Procfile {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalConfiguration {
    caution: Option<CautionConfig>,
    enclave: Option<BTreeMap<String, HistoricalEnclave>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalEnclave {
    build: Option<BuildConfig>,
    debug: Option<DebugConfig>,
    network: Option<HistoricalNetwork>,
    resources: Option<ResourceConfig>,
    restart: Option<RestartConfig>,
    unit: Option<BTreeMap<String, UnitConfig>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalNetwork {
    #[serde(deserialize_with = "single_or_vec", default)]
    ingress: Vec<HistoricalTrafficRule>,
    #[serde(deserialize_with = "single_or_vec", default)]
    egress: Vec<HistoricalTrafficRule>,
    #[serde(default, deserialize_with = "deserialize_recovery_ingress")]
    recovery_ingress: Option<Vec<RecoveryIngress>>,
    http: Option<HttpConfig>,
}

// Match the original flattened traffic-rule decoder, before deployment policy validation.
#[derive(Deserialize)]
struct HistoricalTrafficRule {
    cidr_ipv4: String,
    #[serde(flatten)]
    port_spec: Option<PortSpec>,
    ip_protocol: Option<String>,
}

impl From<HistoricalTrafficRule> for TrafficRule {
    fn from(rule: HistoricalTrafficRule) -> Self {
        Self {
            cidr_ipv4: rule.cidr_ipv4,
            port_spec: rule.port_spec,
            ip_protocol: rule.ip_protocol,
        }
    }
}

impl ConfigurationFile {
    /// Decode pinned HCL for reproduction without applying current deployment policy.
    /// Raw ingress and egress remain historical build inputs, not an enabled policy.
    #[tracing::instrument(skip_all, err)]
    pub fn from_historical_hcl(content: &str) -> Result<Self, HistoricalConfigError> {
        use HistoricalConfigErrorCtx as Ctx;
        let historical: HistoricalConfiguration = hcl::from_str(content).with_context(Ctx::hcl())?;
        let config = Self {
            caution: historical.caution,
            enclave: historical.enclave.map(|enclaves| {
                enclaves
                    .into_iter()
                    .map(|(name, enclave)| {
                        (
                            name,
                            EnclaveConfig {
                                build: enclave.build,
                                debug: enclave.debug,
                                resources: enclave.resources,
                                restart: enclave.restart,
                                unit: enclave.unit,
                                network: enclave.network.map(|network| NetworkConfig {
                                    ingress: network
                                        .ingress
                                        .into_iter()
                                        .map(TrafficRule::from)
                                        .collect(),
                                    egress: network
                                        .egress
                                        .into_iter()
                                        .map(TrafficRule::from)
                                        .collect(),
                                    recovery_ingress: network.recovery_ingress,
                                    http: network.http,
                                }),
                            },
                        )
                    })
                    .collect()
            }),
        };
        Self::validate_parsed_hcl(config).with_context(Ctx::hcl())
    }

    /// Decode a pinned historical Procfile without current deployment port checks.
    #[tracing::instrument(skip_all, err)]
    pub fn from_historical_procfile(content: &str) -> Result<Self, HistoricalConfigError> {
        use HistoricalConfigErrorCtx as Ctx;
        Self::parse_procfile(content, true).with_context(Ctx::procfile())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_procfile_does_not_require_ingress_or_rewrite_http() {
        let input = "run: /app\nhttp_port: 8080\n";
        assert!(ConfigurationFile::from_procfile(input).is_err());
        let cfg = ConfigurationFile::from_historical_procfile(input).unwrap();
        let network = cfg.enclave.as_ref().unwrap()["default"]
            .network
            .as_ref()
            .unwrap();
        assert!(network.ingress.is_empty());
        assert_eq!(network.http.as_ref().unwrap().port, 8080);
        assert!(!network.egress_enabled());
    }

    #[test]
    fn historical_hcl_keeps_legacy_traffic_rule_decoding() {
        let input = r#"enclave "main" {
            network {
                ingress {
                    cidr_ipv4 = "192.0.2.0/24"
                    start_port = 50000
                    end_port = 49000
                }
                ingress {
                    cidr_ipv4 = "192.0.2.0/24"
                    port = 0
                }
                egress {
                    cidr_ipv4 = "0.0.0.0/0"
                    ip_protocol = "udp"
                }
                http { port = 8080 }
            }
        }"#;
        assert!(ConfigurationFile::from_str(input).is_err());
        let cfg = ConfigurationFile::from_historical_hcl(input).unwrap();
        let network = cfg.enclave.as_ref().unwrap()["main"]
            .network
            .as_ref()
            .unwrap();
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::FromTo {
                start_port: 50000,
                end_port: 49000
            })
        );
        assert_eq!(
            network.ingress[1].port_spec,
            Some(PortSpec::Exact { port: 0 })
        );
        assert!(network.egress_enabled());
    }

    #[test]
    fn historical_procfile_keeps_reserved_ports() {
        let input = "run: /app\nports: 49500\nhttp_port: 49500\n";
        assert!(ConfigurationFile::from_procfile(input).is_err());
        let cfg = ConfigurationFile::from_historical_procfile(input).unwrap();
        let network = cfg.enclave.as_ref().unwrap()["default"]
            .network
            .as_ref()
            .unwrap();
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 49500 })
        );
    }
}
