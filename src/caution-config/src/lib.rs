use hcl::expr::Expression;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

pub fn single_or_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    match OneOrMany::<T>::deserialize(d)? {
        OneOrMany::One(v) => Ok(vec![v]),
        OneOrMany::Many(v) => Ok(v),
    }
}

/// Cloud provider configuration (internally-tagged on `type` field).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Provider {
    Aws(AwsProviderConfig),
}

/// Configuration for the `provider { type = "aws" ... }` block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AwsProviderConfig {
    pub region: String,
    pub vpc_id: Option<String>,
    pub subnet_ids: Option<Vec<String>>,
    pub security_group_id: Option<String>,
}

/// Top-level `caution { }` block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CautionConfig {
    pub managed_credentials: Option<String>,
    pub machine_type: Option<String>,
    pub build_machine_type: Option<String>,
    pub provider: Option<Provider>,
}

/// The `build { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildConfig {
    pub containerfile: Option<String>,
    pub binary: Option<String>,
    #[serde(default)]
    pub app_sources: Vec<String>,
    pub cache: Option<bool>,
}

/// The `debug { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugConfig {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ssh_keys: Vec<String>,
}

/// A port specification
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    FromTo { start_port: u16, end_port: u16 },
    Exact { port: u16 },
}

/// A single traffic rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficRule {
    pub cidr_ipv4: String,
    #[serde(flatten)]
    pub port_spec: Option<PortSpec>,
    pub ip_protocol: Option<String>,
}

/// The `e2e_encryption { }` block inside HTTP config.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct E2eEncryption {
    pub enabled: Option<bool>,
    pub cors_origins: Option<Vec<String>>,
}

/// The `http { }` block inside network config.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    pub domain: String,
    pub port: u16,
    pub e2e_encryption: Option<E2eEncryption>,
}

/// The `resources { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub cpu: u32,
    pub memory_mb: u32,
}

/// A single unit block (`unit "label" { }`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnitConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub env: Option<BTreeMap<String, Expression>>,
}

/// The `network { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(deserialize_with = "single_or_vec", default)]
    pub ingress: Vec<TrafficRule>,
    #[serde(deserialize_with = "single_or_vec", default)]
    pub egress: Vec<TrafficRule>,
    pub http: Option<HttpConfig>,
}

impl NetworkConfig {
    /// Outbound internet access is enabled iff at least one egress rule is declared.
    pub fn egress_enabled(&self) -> bool {
        !self.egress.is_empty()
    }
}

/// An enclave definition (`enclave "label" { }`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnclaveConfig {
    pub build: Option<BuildConfig>,
    pub debug: Option<DebugConfig>,
    pub network: Option<NetworkConfig>,
    pub resources: Option<ResourceConfig>,
    pub unit: Option<BTreeMap<String, UnitConfig>>,
}

/// Top-level configuration file matching the `example.hcl` schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationFile {
    pub caution: Option<CautionConfig>,
    pub enclave: Option<BTreeMap<String, EnclaveConfig>>,
}

#[derive(Debug, thiserror::Error)]
pub enum FromProcfileError {
    #[error(
        "Port {0} is reserved for internal enclave services. Ports 49500-49600 are reserved; choose a different application port."
    )]
    ReservedPort(u16),

    #[error("http_port {0} must also be listed in ports")]
    HttpPortNotInPorts(u16),

    #[error("managed_on_prem requires 'platform' to be specified")]
    ManagedOnPremMissingPlatform,

    #[error("Unsupported platform '{0}'. Currently only 'aws' is supported.")]
    ManagedOnPremUnsupportedPlatform(String),

    #[error("managed_on_prem with platform 'aws' requires 'aws_region'")]
    ManagedOnPremMissingRegion,
}

#[derive(Debug, thiserror::Error)]
pub enum FromStrError {
    #[error("Ports 49500-49600 are reserved; choose a different application port.")]
    ReservedPort,

    #[error("Multiple enclaves defined; only one enclave is supported")]
    MultipleEnclaves,

    #[error("http_port {0} must also be present in ingress rules")]
    HttpPortNotInPorts(u16),

    #[error(
        "Invalid env expression for key '{0}'; only string literals and function calls are allowed"
    )]
    InvalidEnvExpression(String),

    #[error("Failed to parse HCL")]
    HclParse(#[from] hcl::Error),
}

const RESERVED_INTERNAL_PORT_START: u16 = 49_500;
const RESERVED_INTERNAL_PORT_END: u16 = 49_600;

fn is_reserved(port: u16) -> bool {
    (RESERVED_INTERNAL_PORT_START..=RESERVED_INTERNAL_PORT_END).contains(&port)
}

impl ConfigurationFile {
    pub fn from_procfile(content: &str) -> Result<Self, FromProcfileError> {
        let mut containerfile = None;
        let mut binary = None;
        let mut app_sources: Vec<String> = Vec::new();
        let mut cache: Option<bool> = None;
        let mut memory_mb = None;
        let mut cpus = None;
        let mut debug = None;
        let mut ssh_keys: Vec<String> = Vec::new();
        let mut ports: Vec<u16> = Vec::new();
        let mut http_port: Option<u16> = None;
        let mut domain: Option<String> = None;
        let mut run = None;
        let mut procfile_e2e: Option<bool> = None;
        let mut managed_on_prem = false;
        let mut platform: Option<String> = None;
        let mut aws_region: Option<String> = None;
        let mut aws_vpc_id: Option<String> = None;
        let mut aws_subnet_id: Option<String> = None;
        let mut aws_security_group_id: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim().to_string();
                match key {
                    "run" => {
                        if !value.is_empty() {
                            run = Some(value);
                        }
                    }
                    "containerfile" => {
                        if !value.is_empty() {
                            containerfile = Some(value);
                        }
                    }
                    "binary" => {
                        if !value.is_empty() {
                            binary = Some(value);
                        }
                    }
                    "app_source" | "app_sources" => {
                        if !value.is_empty() {
                            app_sources = value
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                        }
                    }
                    "cache" => {
                        cache = Some(value.to_lowercase() == "true");
                    }
                    "no_cache" | "nocache" => {
                        cache = Some(value.to_lowercase() != "true");
                    }
                    "memory" | "memory_mb" => {
                        if let Ok(val) = value.parse::<u32>() {
                            memory_mb = Some(val);
                        }
                    }
                    "cpu" | "cpus" => {
                        if let Ok(val) = value.parse::<u32>() {
                            cpus = Some(val);
                        }
                    }
                    "debug" => {
                        debug = Some(value.to_lowercase() == "true");
                    }
                    "ssh_keys" | "ssh_key" => {
                        if !value.is_empty() {
                            let unquoted = value.trim_matches('"').trim_matches('\'').trim();
                            if !unquoted.is_empty()
                                && (unquoted.starts_with("ssh-")
                                    || unquoted.starts_with("ecdsa-")
                                    || unquoted.starts_with("sk-"))
                            {
                                ssh_keys.push(unquoted.to_string());
                            }
                        }
                    }
                    "ports" => {
                        for s in value.split(',') {
                            let trimmed = s.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            match trimmed.parse::<u16>() {
                                Ok(port) if port > 0 => {
                                    if is_reserved(port) {
                                        return Err(FromProcfileError::ReservedPort(port));
                                    }
                                    ports.push(port);
                                }
                                Ok(_) => {}
                                Err(_) => {}
                            }
                        }
                        ports.sort();
                        ports.dedup();
                    }
                    "http_port" => match value.parse::<u16>() {
                        Ok(port) if port > 0 => {
                            http_port = Some(port);
                        }
                        _ => {}
                    },
                    "domain" => {
                        if !value.is_empty() {
                            domain = Some(value);
                        }
                    }
                    "e2e" => {
                        procfile_e2e = Some(value.to_lowercase() == "true");
                    }
                    "managed_on_prem" => {
                        managed_on_prem = value.to_lowercase() == "true";
                    }
                    "platform" => {
                        if !value.is_empty() {
                            platform = Some(value.to_lowercase());
                        }
                    }
                    "aws_region" => {
                        if !value.is_empty() {
                            aws_region = Some(value);
                        }
                    }
                    "aws_vpc_id" => {
                        if !value.is_empty() {
                            aws_vpc_id = Some(value);
                        }
                    }
                    "aws_subnet_id" => {
                        if !value.is_empty() {
                            aws_subnet_id = Some(value);
                        }
                    }
                    "aws_security_group_id" => {
                        if !value.is_empty() {
                            aws_security_group_id = Some(value);
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(hp) = http_port {
            if !ports.contains(&hp) {
                return Err(FromProcfileError::HttpPortNotInPorts(hp));
            }
        }

        let http_port = match http_port {
            Some(hp) => Some(hp),
            None if ports.len() == 1 => Some(ports[0]),
            None => None,
        };

        let build = if containerfile.is_some()
            || binary.is_some()
            || !app_sources.is_empty()
            || cache.is_some()
        {
            Some(BuildConfig {
                containerfile,
                binary,
                app_sources,
                cache,
            })
        } else {
            None
        };

        let has_debug = debug.is_some() || !ssh_keys.is_empty();
        let debug_config = if has_debug {
            Some(DebugConfig {
                enabled: debug,
                ssh_keys,
            })
        } else {
            None
        };

        let resources = match (memory_mb, cpus) {
            (Some(mem), Some(cpu)) => Some(ResourceConfig {
                cpu,
                memory_mb: mem,
            }),
            (Some(mem), None) => Some(ResourceConfig {
                cpu: 2,
                memory_mb: mem,
            }),
            (None, Some(cpu)) => Some(ResourceConfig {
                cpu,
                memory_mb: 512,
            }),
            (None, None) => None,
        };

        let e2e_encryption = procfile_e2e.map(|enabled| E2eEncryption {
            enabled: Some(enabled),
            cors_origins: None,
        });

        let http = match (domain, http_port) {
            (Some(d), Some(p)) => Some(HttpConfig {
                domain: d,
                port: p,
                e2e_encryption: e2e_encryption.clone(),
            }),
            (Some(d), None) => Some(HttpConfig {
                domain: d,
                port: 80,
                e2e_encryption: e2e_encryption.clone(),
            }),
            (None, _) => None,
        };

        let network = if !ports.is_empty() || http.is_some() {
            let ingress: Vec<TrafficRule> = ports
                .iter()
                .map(|&port| TrafficRule {
                    cidr_ipv4: "0.0.0.0/0".into(),
                    port_spec: Some(PortSpec::Exact { port }),
                    ip_protocol: Some("tcp".into()),
                })
                .collect();
            Some(NetworkConfig {
                ingress,
                egress: Vec::new(),
                http,
            })
        } else {
            None
        };

        let unit = run.map(|cmd| {
            let parts = shlex::split(&cmd);
            let (command, args) = match parts {
                Some(p) if !p.is_empty() => (p[0].clone(), p[1..].to_vec()),
                _ => (cmd, Vec::new()),
            };
            let mut units = BTreeMap::new();
            units.insert(
                "default".to_string(),
                UnitConfig {
                    command,
                    args,
                    env: None,
                },
            );
            units
        });

        let has_any_field = build.is_some()
            || debug_config.is_some()
            || network.is_some()
            || resources.is_some()
            || unit.is_some();

        let enclave = if has_any_field {
            Some(BTreeMap::from([(
                "default".to_string(),
                EnclaveConfig {
                    build,
                    debug: debug_config,
                    network,
                    resources,
                    unit,
                },
            )]))
        } else {
            None
        };

        let provider = if managed_on_prem {
            let platform = platform.ok_or(FromProcfileError::ManagedOnPremMissingPlatform)?;
            match platform.as_str() {
                "aws" => {
                    let region = aws_region.ok_or(FromProcfileError::ManagedOnPremMissingRegion)?;
                    Some(Provider::Aws(AwsProviderConfig {
                        region,
                        vpc_id: aws_vpc_id,
                        subnet_ids: aws_subnet_id.map(|id| vec![id]),
                        security_group_id: aws_security_group_id,
                    }))
                }
                other => {
                    return Err(FromProcfileError::ManagedOnPremUnsupportedPlatform(
                        other.to_string(),
                    ));
                }
            }
        } else {
            None
        };

        let caution = provider.map(|p| CautionConfig {
            managed_credentials: None,
            machine_type: None,
            build_machine_type: None,
            provider: Some(p),
        });

        Ok(ConfigurationFile { caution, enclave })
    }

    pub fn from_str(s: &str) -> Result<Self, FromStrError> {
        let config: ConfigurationFile = hcl::from_str(s)?;

        if let Some((_, enclave)) = &config.enclave.iter().flatten().next()
            && let Some(network) = &enclave.network
        {
            for ingress in &network.ingress {
                match ingress.port_spec {
                    // There's no stdlib range intersection, but I think this may be more elegant.
                    Some(PortSpec::FromTo {
                        start_port,
                        end_port,
                    }) if start_port <= RESERVED_INTERNAL_PORT_END
                        && end_port >= RESERVED_INTERNAL_PORT_START =>
                    {
                        return Err(FromStrError::ReservedPort);
                    }
                    Some(PortSpec::Exact { port }) if is_reserved(port) => {
                        return Err(FromStrError::ReservedPort);
                    }
                    _ => (),
                }
            }
        }

        if let Some(ref enclaves) = config.enclave {
            if enclaves.len() > 1 {
                return Err(FromStrError::MultipleEnclaves);
            }

            if let Some((_name, enclave)) = enclaves.iter().next() {
                if let Some(ref network) = enclave.network
                    && let Some(ref http) = network.http
                {
                    let port_covered = network.ingress.iter().any(|rule| match &rule.port_spec {
                        Some(PortSpec::Exact { port }) => *port == http.port,
                        Some(PortSpec::FromTo {
                            start_port,
                            end_port,
                        }) => *start_port <= http.port && http.port <= *end_port,
                        None => false,
                    });
                    if !port_covered {
                        return Err(FromStrError::HttpPortNotInPorts(http.port));
                    }
                }

                if let Some(ref units) = enclave.unit {
                    for (unit_name, unit) in units {
                        if let Some(ref env) = unit.env {
                            for (key, expr) in env {
                                match expr {
                                    Expression::String(_) | Expression::FuncCall(_) => continue,
                                    _ => {
                                        return Err(FromStrError::InvalidEnvExpression(format!(
                                            "{}.{}",
                                            unit_name, key
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(config)
    }

    /// Returns `true` if any `env` block contains `env::vault(...)` expressions,
    /// which requires locksmith to be enabled for secret management.
    pub fn has_vault_env(&self) -> bool {
        self.enclave.as_ref().is_some_and(|enclaves| {
            enclaves.values().any(|enclave| {
                enclave.unit.as_ref().is_some_and(|units| {
                    units.values().any(|unit| {
                        unit.env.as_ref().is_some_and(|env| {
                            env.values().any(|expr| {
                                matches!(expr, Expression::FuncCall(fc)
                                    if fc.name.namespace.iter().any(|n| n.as_str() == "env")
                                    && fc.name.name.as_str() == "vault")
                            })
                        })
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_configuration_file() -> ConfigurationFile {
        ConfigurationFile {
            caution: Some(CautionConfig {
                managed_credentials: Some("credentials.pgp".into()),
                machine_type: Some("c5.xlarge".into()),
                build_machine_type: Some("c5.xlarge".into()),
                provider: None,
            }),
            enclave: Some(BTreeMap::from([(
                "main".into(),
                EnclaveConfig {
                    build: Some(BuildConfig {
                        containerfile: Some("Containerfile.example".into()),
                        binary: Some("static-binary".into()),
                        app_sources: vec![
                            "git@codeberg.org:caution/demo-hello-world-enclave".into(),
                            "https://codeberg.org/caution/demo-hello-world-enclave".into(),
                        ],
                        cache: Some(false),
                    }),
                    debug: Some(DebugConfig {
                        enabled: Some(true),
                        ssh_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiqWyt0v5RpZqVK9EUeTWdCBGQo6+GN6jbUe0mPSEfV ryan@left".into()],
                    }),
                    network: Some(NetworkConfig {
                        ingress: vec![TrafficRule {
                            cidr_ipv4: "0.0.0.0/0".into(),
                            port_spec: Some(PortSpec::FromTo {
                                start_port: 40000,
                                end_port: 40005,
                            }),
                            ip_protocol: Some("tcp".into()),
                        }],
                        egress: vec![TrafficRule {
                            cidr_ipv4: "0.0.0.0/0".into(),
                            port_spec: None,
                            ip_protocol: None,
                        }],
                        http: Some(HttpConfig {
                            domain: "chat.caution.dev".into(),
                            port: 8000,
                            e2e_encryption: Some(E2eEncryption {
                                enabled: Some(true),
                                cors_origins: Some(vec!["*".into()]),
                            }),
                        }),
                    }),
                    resources: Some(ResourceConfig {
                        cpu: 2,
                        memory_mb: 2000,
                    }),
                    unit: Some(BTreeMap::from([(
                        "main".into(),
                        UnitConfig {
                            command: "/usr/bin/hello".into(),
                            args: vec!["hello".into(), "world".into()],
                            env: Some(BTreeMap::from([
                                ("FOO".into(), Expression::from("bar")),
                                ("HELLO".into(), Expression::from("world")),
                            ])),
                        },
                    )])),
                },
            )])),
        }
    }

    #[test]
    fn test_hcl_round_trip() {
        let config = sample_configuration_file();
        let hcl_str = hcl::to_string(&config).expect("serialize to HCL");
        let deserialized: ConfigurationFile =
            hcl::from_str(&hcl_str).expect("deserialize from HCL");
        assert_eq!(config.caution.is_some(), deserialized.caution.is_some());
        assert_eq!(
            config.caution.as_ref().unwrap().managed_credentials,
            deserialized.caution.as_ref().unwrap().managed_credentials
        );
        assert_eq!(
            config.caution.as_ref().unwrap().machine_type,
            deserialized.caution.as_ref().unwrap().machine_type
        );
    }

    #[test]
    fn test_deserialize_example_hcl() {
        let config: ConfigurationFile = hcl::from_str(EXAMPLE_HCL).expect("parse HCL");
        let caution = config.caution.expect("caution block");
        assert_eq!(
            caution.managed_credentials.as_deref(),
            Some("credentials.pgp")
        );
        assert_eq!(caution.machine_type.as_deref(), Some("c5.xlarge"));
        let enclave = config.enclave.expect("enclave block");
        let main = enclave.get("main").expect("enclave main");
        let build = main.build.as_ref().expect("build block");
        assert_eq!(
            build.containerfile.as_deref(),
            Some("Containerfile.example")
        );
        assert!(build.app_sources.len() >= 2);
        let resources = main.resources.as_ref().expect("resources block");
        assert_eq!(resources.cpu, 2);
        assert_eq!(resources.memory_mb, 2000);
    }

    #[test]
    fn test_ingress_egress_single_and_multiple() {
        let hcl_no_network = r#"
enclave "test" {
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config: ConfigurationFile = hcl::from_str(hcl_no_network).expect("parse HCL");
        let enclave = config.enclave.expect("enclave block");
        let test_enclave = enclave.get("test").expect("enclave test");
        assert!(test_enclave.network.is_none());

        let hcl_single = r#"
enclave "test" {
  network {
    ingress {
      cidr_ipv4 = "10.0.0.0/8"
      port = 443
      ip_protocol = "tcp"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config: ConfigurationFile = hcl::from_str(hcl_single).expect("parse HCL");
        let enclave = config.enclave.expect("enclave block");
        let test_enclave = enclave.get("test").expect("enclave test");
        let network = test_enclave.network.as_ref().expect("network block");
        assert_eq!(network.ingress.len(), 1);
        assert_eq!(network.ingress[0].cidr_ipv4, "10.0.0.0/8");

        let hcl_multi = r#"
enclave "test" {
  network {
    ingress {
      cidr_ipv4 = "10.0.0.0/8"
      port = 443
      ip_protocol = "tcp"
    }
    ingress {
      cidr_ipv4 = "192.168.0.0/16"
      port = 80
      ip_protocol = "tcp"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config: ConfigurationFile = hcl::from_str(hcl_multi).expect("parse HCL");
        let enclave = config.enclave.expect("enclave block");
        let test_enclave = enclave.get("test").expect("enclave test");
        let network = test_enclave.network.as_ref().expect("network block");
        assert_eq!(network.ingress.len(), 2);
        assert_eq!(network.ingress[0].cidr_ipv4, "10.0.0.0/8");
        assert_eq!(network.ingress[1].cidr_ipv4, "192.168.0.0/16");
    }

    #[test]
    fn test_env_expression_round_trip() {
        let hcl = r#"
enclave "test" {
  unit "main" {
    command = "/app/run"
    env {
      API_KEY = env::vault("API_KEY")
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config: ConfigurationFile = hcl::from_str(hcl).expect("parse HCL");
        let enclave = config.enclave.as_ref().expect("enclave block");
        let test_enclave = enclave.get("test").expect("enclave test");
        let unit = test_enclave
            .unit
            .as_ref()
            .expect("unit block")
            .get("main")
            .expect("unit main");
        let env = unit.env.as_ref().expect("env block");
        let _api_key = env.get("API_KEY").expect("API_KEY entry");
        let serialized = hcl::to_string(&config).expect("serialize to HCL");
        assert!(
            serialized.contains("env::vault"),
            "expression preserved in output"
        );
        let _: ConfigurationFile = hcl::from_str(&serialized).expect("re-deserialize");
    }

    // ── from_str tests ───────────────────────────────────────────────

    #[test]
    fn test_from_str_valid_hcl() {
        let hcl = r#"
enclave "main" {
  resources {
    cpu = 2
    memory_mb = 2000
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        let enclave = config.enclave.unwrap();
        let main = enclave.get("main").unwrap();
        let resources = main.resources.as_ref().unwrap();
        assert_eq!(resources.cpu, 2);
        assert_eq!(resources.memory_mb, 2000);
    }

    #[test]
    fn test_from_str_rejects_multiple_enclaves() {
        let hcl = r#"
enclave "main" {
  resources {
    cpu = 1
    memory_mb = 512
  }
}
enclave "worker" {
  resources {
    cpu = 1
    memory_mb = 256
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::MultipleEnclaves));
    }

    #[test]
    fn test_from_str_rejects_missing_http_port_in_ingress() {
        let hcl = r#"
enclave "main" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
    http {
      domain = "example.com"
      port = 9090
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::HttpPortNotInPorts(9090)));
    }

    #[test]
    fn test_from_str_rejects_invalid_env_expression() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      BAD_KEY = [1, 2, 3]
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::InvalidEnvExpression(_)));
    }

    #[test]
    fn test_from_str_accepts_string_env() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      KEY = "value"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        ConfigurationFile::from_str(hcl).unwrap();
    }

    #[test]
    fn test_from_str_accepts_funccall_env() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      API_KEY = env::vault("API_KEY")
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        ConfigurationFile::from_str(hcl).unwrap();
    }

    #[test]
    fn test_from_str_single_enclave_extracted() {
        let hcl = r#"
enclave "myapp" {
  build {
    containerfile = "Containerfile.custom"
    binary = "mybinary"
  }
  resources {
    cpu = 4
    memory_mb = 4000
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        let enclaves = config.enclave.unwrap();
        assert_eq!(enclaves.len(), 1);
        let (_label, e) = enclaves.iter().next().unwrap();
        assert_eq!(e.resources.as_ref().unwrap().cpu, 4);
        assert_eq!(e.resources.as_ref().unwrap().memory_mb, 4000);
        assert_eq!(
            e.build.as_ref().unwrap().containerfile.as_deref(),
            Some("Containerfile.custom")
        );
    }

    #[test]
    fn test_from_str_empty_hcl() {
        let config = ConfigurationFile::from_str("").unwrap();
        assert!(config.caution.is_none());
        assert!(config.enclave.is_none());
    }

    #[test]
    fn test_from_str_caution_only() {
        let hcl = r#"
caution {
  managed_credentials = "creds.pgp"
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        assert!(config.enclave.is_none());
        assert_eq!(
            config.caution.unwrap().managed_credentials.as_deref(),
            Some("creds.pgp")
        );
    }

    // ── has_vault_env tests ──────────────────────────────────────────

    #[test]
    fn test_has_vault_env_true() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      API_KEY = env::vault("API_KEY")
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        assert!(config.has_vault_env());
    }

    #[test]
    fn test_has_vault_env_false_when_no_env() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        assert!(!config.has_vault_env());
    }

    #[test]
    fn test_has_vault_env_false_when_string_env() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      KEY = "plaintext"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        assert!(!config.has_vault_env());
    }

    #[test]
    fn test_has_vault_env_false_when_other_funccall() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      KEY = upper("value")
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        assert!(!config.has_vault_env());
    }

    #[test]
    fn test_has_vault_env_false_no_enclave() {
        let config = ConfigurationFile {
            caution: None,
            enclave: None,
        };
        assert!(!config.has_vault_env());
    }

    #[test]
    fn test_has_vault_env_with_plain_env_and_vault() {
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      PLAIN = "value"
      SECRET = env::vault("SECRET")
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        assert!(config.has_vault_env());
    }

    // ── from_procfile tests ──────────────────────────────────────────

    #[test]
    fn test_from_procfile_run_command() {
        let procfile = "run: /app/server\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let default = enclave.get("default").unwrap();
        let unit = default.unit.as_ref().unwrap();
        let main = unit.get("default").unwrap();
        assert_eq!(main.command, "/app/server");
        assert!(main.args.is_empty());
    }

    #[test]
    fn test_from_procfile_run_with_args() {
        let procfile = "run: /app/server --port 8080\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let unit = enclave.get("default").unwrap().unit.as_ref().unwrap();
        let main = unit.get("default").unwrap();
        assert_eq!(main.command, "/app/server");
        assert_eq!(main.args, vec!["--port", "8080"]);
    }

    #[test]
    fn test_from_procfile_ports_mapped_to_ingress() {
        let procfile = "run: /app/server\nports: 80, 443\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let network = enclave.get("default").unwrap().network.as_ref().unwrap();
        assert_eq!(network.ingress.len(), 2);
        assert_eq!(network.ingress[0].cidr_ipv4, "0.0.0.0/0");
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 80 })
        );
        assert_eq!(network.ingress[0].ip_protocol, Some("tcp".into()));
        assert_eq!(
            network.ingress[1].port_spec,
            Some(PortSpec::Exact { port: 443 })
        );
    }

    #[test]
    fn test_from_procfile_all_fields() {
        let procfile = "\
run: /app/server --port 8080
containerfile: Containerfile.custom
binary: myapp
app_sources: url1, url2
memory_mb: 2000
cpus: 4
debug: true
ssh_keys: ssh-ed25519 AAAA...
ports: 8080
http_port: 8080
domain: example.com
cache: false
";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let e = enclave.get("default").unwrap();

        let build = e.build.as_ref().unwrap();
        assert_eq!(build.containerfile.as_deref(), Some("Containerfile.custom"));
        assert_eq!(build.binary.as_deref(), Some("myapp"));
        assert_eq!(build.app_sources, vec!["url1", "url2"]);
        assert_eq!(build.cache, Some(false));

        let resources = e.resources.as_ref().unwrap();
        assert_eq!(resources.memory_mb, 2000);
        assert_eq!(resources.cpu, 4);

        let debug = e.debug.as_ref().unwrap();
        assert_eq!(debug.enabled, Some(true));
        assert_eq!(debug.ssh_keys, vec!["ssh-ed25519 AAAA..."]);

        let network = e.network.as_ref().unwrap();
        assert_eq!(network.ingress.len(), 1);
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 8080 })
        );
        let http = network.http.as_ref().unwrap();
        assert_eq!(http.domain, "example.com");
        assert_eq!(http.port, 8080);

        let unit = e.unit.as_ref().unwrap();
        let main = unit.get("default").unwrap();
        assert_eq!(main.command, "/app/server");
        assert_eq!(main.args, vec!["--port", "8080"]);
        assert!(main.env.is_none());
    }

    #[test]
    fn test_from_procfile_empty() {
        let config = ConfigurationFile::from_procfile("").unwrap();
        assert!(config.caution.is_none());
        assert!(config.enclave.is_none());
    }

    #[test]
    fn test_from_procfile_only_comments() {
        let procfile = "# this is a comment\n# another comment\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        assert!(config.caution.is_none());
        assert!(config.enclave.is_none());
    }

    #[test]
    fn test_from_procfile_comments_and_blank_lines() {
        let procfile = "\n# comment\n\nrun: /app\n# trailing\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let unit = enclave.get("default").unwrap().unit.as_ref().unwrap();
        assert_eq!(unit.get("default").unwrap().command, "/app");
    }

    #[test]
    fn test_from_procfile_unknown_fields_skipped() {
        let procfile = "run: /app\nunknown_field: value\nanother_unknown: 123\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let unit = enclave.get("default").unwrap().unit.as_ref().unwrap();
        assert_eq!(unit.get("default").unwrap().command, "/app");
    }

    #[test]
    fn test_from_procfile_http_port_and_domain() {
        let procfile = "run: /app\nports: 8080\nhttp_port: 8080\ndomain: myapp.example.com\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let network = enclave.get("default").unwrap().network.as_ref().unwrap();
        let http = network.http.as_ref().unwrap();
        assert_eq!(http.domain, "myapp.example.com");
        assert_eq!(http.port, 8080);
    }

    #[test]
    fn test_from_procfile_nocache_inverted() {
        let procfile = "run: /app\nnocache: true\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let build = enclave.get("default").unwrap().build.as_ref().unwrap();
        assert_eq!(build.cache, Some(false));
    }

    #[test]
    fn test_from_procfile_no_cache_inverted() {
        let procfile = "run: /app\nno_cache: true\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let build = enclave.get("default").unwrap().build.as_ref().unwrap();
        assert_eq!(build.cache, Some(false));
    }

    #[test]
    fn test_from_procfile_nocache_false() {
        let procfile = "run: /app\nnocache: false\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let build = enclave.get("default").unwrap().build.as_ref().unwrap();
        assert_eq!(build.cache, Some(true));
    }

    #[test]
    fn test_from_procfile_cache_last_wins() {
        let procfile = "run: /app\ncache: true\nnocache: true\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let build = enclave.get("default").unwrap().build.as_ref().unwrap();
        assert_eq!(build.cache, Some(false));
    }

    #[test]
    fn test_from_procfile_reserved_port_rejected() {
        let procfile = "run: /app\nports: 49500\n";
        let result = ConfigurationFile::from_procfile(procfile);
        assert!(matches!(
            result,
            Err(FromProcfileError::ReservedPort(49500))
        ));
    }

    // ── Real-world Procfile tests ─────────────────────────────────────

    const DEMO_HELLO_WORLD_PROCFILE: &str =
        include_str!("../tests/data/demo-hello-world-enclave/Procfile");

    const DEMO_AI_INFERENCE_PROCFILE: &str =
        include_str!("../tests/data/demo-ai-inference/Procfile");

    const LOCKSMITH_PROCFILE: &str = include_str!("../tests/data/locksmith/Procfile");

    const EXAMPLE_HCL: &str = include_str!("../tests/data/example/caution.hcl");

    const DEMO_HELLO_WORLD_HCL: &str =
        include_str!("../tests/data/demo-hello-world-enclave/caution.hcl");

    const DEMO_AI_INFERENCE_HCL: &str =
        include_str!("../tests/data/demo-ai-inference/caution.hcl");

    const LOCKSMITH_HCL: &str = include_str!("../tests/data/locksmith/caution.hcl");

    #[test]
    fn demo_hello_world_enclave() {
        let config = ConfigurationFile::from_procfile(DEMO_HELLO_WORLD_PROCFILE).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let e = enclave.get("default").unwrap();

        let unit = e.unit.as_ref().unwrap().get("default").unwrap();
        assert_eq!(unit.command, "/usr/local/bin/hello");
        assert!(unit.args.is_empty());

        let build = e.build.as_ref().unwrap();
        assert_eq!(build.binary.as_deref(), Some("/usr/local/bin/hello"));

        assert_eq!(
            build.app_sources,
            vec!["git@codeberg.org:caution/demo-hello-world-enclave.git"]
        );

        let network = e.network.as_ref().unwrap();
        assert_eq!(network.ingress.len(), 1);
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 8083 })
        );
        assert!(network.http.is_none());
    }

    #[test]
    fn demo_ai_inference() {
        let config = ConfigurationFile::from_procfile(DEMO_AI_INFERENCE_PROCFILE).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let e = enclave.get("default").unwrap();

        let unit = e.unit.as_ref().unwrap().get("default").unwrap();
        assert_eq!(unit.command, "/usr/bin/llama-server");
        assert_eq!(
            unit.args,
            vec![
                "--host",
                "0.0.0.0",
                "--port",
                "8083",
                "-m",
                "/workdir/models/model.gguf",
                "--path",
                "/workdir/public",
                "--ctx-size",
                "2048",
                "-t",
                "8",
            ]
        );

        let network = e.network.as_ref().unwrap();
        let http = network.http.as_ref().unwrap();
        assert_eq!(http.domain, "chat.caution.dev");
        assert_eq!(http.port, 80);

        let build = e.build.as_ref().unwrap();
        assert_eq!(
            build.app_sources,
            vec!["https://codeberg.org/caution/demo-ai-inference.git"]
        );

        let resources = e.resources.as_ref().unwrap();
        assert_eq!(resources.memory_mb, 55000);
        assert_eq!(resources.cpu, 14);

        assert_eq!(build.cache, Some(false));

        assert!(network.ingress.is_empty());
    }

    #[test]
    fn locksmith() {
        let config = ConfigurationFile::from_procfile(LOCKSMITH_PROCFILE).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let e = enclave.get("default").unwrap();

        let unit = e.unit.as_ref().unwrap().get("default").unwrap();
        assert_eq!(unit.command, "/keymaker");
        assert!(unit.args.is_empty());

        let build = e.build.as_ref().unwrap();
        assert_eq!(
            build.app_sources,
            vec!["https://codeberg.org/caution/locksmith/archive/${COMMIT}.tar.gz"]
        );

        let network = e.network.as_ref().unwrap();
        assert_eq!(network.ingress.len(), 1);
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 8080 })
        );
        assert!(network.http.is_none());

        let debug = e.debug.as_ref().unwrap();
        assert_eq!(debug.enabled, Some(true));
        assert_eq!(debug.ssh_keys.len(), 1);
        assert!(debug.ssh_keys[0].starts_with("ssh-rsa"));
    }

    // ── from_str real-world fixture tests ────────────────────────────

    #[test]
    fn demo_hello_world_enclave_hcl() {
        let config = ConfigurationFile::from_str(DEMO_HELLO_WORLD_HCL).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let e = enclave.get("default").unwrap();

        let unit = e.unit.as_ref().unwrap().get("default").unwrap();
        assert_eq!(unit.command, "/usr/local/bin/hello");
        assert!(unit.args.is_empty());

        let build = e.build.as_ref().unwrap();
        assert_eq!(build.binary.as_deref(), Some("/usr/local/bin/hello"));

        assert_eq!(
            build.app_sources,
            vec!["git@codeberg.org:caution/demo-hello-world-enclave.git"]
        );

        let network = e.network.as_ref().unwrap();
        assert_eq!(network.ingress.len(), 1);
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 8083 })
        );
        assert!(network.http.is_none());
    }

    #[test]
    fn demo_ai_inference_hcl() {
        let config = ConfigurationFile::from_str(DEMO_AI_INFERENCE_HCL).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let e = enclave.get("default").unwrap();

        let unit = e.unit.as_ref().unwrap().get("default").unwrap();
        assert_eq!(unit.command, "/usr/bin/llama-server");
        assert_eq!(
            unit.args,
            vec![
                "--host",
                "0.0.0.0",
                "--port",
                "8083",
                "-m",
                "/workdir/models/model.gguf",
                "--path",
                "/workdir/public",
                "--ctx-size",
                "2048",
                "-t",
                "8",
            ]
        );

        let network = e.network.as_ref().unwrap();
        let http = network.http.as_ref().unwrap();
        assert_eq!(http.domain, "chat.caution.dev");
        assert_eq!(http.port, 80);

        let build = e.build.as_ref().unwrap();
        assert_eq!(
            build.app_sources,
            vec!["https://codeberg.org/caution/demo-ai-inference.git"]
        );

        let resources = e.resources.as_ref().unwrap();
        assert_eq!(resources.memory_mb, 55000);
        assert_eq!(resources.cpu, 14);

        assert_eq!(build.cache, Some(false));

        assert_eq!(network.ingress.len(), 1);
        assert_eq!(network.ingress[0].port_spec, Some(PortSpec::Exact { port: 80 }));
    }

    #[test]
    fn locksmith_hcl() {
        let config = ConfigurationFile::from_str(LOCKSMITH_HCL).unwrap();
        let enclave = config.enclave.as_ref().unwrap();
        let e = enclave.get("default").unwrap();

        let unit = e.unit.as_ref().unwrap().get("default").unwrap();
        assert_eq!(unit.command, "/keymaker");
        assert!(unit.args.is_empty());

        let build = e.build.as_ref().unwrap();
        assert_eq!(
            build.app_sources,
            vec!["https://codeberg.org/caution/locksmith/archive/${COMMIT}.tar.gz"]
        );

        let network = e.network.as_ref().unwrap();
        assert_eq!(network.ingress.len(), 1);
        assert_eq!(
            network.ingress[0].port_spec,
            Some(PortSpec::Exact { port: 8080 })
        );
        assert!(network.http.is_none());

        let debug = e.debug.as_ref().unwrap();
        assert_eq!(debug.enabled, Some(true));
        assert_eq!(debug.ssh_keys.len(), 1);
        assert!(debug.ssh_keys[0].starts_with("ssh-rsa"));
    }

    // ── Provider HCL tests ──────────────────────────────────────────

    #[test]
    fn test_provider_block_parsed_as_aws() {
        let hcl = r#"
caution {
  provider {
    type = "aws"
    region = "us-east-1"
    vpc_id = "vpc-123"
    subnet_ids = ["subnet-a", "subnet-b"]
    security_group_id = "sg-456"
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        let caution = config.caution.expect("caution block");
        let provider = caution.provider.expect("provider");
        let aws = match provider {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-123"));
        assert_eq!(
            aws.subnet_ids,
            Some(vec!["subnet-a".into(), "subnet-b".into()])
        );
        assert_eq!(aws.security_group_id.as_deref(), Some("sg-456"));
    }

    #[test]
    fn test_provider_block_minimal_region_only() {
        let hcl = r#"
caution {
  provider {
    type = "aws"
    region = "us-west-2"
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        let caution = config.caution.expect("caution block");
        let provider = caution.provider.expect("provider");
        let aws = match provider {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "us-west-2");
        assert!(aws.vpc_id.is_none());
        assert!(aws.subnet_ids.is_none());
        assert!(aws.security_group_id.is_none());
    }

    #[test]
    fn test_provider_block_full_with_all_fields() {
        let hcl = r#"
caution {
  provider {
    type = "aws"
    region = "eu-west-1"
    vpc_id = "vpc-xxx"
    subnet_ids = ["subnet-1"]
    security_group_id = "sg-yyy"
  }
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        let caution = config.caution.expect("caution block");
        let provider = caution.provider.expect("provider");
        let aws = match provider {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "eu-west-1");
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-xxx"));
        assert_eq!(aws.subnet_ids, Some(vec!["subnet-1".into()]));
        assert_eq!(aws.security_group_id.as_deref(), Some("sg-yyy"));
    }

    #[test]
    fn test_provider_block_omitted_is_none() {
        let hcl = r#"
caution {
  managed_credentials = "creds.pgp"
}
"#;
        let config = ConfigurationFile::from_str(hcl).unwrap();
        let caution = config.caution.expect("caution block");
        assert!(caution.provider.is_none());
    }

    #[test]
    fn test_provider_round_trip() {
        let config = ConfigurationFile {
            caution: Some(CautionConfig {
                managed_credentials: None,
                machine_type: None,
                build_machine_type: None,
                provider: Some(Provider::Aws(AwsProviderConfig {
                    region: "ap-southeast-1".into(),
                    vpc_id: Some("vpc-roundtrip".into()),
                    subnet_ids: Some(vec!["subnet-a".into()]),
                    security_group_id: None,
                })),
            }),
            enclave: None,
        };
        let hcl_str = hcl::to_string(&config).expect("serialize");
        let deserialized = ConfigurationFile::from_str(&hcl_str).expect("deserialize");
        let caution = deserialized.caution.expect("caution block");
        let aws = match caution.provider.expect("provider") {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "ap-southeast-1");
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-roundtrip"));
    }

    #[test]
    fn test_provider_unknown_type_rejected() {
        let hcl = r#"
caution {
  provider {
    type = "gcp"
    region = "us-central1"
  }
}
"#;
        let result = ConfigurationFile::from_str(hcl);
        assert!(result.is_err());
    }

    // ── from_procfile managed_on_prem tests ─────────────────────────

    #[test]
    fn test_from_procfile_managed_on_prem_all_fields() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: aws
aws_region: us-east-1
aws_vpc_id: vpc-123
aws_subnet_id: subnet-a
aws_security_group_id: sg-456
";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let caution = config.caution.expect("caution block");
        let aws = match caution.provider.expect("provider") {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-123"));
        assert_eq!(aws.subnet_ids, Some(vec!["subnet-a".into()]));
        assert_eq!(aws.security_group_id.as_deref(), Some("sg-456"));
    }

    #[test]
    fn test_from_procfile_managed_on_prem_minimal() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: aws
aws_region: us-west-2
";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let caution = config.caution.expect("caution block");
        let aws = match caution.provider.expect("provider") {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "us-west-2");
        assert!(aws.vpc_id.is_none());
        assert!(aws.subnet_ids.is_none());
        assert!(aws.security_group_id.is_none());
    }

    #[test]
    fn test_from_procfile_managed_on_prem_without_managed_on_prem() {
        let procfile = "\
run: /app
platform: aws
aws_region: us-east-1
";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        assert!(config.caution.is_none() || config.caution.as_ref().unwrap().provider.is_none());
    }

    #[test]
    fn test_from_procfile_managed_on_prem_missing_platform() {
        let procfile = "\
run: /app
managed_on_prem: true
aws_region: us-east-1
";
        let err = ConfigurationFile::from_procfile(procfile).unwrap_err();
        assert!(matches!(
            err,
            FromProcfileError::ManagedOnPremMissingPlatform
        ));
    }

    #[test]
    fn test_from_procfile_managed_on_prem_unsupported_platform() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: azure
aws_region: us-east-1
";
        let err = ConfigurationFile::from_procfile(procfile).unwrap_err();
        assert!(matches!(
            err,
            FromProcfileError::ManagedOnPremUnsupportedPlatform(_)
        ));
    }

    #[test]
    fn test_from_procfile_managed_on_prem_missing_region() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: aws
";
        let err = ConfigurationFile::from_procfile(procfile).unwrap_err();
        assert!(matches!(err, FromProcfileError::ManagedOnPremMissingRegion));
    }

    #[test]
    fn test_egress_enabled_reflects_rule_presence() {
        let hcl = r#"
enclave "main" {
  network {
    egress { cidr_ipv4 = "0.0.0.0/0" }
  }
}
"#;
        let cfg: ConfigurationFile = hcl::from_str(hcl).expect("parse HCL");
        let net = cfg.enclave.unwrap().get("main").unwrap().network.clone().unwrap();
        assert!(net.egress_enabled());

        let hcl_empty = r#"
enclave "main" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
  }
}
"#;
        let cfg2: ConfigurationFile = hcl::from_str(hcl_empty).expect("parse HCL");
        let net2 = cfg2.enclave.unwrap().get("main").unwrap().network.clone().unwrap();
        assert!(!net2.egress_enabled());
    }
}
