use hcl::expr::Expression;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

fn single_or_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    match OneOrMany::<T>::deserialize(d)? {
        OneOrMany::One(v) => Ok(vec![v]),
        OneOrMany::Many(v) => Ok(v),
    }
}

/// Top-level `caution { }` block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CautionConfig {
    pub managed_credentials: Option<String>,
    pub machine_type: Option<String>,
    pub build_machine_type: Option<String>,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    FromTo { from_port: u16, to_port: u16 },
    Exact { port: u16 }
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
    pub port: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_configuration_file() -> ConfigurationFile {
        ConfigurationFile {
            caution: Some(CautionConfig {
                managed_credentials: Some("credentials.pgp".into()),
                machine_type: Some("c5.xlarge".into()),
                build_machine_type: Some("c5.xlarge".into()),
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
                                from_port: 80,
                                to_port: 80,
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
                            port: "8000".into(),
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
        let hcl = r#"
caution {
  managed_credentials = "credentials.pgp"
  machine_type = "c5.xlarge"
  build_machine_type = "c5.xlarge"
}

enclave "main" {
  build {
    containerfile = "Containerfile.example"
    binary = "static-binary"
    app_sources = [
      "git@codeberg.org:caution/demo-hello-world-enclave",
      "https://codeberg.org/caution/demo-hello-world-enclave",
    ]
    cache = false
  }

  debug {
    enabled = true
    ssh_keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiqWyt0v5RpZqVK9EUeTWdCBGQo6+GN6jbUe0mPSEfV ryan@left"
    ]
  }

  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      from_port = 80
      to_port = 80
      ip_protocol = "tcp"
    }
    egress {
      cidr_ipv4 = "0.0.0.0/0"
    }
    http {
      domain = "chat.caution.dev"
      port = "8000"
      e2e_encryption {
        enabled = true
        cors_origins = ["*"]
      }
    }
  }

  resources {
    cpu = 2
    memory_mb = 2000
  }

  unit "main" {
    command = "/usr/bin/hello"
    args = ["hello", "world"]
    env {
      FOO = "bar"
      HELLO = "world"
    }
  }
}
"#;
        let config: ConfigurationFile = hcl::from_str(hcl).expect("parse HCL");
        let caution = config.caution.expect("caution block");
        assert_eq!(caution.managed_credentials.as_deref(), Some("credentials.pgp"));
        assert_eq!(caution.machine_type.as_deref(), Some("c5.xlarge"));
        let enclave = config.enclave.expect("enclave block");
        let main = enclave.get("main").expect("enclave main");
        let build = main.build.as_ref().expect("build block");
        assert_eq!(build.containerfile.as_deref(), Some("Containerfile.example"));
        assert!(build.app_sources.len() >= 2);
        let resources = main.resources.as_ref().expect("resources block");
        assert_eq!(resources.cpu, 2);
        assert_eq!(resources.memory_mb, 2000);
    }

    #[test]
    fn test_ingress_egress_single_and_multiple() {
        // Zero blocks — both fields should deserialize as empty Vec via default
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

        // Single ingress block
        let hcl_single = r#"
enclave "test" {
  network {
    ingress {
      cidr_ipv4 = "10.0.0.0/8"
      from_port = 443
      to_port = 443
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

        // Multiple ingress blocks
        let hcl_multi = r#"
enclave "test" {
  network {
    ingress {
      cidr_ipv4 = "10.0.0.0/8"
      from_port = 443
      to_port = 443
      ip_protocol = "tcp"
    }
    ingress {
      cidr_ipv4 = "192.168.0.0/16"
      from_port = 80
      to_port = 80
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
        assert!(serialized.contains("env::vault"), "expression preserved in output");
        let _: ConfigurationFile = hcl::from_str(&serialized).expect("re-deserialize");
    }
}
