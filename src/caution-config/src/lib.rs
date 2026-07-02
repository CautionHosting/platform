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
#[serde(deny_unknown_fields)]
pub struct AwsProviderConfig {
    pub region: String,
    pub vpc_id: Option<String>,
    pub subnet_ids: Option<Vec<String>>,
    pub security_group_id: Option<String>,
}

/// Top-level `caution { }` block.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CautionConfig {
    pub managed_credentials: Option<String>,
    pub machine_type: Option<String>,
    pub build_machine_type: Option<String>,
    pub provider: Option<Provider>,
}

/// The `build { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    pub containerfile: Option<String>,
    pub binary: Option<String>,
    #[serde(default)]
    pub app_sources: Vec<String>,
    pub cache: Option<bool>,
}

/// The `debug { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
///
/// NOTE: `deny_unknown_fields` is intentionally absent here -- `#[serde(flatten)]`
/// on `Option<PortSpec>` (untagged) is incompatible with it. Serde can't
/// distinguish "field consumed by flattened type" from "unknown field" when
/// the flattened type uses multi-field untagged variants (e.g. `FromTo`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficRule {
    pub cidr_ipv4: String,
    #[serde(flatten)]
    pub port_spec: Option<PortSpec>,
    pub ip_protocol: Option<String>,
}

/// The `e2e_encryption { }` block inside HTTP config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2eEncryption {
    pub enabled: Option<bool>,
    pub cors_origins: Option<Vec<String>>,
}

/// The `http { }` block inside network config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    #[serde(default)]
    pub domain: Option<String>,
    pub port: u16,
    pub e2e_encryption: Option<E2eEncryption>,
}

/// The `resources { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    pub cpu: u32,
    pub memory_mb: u32,
}

/// A single unit block (`unit "label" { }`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub env: Option<BTreeMap<String, Expression>>,
}

/// Returns true if `key` is a safe POSIX shell environment variable name.
///
/// Keys are emitted into the run script unquoted (`export KEY=...`), so an
/// unvalidated key like `X; rm -rf /` would be a shell-injection vector. Values
/// are always shlex-quoted, but keys cannot be, so they must be validated.
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Returns true if `expr` is an `env::vault(...)` function call.
///
/// Vault calls are the only function-call env values the platform supports:
/// they are resolved inside the enclave by locksmith. Any other function call
/// (e.g. `upper("x")`) is unsupported and would be silently dropped at deploy,
/// so it is rejected at validation instead.
fn is_vault_funccall(expr: &Expression) -> bool {
    matches!(expr, Expression::FuncCall(fc)
        if fc.name.namespace.iter().any(|n| n.as_str() == "env")
        && fc.name.name.as_str() == "vault")
}

impl UnitConfig {
    /// Build the shell command string the enclave runs for this unit.
    ///
    /// The whole result is executed via `sh -c` by the deploy path, so:
    /// - `command` + `args` are re-joined with shlex quoting (automatic,
    ///   injection-safe escaping of every token);
    /// - a leading run of `NAME=value` tokens is treated as inline shell
    ///   environment assignments (e.g. `FOO=1 /app/server`) and emitted as
    ///   `NAME=<quoted value>` rather than shlex-quoting the whole token.
    ///   Quoting the whole `FOO=1` token yields `'FOO=1'`, which the shell
    ///   runs as a command literally named `FOO=1` instead of an assignment;
    ///   the value is still shlex-quoted and the key validated, so this is
    ///   injection-safe;
    /// - literal `env` string values are emitted as `export KEY=<quoted>` lines
    ///   ahead of the command. Keys are validated (they cannot be quoted);
    ///   values are shlex-quoted.
    ///
    /// `env::vault(...)` (and any other function-call) entries are skipped here:
    /// they are resolved inside the enclave by locksmith-oneshot, not exported
    /// from the build host.
    pub fn run_command_string(&self) -> Result<String, FromStrError> {
        let mut out = String::new();

        if let Some(env) = &self.env {
            for (key, expr) in env {
                let value = match expr {
                    Expression::String(s) => s,
                    // Function-call values (only env::vault(...) survives
                    // validation) are injected at runtime by locksmith, not
                    // exported here.
                    _ => continue,
                };
                if !is_valid_env_key(key) {
                    return Err(FromStrError::InvalidEnvKey(key.clone()));
                }
                let quoted =
                    shlex::try_quote(value).map_err(|_| FromStrError::UnquotableCommand)?;
                out.push_str("export ");
                out.push_str(key);
                out.push('=');
                out.push_str(&quoted);
                out.push('\n');
            }
        }

        let mut argv = std::iter::once(self.command.as_str())
            .chain(self.args.iter().map(String::as_str))
            .peekable();

        // Preserve a leading run of `NAME=value` inline env assignments
        // verbatim (with the value shlex-quoted). Stop at the first token that
        // is not a valid assignment, matching shell semantics where such
        // prefixes must precede the command.
        let mut parts: Vec<String> = Vec::new();
        while let Some(token) = argv.peek() {
            let Some((name, value)) = token.split_once('=') else {
                break;
            };
            if !is_valid_env_key(name) {
                break;
            }
            let quoted =
                shlex::try_quote(value).map_err(|_| FromStrError::UnquotableCommand)?;
            parts.push(format!("{name}={quoted}"));
            argv.next();
        }

        let rest: Vec<&str> = argv.collect();
        if rest.is_empty() {
            return Err(FromStrError::NoCommand);
        }
        let joined = shlex::try_join(rest).map_err(|_| FromStrError::UnquotableCommand)?;
        parts.push(joined);
        out.push_str(&parts.join(" "));

        Ok(out)
    }
}

/// The `network { }` block inside an enclave definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EnclaveConfig {
    pub build: Option<BuildConfig>,
    pub debug: Option<DebugConfig>,
    pub network: Option<NetworkConfig>,
    pub resources: Option<ResourceConfig>,
    pub unit: Option<BTreeMap<String, UnitConfig>>,
}

/// Top-level configuration file matching the `example.hcl` schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    #[error(
        "`binary:` and `locksmith: true` cannot be used together. The `binary:` directive \
         extracts only the binary's directory, so /etc/caution/ (bundle + secrets) is \
         dropped and locksmithd panics at boot. Remove one of them."
    )]
    BinaryWithLocksmith,

    #[error("managed_on_prem requires 'platform' to be specified")]
    ManagedOnPremMissingPlatform,

    #[error("Unsupported platform '{0}'. Currently only 'aws' is supported.")]
    ManagedOnPremUnsupportedPlatform(String),

    #[error("managed_on_prem with platform 'aws' requires 'aws_region'")]
    ManagedOnPremMissingRegion,

    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    #[error("invalid provider config: {0}")]
    InvalidProvider(String),
}

#[derive(Debug, thiserror::Error)]
pub enum FromStrError {
    #[error("Ports 49500-49600 are reserved; choose a different application port.")]
    ReservedPort,

    #[error("Multiple enclaves defined; only one enclave is supported")]
    MultipleEnclaves,

    #[error("Multiple units defined; only one unit is supported")]
    MultipleUnits,

    #[error("http_port {0} must also be present in ingress rules")]
    HttpPortNotInPorts(u16),

    #[error(
        "Invalid env expression for key '{0}'; only string literals and env::vault(...) are allowed"
    )]
    InvalidEnvExpression(String),

    #[error(
        "Invalid env key '{0}'; keys must match [A-Za-z_][A-Za-z0-9_]* to be safely exported"
    )]
    InvalidEnvKey(String),

    #[error("Command contains characters that cannot be shell-quoted (e.g. NUL byte)")]
    UnquotableCommand,

    #[error("Unit has no executable command (only inline env assignments found)")]
    NoCommand,

    #[error("Failed to parse HCL")]
    HclParse(#[from] hcl::Error),

    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    #[error("invalid provider config: {0}")]
    InvalidProvider(String),
}

const RESERVED_INTERNAL_PORT_START: u16 = 49_500;
const RESERVED_INTERNAL_PORT_END: u16 = 49_600;

fn is_reserved(port: u16) -> bool {
    (RESERVED_INTERNAL_PORT_START..=RESERVED_INTERNAL_PORT_END).contains(&port)
}

/// Validate that `domain` is a well-formed fully-qualified hostname.
///
/// The value flows into generated infrastructure (Terraform variables, the
/// instance bootstrap script, and the Caddy config), so it must be a plain DNS
/// name with no characters that could carry meaning in those contexts.
fn validate_domain(domain: Option<&str>) -> Result<(), String> {
    let Some(domain) = domain else {
        return Ok(());
    };
    if domain.is_empty() || domain.len() > 253 {
        return Err("domain must be between 1 and 253 characters".to_string());
    }
    if !domain.contains('.') {
        return Err("domain must be a fully-qualified hostname".to_string());
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("domain must not start or end with '.'".to_string());
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err("domain must not contain empty labels".to_string());
        }
        if label.len() > 63 {
            return Err("domain labels must be 63 characters or fewer".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain labels must not start or end with '-'".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("domain contains invalid characters".to_string());
        }
    }
    Ok(())
}

/// Validate that `value` is a well-formed AWS resource id of the form
/// `<prefix>-<id>`, where `<id>` is 8 or 17 lowercase hex digits.
///
/// These ids flow from the deployer-controlled `provider { }` block into
/// generated Terraform, so they must contain no characters that could carry
/// meaning there. Real AWS ids always match this shape, so the check is strict
/// without rejecting any legitimate value.
fn validate_aws_id(prefix: &str, value: &str) -> Result<(), String> {
    let id = value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .ok_or_else(|| format!("expected an AWS {prefix}-… id, got {value:?}"))?;
    if !matches!(id.len(), 8 | 17)
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("malformed AWS {prefix} id: {value:?}"));
    }
    Ok(())
}

/// Validate every AWS resource identifier carried by a `provider { }` block.
fn validate_provider(provider: &Provider) -> Result<(), String> {
    let Provider::Aws(aws) = provider;
    if let Some(ref vpc_id) = aws.vpc_id {
        validate_aws_id("vpc", vpc_id)?;
    }
    for subnet_id in aws.subnet_ids.iter().flatten() {
        validate_aws_id("subnet", subnet_id)?;
    }
    if let Some(ref sg_id) = aws.security_group_id {
        validate_aws_id("sg", sg_id)?;
    }
    Ok(())
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
        let mut locksmith = false;
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
                    "locksmith" => {
                        locksmith = value.to_lowercase() == "true";
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

        if binary.is_some() && locksmith {
            return Err(FromProcfileError::BinaryWithLocksmith);
        }

        if let Some(hp) = http_port {
            if !ports.contains(&hp) {
                return Err(FromProcfileError::HttpPortNotInPorts(hp));
            }
        }

        let explicit_http_port = http_port;

        let http_port = match http_port {
            Some(hp) => Some(hp),
            None if ports.len() == 1 => Some(ports[0]),
            None => None,
        };

        // Only construct HttpConfig when http_port was explicitly set in the
        // Procfile (not auto-derived from a single ports entry).
        let has_explicit_http_port = explicit_http_port.is_some() || domain.is_some();

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

        validate_domain(domain.as_deref()).map_err(FromProcfileError::InvalidDomain)?;

        let http = if has_explicit_http_port {
            let port = http_port.unwrap_or(80);
            Some(HttpConfig {
                domain,
                port,
                e2e_encryption: e2e_encryption.clone(),
            })
        } else {
            None
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

        if let Some(ref p) = provider {
            validate_provider(p).map_err(FromProcfileError::InvalidProvider)?;
        }

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

        if let Some(provider) = config.caution.as_ref().and_then(|c| c.provider.as_ref()) {
            validate_provider(provider).map_err(FromStrError::InvalidProvider)?;
        }

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
                    validate_domain(http.domain.as_deref()).map_err(FromStrError::InvalidDomain)?;

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
                    if units.len() > 1 {
                        return Err(FromStrError::MultipleUnits);
                    }

                    for (unit_name, unit) in units {
                        if let Some(ref env) = unit.env {
                            for (key, expr) in env {
                                let allowed = matches!(expr, Expression::String(_))
                                    || is_vault_funccall(expr);
                                if !allowed {
                                    return Err(FromStrError::InvalidEnvExpression(format!(
                                        "{}.{}",
                                        unit_name, key
                                    )));
                                }
                                if matches!(expr, Expression::String(_))
                                    && !is_valid_env_key(key)
                                {
                                    return Err(FromStrError::InvalidEnvKey(format!(
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
                            env.values().any(is_vault_funccall)
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
                            domain: Some("chat.caution.dev".into()),
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
    fn test_from_str_rejects_multiple_units() {
        let hcl = r#"
enclave "main" {
  unit "web" {
    command = "/app/web"
  }
  unit "worker" {
    command = "/app/worker"
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::MultipleUnits));
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
    fn test_from_str_rejects_non_vault_funccall_env() {
        // Only env::vault(...) is a supported function-call env value; any other
        // call (e.g. upper(...)) would be silently dropped at deploy, so it must
        // be rejected at parse time.
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
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::InvalidEnvExpression(_)));
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
        assert_eq!(http.domain.as_deref(), Some("example.com"));
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
        assert_eq!(http.domain.as_deref(), Some("myapp.example.com"));
        assert_eq!(http.port, 8080);
    }

    #[test]
    fn test_from_procfile_rejects_malformed_domain() {
        // Shell/HCL metacharacters must not survive parsing.
        for bad in [
            "x.$(id).example.com",
            "a\"b.example.com",
            "a b.example.com",
            "nodot",
        ] {
            let procfile = format!("run: /app\nports: 8080\nhttp_port: 8080\ndomain: {bad}\n");
            assert!(
                matches!(
                    ConfigurationFile::from_procfile(&procfile),
                    Err(FromProcfileError::InvalidDomain(_))
                ),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_from_str_rejects_malformed_domain() {
        let hcl = r#"
enclave "main" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port      = 8080
    }
    http {
      domain = "x.$(id).example.com"
      port   = 8080
    }
  }
  unit "default" {
    command = "/app"
  }
}
"#;
        assert!(matches!(
            ConfigurationFile::from_str(hcl),
            Err(FromStrError::InvalidDomain(_))
        ));
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
        assert_eq!(http.domain.as_deref(), Some("chat.caution.dev"));
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
        let http = network.http.as_ref().unwrap();
        assert!(http.domain.is_none());
        assert_eq!(http.port, 8080);

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
        assert_eq!(http.domain.as_deref(), Some("chat.caution.dev"));
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
    vpc_id = "vpc-0a1b2c3d"
    subnet_ids = ["subnet-01234567", "subnet-0123456789abcdef0"]
    security_group_id = "sg-0a1b2c3d"
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
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-0a1b2c3d"));
        assert_eq!(
            aws.subnet_ids,
            Some(vec![
                "subnet-01234567".into(),
                "subnet-0123456789abcdef0".into()
            ])
        );
        assert_eq!(aws.security_group_id.as_deref(), Some("sg-0a1b2c3d"));
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
    vpc_id = "vpc-0123456789abcdef0"
    subnet_ids = ["subnet-89abcdef"]
    security_group_id = "sg-89abcdef"
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
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-0123456789abcdef0"));
        assert_eq!(aws.subnet_ids, Some(vec!["subnet-89abcdef".into()]));
        assert_eq!(aws.security_group_id.as_deref(), Some("sg-89abcdef"));
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
                    vpc_id: Some("vpc-0a1b2c3d".into()),
                    subnet_ids: Some(vec!["subnet-0a1b2c3d".into()]),
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
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-0a1b2c3d"));
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

    #[test]
    fn test_from_str_rejects_malformed_provider_ids() {
        // Values that parse as valid HCL strings but are not well-formed AWS ids
        // must be rejected by the provider validator. (Embedded quotes/newlines
        // are separately caught by the HCL parser before this point.)
        for (field, value) in [
            ("vpc_id", "vpc-$(id)"),           // shell command substitution
            ("vpc_id", "vpc-123"),             // too short to be a real id
            ("vpc_id", "vpc-0A1B2C3D"),        // uppercase is not a valid id
            ("subnet_ids", "subnet-zzzzzzzz"), // non-hex
            ("security_group_id", "sg-../etc"), // path traversal characters
        ] {
            let line = if field == "subnet_ids" {
                format!("subnet_ids = [\"{value}\"]")
            } else {
                format!("{field} = \"{value}\"")
            };
            let hcl = format!(
                "caution {{\n  provider {{\n    type = \"aws\"\n    region = \"us-east-1\"\n    {line}\n  }}\n}}\n"
            );
            assert!(
                matches!(
                    ConfigurationFile::from_str(&hcl),
                    Err(FromStrError::InvalidProvider(_))
                ),
                "expected {field}={value:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_from_procfile_rejects_malformed_provider_ids() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: aws
aws_region: us-east-1
aws_vpc_id: vpc-$(id).example
";
        assert!(matches!(
            ConfigurationFile::from_procfile(procfile),
            Err(FromProcfileError::InvalidProvider(_))
        ));
    }

    #[test]
    fn test_validate_aws_id_accepts_8_and_17_hex() {
        assert!(validate_aws_id("vpc", "vpc-0a1b2c3d").is_ok());
        assert!(validate_aws_id("vpc", "vpc-0123456789abcdef0").is_ok());
        assert!(validate_aws_id("subnet", "subnet-00000000").is_ok());
        // Wrong prefix, wrong length, and uppercase are all rejected.
        assert!(validate_aws_id("vpc", "subnet-0a1b2c3d").is_err());
        assert!(validate_aws_id("vpc", "vpc-0a1b2c3").is_err());
        assert!(validate_aws_id("vpc", "vpc-0A1B2C3D").is_err());
        assert!(validate_aws_id("vpc", "vpc-").is_err());
    }

    // ── from_procfile managed_on_prem tests ─────────────────────────

    #[test]
    fn test_from_procfile_managed_on_prem_all_fields() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: aws
aws_region: us-east-1
aws_vpc_id: vpc-0a1b2c3d
aws_subnet_id: subnet-0a1b2c3d
aws_security_group_id: sg-0a1b2c3d
";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let caution = config.caution.expect("caution block");
        let aws = match caution.provider.expect("provider") {
            Provider::Aws(aws) => aws,
        };
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.vpc_id.as_deref(), Some("vpc-0a1b2c3d"));
        assert_eq!(aws.subnet_ids, Some(vec!["subnet-0a1b2c3d".into()]));
        assert_eq!(aws.security_group_id.as_deref(), Some("sg-0a1b2c3d"));
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
    fn test_from_procfile_rejects_binary_with_locksmith() {
        let procfile = "run: /app\nbinary: /app/x\nlocksmith: true\n";
        let err = ConfigurationFile::from_procfile(procfile).unwrap_err();
        assert!(
            matches!(err, FromProcfileError::BinaryWithLocksmith),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_from_procfile_allows_binary_without_locksmith() {
        let procfile = "run: /app\nbinary: /app/x\nports: 8080\n";
        ConfigurationFile::from_procfile(procfile).unwrap();
    }

    #[test]
    fn test_from_procfile_rejects_http_port_not_in_ports() {
        let procfile = "run: /app\nports: 8080\nhttp_port: 9000\ndomain: x.example.com\n";
        let err = ConfigurationFile::from_procfile(procfile).unwrap_err();
        assert!(
            matches!(err, FromProcfileError::HttpPortNotInPorts(9000)),
            "unexpected error: {err}"
        );
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

    fn default_unit(hcl: &str) -> UnitConfig {
        let config = ConfigurationFile::from_str(hcl).unwrap();
        config
            .enclave
            .unwrap()
            .values()
            .next()
            .unwrap()
            .unit
            .as_ref()
            .unwrap()
            .get("default")
            .unwrap()
            .clone()
    }

    #[test]
    fn run_command_string_joins_command_and_args() {
        let unit = default_unit(
            r#"
enclave "main" {
  unit "default" {
    command = "/app/server"
    args = ["--port", "8080"]
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#,
        );
        assert_eq!(unit.run_command_string().unwrap(), "/app/server --port 8080");
    }

    #[test]
    fn run_command_string_quotes_args_with_spaces() {
        let unit = default_unit(
            r#"
enclave "main" {
  unit "default" {
    command = "/app"
    args = ["--msg", "hello world", "--inject", "$(rm -rf /)"]
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#,
        );
        // Spaces and shell metacharacters are quoted, not interpreted.
        assert_eq!(
            unit.run_command_string().unwrap(),
            "/app --msg 'hello world' --inject '$(rm -rf /)'"
        );
    }

    #[test]
    fn run_command_string_exports_literal_env() {
        let unit = default_unit(
            r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      FOO = "bar"
      WITH_SPACE = "a b"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#,
        );
        // BTreeMap orders keys; values are shlex-quoted.
        assert_eq!(
            unit.run_command_string().unwrap(),
            "export FOO=bar\nexport WITH_SPACE='a b'\n/app"
        );
    }

    #[test]
    fn run_command_string_quotes_malicious_env_value() {
        // A shell-metacharacter-laden value must be quoted, not interpreted.
        let unit = default_unit(
            r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      EVIL = "$(rm -rf /); `id`"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#,
        );
        assert_eq!(
            unit.run_command_string().unwrap(),
            "export EVIL='$(rm -rf /); `id`'\n/app"
        );
    }

    #[test]
    fn run_command_string_preserves_inline_env_prefix() {
        // A Procfile `run:` line like `FOO=1 /app/server` parses into
        // command = "FOO=1", args = ["/app/server", ...]. The assignment must
        // be emitted verbatim (not as '\''FOO=1'\''), so the shell treats it as
        // an env assignment rather than a command literally named "FOO=1".
        let unit = UnitConfig {
            command: "PQ_SUBKEYS_AUTH=30".to_string(),
            args: vec![
                "/app/pq-ceremony".to_string(),
                "--bind".to_string(),
                "0.0.0.0:8080".to_string(),
            ],
            env: None,
        };
        assert_eq!(
            unit.run_command_string().unwrap(),
            "PQ_SUBKEYS_AUTH=30 /app/pq-ceremony --bind 0.0.0.0:8080"
        );
    }

    #[test]
    fn run_command_string_quotes_malicious_inline_env_value() {
        // The assignment value is still shlex-quoted, so shell metacharacters
        // in an inline env prefix cannot inject.
        let unit = UnitConfig {
            command: "EVIL=$(rm -rf /)".to_string(),
            args: vec!["/app".to_string()],
            env: None,
        };
        assert_eq!(
            unit.run_command_string().unwrap(),
            "EVIL='$(rm -rf /)' /app"
        );
    }

    #[test]
    fn run_command_string_does_not_treat_command_with_equals_as_assignment() {
        // Once the command is reached, assignment-prefix scanning stops, so an
        // `=`-bearing argument after it (e.g. `--opt=a b`) is shlex-quoted as a
        // whole token rather than split into a `NAME=value` assignment.
        let unit = UnitConfig {
            command: "/app/server".to_string(),
            args: vec!["--opt=a b".to_string()],
            env: None,
        };
        assert_eq!(
            unit.run_command_string().unwrap(),
            "/app/server '--opt=a b'"
        );
    }

    #[test]
    fn run_command_string_rejects_nul_byte() {
        // shlex cannot quote a NUL byte; it must surface as an error, not panic.
        let unit = UnitConfig {
            command: "/app\0".to_string(),
            args: Vec::new(),
            env: None,
        };
        let err = unit.run_command_string().unwrap_err();
        assert!(matches!(err, FromStrError::UnquotableCommand));
    }

    #[test]
    fn run_command_string_skips_vault_env() {
        let unit = default_unit(
            r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env {
      API_KEY = env::vault("API_KEY")
      PLAIN = "x"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#,
        );
        // Vault entry is resolved by locksmith at runtime, not exported here.
        assert_eq!(
            unit.run_command_string().unwrap(),
            "export PLAIN=x\n/app"
        );
    }

    #[test]
    fn run_command_string_rejects_malicious_env_key() {
        // A key cannot be shell-quoted, so an injection-shaped key must be
        // rejected rather than emitted into the run script.
        let unit = UnitConfig {
            command: "/app".to_string(),
            args: Vec::new(),
            env: Some(BTreeMap::from([(
                "X; rm -rf /".to_string(),
                Expression::from("1"),
            )])),
        };
        let err = unit.run_command_string().unwrap_err();
        assert!(matches!(err, FromStrError::InvalidEnvKey(_)));
    }

    #[test]
    fn run_command_string_errors_when_no_executable() {
        // If every token is a NAME=value assignment, there is no command to run.
        let unit = UnitConfig {
            command: "FOO=1".to_string(),
            args: Vec::new(),
            env: None,
        };
        let err = unit.run_command_string().unwrap_err();
        assert!(matches!(err, FromStrError::NoCommand));
    }

    #[test]
    fn from_str_rejects_invalid_env_key_at_parse_time() {
        // Quoted HCL map keys can contain hyphens and other chars that are
        // invalid POSIX env var names. The validator must reject these at parse
        // time, not silently accept and fail at deploy.
        let hcl = r#"
enclave "main" {
  unit "default" {
    command = "/app"
    env = {
      "MY-KEY" = "val"
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::InvalidEnvKey(_)));
    }

    #[test]
    fn is_valid_env_key_rules() {
        assert!(is_valid_env_key("FOO"));
        assert!(is_valid_env_key("_x9"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("9FOO"));
        assert!(!is_valid_env_key("FO O"));
        assert!(!is_valid_env_key("FOO;BAR"));
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

    #[test]
    fn test_deny_unknown_caution_config() {
        let hcl = r#"managed_credentials = "x" unknown = 1"#;
        let err = hcl::from_str::<CautionConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_aws_provider_config() {
        let hcl = r#"region = "us-east-1" unknown = "x""#;
        let err = hcl::from_str::<AwsProviderConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_provider_block() {
        let hcl = r#"
caution {
  provider {
    type = "aws"
    region = "us-east-1"
    unknown = 1
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::HclParse(_)));
    }

    #[test]
    fn test_deny_unknown_build_config() {
        let hcl = r#"containerfile = "C" unknown = true"#;
        let err = hcl::from_str::<BuildConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_debug_config() {
        let hcl = r#"enabled = true unknown = 1"#;
        let err = hcl::from_str::<DebugConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_e2e_encryption() {
        let hcl = r#"enabled = true unknown = false"#;
        let err = hcl::from_str::<E2eEncryption>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_http_config() {
        let hcl = r#"domain = "x.com" port = 80 unknown = "y""#;
        let err = hcl::from_str::<HttpConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_resource_config() {
        let hcl = r#"cpu = 1 memory_mb = 512 unknown = 2"#;
        let err = hcl::from_str::<ResourceConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_unit_config() {
        let hcl = r#"command = "/bin/sh" unknown = true"#;
        let err = hcl::from_str::<UnitConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_network_config() {
        let hcl = r#"unknown = true"#;
        let err = hcl::from_str::<NetworkConfig>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_enclave_config() {
        let hcl = r#"
enclave "test" {
  resources {
    cpu = 1
    memory_mb = 512
  }
  unknown_block {
    foo = 1
  }
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::HclParse(_)));
    }

    #[test]
    fn test_deny_unknown_configuration_file() {
        let hcl = r#"
unknown_top_block { }
"#;
        let err = hcl::from_str::<ConfigurationFile>(hcl).unwrap_err();
        assert!(err.to_string().contains("unknown_top_block") || err.to_string().contains("unknown"));
    }

    #[test]
    fn test_deny_unknown_enclave_field() {
        let hcl = r#"
enclave "test" {
  resources {
    cpu = 1
    memory_mb = 512
  }
  unknown_field = "x"
}
"#;
        let err = ConfigurationFile::from_str(hcl).unwrap_err();
        assert!(matches!(err, FromStrError::HclParse(_)));
    }

    #[test]
    fn test_network_without_http_is_valid() {
        let hcl = r#"
enclave "test" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let cfg = ConfigurationFile::from_str(hcl).expect("should accept network without http");
        let enclave = cfg.enclave.unwrap().get("test").unwrap().clone();
        assert!(enclave.network.unwrap().http.is_none());
    }

    #[test]
    fn test_enclave_without_unit_is_valid() {
        let hcl = r#"
enclave "test" {
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let cfg = ConfigurationFile::from_str(hcl).expect("should accept enclave without unit");
        let enclave = cfg.enclave.unwrap().get("test").unwrap().clone();
        assert!(enclave.unit.is_none());
    }

    #[test]
    fn test_from_str_http_without_domain_is_valid() {
        let hcl = r#"
enclave "main" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }
    http {
      port = 8080
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let cfg = ConfigurationFile::from_str(hcl)
            .expect("should accept http without domain");
        let enclave = cfg.enclave.unwrap();
        let main = enclave.get("main").unwrap();
        let http = main.network.as_ref().unwrap().http.as_ref().unwrap();
        assert!(http.domain.is_none());
        assert_eq!(http.port, 8080);
    }

    #[test]
    fn test_from_str_http_with_domain_still_works() {
        let hcl = r#"
enclave "main" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }
    http {
      domain = "x.com"
      port = 8080
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        let cfg = ConfigurationFile::from_str(hcl)
            .expect("should accept http with domain");
        let enclave = cfg.enclave.unwrap();
        let main = enclave.get("main").unwrap();
        let http = main.network.as_ref().unwrap().http.as_ref().unwrap();
        assert_eq!(http.domain.as_deref(), Some("x.com"));
        assert_eq!(http.port, 8080);
    }

    #[test]
    fn test_from_procfile_http_port_only() {
        let procfile = "run: /app\nports: 8080\nhttp_port: 8080\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let network = enclave.get("default").unwrap().network.as_ref().unwrap();
        let http = network.http.as_ref().unwrap();
        assert!(http.domain.is_none());
        assert_eq!(http.port, 8080);
    }

    #[test]
    fn test_from_procfile_no_http_at_all() {
        let procfile = "run: /app\nports: 8080\n";
        let config = ConfigurationFile::from_procfile(procfile).unwrap();
        let enclave = config.enclave.unwrap();
        let network = enclave.get("default").unwrap().network.as_ref().unwrap();
        assert!(network.http.is_none());
    }

    #[test]
    fn test_network_with_only_http_is_valid() {
        let hcl = r#"
enclave "test" {
  network {
    http {
      domain = "x.com"
      port = 80
    }
  }
  resources {
    cpu = 1
    memory_mb = 512
  }
}
"#;
        // Use raw hcl::from_str to test serde deserialization independently
        // of the extra from_str() validation (which requires the port to be
        // covered by an ingress rule).
        let cfg: ConfigurationFile =
            hcl::from_str(hcl).expect("should accept network with only http");
        let enclave = cfg.enclave.unwrap().get("test").unwrap().clone();
        let net = enclave.network.unwrap();
        assert!(net.ingress.is_empty());
        assert!(net.egress.is_empty());
        assert!(net.http.is_some());
    }
}
