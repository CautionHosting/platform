// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::Args;
use std::fs;
use std::path::PathBuf;

use crate::ApiClient;

#[derive(Args, Debug)]
pub(crate) struct MigrateProcfileArgs {
    #[arg(long, help = "Path to Procfile (default: ./Procfile)")]
    pub(crate) procfile: Option<PathBuf>,

    #[arg(long, help = "Output path (default: ./caution.hcl)")]
    pub(crate) output: Option<PathBuf>,

    #[arg(short, long, help = "Overwrite existing output file")]
    pub(crate) force: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MigrateProcfileError {
    #[error("failed to read {path}: {source}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse Procfile: {0}")]
    ParseError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("output file already exists: {0}; use --force to overwrite")]
    OutputExists(PathBuf),

    #[error("failed to write {path}: {source}")]
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub(crate) async fn migrate_procfile(
    _client: &ApiClient,
    args: &MigrateProcfileArgs,
) -> Result<(), MigrateProcfileError> {
    let procfile_path = args
        .procfile
        .clone()
        .unwrap_or_else(|| PathBuf::from("Procfile"));

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("caution.hcl"));

    let content = fs::read_to_string(&procfile_path).map_err(|source| {
        MigrateProcfileError::ReadError {
            path: procfile_path.clone(),
            source,
        }
    })?;

    let config = caution_config::ConfigurationFile::from_procfile(&content)
        .map_err(|e| MigrateProcfileError::ParseError(e.into()))?;

    if output_path.exists() && !args.force {
        return Err(MigrateProcfileError::OutputExists(output_path));
    }

    let hcl_output = build_body(&config);

    fs::write(&output_path, &hcl_output).map_err(|source| {
        MigrateProcfileError::WriteError {
            path: output_path.clone(),
            source,
        }
    })?;

    println!(
        "✓ Migrated {} → {}",
        procfile_path.display(),
        output_path.display()
    );

    Ok(())
}

fn build_body(config: &caution_config::ConfigurationFile) -> String {
    let caution_str = build_caution_block(&config.caution);

    if let Some(ref enclaves) = config.enclave
        && let Some((_label, enclave)) = enclaves.iter().next()
    {
        return format!(
            "{}\n{}",
            caution_str.trim_end(),
            hcl::format::to_string(&build_enclave_block(enclave)).unwrap()
        );
    }

    caution_str.trim_end().to_string()
}

fn build_caution_block(caution: &Option<caution_config::CautionConfig>) -> String {
    let mut s = String::from("caution {\n");

    if let Some(config) = caution
        && let Some(ref provider) = config.provider
    {
            let formatted = hcl::format::to_string(&build_provider_block(provider)).unwrap();
            for line in formatted.lines() {
                s.push_str("  ");
                s.push_str(line);
                s.push('\n');
            }
            s.push('\n');
    }

    s.push_str("  # managed_credentials = \"credentials.pgp\"\n");
    s.push_str("  # machine_type = \"c5.xlarge\"\n");
    s.push_str("  # build_machine_type = \"c5.xlarge\"\n");

    s.push_str("}\n");
    s
}

fn build_provider_block(provider: &caution_config::Provider) -> hcl::Block {
    match provider {
        caution_config::Provider::Aws(aws) => {
            let mut builder = hcl::Block::builder("provider")
                .add_attribute(("type", "aws"));

            builder = builder.add_attribute(("region", aws.region.as_str()));

            if let Some(ref vpc_id) = aws.vpc_id {
                builder = builder.add_attribute(("vpc_id", vpc_id.as_str()));
            }

            if let Some(ref subnet_ids) = aws.subnet_ids {
                let exprs: Vec<hcl::Expression> = subnet_ids
                    .iter()
                    .map(|s| hcl::Expression::from(s.as_str()))
                    .collect();
                builder = builder.add_attribute(("subnet_ids", exprs));
            }

            if let Some(ref sg_id) = aws.security_group_id {
                builder = builder.add_attribute(("security_group_id", sg_id.as_str()));
            }

            builder.build()
        }
    }
}

fn build_build_block(build: &caution_config::BuildConfig) -> Option<hcl::Block> {
    let mut builder = hcl::Block::builder("build");
    let mut has_content = false;

    if let Some(ref val) = build.containerfile {
        builder = builder.add_attribute(("containerfile", val.as_str()));
        has_content = true;
    }

    if let Some(ref val) = build.binary {
        builder = builder.add_attribute(("binary", val.as_str()));
        has_content = true;
    }

    if !build.app_sources.is_empty() {
        let exprs: Vec<hcl::Expression> = build
            .app_sources
            .iter()
            .map(|s| hcl::Expression::from(s.as_str()))
            .collect();
        builder = builder.add_attribute(("app_sources", exprs));
        has_content = true;
    }

    if let Some(val) = build.cache {
        builder = builder.add_attribute(("cache", val));
        has_content = true;
    }

    if has_content {
        Some(builder.build())
    } else {
        None
    }
}

fn build_debug_block(debug: &caution_config::DebugConfig) -> Option<hcl::Block> {
    let has_ssh_keys = !debug.ssh_keys.is_empty();
    if debug.enabled.is_none() && !has_ssh_keys {
        return None;
    }

    let mut builder = hcl::Block::builder("debug");

    if let Some(val) = debug.enabled {
        builder = builder.add_attribute(("enabled", val));
    }

    if has_ssh_keys {
        let exprs: Vec<hcl::Expression> = debug
            .ssh_keys
            .iter()
            .map(|s| hcl::Expression::from(s.as_str()))
            .collect();
        builder = builder.add_attribute(("ssh_keys", exprs));
    }

    Some(builder.build())
}

fn build_network_block(network: &caution_config::NetworkConfig) -> Option<hcl::Block> {
    if network.ingress.is_empty() && network.egress.is_empty() && network.http.is_none() {
        return None;
    }

    let mut builder = hcl::Block::builder("network");

    for rule in &network.ingress {
        let mut ingress_builder = hcl::Block::builder("ingress");
        ingress_builder = ingress_builder.add_attribute(("cidr_ipv4", rule.cidr_ipv4.as_str()));

        match rule.port_spec {
            Some(caution_config::PortSpec::Exact { port }) => {
                ingress_builder = ingress_builder.add_attribute(("port", port));
            }
            Some(caution_config::PortSpec::FromTo {
                start_port,
                end_port,
            }) => {
                ingress_builder = ingress_builder.add_attribute(("start_port", start_port));
                ingress_builder = ingress_builder.add_attribute(("end_port", end_port));
            }
            None => {}
        }

        if let Some(ref proto) = rule.ip_protocol {
            ingress_builder = ingress_builder.add_attribute(("ip_protocol", proto.as_str()));
        }

        builder = builder.add_block(ingress_builder.build());
    }

    for rule in &network.egress {
        let mut egress_builder = hcl::Block::builder("egress");
        egress_builder = egress_builder.add_attribute(("cidr_ipv4", rule.cidr_ipv4.as_str()));

        match rule.port_spec {
            Some(caution_config::PortSpec::Exact { port }) => {
                egress_builder = egress_builder.add_attribute(("port", port));
            }
            Some(caution_config::PortSpec::FromTo {
                start_port,
                end_port,
            }) => {
                egress_builder = egress_builder.add_attribute(("start_port", start_port));
                egress_builder = egress_builder.add_attribute(("end_port", end_port));
            }
            None => {}
        }

        if let Some(ref proto) = rule.ip_protocol {
            egress_builder = egress_builder.add_attribute(("ip_protocol", proto.as_str()));
        }

        builder = builder.add_block(egress_builder.build());
    }

    if let Some(ref http) = network.http {
        let mut http_builder = hcl::Block::builder("http");
        http_builder = http_builder.add_attribute(("domain", http.domain.as_str()));
        http_builder = http_builder.add_attribute(("port", http.port));

        if let Some(ref e2e) = http.e2e_encryption {
            let mut e2e_builder = hcl::Block::builder("e2e_encryption");

            if let Some(val) = e2e.enabled {
                e2e_builder = e2e_builder.add_attribute(("enabled", val));
            }

            if let Some(ref origins) = e2e.cors_origins {
                let exprs: Vec<hcl::Expression> = origins
                    .iter()
                    .map(|s| hcl::Expression::from(s.as_str()))
                    .collect();
                e2e_builder = e2e_builder.add_attribute(("cors_origins", exprs));
            }

            http_builder = http_builder.add_block(e2e_builder.build());
        }

        builder = builder.add_block(http_builder.build());
    }

    Some(builder.build())
}

fn build_resources_block(resources: &caution_config::ResourceConfig) -> Option<hcl::Block> {
    Some(
        hcl::Block::builder("resources")
            .add_attribute(("cpu", resources.cpu))
            .add_attribute(("memory_mb", resources.memory_mb))
            .build(),
    )
}

fn build_unit_blocks(units: &std::collections::BTreeMap<String, caution_config::UnitConfig>) -> Option<Vec<hcl::Block>> {
    if units.is_empty() {
        return None;
    }

    let mut blocks = Vec::new();

    for (name, unit) in units {
        let mut builder = hcl::Block::builder("unit")
            .add_label(name.as_str())
            .add_attribute(("command", unit.command.as_str()));

        if !unit.args.is_empty() {
            let exprs: Vec<hcl::Expression> = unit
                .args
                .iter()
                .map(|s| hcl::Expression::from(s.as_str()))
                .collect();
            builder = builder.add_attribute(("args", exprs));
        }

        if let Some(ref env) = unit.env {
            let mut env_builder = hcl::Block::builder("env");
            for (key, expr) in env {
                env_builder = env_builder.add_attribute((key.as_str(), expr.clone()));
            }
            builder = builder.add_block(env_builder.build());
        }

        blocks.push(builder.build());
    }

    Some(blocks)
}

fn build_enclave_block(enclave: &caution_config::EnclaveConfig) -> hcl::Block {
    let mut builder = hcl::Block::builder("enclave").add_label("default");

    if let Some(ref build) = enclave.build
        && let Some(block) = build_build_block(build)
    {
        builder = builder.add_block(block);
    }

    if let Some(ref debug) = enclave.debug
        && let Some(block) = build_debug_block(debug)
    {
        builder = builder.add_block(block);
    }

    if let Some(ref network) = enclave.network
        && let Some(block) = build_network_block(network)
    {
        builder = builder.add_block(block);
    }

    if let Some(ref resources) = enclave.resources
        && let Some(block) = build_resources_block(resources)
    {
        builder = builder.add_block(block);
    }

    if let Some(ref units) = enclave.unit
        && let Some(blocks) = build_unit_blocks(units)
    {
        for block in blocks {
            builder = builder.add_block(block);
        }
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_procfile_produces_caution_block_only() {
        let config = caution_config::ConfigurationFile::from_procfile("").unwrap();
        let output = build_body(&config);
        assert!(output.starts_with("caution {"), "should start with caution block");
        assert!(
            output.contains("# managed_credentials = \"credentials.pgp\""),
            "should contain commented placeholder"
        );
        assert!(
            !output.contains("enclave"),
            "should not contain an enclave block"
        );
        assert!(!output.contains("= null"), "should not contain null");
        assert!(!output.contains("= {"), "should not use map attribute syntax");
    }

    #[test]
    fn run_only_procfile_uses_block_syntax() {
        let config = caution_config::ConfigurationFile::from_procfile("run: /app/start\n").unwrap();
        let output = build_body(&config);
        assert!(output.starts_with("caution {"), "should start with caution block");
        assert!(
            output.contains("enclave \"default\""),
            "should use labeled enclave block"
        );
        assert!(
            output.contains("unit \"default\""),
            "should use labeled unit block"
        );
        assert!(
            output.contains("command = \"/app/start\""),
            "should contain command attribute"
        );
        assert!(!output.contains("= null"), "should not contain null");
    }

    #[test]
    fn hello_world_procfile_uses_block_syntax() {
        let procfile = r#"run: /usr/local/bin/hello
containerfile: Containerfile
binary: /usr/local/bin/hello
app_sources: git@codeberg.org:caution/demo-hello-world-enclave.git
cache: false
ports: 8083
"#;
        let config = caution_config::ConfigurationFile::from_procfile(procfile).unwrap();
        let output = build_body(&config);
        assert!(output.contains("enclave \"default\""), "labeled enclave block");
        assert!(output.contains("build {"), "build block");
        assert!(output.contains("binary = \"/usr/local/bin/hello\""), "binary attribute");
        assert!(output.contains("port = 8083"), "port attribute in ingress");
        assert!(output.contains("ingress {"), "ingress block");
        assert!(!output.contains("= null"), "no null values");
        assert!(!output.contains("= {"), "no map attribute syntax");
    }

    #[test]
    fn generated_hcl_round_trips() {
        let procfile = "run: /app/server --port 8080\nports: 8080\nmemory_mb: 2000\ncpus: 4\ndebug: true\nssh_keys: ssh-ed25519 AAAA...\n";
        let config = caution_config::ConfigurationFile::from_procfile(procfile).unwrap();
        let output = build_body(&config);
        let reparsed = caution_config::ConfigurationFile::from_str(&output);
        assert!(reparsed.is_ok(), "generated HCL should parse: {:?}", reparsed.err());
    }

    #[test]
    fn full_procfile_populates_all_blocks() {
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
e2e: true
";
        let config = caution_config::ConfigurationFile::from_procfile(procfile).unwrap();
        let output = build_body(&config);
        assert!(output.contains("caution {"), "caution block");
        assert!(output.contains("enclave \"default\""), "enclave with label");
        assert!(output.contains("build {"), "build block");
        assert!(output.contains("debug {"), "debug block");
        assert!(output.contains("network {"), "network block");
        assert!(output.contains("ingress {"), "ingress block");
        assert!(output.contains("http {"), "http block");
        assert!(output.contains("resources {"), "resources block");
        assert!(output.contains("unit \"default\""), "unit with label");
        assert!(!output.contains("= null"), "no null values");
    }

    #[test]
    fn no_serde_style_output() {
        let procfile = "run: /app\nports: 8080\n";
        let config = caution_config::ConfigurationFile::from_procfile(procfile).unwrap();
        let output = build_body(&config);
        assert!(!output.contains("= null"), "should not have null value attributes");
        assert!(
            !output.contains("enclave = {"),
            "should not use flat map attribute syntax for enclave"
        );
    }

    #[test]
    fn caution_block_with_provider_from_managed_on_prem() {
        let procfile = "\
run: /app
managed_on_prem: true
platform: aws
aws_region: us-east-1
aws_vpc_id: vpc-123
";
        let config = caution_config::ConfigurationFile::from_procfile(procfile).unwrap();
        let output = build_body(&config);
        assert!(output.contains("caution {"), "caution block");
        assert!(output.contains("provider {"), "provider block");
        assert!(output.contains("type = \"aws\""), "aws provider type");
        assert!(output.contains("region = \"us-east-1\""), "aws region");
        assert!(output.contains("vpc_id = \"vpc-123\""), "vpc id");
    }
}
