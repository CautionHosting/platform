// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Nitro Enclave build mechanism.
//!
//! Turns a built application Docker image into a Nitro EIF plus the AWS host
//! user-data template that launches it. Nitro is an AWS-only mechanism.

use caution_config::{ConfigurationFile, E2eMode, KeyExchange};
use dterror::ResultExt;
use enclave_build::{
    AppSource, BuildArtifacts, BuildInput, BuildWorkspace, EifFile, ImageBuildError,
    ImageBuildErrorCtx as Ctx, ImageBuildMechanism, Platform, UserData,
};

use crate::EnclaveBuilder;

/// User-data template for the Nitro Enclave host, authored by this mechanism.
const USER_DATA_TEMPLATE: &str =
    include_str!("../../../terraform/modules/aws/nitro-enclave/user-data.sh");

/// Builds a Nitro Enclave EIF (AWS only) from a built application Docker image.
#[derive(Debug, Default, Clone, Copy)]
pub struct NitroEifMechanism;

impl NitroEifMechanism {
    pub fn new() -> Self {
        Self
    }

    /// The AWS host user-data template this mechanism authors.
    pub fn user_data_template() -> &'static str {
        USER_DATA_TEMPLATE
    }
}

/// Configuration-derived values the EIF build needs.
struct BuildParams {
    run_command: Option<String>,
    ports: Vec<u16>,
    http_port: Option<u16>,
    domain: Option<String>,
    http_upstream_protocol: String,
    e2e: bool,
    e2e_mode: String,
    e2e_key_exchange: String,
    allow_plaintext_fallback: bool,
    locksmith: bool,
    e2e_cors_origins: Option<String>,
    egress: bool,
    config_no_cache: bool,
}

#[tracing::instrument(skip_all, err)]
fn build_params(config: &ConfigurationFile) -> Result<BuildParams, ImageBuildError> {
    let enclave = config.configured_enclave();

    let run_command = enclave
        .and_then(|e| e.unit.as_ref())
        .and_then(|units| units.values().next())
        .map(|unit| unit.run_command_string())
        .transpose()
        .with_context(Ctx::invalid_configuration())?;

    let network = enclave.and_then(|e| e.network.as_ref());
    let http = network.and_then(|n| n.http.as_ref());

    let ports = match network {
        Some(network) => network
            .policy()
            .with_context(Ctx::invalid_configuration())?
            .ports(),
        None => Vec::new(),
    };

    let e2e_config = http.and_then(|h| h.e2e_encryption.as_ref());
    let e2e_mode = e2e_config.and_then(|e| e.effective_mode());

    Ok(BuildParams {
        run_command,
        ports,
        http_port: http.map(|h| h.port),
        domain: http.and_then(|h| h.domain.clone()),
        http_upstream_protocol: http
            .and_then(|h| h.upstream_protocol)
            .map(|protocol| protocol.as_str())
            .unwrap_or("http")
            .to_string(),
        e2e: e2e_mode == Some(E2eMode::Steve),
        e2e_mode: e2e_mode
            .map(|mode| mode.as_str())
            .unwrap_or("disabled")
            .to_string(),
        e2e_key_exchange: e2e_config
            .map(|e| e.key_exchange().steve_env_value())
            .unwrap_or(KeyExchange::X25519.steve_env_value())
            .to_string(),
        allow_plaintext_fallback: e2e_config
            .map(|e| e.allow_plaintext_fallback())
            .unwrap_or(false),
        locksmith: config.has_vault_env(),
        e2e_cors_origins: e2e_config
            .and_then(|e| e.cors_origins.as_ref())
            .map(|origins| origins.join(",")),
        egress: network.map(|n| n.egress_enabled()).unwrap_or(false),
        config_no_cache: enclave
            .and_then(|e| e.build.as_ref())
            .and_then(|b| b.cache)
            .map(|cache| !cache)
            .unwrap_or(false),
    })
}

#[async_trait::async_trait]
impl ImageBuildMechanism for NitroEifMechanism {
    fn name(&self) -> &'static str {
        "nitro-eif"
    }

    fn supported_platforms(&self) -> &'static [Platform] {
        &[Platform::Aws]
    }

    #[tracing::instrument(skip_all, err)]
    async fn build(
        &self,
        input: BuildInput,
        config: &ConfigurationFile,
    ) -> Result<BuildArtifacts, ImageBuildError> {
        let params = build_params(config)?;
        let no_cache = input.no_cache || params.config_no_cache;

        let builder = match &input.workspace {
            BuildWorkspace::Cache {
                base_dir,
                org_id,
                cache_key,
                cache_type,
            } => EnclaveBuilder::new_with_cache(
                input.enclave_source.clone(),
                input.enclave_version.clone(),
                input.framework_source.clone(),
                org_id,
                cache_key,
                *cache_type,
                no_cache,
                base_dir,
            )
            .with_context(Ctx::build())?,
            BuildWorkspace::Directory(dir) => EnclaveBuilder::new(
                input.enclave_source.clone(),
                input.enclave_version.clone(),
                input.framework_source.clone(),
                dir,
            )
            .with_context(Ctx::build())?
            .with_no_cache(no_cache),
        };
        let builder = match &input.prebuilt_components {
            Some(dir) => builder.with_prebuilt_components(dir.clone()),
            None => builder,
        };

        let app_source: Option<AppSource> = input.app_source.clone();
        let app_source_urls = app_source.as_ref().map(|source| source.urls.clone());
        let app_branch = app_source.as_ref().and_then(|source| source.branch.clone());
        let app_commit = app_source.as_ref().map(|source| source.commit.clone());

        let run_command = match &input.manifest {
            Some(manifest) => manifest.run_command.clone(),
            None => params.run_command.clone(),
        };
        let metadata = input.metadata.clone();
        let binary_path = input.manifest.as_ref().and_then(|m| m.binary.clone());

        let deployment = if let Some(binary_path) = binary_path {
            builder
                .build_enclave_auto(
                    &input.docker_image,
                    &binary_path,
                    run_command,
                    app_source_urls,
                    app_branch,
                    app_commit,
                    metadata,
                    input.manifest.clone(),
                    &params.ports,
                    params.http_port,
                    params.e2e,
                    &params.e2e_mode,
                    &params.e2e_key_exchange,
                    params.allow_plaintext_fallback,
                    params.domain.as_deref(),
                    &params.http_upstream_protocol,
                    params.locksmith,
                    params.e2e_cors_origins.clone(),
                    params.egress,
                )
                .await
        } else {
            builder
                .build_enclave(
                    &input.docker_image,
                    None,
                    run_command,
                    app_source_urls,
                    app_branch,
                    app_commit,
                    metadata,
                    input.manifest.clone(),
                    &params.ports,
                    params.http_port,
                    params.e2e,
                    &params.e2e_mode,
                    &params.e2e_key_exchange,
                    params.allow_plaintext_fallback,
                    params.domain.as_deref(),
                    &params.http_upstream_protocol,
                    params.locksmith,
                    params.e2e_cors_origins.clone(),
                    params.egress,
                )
                .await
        }
        .with_context(Ctx::build())?;

        let tap_framer = if params.egress {
            let sidecar = deployment.eif.path.with_extension("tap-framer");
            sidecar.exists().then_some(sidecar)
        } else {
            None
        };

        let image: EifFile = deployment.eif;
        Ok(BuildArtifacts {
            image,
            user_data: UserData {
                template: USER_DATA_TEMPLATE.to_string(),
            },
            pcrs: Some(deployment.pcrs),
            tap_framer,
            work_dir: builder.work_dir.clone(),
        })
    }
}
