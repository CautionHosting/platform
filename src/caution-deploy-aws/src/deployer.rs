// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! AWS Nitro deployer implementing the [`EnclaveDeployer`] interface.
//!
//! Configuration-derived values (sizing, network policy, debug, E2E mode) are
//! read from the whole [`ConfigurationFile`]; non-configuration facts (resource
//! identity, credentials, region, deployment lifecycle flags) arrive through
//! [`AwsDeployContext`].

use caution_config::{ConfigurationFile, E2eMode, Platform};
use caution_deploy::{
    DeployArtifacts, DeployError, DeployErrorCtx as Ctx, DeploymentResult, EnclaveDeployer,
};
use dterror::ResultExt;
use uuid::Uuid;

use crate::deployment::{
    AwsCredentials, ManagedOnPremConfig, NitroDeploymentRequest, deploy_nitro_enclave,
    destroy_app_with_credentials,
};

/// Disk size; the configuration file has no equivalent field today.
const DEFAULT_DISK_GB: u32 = 30;

/// Non-configuration facts required to deploy to AWS.
#[derive(Debug, Clone)]
pub struct AwsDeployContext {
    pub org_id: Uuid,
    pub resource_id: Uuid,
    pub resource_name: String,
    pub aws_account_id: String,
    pub role_arn: Option<String>,
    pub credentials: Option<AwsCredentials>,
    pub managed_onprem: Option<ManagedOnPremConfig>,
    pub region: Option<String>,
    /// Deployments-lifecycle tls build: publish the IP and await the app domain.
    pub tls_await_app_address: bool,
    /// Exact host-helper digest paired with this deployment, if any.
    pub tap_framer_sha256: Option<String>,
}

/// Non-configuration facts required to tear down an AWS deployment.
#[derive(Debug, Clone)]
pub struct AwsDestroyContext {
    pub org_id: Uuid,
    pub resource_id: Uuid,
    pub resource_name: String,
    pub credentials: Option<AwsCredentials>,
    pub asg_name: Option<String>,
}

/// AWS Nitro Enclave deployer.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsNitroDeployer;

impl AwsNitroDeployer {
    pub fn new() -> Self {
        Self
    }

    /// Build the AWS deployment request from the configuration file, artifacts,
    /// and non-configuration context. Exposed so callers that need the request
    /// (e.g. per-deployment candidate provisioning) share one interpretation of
    /// the configuration.
    #[tracing::instrument(skip_all, err)]
    pub fn build_request(
        &self,
        config: &ConfigurationFile,
        artifacts: &DeployArtifacts,
        ctx: &AwsDeployContext,
    ) -> Result<NitroDeploymentRequest, DeployError> {
        let params = deploy_params(config)?;
        Ok(NitroDeploymentRequest {
            org_id: ctx.org_id,
            resource_id: ctx.resource_id,
            resource_name: ctx.resource_name.clone(),
            aws_account_id: ctx.aws_account_id.clone(),
            role_arn: ctx.role_arn.clone(),
            eif_path: artifacts.image_path.clone(),
            eif_s3_key: artifacts.image_s3_key.clone(),
            tap_framer_sha256: ctx.tap_framer_sha256.clone(),
            memory_mb: params.memory_mb,
            cpu_count: params.cpu_count,
            disk_gb: DEFAULT_DISK_GB,
            debug_mode: params.debug_mode,
            restart: params.restart,
            ports: params.ports,
            network: params.network,
            http_port: params.http_port,
            e2e: params.e2e,
            e2e_mode: params.e2e_mode,
            locksmith: params.locksmith,
            egress: params.egress,
            ssh_keys: params.ssh_keys,
            domain: params.domain,
            region: ctx.region.clone(),
            credentials: ctx.credentials.clone(),
            managed_onprem: ctx.managed_onprem.clone(),
            tls_await_app_address: ctx.tls_await_app_address,
            user_data: artifacts.user_data.clone(),
        })
    }
}

/// Configuration-derived values the Nitro deploy needs.
struct DeployParams {
    memory_mb: u32,
    cpu_count: u32,
    debug_mode: bool,
    ssh_keys: Vec<String>,
    ports: Vec<u16>,
    network: caution_config::NetworkConfig,
    http_port: Option<u16>,
    domain: Option<String>,
    e2e: bool,
    e2e_mode: String,
    locksmith: bool,
    egress: bool,
    restart: caution_config::RestartConfig,
}

#[tracing::instrument(skip_all, err)]
fn deploy_params(config: &ConfigurationFile) -> Result<DeployParams, DeployError> {
    let enclave = config.configured_enclave();

    let resources = enclave.and_then(|e| e.resources.as_ref());
    let debug = enclave.and_then(|e| e.debug.as_ref());
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

    Ok(DeployParams {
        memory_mb: resources.map(|r| r.memory_mb).unwrap_or(512),
        cpu_count: resources.map(|r| r.cpu).unwrap_or(2),
        debug_mode: debug.and_then(|d| d.enabled).unwrap_or(false),
        ssh_keys: debug.map(|d| d.ssh_keys.clone()).unwrap_or_default(),
        ports,
        network: network
            .cloned()
            .unwrap_or_else(|| caution_config::NetworkConfig {
                ingress: Vec::new(),
                egress: Vec::new(),
                recovery_ingress: None,
                http: None,
            }),
        http_port: http.map(|h| h.port),
        domain: http.and_then(|h| h.domain.clone()),
        e2e: e2e_mode == Some(E2eMode::Steve),
        e2e_mode: e2e_mode
            .map(|mode| mode.as_str())
            .unwrap_or("disabled")
            .to_string(),
        locksmith: config.has_vault_env(),
        egress: network.map(|n| n.egress_enabled()).unwrap_or(false),
        restart: enclave.and_then(|e| e.restart).unwrap_or_default(),
    })
}

#[async_trait::async_trait]
impl EnclaveDeployer for AwsNitroDeployer {
    type DeployContext = AwsDeployContext;
    type DestroyContext = AwsDestroyContext;

    fn platform(&self) -> Platform {
        Platform::Aws
    }

    #[tracing::instrument(skip_all, err)]
    async fn deploy(
        &self,
        config: &ConfigurationFile,
        artifacts: &DeployArtifacts,
        ctx: &Self::DeployContext,
    ) -> Result<DeploymentResult, DeployError> {
        let request = self.build_request(config, artifacts, ctx)?;
        deploy_nitro_enclave(request)
            .await
            .with_context(Ctx::deploy())
    }

    #[tracing::instrument(skip_all, err)]
    async fn destroy(&self, ctx: &Self::DestroyContext) -> Result<(), DeployError> {
        destroy_app_with_credentials(
            ctx.org_id,
            ctx.resource_id,
            ctx.resource_name.clone(),
            ctx.credentials.clone(),
            ctx.asg_name.clone(),
        )
        .await
        .with_context(Ctx::destroy())
    }
}
