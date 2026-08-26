// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! The `caution init` / `caution teardown` command pair.
//!
//! The module is named after the bring-your-own-compute (BYOC) domain, but it
//! also holds the managed (non-BYOC) `init` path: that path is a thin
//! dispatcher that hands off to the BYOC provisioning flows when `--byoc` or
//! an explicit credentials file (`--config`) is passed. Grouping both commands
//! here keeps the full init/teardown lifecycle in one place.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use dterror::{BoxError, CtxError, Location, ResultExt};

use crate::output;
use crate::output::{Spinner, SpinnerStyle};
use crate::prompt;
use crate::resolve_local_build_command_from_dir;
use crate::{
    ApiClient, CreateAppResponse, deployment_target_summary, inspect_checkout_link,
    linked_checkout_error, print_managed_dns_details,
};

const BYOC_PROVISIONER_IMAGE: &str =
    "codeberg.org/caution/caution-managed-on-prem-aws-provisioner:latest";
const BYOC_STATE_FILE_NAME: &str = "bring-your-own-compute.json";
// Legacy state file name, kept for backward compatibility so that deployments
// created before the bring-your-own-cloud -> bring-your-own-compute rename can
// still be located (e.g. for teardown).
const BYOC_STATE_FILE_NAME_LEGACY: &str = "bring-your-own-cloud.json";

fn byoc_state_path(base_dir: &Path) -> PathBuf {
    base_dir.join(BYOC_STATE_FILE_NAME)
}

/// Resolve the state file to read: prefer the current name, then fall back to
/// the legacy name for deployments created before the rename. Returns the
/// current path when neither exists.
fn byoc_state_read_path(base_dir: &Path) -> PathBuf {
    let current = base_dir.join(BYOC_STATE_FILE_NAME);
    if current.exists() {
        return current;
    }
    let legacy = base_dir.join(BYOC_STATE_FILE_NAME_LEGACY);
    if legacy.exists() {
        return legacy;
    }
    current
}

fn linked_encrypted_byoc_config(is_encrypted: bool, resource_id: Option<&str>) -> bool {
    is_encrypted && resource_id.is_some()
}

pub(crate) fn aws_credentials_error(profile: &str, action: &str) -> String {
    [
        "AWS credentials not found for profile \"",
        profile,
        "\". The CLI reads environment credentials and static keys from ~/.aws/credentials. For assume-role, SSO, or credential_process profiles, export AWS CLI v2 credentials:\n\n  aws sso login --profile ",
        profile,
        "  # SSO only\n  eval \"$(aws configure export-credentials --profile ",
        profile,
        " --format env)\"\n  aws sts get-caller-identity\n\nThen rerun `",
        action,
        "`. Export immediately before the operation; temporary credentials must remain valid until it completes. Required permissions: ec2:*, autoscaling:*, s3:*, iam:*, and sts:GetCallerIdentity.",
    ]
    .concat()
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum InitError {
    #[error("failed to check git repository [{location:?}]")]
    CheckGitRepo {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to get deployment path [{location:?}]")]
    GetDeploymentPath {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to inspect checkout link [{location:?}]")]
    InspectCheckoutLink {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to verify existing app link [{location:?}]")]
    TryRelink {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "failed to initialize bring-your-own-compute deployment from config file [{location:?}]"
    )]
    InitByoc {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("bring-your-own-compute provisioning failed [{location:?}]")]
    InitByocInteractive {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create config file [{location:?}]")]
    CreateConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read configuration [{location:?}]")]
    ReadConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to resolve local build command [{location:?}]")]
    ResolveBuildCommand {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("{message} [{location:?}]")]
    LinkedCheckout {
        message: String,

        #[location]
        location: Location,
    },

    #[error("failed to ensure authentication [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send create app request [{location:?}]")]
    SendCreateRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("account initialization failed [{location:?}]")]
    AccountInitializationFailed {
        #[location]
        location: Location,
    },

    #[error("failed to create app (status {status}): {error} [{location:?}]")]
    CreateApp {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse create app response [{location:?}]")]
    ParseCreateResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to save deployment info [{location:?}]")]
    SaveDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to set git remote [{location:?}]")]
    SetGitRemote {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum InitByocError {
    #[error("failed to load authenticated configuration [{location:?}]")]
    RequireAuthenticatedConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read config file [{location:?}]")]
    ReadConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "refusing encrypted BYOC config update for linked app {resource_id}: the CLI cannot verify or inject its resource ID into ciphertext. Decrypt the config and retry with `caution init --byoc --config <decrypted-json>`. [{location:?}]"
    )]
    EncryptedConfigUpdateRefused {
        resource_id: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse config file as JSON [{location:?}]")]
    ParseConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("config file must have platform: \"aws\" (got: {platform:?}) [{location:?}]")]
    InvalidPlatform {
        platform: Option<String>,

        #[location]
        location: Location,
    },

    #[error("config file must have managed_on_prem: true for BYOC deployments [{location:?}]")]
    ManagedOnPremNotEnabled {
        #[location]
        location: Location,
    },

    #[error("config file missing required field: {field} [{location:?}]")]
    MissingRequiredField {
        field: String,

        #[location]
        location: Location,
    },

    #[error("config field builder_instance_profile_name must be a string [{location:?}]")]
    BuilderInstanceProfileNotString {
        #[location]
        location: Location,
    },

    #[error("failed to serialize config file [{location:?}]")]
    SerializeConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create config file [{location:?}]")]
    CreateConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read configuration [{location:?}]")]
    ReadConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send bring-your-own-compute request [{location:?}]")]
    SendByocRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read response body [{location:?}]")]
    ReadResponseBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "failed to {action} bring-your-own-compute resource (status {status}): {error} [{location:?}]"
    )]
    ByocRequestFailed {
        action: &'static str,

        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse response [{location:?}]")]
    ParseResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to save deployment info [{location:?}]")]
    SaveDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to set git remote [{location:?}]")]
    SetGitRemote {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum InitByocInteractiveError {
    #[error("docker is required but not found. Please install Docker first. [{location:?}]")]
    DockerNotFound {
        #[location]
        location: Location,
    },

    #[error(
        "app name must contain only alphanumeric characters, hyphens, and underscores [{location:?}]"
    )]
    InvalidAppName {
        #[location]
        location: Location,
    },

    #[error("{message} [{location:?}]")]
    AwsCredentialsNotFound {
        message: String,

        #[location]
        location: Location,
    },

    #[error("failed to read confirmation prompt [{location:?}]")]
    ConfirmPrompt {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to ensure authentication [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to pull provisioner image [{location:?}]")]
    PullProvisionerImage {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to pull provisioner image: {stderr} [{location:?}]")]
    ProvisionerImagePullFailed {
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("failed to run provisioner container [{location:?}]")]
    RunProvisionerContainer {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("provisioning failed (exit code: {exit_code:?}) [{location:?}]")]
    ProvisioningFailed {
        exit_code: Option<i32>,

        #[location]
        location: Location,
    },

    #[error("provisioner returned empty output (expected JSON) [{location:?}]")]
    ProvisionerOutputEmpty {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse provisioner output as JSON. raw output:\n{raw_output} [{location:?}]")]
    ParseProvisionerOutput {
        raw_output: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("missing deployment_id in provisioner output [{location:?}]")]
    MissingDeploymentId {
        #[location]
        location: Location,
    },

    #[error("failed to resolve local build command [{location:?}]")]
    ResolveBuildCommand {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create app [{location:?}]")]
    CreateAppRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read response body [{location:?}]")]
    ReadResponseBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create app (status {status}): {error} [{location:?}]")]
    CreateAppFailed {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse create app response [{location:?}]")]
    ParseCreateResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize BYOC credentials [{location:?}]")]
    SerializeCredentials {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to register BYOC credentials [{location:?}]")]
    RegisterCredentialsRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to register credentials (status {status}): {error} [{location:?}]")]
    RegisterCredentialsFailed {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,
    },

    #[error("cannot find home directory [{location:?}]")]
    HomeDirectoryNotFound {
        #[location]
        location: Location,
    },

    #[error("failed to create local state directory [{location:?}]")]
    CreateStateDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize BYOC state [{location:?}]")]
    SerializeByocState {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to write BYOC state file [{location:?}]")]
    WriteByocState {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to save deployment info [{location:?}]")]
    SaveDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create config file [{location:?}]")]
    CreateConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to set git remote [{location:?}]")]
    SetGitRemote {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TeardownError {
    #[error("cannot find home directory [{location:?}]")]
    HomeDirectoryNotFound {
        #[location]
        location: Location,
    },

    #[error("missing deployment_id in state file [{location:?}]")]
    MissingDeploymentId {
        #[location]
        location: Location,
    },

    #[error(
        "no bring-your-own-compute state found.\nrun this command from your app directory or ensure the BYOC state file exists in ~/.caution/<app>/. [{location:?}]"
    )]
    ByocStateNotFound {
        #[location]
        location: Location,
    },

    #[error("failed to read confirmation prompt [{location:?}]")]
    ConfirmPrompt {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("{message} [{location:?}]")]
    AwsCredentialsNotFound {
        message: String,

        #[location]
        location: Location,
    },

    #[error(
        "caution app ID is unavailable; AWS teardown was not started and local BYOC state was preserved [{location:?}]"
    )]
    ResourceIdUnavailable {
        #[location]
        location: Location,
    },

    #[error("failed to ensure authentication [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "caution app deletion is unresolved (status {status}): {error}. AWS teardown was not started and local BYOC state was preserved. [{location:?}]"
    )]
    AppDeletionUnresolved {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,
    },

    #[error(
        "caution app deletion is unresolved. AWS teardown was not started and local BYOC state was preserved. [{location:?}]"
    )]
    AppDeletionRequestFailed {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to run teardown [{location:?}]")]
    RunTeardownContainer {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "aws teardown failed; local BYOC state was preserved for retry: {stderr} [{location:?}]"
    )]
    AwsTeardownFailed {
        stderr: String,

        #[location]
        location: Location,
    },
}

pub(crate) async fn init(
    client: &ApiClient,
    bring_your_own_cloud: bool,
    name: Option<String>,
    region: Option<String>,
    local: bool,
    config_path: Option<PathBuf>,
    yes: bool,
) -> Result<(), InitError> {
    use InitErrorCtx as Ctx;

    output::status("Initializing new deployment...");

    output::verbose(client.verbose, "Checking git repository...");
    client
        .check_git_repo()
        .with_context(Ctx::check_git_repo())?;
    output::success("Git repository found");

    let deployment_path = client
        .get_deployment_path()
        .with_context(Ctx::get_deployment_path())?;
    let mut checkout_link = inspect_checkout_link(deployment_path, Path::new("."), None)
        .with_context(Ctx::inspect_checkout_link())?;
    let relinked = crate::apps::crud::try_relink(client, &checkout_link)
        .await
        .with_context(Ctx::try_relink())?;

    if let Some(ref path) = config_path {
        return init_byoc(client, path).await.with_context(Ctx::init_byoc());
    }

    if relinked {
        output::status("\nYou can now push to 'caution' remote:");
        output::status("  git push caution main");
        return Ok(());
    }

    if bring_your_own_cloud {
        return init_byoc_interactive(client, name, region, local, yes)
            .await
            .with_context(Ctx::init_byoc_interactive());
    }

    client
        .create_config_file_if_needed(false)
        .with_context(Ctx::create_config_file())?;

    output::verbose(client.verbose, "Reading configuration...");
    let config_file = client.read_config().with_context(Ctx::read_config())?;
    let cmd = resolve_local_build_command_from_dir(Path::new("."), false)
        .with_context(Ctx::resolve_build_command())?;
    output::success("Configuration found");
    output::status(&format!("Build command: {}", cmd));

    checkout_link.byoc_provider = config_file
        .caution
        .as_ref()
        .and_then(|caution| caution.provider.as_ref())
        .is_some();

    if checkout_link.blocks_managed_creation() {
        return Err(InitError::LinkedCheckout {
            message: linked_checkout_error(&checkout_link),
            location: std::panic::Location::caller(),
        });
    }

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let app_name = name.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .map(|s| s.to_lowercase().replace(' ', "-"))
            .filter(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            })
            .unwrap_or_else(|| "app".to_string())
    });

    output::verbose(client.verbose, "Creating app on server...");
    let body = serde_json::json!({
        "cmd": cmd,
        "name": app_name
    });

    let loader = Spinner::new("Setting up your app", SpinnerStyle::Processing);

    let response = client
        .client
        .post(format!("{}/api/resources", client.base_url))
        .header("X-Session-ID", config.session_id)
        .json(&body)
        .send()
        .await
        .with_context(Ctx::send_create_request())?;

    if !response.status().is_success() {
        let status = response.status();
        let error = client.api_error_message(response).await;
        loader.finish();

        if error.contains("initialize")
            || error.contains("provisioning")
            || error.contains("AWS account")
        {
            output::error("\n❌ Failed to initialize your AWS account");
            output::error("\nThis is your first time using Caution. We attempted to provision");
            output::error(
                "a dedicated AWS account for your organization, but encountered an error:",
            );
            output::error(format!("\n{}", error));
            output::error("\nPlease check:");
            output::error("  • AWS Organizations is enabled in your main account");
            output::error("  • Your IAM user has organizations:CreateAccount permission");
            output::error("  • Run: aws organizations create-organization --feature-set ALL");
            return Err(InitError::AccountInitializationFailed {
                location: std::panic::Location::caller(),
            });
        }

        return Err(InitError::CreateApp {
            status,
            error,
            location: std::panic::Location::caller(),
        });
    }

    let create_response: CreateAppResponse = response
        .json()
        .await
        .with_context(Ctx::parse_create_response())?;

    loader.finish();

    output::success("App created!");
    output::status(format!("ID: {}", create_response.id));
    output::status(format!("Name: {}", create_response.resource_name));
    output::status(format!("State: {}", create_response.state));
    output::status(format!("Git URL: {}", create_response.git_url));
    output::status(deployment_target_summary(
        "Caution-managed",
        "platform-managed",
        "pending",
    ));

    print_managed_dns_details(
        create_response.managed_hostname.as_deref(),
        create_response.dns_status.as_deref(),
        create_response.dns_error.as_deref(),
        None,
    );

    output::verbose(client.verbose, "Saving deployment info...");
    client
        .save_deployment(&create_response.id)
        .with_context(Ctx::save_deployment())?;
    output::verbose(client.verbose, "Saved deployment info");

    output::verbose(client.verbose, "Setting git remote...");
    client
        .set_git_remote(&create_response.git_url)
        .with_context(Ctx::set_git_remote())?;

    client
        .create_config_file_if_needed(false)
        .with_context(Ctx::create_config_file())?;

    output::status("\nYou can now push to 'caution' remote:");
    output::status("  git push caution main");
    output::status("\nAfter pushing, check your app status:");
    output::status("  caution apps list");
    output::status("\nVerify attestation:");
    output::status("  caution verify");

    Ok(())
}

async fn init_byoc(client: &ApiClient, config_path: &PathBuf) -> Result<(), InitByocError> {
    use InitByocErrorCtx as Ctx;

    output::status("Initializing bring-your-own-compute deployment...");

    let auth_config = client
        .require_existing_authenticated_config()
        .with_context(Ctx::require_authenticated_config())?;

    output::verbose(
        client.verbose,
        &format!("Reading config from {:?}", config_path),
    );
    let config_content = fs::read_to_string(config_path).with_context(Ctx::read_config_file())?;

    let has_gpg_extension = config_path
        .extension()
        .map(|ext| ext == "gpg" || ext == "asc")
        .unwrap_or(false);
    let has_gpg_header = config_content
        .trim()
        .starts_with("-----BEGIN PGP MESSAGE-----");
    let is_gpg_encrypted = has_gpg_extension || has_gpg_header;
    let existing_resource_id = client.load_deployment().ok().map(|d| d.resource_id);

    if linked_encrypted_byoc_config(is_gpg_encrypted, existing_resource_id.as_deref()) {
        return Err(InitByocError::EncryptedConfigUpdateRefused {
            resource_id: existing_resource_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            location: std::panic::Location::caller(),
        });
    }

    let request_body = if is_gpg_encrypted {
        output::verbose(
            client.verbose,
            "Config file is GPG-encrypted (will be decrypted server-side)",
        );
        output::status("Detected GPG-encrypted config file");

        config_content
    } else {
        let mut config_json: serde_json::Value =
            serde_json::from_str(&config_content).with_context(Ctx::parse_config_file())?;

        if let Some(ref id) = existing_resource_id {
            output::status(format!("Found existing deployment: {}", id));
            output::status("Updating existing resource with new configuration...");
            config_json["resource_id"] = serde_json::json!(id);
        }

        let platform = config_json.get("platform").and_then(|v| v.as_str());
        if platform != Some("aws") {
            return Err(InitByocError::InvalidPlatform {
                platform: platform.map(str::to_string),
                location: std::panic::Location::caller(),
            });
        }

        let byoc_enabled = config_json.get("managed_on_prem").and_then(|v| v.as_bool());
        if byoc_enabled != Some(true) {
            return Err(InitByocError::ManagedOnPremNotEnabled {
                location: std::panic::Location::caller(),
            });
        }

        let required_fields = [
            "aws_region",
            "aws_access_key_id",
            "aws_secret_access_key",
            "deployment_id",
            "asg_name",
            "eif_bucket",
            "launch_template_name",
            "launch_template_id",
            "vpc_id",
            "subnet_ids",
            "instance_profile_name",
            "iam_user",
            "aws_account_id",
            "scope_tag",
        ];
        for field in required_fields {
            if config_json.get(field).is_none() {
                return Err(InitByocError::MissingRequiredField {
                    field: field.to_string(),
                    location: std::panic::Location::caller(),
                });
            }
        }

        if let Some(value) = config_json.get("builder_instance_profile_name") {
            if !value.is_string() {
                return Err(InitByocError::BuilderInstanceProfileNotString {
                    location: std::panic::Location::caller(),
                });
            }
        }

        output::verbose(client.verbose, "Config file validated");
        serde_json::to_string(&config_json).with_context(Ctx::serialize_config_file())?
    };

    client
        .create_config_file_if_needed(true)
        .with_context(Ctx::create_config_file())?;

    output::verbose(client.verbose, "Reading configuration...");
    let _config = client.read_config().with_context(Ctx::read_config())?;
    output::success("Configuration found");

    let is_update = existing_resource_id.is_some();
    let loader_msg = if is_update {
        "Updating bring-your-own-compute resource"
    } else {
        "Creating bring-your-own-compute resource"
    };
    let loader = Spinner::new(loader_msg, SpinnerStyle::Processing);

    let response = client
        .client
        .post(format!("{}/api/resources/managed-onprem", client.base_url))
        .header("X-Session-ID", &auth_config.session_id)
        .header("Content-Type", "text/plain")
        .body(request_body)
        .send()
        .await
        .with_context(Ctx::send_byoc_request())?;

    if !response.status().is_success() {
        let status = response.status();
        let error = response
            .text()
            .await
            .with_context(Ctx::read_response_body())?;
        loader.finish();
        let action = if is_update { "update" } else { "create" };
        return Err(InitByocError::ByocRequestFailed {
            action,
            status,
            error,
            location: std::panic::Location::caller(),
        });
    }

    let create_response: serde_json::Value =
        response.json().await.with_context(Ctx::parse_response())?;

    loader.finish();

    let id = create_response["id"].as_str().unwrap_or("unknown");
    let resource_name = create_response["resource_name"]
        .as_str()
        .unwrap_or("unnamed");
    let git_url = create_response["git_url"].as_str().unwrap_or("");
    let state = create_response["state"].as_str().unwrap_or("unknown");
    let aws_account = create_response["managed_onprem"]["aws_account_id"]
        .as_str()
        .unwrap_or("unknown");
    let aws_region = create_response["managed_onprem"]["aws_region"]
        .as_str()
        .unwrap_or("unknown");

    if is_update {
        output::success("Bring-your-own-compute resource updated");
    } else {
        output::success("Bring-your-own-compute resource created");
    }
    output::status(&format!("ID: {}", id));
    output::status(&format!("Name: {}", resource_name));
    output::status(&format!("State: {}", state));
    output::status(&format!("Git URL: {}", git_url));
    output::status(deployment_target_summary("BYOC", aws_account, aws_region));
    print_managed_dns_details(
        create_response["managed_hostname"].as_str(),
        create_response["dns_status"].as_str(),
        create_response["dns_error"].as_str(),
        None,
    );

    output::verbose(client.verbose, "Saving deployment info...");
    client
        .save_deployment(id)
        .with_context(Ctx::save_deployment())?;
    output::verbose(client.verbose, "Saved deployment info");

    if !git_url.is_empty() {
        output::verbose(client.verbose, "Setting git remote...");
        client
            .set_git_remote(git_url)
            .with_context(Ctx::set_git_remote())?;
    }

    output::success("\nYou can now push to 'caution' remote to deploy:");
    output::status("  git push caution main");
    output::success("\nAfter pushing, check your app status:");
    output::status("  caution apps list");

    Ok(())
}

/// Detect AWS credentials from environment or ~/.aws/credentials
/// Returns (access_key, secret_key, region, session_token)
fn detect_aws_credentials() -> Option<(String, String, Option<String>, Option<String>)> {
    // First check environment variables
    if let (Ok(key), Ok(secret)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .ok();
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        return Some((key, secret, region, session_token));
    }

    // Determine which profile to use
    let profile = std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());

    // Fall back to ~/.aws/credentials and ~/.aws/config
    let home = dirs::home_dir()?;
    let creds_path = home.join(".aws").join("credentials");
    let config_path = home.join(".aws").join("config");

    // Parse credentials file for the selected profile
    let (access_key, secret_key, session_token) =
        if let Ok(creds_content) = fs::read_to_string(&creds_path) {
            parse_aws_credentials_file(&creds_content, &profile)
        } else {
            (None, None, None)
        };

    // Parse config file for region (and potentially credentials for SSO profiles)
    let region = if let Ok(config_content) = fs::read_to_string(&config_path) {
        parse_aws_config_region(&config_content, &profile)
    } else {
        None
    };

    match (access_key, secret_key) {
        (Some(k), Some(s)) => Some((k, s, region, session_token)),
        _ => None,
    }
}

fn parse_aws_credentials_file(
    content: &str,
    profile: &str,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut access_key = None;
    let mut secret_key = None;
    let mut session_token = None;
    let mut in_target_section = false;

    let section_header = format!("[{}]", profile);

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_target_section = trimmed == section_header;
            continue;
        }
        if in_target_section {
            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "aws_access_key_id" => access_key = Some(value.to_string()),
                    "aws_secret_access_key" => secret_key = Some(value.to_string()),
                    "aws_session_token" => session_token = Some(value.to_string()),
                    _ => {}
                }
            }
        }
    }

    (access_key, secret_key, session_token)
}

fn parse_aws_config_region(content: &str, profile: &str) -> Option<String> {
    let mut region = None;
    let mut in_target_section = false;

    // In config file, default profile is [default], others are [profile name]
    let section_headers: Vec<String> = if profile == "default" {
        vec!["[default]".to_string(), "[profile default]".to_string()]
    } else {
        vec![format!("[profile {}]", profile)]
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_target_section = section_headers.iter().any(|h| h == trimmed);
            continue;
        }
        if in_target_section {
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == "region" {
                    region = Some(value.trim().to_string());
                }
            }
        }
    }

    region
}

/// Interactive bring-your-own-compute initialization
async fn init_byoc_interactive(
    client: &ApiClient,
    name: Option<String>,
    region: Option<String>,
    local: bool,
    yes: bool,
) -> Result<(), InitByocInteractiveError> {
    use InitByocInteractiveErrorCtx as Ctx;

    output::status("\n╔══════════════════════════════════════════════════════════════════╗");
    output::status("║          Bring-Your-Own-Compute Deployment Setup (AWS)           ║");
    output::status("╚══════════════════════════════════════════════════════════════════╝\n");

    // Check for Docker
    let docker_check = Command::new("docker").arg("--version").output();
    if docker_check.is_err() || !docker_check.unwrap().status.success() {
        return Err(InitByocInteractiveError::DockerNotFound {
            location: std::panic::Location::caller(),
        });
    }

    let app_name = name.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .map(|s| s.to_lowercase().replace(' ', "-"))
            .filter(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            })
            .unwrap_or_else(|| "app".to_string())
    });

    if !app_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(InitByocInteractiveError::InvalidAppName {
            location: std::panic::Location::caller(),
        });
    }

    output::status(format!("App name: {}", app_name));

    // Check AWS credentials
    let aws_profile = std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());
    let (aws_key, aws_secret, detected_region, aws_session_token) = detect_aws_credentials()
        .ok_or_else(|| InitByocInteractiveError::AwsCredentialsNotFound {
            message: aws_credentials_error(&aws_profile, "caution init --byoc"),
            location: std::panic::Location::caller(),
        })?;

    let aws_region = region
        .or(detected_region)
        .unwrap_or_else(|| "us-west-2".to_string());

    if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
        output::status("AWS credentials detected (from environment)");
    } else if aws_profile == "default" {
        output::status("AWS credentials detected (from ~/.aws/credentials)");
    } else {
        output::status(format!(
            "AWS credentials detected (profile: {})",
            aws_profile
        ));
    }
    output::status(format!("Region: {}", aws_region));
    output::status(deployment_target_summary(
        "BYOC",
        "current-credentials",
        &aws_region,
    ));

    // Display what will be created
    output::status("\nThis will create the following AWS resources:");
    output::status("  • VPC with 3 subnets across availability zones");
    output::status("  • S3 bucket for enclave images");
    output::status("  • EC2 Auto Scaling Group and Launch Template");
    output::status("  • IAM user with scoped permissions");
    output::status("  • IAM role and instance profile for EC2");
    output::status("\nAll resources will be tagged for easy identification and cleanup.\n");

    if !yes {
        let confirmed = prompt::confirm("Do you want to proceed? [y/N]: ")
            .with_context(Ctx::confirm_prompt())?;
        if !confirmed {
            output::status("Aborted.");
            return Ok(());
        }
    }

    let auth_config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    // Pull the provisioner image (unless --local is set)
    if local {
        output::status("\nUsing local provisioner image (--local)...");
    } else {
        output::status("\nPulling provisioner image...");
        let pull_output = Command::new("docker")
            .args(&["pull", BYOC_PROVISIONER_IMAGE])
            .output()
            .with_context(Ctx::pull_provisioner_image())?;

        if !pull_output.status.success() {
            let stderr = String::from_utf8_lossy(&pull_output.stderr);
            return Err(InitByocInteractiveError::ProvisionerImagePullFailed {
                stderr: stderr.to_string(),
                location: std::panic::Location::caller(),
            });
        }
    }

    // Run the provisioner
    output::status("Provisioning AWS resources (this may take a few minutes)...");
    output::status("---");

    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-e".to_string(),
        format!("AWS_ACCESS_KEY_ID={}", aws_key),
        "-e".to_string(),
        format!("AWS_SECRET_ACCESS_KEY={}", aws_secret),
        "-e".to_string(),
        format!("AWS_REGION={}", aws_region),
        "-e".to_string(),
        "CLI_MODE=true".to_string(),
    ];

    // Add session token if present (needed for temporary credentials/SSO)
    if let Some(token) = aws_session_token {
        docker_args.push("-e".to_string());
        docker_args.push(format!("AWS_SESSION_TOKEN={}", token));
    }

    docker_args.push(BYOC_PROVISIONER_IMAGE.to_string());

    let output = Command::new("docker")
        .args(&docker_args)
        .output()
        .with_context(Ctx::run_provisioner_container())?;

    // Always print stderr (contains progress messages)
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprint!("{}", stderr);
    }

    output::status("---");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            eprintln!("stdout: {}", stdout);
        }
        return Err(InitByocInteractiveError::ProvisioningFailed {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the JSON output from the provisioner (CLI_MODE outputs to stdout)
    let credentials_json: serde_json::Value = if stdout.trim().is_empty() {
        serde_json::from_str(&stdout).with_context(Ctx::provisioner_output_empty())?
    } else {
        serde_json::from_str(&stdout)
            .with_context(Ctx::parse_provisioner_output(stdout.as_ref()))?
    };

    let deployment_id = credentials_json["deployment_id"].as_str().ok_or(
        InitByocInteractiveError::MissingDeploymentId {
            location: std::panic::Location::caller(),
        },
    )?;
    let aws_account_id = credentials_json["aws_account_id"]
        .as_str()
        .unwrap_or("unknown");

    let create_cmd = resolve_local_build_command_from_dir(Path::new("."), true)
        .with_context(Ctx::resolve_build_command())?;

    // Create app on Caution
    output::status("\nCreating app on Caution...");
    let loader = Spinner::new("Creating app", SpinnerStyle::Processing);

    // Create the app first
    let create_body = serde_json::json!({
        "name": app_name,
        "cmd": create_cmd
    });

    let create_response = client
        .client
        .post(format!("{}/api/resources", client.base_url))
        .header("X-Session-ID", &auth_config.session_id)
        .json(&create_body)
        .send()
        .await
        .with_context(Ctx::create_app_request())?;

    if !create_response.status().is_success() {
        loader.finish();
        let status = create_response.status();
        let error = create_response
            .text()
            .await
            .with_context(Ctx::read_response_body())?;
        return Err(InitByocInteractiveError::CreateAppFailed {
            status,
            error,
            location: std::panic::Location::caller(),
        });
    }

    let app_data: serde_json::Value = create_response
        .json()
        .await
        .with_context(Ctx::parse_create_response())?;

    let resource_id = app_data["id"].as_str().unwrap_or("");
    let git_url = app_data["git_url"].as_str().unwrap_or("");

    loader.finish();
    output::success(format!("App created: {}", app_name));

    // Now register the BYOC credentials
    output::status("Registering bring-your-own-compute configuration...");
    let loader = Spinner::new("Registering credentials", SpinnerStyle::Processing);

    // Add resource_id to credentials
    let mut creds_with_resource = credentials_json.clone();
    creds_with_resource["resource_id"] = serde_json::json!(resource_id);

    let register_response = client
        .client
        .post(format!("{}/api/resources/managed-onprem", client.base_url))
        .header("X-Session-ID", &auth_config.session_id)
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_string(&creds_with_resource)
                .with_context(Ctx::serialize_credentials())?,
        )
        .send()
        .await
        .with_context(Ctx::register_credentials_request())?;

    if !register_response.status().is_success() {
        loader.finish();
        let status = register_response.status();
        let error = register_response
            .text()
            .await
            .with_context(Ctx::read_response_body())?;
        return Err(InitByocInteractiveError::RegisterCredentialsFailed {
            status,
            error,
            location: std::panic::Location::caller(),
        });
    }

    let registered_app_data = match register_response.json::<serde_json::Value>().await {
        Ok(data) => data,
        Err(_) => {
            output::verbose(
                client.verbose,
                "Could not parse the BYOC registration response; using initial DNS details",
            );
            app_data.clone()
        }
    };
    loader.finish();

    // Save local state
    let caution_dir = dirs::home_dir()
        .ok_or(InitByocInteractiveError::HomeDirectoryNotFound {
            location: std::panic::Location::caller(),
        })?
        .join(".caution")
        .join(&app_name);

    fs::create_dir_all(&caution_dir).with_context(Ctx::create_state_dir())?;

    let byoc_state = serde_json::json!({
        "deployment_id": deployment_id,
        "resource_id": resource_id,
        "app_name": app_name,
        "aws_region": aws_region,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });

    let byoc_state_json =
        serde_json::to_string_pretty(&byoc_state).with_context(Ctx::serialize_byoc_state())?;
    fs::write(byoc_state_path(&caution_dir), byoc_state_json)
        .with_context(Ctx::write_byoc_state())?;

    // Also save deployment.json and caution.hcl in current directory
    client
        .save_deployment(resource_id)
        .with_context(Ctx::save_deployment())?;
    client
        .create_config_file_if_needed(true)
        .with_context(Ctx::create_config_file())?;

    // Set up git remote
    if !git_url.is_empty() {
        client
            .set_git_remote(git_url)
            .with_context(Ctx::set_git_remote())?;
    }

    output::status("\n╔══════════════════════════════════════════════════════════════════╗");
    output::success("║                    Setup Complete!                               ║");
    output::status("╚══════════════════════════════════════════════════════════════════╝");
    output::status(format!("\nApp: {}", app_name));
    output::status(format!("Resource ID: {}", resource_id));
    output::status(format!("Deployment ID: {}", deployment_id));
    output::status(format!("Git URL: {}", git_url));
    output::status(deployment_target_summary(
        "BYOC",
        aws_account_id,
        &aws_region,
    ));
    print_managed_dns_details(
        registered_app_data["managed_hostname"].as_str(),
        registered_app_data["dns_status"].as_str(),
        registered_app_data["dns_error"].as_str(),
        None,
    );
    output::status(format!("\nState saved to: {}", caution_dir.display()));
    output::status("\nNext steps:");
    output::status("  1. Create your Procfile with 'run:' and optional 'containerfile:'");
    output::status(
        "     If containerfile is absent, Caution auto-detects a repo-root Containerfile before Dockerfile",
    );
    output::status("  2. Push to deploy: git push caution main");
    output::status("\nTo tear down this deployment:");
    output::status("  caution teardown --byoc");

    Ok(())
}

/// Tear down bring-your-own-compute deployment
pub(crate) async fn teardown(
    client: &ApiClient,
    force: bool,
    local: bool,
) -> Result<(), TeardownError> {
    use TeardownErrorCtx as Ctx;

    output::status("\n╔══════════════════════════════════════════════════════════════════╗");
    output::status("║          Bring-Your-Own-Compute Teardown (AWS)                   ║");
    output::status("╚══════════════════════════════════════════════════════════════════╝\n");

    // Try to find local state
    let deployment = client.load_deployment().ok();
    let resource_id = deployment.as_ref().map(|d| d.resource_id.clone());

    // Look for the BYOC state file in ~/.caution/*/
    let home = dirs::home_dir().ok_or(TeardownError::HomeDirectoryNotFound {
        location: std::panic::Location::caller(),
    })?;
    let caution_dir = home.join(".caution");

    let mut byoc_state: Option<serde_json::Value> = None;
    let mut byoc_state_dir: Option<PathBuf> = None;

    if let Some(ref rid) = resource_id {
        // Look for state file that matches this resource_id
        if let Ok(entries) = fs::read_dir(&caution_dir) {
            for entry in entries.flatten() {
                let state_path = byoc_state_read_path(&entry.path());
                if state_path.exists() {
                    if let Ok(content) = fs::read_to_string(&state_path) {
                        if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
                            if state.get("resource_id").and_then(|v| v.as_str()) == Some(rid) {
                                byoc_state = Some(state);
                                byoc_state_dir = Some(entry.path());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    let (deployment_id, app_name, aws_region) = match &byoc_state {
        Some(state) => {
            let did =
                state["deployment_id"]
                    .as_str()
                    .ok_or(TeardownError::MissingDeploymentId {
                        location: std::panic::Location::caller(),
                    })?;
            let name = state["app_name"].as_str().unwrap_or("unknown");
            let region = state["aws_region"].as_str().unwrap_or("us-west-2");
            (did.to_string(), name.to_string(), region.to_string())
        }
        None => {
            return Err(TeardownError::ByocStateNotFound {
                location: std::panic::Location::caller(),
            });
        }
    };

    output::status("Found bring-your-own-compute deployment:");
    output::status(format!("  App: {}", app_name));
    output::status(format!("  Deployment ID: {}", deployment_id));
    output::status(format!("  Region: {}", aws_region));

    if !force {
        output::warning("\n⚠️  WARNING: This will permanently destroy:");
        output::warning("    • The Caution app and all deployment data");
        output::warning("    • AWS VPC and all associated resources");
        output::warning("    • S3 bucket and all stored images");
        output::warning("    • IAM user, role, and policies");
        output::warning("\n    This action cannot be undone!\n");

        let confirm = prompt::text(&format!(
            "Type the app name to confirm deletion [{}]: ",
            app_name
        ))
        .with_context(Ctx::confirm_prompt())?;
        if confirm != app_name {
            output::status("Aborted.");
            return Ok(());
        }
    }

    // Check AWS credentials for teardown
    let aws_profile = std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());
    let (aws_key, aws_secret, _, aws_session_token) =
        detect_aws_credentials().ok_or_else(|| TeardownError::AwsCredentialsNotFound {
            message: aws_credentials_error(&aws_profile, "caution teardown --byoc"),
            location: std::panic::Location::caller(),
        })?;

    resource_id
        .as_ref()
        .ok_or(TeardownError::ResourceIdUnavailable {
            location: std::panic::Location::caller(),
        })?;

    // Destroy Caution resource first
    if let Some(ref rid) = resource_id {
        output::status("\nDestroying Caution app...");
        let loader = Spinner::new("Destroying app", SpinnerStyle::Processing);

        let auth_config = client
            .ensure_authenticated()
            .await
            .with_context(Ctx::ensure_authenticated())?;
        let response = client
            .client
            .delete(format!("{}/api/resources/{}", client.base_url, rid))
            .header("X-Session-ID", &auth_config.session_id)
            .send()
            .await
            .with_context(Ctx::app_deletion_request_failed())?;

        loader.finish();

        if response.status().is_success() {
            output::success("Caution app destroyed");
        } else {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            return Err(TeardownError::AppDeletionUnresolved {
                status,
                error,
                location: std::panic::Location::caller(),
            });
        }
    }

    // Run teardown container
    output::status("\nDestroying AWS infrastructure...");
    let loader = Spinner::new("Running teardown", SpinnerStyle::Processing);

    let provisioner_image = BYOC_PROVISIONER_IMAGE;
    if local {
        output::status("Using local provisioner image (--local)...");
    } else {
        let _ = Command::new("docker")
            .args(&["pull", provisioner_image])
            .output();
    }

    let mut teardown_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-e".to_string(),
        format!("AWS_ACCESS_KEY_ID={}", aws_key),
        "-e".to_string(),
        format!("AWS_SECRET_ACCESS_KEY={}", aws_secret),
        "-e".to_string(),
        format!("AWS_REGION={}", aws_region),
        "-e".to_string(),
        format!("DEPLOYMENT_ID={}", deployment_id),
        "-e".to_string(),
        "TEARDOWN=true".to_string(),
    ];

    // Add session token if present (needed for temporary credentials/SSO)
    if let Some(token) = aws_session_token {
        teardown_args.push("-e".to_string());
        teardown_args.push(format!("AWS_SESSION_TOKEN={}", token));
    }

    teardown_args.push(provisioner_image.to_string());

    let output = Command::new("docker")
        .args(&teardown_args)
        .output()
        .with_context(Ctx::run_teardown_container())?;

    loader.finish();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TeardownError::AwsTeardownFailed {
            stderr: stderr.trim().to_string(),
            location: std::panic::Location::caller(),
        });
    } else {
        output::success("AWS infrastructure destroyed");
    }

    // Clean up local state
    if let Some(path) = byoc_state_dir {
        if let Err(e) = fs::remove_dir_all(&path) {
            output::warning(format!("Warning: Failed to remove local state: {}", e));
        } else {
            output::success("Local state cleaned up");
        }
    }

    // Remove .caution/deployment.json
    let deployment_file = PathBuf::from(".caution").join("deployment.json");
    if deployment_file.exists() {
        let _ = fs::remove_file(&deployment_file);
    }

    output::status("\n╔══════════════════════════════════════════════════════════════════╗");
    output::success("║                    Teardown Complete                             ║");
    output::status("╚══════════════════════════════════════════════════════════════════╝");
    output::status("\nAll bring-your-own-compute resources have been destroyed.");

    Ok(())
}

#[cfg(test)]
mod tests {
     use super::{init_byoc, linked_encrypted_byoc_config};
     use crate::ApiClient;
     use std::path::PathBuf;
     use tempfile::tempdir;

    fn test_api_client() -> ApiClient {
        ApiClient {
            base_url: "http://localhost".to_string(),
            client: reqwest::Client::new(),
            config_path: PathBuf::new(),
            deployment_path: None,
            verbose: false,
            qr: false,
            workdir: None,
        }
    }

    #[test]
    fn linked_encrypted_byoc_config_requires_decrypted_update() {
        assert!(linked_encrypted_byoc_config(true, Some("existing-app")));
        assert!(!linked_encrypted_byoc_config(false, Some("existing-app")));
        assert!(!linked_encrypted_byoc_config(true, None));
    }

    #[tokio::test]
    async fn init_byoc_requires_login_before_reading_credentials_file() {
        let work_dir = tempdir().unwrap();
        let missing_credentials = work_dir.path().join("missing-byoc-credentials.json");
        let client = ApiClient {
            config_path: work_dir.path().join("missing-session.json"),
            ..test_api_client()
        };

        let err = init_byoc(&client, &missing_credentials).await.unwrap_err();

        // Auth is checked before any credential material is read, so the error
        // must be the authentication failure rather than a config read error.
        assert!(
            matches!(err, super::InitByocError::RequireAuthenticatedConfig { .. }),
            "BYOC init should check authentication before reading credential material: {err:?}"
        );
    }
}
