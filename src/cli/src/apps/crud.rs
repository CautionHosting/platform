// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::{Path, PathBuf};
use std::process::Command;

use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::Deserialize;

use crate::output;
use crate::output::{Spinner, SpinnerStyle};
use crate::prompt;
use crate::resolve_local_build_command_from_dir;
use crate::{ApiClient, App, CheckoutLink, CreateAppResponse, GetProtectedJsonError};

/// Extract a UUID-formatted resource ID from a Caution git remote URL.
///
/// The API constructs git URLs as `git@hostname:<uuid>.git` (standard SSH) or
/// `ssh://git@hostname:port/<uuid>.git` (SSH with explicit port). This function
/// parses the last path segment and validates it as a UUID so that callers can
/// attempt to re-link an app when only the git remote is set (no local
/// `.caution/deployment.json`).
fn extract_resource_id_from_git_url(url: &str) -> Option<String> {
    if url.starts_with("ssh://") {
        let parsed = url::Url::parse(url).ok()?;
        if parsed.scheme() != "ssh" || parsed.username() != "git" || parsed.password().is_some() {
            return None;
        }
        let mut segments = parsed.path_segments()?;
        let candidate = segments.next()?.strip_suffix(".git")?;
        if segments.next().is_some() {
            return None;
        }
        return uuid::Uuid::parse_str(candidate)
            .ok()
            .map(|id| id.to_string());
    }

    let after_at = url.strip_prefix("git@")?;
    let (host, path) = after_at.split_once(':')?;
    if host.is_empty() || path.contains('/') {
        return None;
    }
    let candidate = path.strip_suffix(".git")?;
    uuid::Uuid::parse_str(candidate)
        .ok()
        .map(|id| id.to_string())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RelinkCandidateError {
    #[error(
        "Caution git remote is set to '{remote_url}' but does not contain a valid Caution app ID. Preserve and inspect the remote; refusing to create a successor. [{location:?}]"
    )]
    RemoteWithoutAppId {
        remote_url: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },

    #[error(
        ".caution/deployment.json exists but does not contain a valid resource_id. Preserve and inspect it; refusing to create a successor. [{location:?}]"
    )]
    DeploymentFileWithoutResourceId {
        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) fn relink_candidate(
    checkout_link: &CheckoutLink,
) -> Result<Option<(String, bool)>, RelinkCandidateError> {
    if let Some(resource_id) = checkout_link.resource_id.as_ref() {
        return Ok(Some((resource_id.clone(), false)));
    }

    if let Some(remote_url) = checkout_link.caution_remote.as_deref() {
        let resource_id = extract_resource_id_from_git_url(remote_url).ok_or_else(|| {
            RelinkCandidateError::RemoteWithoutAppId {
                remote_url: remote_url.to_string(),
                location: std::panic::Location::caller(),
                source: None,
            }
        })?;
        return Ok(Some((resource_id, true)));
    }

    if checkout_link.deployment_file_exists {
        return Err(RelinkCandidateError::DeploymentFileWithoutResourceId {
            location: std::panic::Location::caller(),
            source: None,
        });
    }

    Ok(None)
}

fn print_destroy_redeploy_guidance(app: &App) {
    output::status(
        "The app ID, Git repository, and managed hostname were retained. Any linked BYOC credential was also retained.",
    );
    output::status("Redeploy with: git push caution HEAD:main");
    if !app.git_url.is_empty() {
        output::status(["Existing Git URL: ", app.git_url.as_str()].concat());
    }
    output::warning(
        "Do not run `caution apps create` or plain `caution init` for this redeploy. For BYOC apps, do not run `caution teardown --byoc`.",
    );
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateError {
    #[error("failed to check git repository [{location:?}]")]
    CheckGitRepo {
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

    #[error("{message} [{location:?}]")]
    LinkedCheckout {
        message: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
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

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },

    #[error("failed to create app (status {status}): {error} [{location:?}]")]
    CreateApp {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
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

    #[error("failed to create config file [{location:?}]")]
    CreateConfigFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn create(client: &ApiClient) -> Result<(), CreateError> {
    use CreateErrorCtx as Ctx;

    output::status("Creating new Caution-managed app...");

    output::verbose(client.verbose, "Checking git repository...");
    client
        .check_git_repo()
        .with_context(Ctx::check_git_repo())?;
    output::success("Git repository found");

    output::verbose(client.verbose, "Reading configuration...");
    let config_file = client.read_config().with_context(Ctx::read_config())?;
    let cmd = resolve_local_build_command_from_dir(Path::new("."), false)
        .with_context(Ctx::resolve_build_command())?;
    output::success("Configuration found");
    output::status(format!("Build command: {}", cmd));

    let checkout_link = crate::inspect_checkout_link(
        client
            .get_deployment_path()
            .with_context(Ctx::get_deployment_path())?,
        Path::new("."),
        Some(&config_file),
    )
    .with_context(Ctx::inspect_checkout_link())?;

    if checkout_link.blocks_managed_creation() {
        return Err(CreateError::LinkedCheckout {
            message: crate::linked_checkout_error(&checkout_link),
            location: std::panic::Location::caller(),
            source: None,
        });
    }

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    output::verbose(client.verbose, "Creating app on server...");
    let body = serde_json::json!({
        "cmd": cmd
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
            output::warning("\nPlease check:");
            output::warning("  • AWS Organizations is enabled in your main account");
            output::warning("  • Your IAM user has organizations:CreateAccount permission");
            output::warning("  • Run: aws organizations create-organization --feature-set ALL");
            return Err(CreateError::AccountInitializationFailed {
                location: std::panic::Location::caller(),
                source: None,
            });
        }

        return Err(CreateError::CreateApp {
            status,
            error,
            location: std::panic::Location::caller(),
            source: None,
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
    output::status(crate::deployment_target_summary(
        "Caution-managed",
        "platform-managed",
        "pending",
    ));
    crate::print_managed_dns_details(
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

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListError {
    #[error("failed to ensure authentication [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to list apps [{location:?}]")]
    ListApps {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn list(client: &ApiClient) -> Result<(), ListError> {
    use ListErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let apps: Vec<App> = client
        .get_protected_json(&config.session_id, "/api/resources", "Failed to list apps")
        .await
        .with_context(Ctx::list_apps())?;

    if apps.is_empty() {
        output::status("No deployed apps found.");
    } else {
        output::data_header("Apps:");
        for app in apps {
            let name = app.resource_name.as_deref().unwrap_or("unnamed");
            let mut details = vec![app.state.clone()];

            if let Some(config) = &app.configuration
                && let Some(enclave_config) = config.get("enclave_config")
                && let (Some(mem), Some(cpus)) = (
                    enclave_config.get("memory_mb").and_then(|v| v.as_u64()),
                    enclave_config.get("cpus").and_then(|v| v.as_u64()),
                )
            {
                details.push(format!("{}MB/{}cpu", mem, cpus));
            }

            if let Some(ip) = &app.public_ip {
                details.push(ip.clone());
            }
            if let Some(dns_status) = &app.dns_status {
                details.push(["dns:", dns_status].concat());
            }

            output::status(format!("  {} - {} ({})", app.id, name, details.join(", ")));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetError {
    #[error("failed to load deployment info [{location:?}]")]
    LoadDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app via SSH HTTPS [{location:?}]")]
    FetchAppViaSshHttps {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app [{location:?}]")]
    FetchApp {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to list deployments [{location:?}]")]
    ListDeployments {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn get(
    client: &ApiClient,
    id: Option<String>,
    allow_ci_ssh: bool,
) -> Result<(), GetError> {
    use GetErrorCtx as Ctx;

    let app_id = match id {
        Some(id) => id,
        None => {
            client
                .load_deployment()
                .with_context(Ctx::load_deployment())?
                .resource_id
        }
    };
    let app = if allow_ci_ssh {
        match client
            .fetch_app_via_ssh_https(&app_id)
            .await
            .with_context(Ctx::fetch_app_via_ssh_https())?
        {
            Some(app) => app,
            None => client
                .fetch_app(&app_id)
                .await
                .with_context(Ctx::fetch_app())?,
        }
    } else {
        client
            .fetch_app(&app_id)
            .await
            .with_context(Ctx::fetch_app())?
    };
    let name = app.resource_name.as_deref().unwrap_or("unnamed");

    output::data_header("App Details:");
    output::status(format!("  ID: {}", app.id));
    output::status(format!("  Name: {}", name));
    output::status(format!("  State: {}", app.state));

    if let Some(domain) = &app.domain {
        output::status(format!("  Domain: {}", domain));
    }

    if let Some(config) = &app.configuration
        && let Some(enclave_config) = config.get("enclave_config")
    {
        if let Some(memory) = enclave_config.get("memory_mb").and_then(|v| v.as_u64()) {
            output::status(format!("  Memory: {} MB", memory));
        }
        if let Some(cpus) = enclave_config.get("cpus").and_then(|v| v.as_u64()) {
            output::status(format!("  CPUs: {}", cpus));
        }
        if let Some(debug) = enclave_config.get("debug").and_then(|v| v.as_bool())
            && debug
        {
            output::status("  Debug Mode: enabled");
        }
        if let Some(ports) = enclave_config.get("ports").and_then(|v| v.as_array())
            && !ports.is_empty()
        {
            let ports_str: Vec<String> = ports
                .iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect();
            output::status(format!("  Ports: {}", ports_str.join(", ")));
        }
        if let Some(http_port) = enclave_config.get("http_port").and_then(|v| v.as_u64())
            && http_port > 0
        {
            output::status(format!("  HTTP Port: {}", http_port));
        }
    }

    if let Some(ip) = &app.public_ip {
        output::status(format!("  Public IP: {}", ip));
        output::status(format!(
            "  URL: http://{}",
            app.domain.as_deref().unwrap_or(ip)
        ));
        output::status(format!("  Attestation: http://{}/attestation", ip));
    }

    crate::print_managed_dns_details(
        app.managed_hostname.as_deref(),
        app.dns_status.as_deref(),
        app.dns_error.as_deref(),
        app.domain.as_deref(),
    );

    if app.lifecycle.as_deref() == Some("deployments") {
        let deployments = list_deployments(client, &app.id, allow_ci_ssh)
            .await
            .with_context(Ctx::list_deployments())?;
        print_deployments(&app, deployments);
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyError {
    #[error("failed to load deployment info [{location:?}]")]
    LoadDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app via SSH HTTPS [{location:?}]")]
    FetchAppViaSshHttps {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app [{location:?}]")]
    FetchApp {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to confirm destruction [{location:?}]")]
    Confirm {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to destroy app via SSH HTTPS [{location:?}]")]
    DestroyViaSshHttps {
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

    #[error("failed to get app status [{location:?}]")]
    GetAppStatus {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send delete request [{location:?}]")]
    SendDeleteRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to destroy app (status {status}): {error} [{location:?}]")]
    DestroyApp {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) async fn destroy(
    client: &ApiClient,
    id: Option<String>,
    force: bool,
    force_delete: bool,
    allow_ci_ssh: bool,
) -> Result<(), DestroyError> {
    use DestroyErrorCtx as Ctx;

    let app_id = match id {
        Some(id) => id,
        None => {
            client
                .load_deployment()
                .with_context(Ctx::load_deployment())?
                .resource_id
        }
    };
    let app = if allow_ci_ssh {
        match client
            .fetch_app_via_ssh_https(&app_id)
            .await
            .with_context(Ctx::fetch_app_via_ssh_https())?
        {
            Some(app) => app,
            None => client
                .fetch_app(&app_id)
                .await
                .with_context(Ctx::fetch_app())?,
        }
    } else {
        client
            .fetch_app(&app_id)
            .await
            .with_context(Ctx::fetch_app())?
    };

    let name = app.resource_name.as_deref().unwrap_or("unnamed");

    if !force {
        output::status("About to destroy app:");
        output::status(format!("  ID: {}", app.id));
        output::status(format!("  Name: {}", name));
        output::status(format!("  State: {}", app.state));
        if let Some(ip) = &app.public_ip {
            output::status(format!("  Public IP: {}", ip));
        }
        output::warning(
            "  WARNING: Destroy causes downtime and temporarily withdraws managed DNS.",
        );
        output::status(
            "  The app ID, Git repository, and managed hostname will be retained. Any linked BYOC credential will also be retained.",
        );
        if force_delete {
            output::status("");
            output::warning(
                "  WARNING: --force-delete may bypass cloud cleanup failure only after managed DNS is withdrawn and drained.",
            );
        }
        output::status("");
        let confirmed = prompt::confirm("Are you sure you want to destroy this app? [y/N] ")
            .with_context(Ctx::confirm())?;
        if !confirmed {
            output::status("Aborted.");
            return Ok(());
        }
    }

    let loader = Spinner::new(
        &format!("Destroying app {} ({})", name, app.id),
        SpinnerStyle::Processing,
    );

    if allow_ci_ssh
        && client
            .destroy_app_via_ssh_https(&app.id, force_delete)
            .await
            .with_context(Ctx::destroy_via_ssh_https())?
    {
        loader.finish();
        output::success(format!("App {} ({}) destroyed", name, app.id));
        print_destroy_redeploy_guidance(&app);
        Ok(())
    } else {
        let config = client
            .ensure_authenticated()
            .await
            .with_context(Ctx::ensure_authenticated())?;

        // We can't use get_protected_json here since DELETE returns no body.
        // Instead, we check if username_required error appears during the call.
        let path = if force_delete {
            format!("{}/api/resources/{}?force=true", client.base_url, app.id)
        } else {
            format!("{}/api/resources/{}", client.base_url, app.id)
        };

        // First check: try a protected GET to ensure username is claimed
        // This will prompt for username if needed, then proceed with DELETE
        let _: serde_json::Value = client
            .get_protected_json(
                &config.session_id,
                &format!("/api/resources/{}", app.id),
                "Failed to get app status",
            )
            .await
            .with_context(Ctx::get_app_status())?;

        // If we got here, username claim is handled. Now perform the DELETE.
        let response = client
            .client
            .delete(&path)
            .header("X-Session-ID", config.session_id)
            .send()
            .await
            .with_context(Ctx::send_delete_request())?;

        if response.status().is_success() {
            loader.finish();
            output::success(format!("App {} ({}) destroyed", name, app.id));
            print_destroy_redeploy_guidance(&app);
            Ok(())
        } else {
            let status = response.status();
            let error = client.api_error_message(response).await;
            loader.finish();
            Err(DestroyError::DestroyApp {
                status,
                error,
                location: std::panic::Location::caller(),
                source: None,
            })
        }
    }
}

/// A deployment of a deployments-lifecycle app, as the API returns it.
#[derive(Debug, Deserialize)]
pub(crate) struct DeploymentView {
    id: String,
    app_id: String,
    role: String,
    status: String,
    failure_kind: Option<String>,
    pushed_ref: Option<String>,
    commit_sha: Option<String>,
    commit_subject: Option<String>,
    instance_type: Option<String>,
    public_ip: Option<String>,
    created_at: String,
    error: Option<String>,
    /// Not read yet: `send-shard -d` checks the release bundle against it.
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) bundle_hash: Option<String>,
    #[serde(default)]
    pub(crate) tls_after_switch: bool,
}

/// The `error` text of an API error body, or the whole body when it has none.
fn api_error_text(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|body| Some(body.get("error")?.as_str()?.to_string()))
        .unwrap_or_else(|| body.to_string())
}

/// The canonical form of a UUID, so IDs are safe to put in URLs and file paths.
fn canonical_id(id: &str) -> Option<String> {
    uuid::Uuid::parse_str(id).ok().map(|id| id.to_string())
}

/// Failure modes for [`get_json`].
#[derive(Debug, thiserror::Error, CtxError)]
enum GetJsonError {
    #[error("failed to send SSH-signed request for {path} [{location:?}]")]
    SshRequest {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read the response for {path} [{location:?}]")]
    ReadBody {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse the response for {path} [{location:?}]")]
    Parse {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("request for {path} failed (status {status}): {message} [{location:?}]")]
    Api {
        path: String,

        status: reqwest::StatusCode,

        message: String,

        location: Location,
    },

    #[error("failed to ensure authentication [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to get {path} [{location:?}]")]
    Session {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// GETs `path`: SSH-signed when `allow_ci_ssh` and an SSH signing identity is
/// configured (the gateway allows it on the app-scoped deployment paths),
/// session-authenticated otherwise.
async fn get_json<T: serde::de::DeserializeOwned>(
    client: &ApiClient,
    path: &str,
    allow_ci_ssh: bool,
) -> Result<T, GetJsonError> {
    use GetJsonErrorCtx as Ctx;

    if allow_ci_ssh
        && let Some(response) = client
            .ssh_signed_request(reqwest::Method::GET, path, None)
            .await
            .with_context(Ctx::ssh_request(path))?
    {
        let status = response.status();
        let body = response.text().await.with_context(Ctx::read_body(path))?;
        if !status.is_success() {
            return Err(GetJsonError::Api {
                path: path.to_string(),
                status,
                message: api_error_text(&client.format_api_error(status, &body)),
                location: std::panic::Location::caller(),
            });
        }
        return serde_json::from_str(&body).with_context(Ctx::parse(path));
    }

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;
    match client
        .get_protected_json(&config.session_id, path, "Failed to get deployment data")
        .await
    {
        Ok(value) => Ok(value),
        Err(GetProtectedJsonError::ApiFailure {
            status,
            api_response,
            ..
        }) => Err(GetJsonError::Api {
            path: path.to_string(),
            status,
            message: api_error_text(&api_response),
            location: std::panic::Location::caller(),
        }),
        Err(error) => Err(error).with_context(Ctx::session(path)),
    }
}

/// Failure modes for [`fetch_deployment`].
#[derive(Debug, thiserror::Error, CtxError)]
enum FetchDeploymentError {
    #[error("{id:?} is not a valid ID; expected a UUID [{location:?}]")]
    InvalidId { id: String, location: Location },

    #[error(
        "Pass the app ID or run from a linked checkout when using --this-is-a-ci-machine. [{location:?}]"
    )]
    CiNeedsApp { location: Location },

    #[error("Deployment {id} was not found in app {app}. Pass the right app ID. [{location:?}]")]
    NotInApp {
        id: String,
        app: String,
        location: Location,
    },

    #[error(
        "Deployment {id} belongs to app {actual}, not {app}. Pass the right app ID. [{location:?}]"
    )]
    AppMismatch {
        id: String,
        app: String,
        actual: String,
        location: Location,
    },

    #[error("The platform answered with deployment {returned:?} for {requested} [{location:?}]")]
    WrongDeployment {
        requested: String,
        returned: String,
        location: Location,
    },

    #[error("failed to fetch deployment {id} [{location:?}]")]
    Get {
        #[context(borrow = str)]
        id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// The one deployment `deployment`, whatever the checkout is linked to
/// (`-d` selects any deployment, and with it the app). A session caller asks
/// by deployment ID alone; an explicit `app` must then be the deployment's
/// app. SSH-signed CI requests are authorized by the app in the path, so a CI
/// caller reads the app-scoped path of `app`, else of the linked checkout's
/// app. The answer must be the deployment asked for: its ID names the trust
/// state file, so it is never taken from the platform's answer.
async fn fetch_deployment(
    client: &ApiClient,
    app: Option<String>,
    deployment: &str,
    allow_ci_ssh: bool,
) -> Result<DeploymentView, FetchDeploymentError> {
    use FetchDeploymentErrorCtx as Ctx;

    let invalid = |id: &str| FetchDeploymentError::InvalidId {
        id: id.to_string(),
        location: std::panic::Location::caller(),
    };
    let deployment_id = canonical_id(deployment).ok_or_else(|| invalid(deployment))?;
    let mut app_id = app
        .as_deref()
        .map(|app| canonical_id(app).ok_or_else(|| invalid(app)))
        .transpose()?;
    let path = if allow_ci_ssh {
        if app_id.is_none() {
            app_id = client
                .load_deployment()
                .ok()
                .and_then(|link| canonical_id(&link.resource_id));
        }
        let Some(app_id) = &app_id else {
            return Err(FetchDeploymentError::CiNeedsApp {
                location: std::panic::Location::caller(),
            });
        };
        format!("/api/resources/{app_id}/deployments/{deployment_id}")
    } else {
        format!("/api/deployments/{deployment_id}")
    };

    let mut view: DeploymentView = match get_json(client, &path, allow_ci_ssh).await {
        Err(GetJsonError::Api {
            status: reqwest::StatusCode::NOT_FOUND,
            ..
        }) if allow_ci_ssh => {
            return Err(FetchDeploymentError::NotInApp {
                id: deployment_id,
                app: app_id.unwrap_or_default(),
                location: std::panic::Location::caller(),
            });
        }
        found => found.with_context(Ctx::get(&deployment_id))?,
    };

    if canonical_id(&view.id).as_deref() != Some(deployment_id.as_str()) {
        return Err(FetchDeploymentError::WrongDeployment {
            requested: deployment_id,
            returned: view.id,
            location: std::panic::Location::caller(),
        });
    }
    let actual_app = canonical_id(&view.app_id).ok_or_else(|| invalid(&view.app_id))?;
    if let Some(app_id) = app_id
        && app_id != actual_app
    {
        return Err(FetchDeploymentError::AppMismatch {
            id: deployment_id,
            app: app_id,
            actual: actual_app,
            location: std::panic::Location::caller(),
        });
    }
    view.id = deployment_id;
    view.app_id = actual_app;
    Ok(view)
}

/// Failure modes for [`list_deployments`].
#[derive(Debug, thiserror::Error, CtxError)]
enum ListDeploymentsError {
    #[error("failed to list the deployments of app {app_id} [{location:?}]")]
    Get {
        #[context(borrow = str)]
        app_id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`ensure_bare_target`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum BareTargetError {
    #[error(
        "app {app_id} has {running} running deployments; name one with -d <deployment> [{location:?}]"
    )]
    SeveralDeployments {
        app_id: String,
        running: usize,
        #[location]
        location: Location,
    },

    #[error("failed to list the app's deployments [{location:?}]")]
    ListDeployments {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Bare `verify` and `secret send-shard` target the app's address. That is
/// unambiguous for Legacy apps and while at most one deployment runs.
pub(crate) fn bare_target_allowed(lifecycle: Option<&str>, running: usize) -> bool {
    lifecycle != Some("deployments") || running <= 1
}

pub(crate) async fn ensure_bare_target(
    client: &ApiClient,
    app: &App,
) -> Result<(), BareTargetError> {
    if app.lifecycle.as_deref() != Some("deployments") {
        return Ok(());
    }
    let running = list_deployments(client, &app.id, false)
        .await
        .with_context(BareTargetErrorCtx::list_deployments())?
        .iter()
        .filter(|deployment| deployment.status == "running")
        .count();
    if bare_target_allowed(app.lifecycle.as_deref(), running) {
        Ok(())
    } else {
        Err(BareTargetError::SeveralDeployments {
            app_id: app.id.clone(),
            running,
            location: std::panic::Location::caller(),
        })
    }
}

async fn list_deployments(
    client: &ApiClient,
    app_id: &str,
    allow_ci_ssh: bool,
) -> Result<Vec<DeploymentView>, ListDeploymentsError> {
    get_json(
        client,
        &format!("/api/resources/{app_id}/deployments"),
        allow_ci_ssh,
    )
    .await
    .with_context(ListDeploymentsErrorCtx::get(app_id))
}

fn short_sha(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

/// The live deployment first, then the API's order (newest first).
fn print_deployments(app: &App, mut deployments: Vec<DeploymentView>) {
    output::status("  Lifecycle: deployments");
    output::status(format!(
        "  Live deployment: {}",
        app.live_deployment_id.as_deref().unwrap_or("none")
    ));
    if deployments.is_empty() {
        output::status("  No deployments yet.");
        return;
    }
    deployments.sort_by_key(|deployment| deployment.role != "live");
    output::data_header("Deployments:");
    for deployment in &deployments {
        output::status(format!(
            "  {}  {:<9}  {:<12}  {:<7}  {}  {}",
            deployment.id,
            deployment.role,
            deployment.status,
            deployment.commit_sha.as_deref().map_or("-", short_sha),
            deployment.pushed_ref.as_deref().unwrap_or("-"),
            deployment.public_ip.as_deref().unwrap_or("-"),
        ));
    }
    output::status(format!(
        "Inspect one: caution apps get {} -d <deployment>",
        app.id
    ));
}

/// Failure modes for [`get_deployment`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetDeploymentError {
    #[error("failed to fetch the deployment [{location:?}]")]
    Fetch {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// `apps get -d`: one deployment, one field per line.
pub(crate) async fn get_deployment(
    client: &ApiClient,
    app: Option<String>,
    deployment: &str,
    allow_ci_ssh: bool,
) -> Result<(), GetDeploymentError> {
    use GetDeploymentErrorCtx as Ctx;

    let deployment = fetch_deployment(client, app, deployment, allow_ci_ssh)
        .await
        .with_context(Ctx::fetch())?;

    output::data_header("Deployment Details:");
    output::status(format!("  ID: {}", deployment.id));
    output::status(format!("  Role: {}", deployment.role));
    match &deployment.failure_kind {
        Some(kind) => output::status(format!("  Status: {} ({})", deployment.status, kind)),
        None => output::status(format!("  Status: {}", deployment.status)),
    }
    for (label, value) in [
        ("Commit", &deployment.commit_sha),
        ("Subject", &deployment.commit_subject),
        ("Pushed ref", &deployment.pushed_ref),
        ("Public IP", &deployment.public_ip),
        ("Instance type", &deployment.instance_type),
    ] {
        if let Some(value) = value {
            output::status(format!("  {label}: {value}"));
        }
    }
    output::status(format!("  Created: {}", deployment.created_at));
    if let Some(error) = &deployment.error {
        output::status(format!("  Error: {error}"));
    }
    Ok(())
}

/// Failure modes for [`git_head`].
#[derive(Debug, thiserror::Error, CtxError)]
enum GitHeadError {
    #[error("failed to run git [{location:?}]")]
    Run {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("`git rev-parse HEAD` failed: {stderr} [{location:?}]")]
    Failed { stderr: String, location: Location },
}

fn git_head() -> Result<String, GitHeadError> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .with_context(GitHeadErrorCtx::run())?;
    if !output.status.success() {
        return Err(GitHeadError::Failed {
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Why a deployment cannot be verified from this checkout. Neither failure
/// has an underlying cause.
#[derive(Debug, thiserror::Error, CtxError)]
enum VerifyTargetError {
    #[error("Deployment {id} has no reachable endpoint (status: {status}) [{location:?}]")]
    NoEndpoint {
        id: String,
        status: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },

    #[error(
        "This checkout is at {head}, but deployment {id} was built from {commit_sha}. Check out that commit and retry. [{location:?}]"
    )]
    CheckoutMismatch {
        head: String,
        id: String,
        commit_sha: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) struct DeploymentVerifyTarget {
    pub(crate) attestation_url: String,
    pub(crate) trust_path: PathBuf,
    /// Not the live deployment: the app's domain points at the live one.
    pub(crate) candidate: bool,
}

/// Where to verify `deployment` and where to keep its trust. `head` is the
/// checkout's commit when the verification rebuilds from it: the rebuild only
/// matches the deployment's measurements at the commit it was built from. The
/// trust file is named by `deployment.id`, which [`fetch_deployment`] makes the
/// ID that was asked for.
fn verify_target(
    deployment: &DeploymentView,
    head: Option<&str>,
) -> Result<DeploymentVerifyTarget, VerifyTargetError> {
    let Some(ip) = deployment.public_ip.as_deref().filter(|ip| !ip.is_empty()) else {
        return Err(VerifyTargetError::NoEndpoint {
            id: deployment.id.clone(),
            status: deployment.status.clone(),
            location: std::panic::Location::caller(),
            source: None,
        });
    };
    if let (Some(head), Some(commit_sha)) = (head, deployment.commit_sha.as_deref())
        && !head.eq_ignore_ascii_case(commit_sha)
    {
        return Err(VerifyTargetError::CheckoutMismatch {
            head: head.to_string(),
            id: deployment.id.clone(),
            commit_sha: commit_sha.to_string(),
            location: std::panic::Location::caller(),
            source: None,
        });
    }
    Ok(DeploymentVerifyTarget {
        attestation_url: format!("http://{ip}/attestation"),
        trust_path: crate::verify::trusted_hashes_path(Some(&deployment.id)),
        candidate: deployment.role != "live",
    })
}

/// Failure modes for [`prepare_deployment_verify`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PrepareDeploymentVerifyError {
    #[error("failed to fetch the deployment [{location:?}]")]
    Fetch {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read the checkout's commit [{location:?}]")]
    GitHead {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("deployment cannot be verified [{location:?}]")]
    Target {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// `verify -d`: resolves the deployment's current endpoint (a candidate's IP
/// changes on stop/start, so it is read now) and checks the checkout.
pub(crate) async fn prepare_deployment_verify(
    client: &ApiClient,
    deployment: &str,
    rebuilds_checkout: bool,
) -> Result<DeploymentVerifyTarget, PrepareDeploymentVerifyError> {
    use PrepareDeploymentVerifyErrorCtx as Ctx;

    let deployment = fetch_deployment(client, None, deployment, false)
        .await
        .with_context(Ctx::fetch())?;
    let head = if rebuilds_checkout {
        Some(git_head().with_context(Ctx::git_head())?)
    } else {
        None
    };
    let target = verify_target(&deployment, head.as_deref()).with_context(Ctx::target())?;
    output::status(format!(
        "Verifying deployment {} ({}) at {}",
        deployment.id,
        deployment.role,
        deployment.public_ip.as_deref().unwrap_or_default()
    ));
    Ok(target)
}

/// Failure modes for [`switch`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SwitchError {
    #[error("failed to fetch the deployment [{location:?}]")]
    FetchDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app [{location:?}]")]
    FetchApp {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to confirm the switch [{location:?}]")]
    Confirm {
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

    #[error("failed to send the signed switch request [{location:?}]")]
    SignedPost {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read the switch response [{location:?}]")]
    ReadBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to switch deployment (status {status}): {message} [{location:?}]")]
    Api {
        status: reqwest::StatusCode,

        message: String,

        location: Location,
    },

    #[error("failed to parse the switch response [{location:?}]")]
    ParseResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, Deserialize)]
struct SwitchResponse {
    live_deployment_id: String,
    stable_ip: String,
    #[serde(default)]
    tls_after_switch: bool,
}

/// `apps switch -d`: moves the app's stable IP to the deployment, signed with
/// a passkey. The deployment and the app's live deployment are read afresh on
/// every run: the request names the live deployment it was confirmed against,
/// and the API refuses it if that changed.
pub(crate) async fn switch(
    client: &ApiClient,
    app: Option<String>,
    deployment: &str,
    force: bool,
) -> Result<(), SwitchError> {
    use SwitchErrorCtx as Ctx;

    let target = fetch_deployment(client, app, deployment, false)
        .await
        .with_context(Ctx::fetch_deployment())?;
    let app = client
        .fetch_app(&target.app_id)
        .await
        .with_context(Ctx::fetch_app())?;

    if !force {
        output::status("About to make a deployment live:");
        output::status(format!(
            "  App: {} ({})",
            app.id,
            app.resource_name.as_deref().unwrap_or("unnamed")
        ));
        output::status(format!(
            "  Current live deployment: {}",
            app.live_deployment_id.as_deref().unwrap_or("none")
        ));
        output::status(format!("  Target deployment: {}", target.id));
        if let Some(commit_sha) = &target.commit_sha {
            match &target.commit_subject {
                Some(subject) => output::status(format!("  Commit: {commit_sha} {subject}")),
                None => output::status(format!("  Commit: {commit_sha}")),
            }
        }
        output::status(format!(
            "  Stable IP: {}",
            app.public_ip.as_deref().unwrap_or("none yet")
        ));
        output::status("  The previous deployment stays running and billable.");
        if target.tls_after_switch {
            output::status(
                "  Application TLS verification pending: this deployment gets its certificate only after this switch.",
            );
            output::status(
                "  Existing connections may close and HTTPS can be unavailable while it is issued.",
            );
        }
        output::status("");
        let confirmed = prompt::confirm("Confirm you verified and tested this deployment [y/N] ")
            .with_context(Ctx::confirm())?;
        if !confirmed {
            output::status("Aborted.");
            return Ok(());
        }
    }

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;
    // Only a TLS-after-switch target signs the acknowledgement, so every other
    // switch body stays unchanged.
    let mut switch_body = serde_json::json!({
        "expected_live_deployment_id": app.live_deployment_id,
        "acknowledged_verification": true,
    });
    if target.tls_after_switch {
        switch_body["acknowledged_tls_pending"] = true.into();
    }
    // The `/api` prefix is part of the request path; the signing challenge
    // strips it.
    let response = client
        .signed_post(
            &config.session_id,
            &format!(
                "/api/resources/{}/deployments/{}/switch",
                target.app_id, target.id
            ),
            &switch_body,
        )
        .await
        .with_context(Ctx::signed_post())?;
    let status = response.status();
    let body = response.text().await.with_context(Ctx::read_body())?;
    if !status.is_success() {
        return Err(SwitchError::Api {
            status,
            message: api_error_text(&client.format_api_error(status, &body)),
            location: std::panic::Location::caller(),
        });
    }
    let switched: SwitchResponse =
        serde_json::from_str(&body).with_context(Ctx::parse_response())?;

    output::success(format!(
        "Deployment {} is now live",
        switched.live_deployment_id
    ));
    output::status(format!("Stable IP: {}", switched.stable_ip));
    if switched.tls_after_switch {
        output::status(format!(
            "Complete TLS checks once issued: caution verify -d {}",
            switched.live_deployment_id
        ));
    }
    Ok(())
}

/// Failure modes for [`destroy_deployment`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyDeploymentError {
    #[error("failed to fetch the deployment [{location:?}]")]
    FetchDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to list deployments [{location:?}]")]
    ListDeployments {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to confirm destruction [{location:?}]")]
    Confirm {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send SSH-signed delete request [{location:?}]")]
    SshRequest {
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

    #[error("failed to send delete request [{location:?}]")]
    SendDeleteRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to destroy deployment (status {status}): {message} [{location:?}]")]
    Api {
        status: reqwest::StatusCode,

        message: String,

        location: Location,
    },
}

/// `apps destroy -d`: destroys one non-live deployment; the API refuses the
/// live one whatever the flags.
pub(crate) async fn destroy_deployment(
    client: &ApiClient,
    app: Option<String>,
    deployment: &str,
    force: bool,
    allow_ci_ssh: bool,
) -> Result<(), DestroyDeploymentError> {
    use DestroyDeploymentErrorCtx as Ctx;

    let target = fetch_deployment(client, app, deployment, allow_ci_ssh)
        .await
        .with_context(Ctx::fetch_deployment())?;

    if !force {
        let deployments = list_deployments(client, &target.app_id, allow_ci_ssh)
            .await
            .with_context(Ctx::list_deployments())?;
        output::status("About to destroy deployment:");
        output::status(format!("  ID: {}", target.id));
        output::status(format!("  App: {}", target.app_id));
        output::status(format!("  Status: {}", target.status));
        if let Some(commit_sha) = &target.commit_sha {
            output::status(format!("  Commit: {commit_sha}"));
        }
        match deployments
            .iter()
            .find(|candidate| candidate.role == "live")
        {
            Some(live) if live.id == target.id => output::warning(
                "  WARNING: This is the live deployment; the platform refuses to destroy it.",
            ),
            Some(live) => {
                output::status(format!("  The live deployment {} keeps serving.", live.id))
            }
            None => output::status("  No deployment is live."),
        }
        output::status("");
        let confirmed = prompt::confirm("Are you sure you want to destroy this deployment? [y/N] ")
            .with_context(Ctx::confirm())?;
        if !confirmed {
            output::status("Aborted.");
            return Ok(());
        }
    }

    let loader = Spinner::new(
        &format!("Destroying deployment {}", target.id),
        SpinnerStyle::Processing,
    );
    let path = format!("/api/resources/{}/deployments/{}", target.app_id, target.id);
    let signed = if allow_ci_ssh {
        client
            .ssh_signed_request(reqwest::Method::DELETE, &path, None)
            .await
            .with_context(Ctx::ssh_request())?
    } else {
        None
    };
    let response = match signed {
        Some(response) => response,
        None => {
            let config = client
                .ensure_authenticated()
                .await
                .with_context(Ctx::ensure_authenticated())?;
            client
                .client
                .delete(format!("{}{}", client.base_url, path))
                .header("X-Session-ID", config.session_id)
                .send()
                .await
                .with_context(Ctx::send_delete_request())?
        }
    };
    let status = response.status();
    if status.is_success() {
        loader.finish();
        output::success(format!("Deployment {} destroyed", target.id));
        return Ok(());
    }
    let message = api_error_text(&client.api_error_message(response).await);
    loader.finish();
    Err(DestroyDeploymentError::Api {
        status,
        message,
        location: std::panic::Location::caller(),
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RenameError {
    #[error("failed to fetch app [{location:?}]")]
    FetchApp {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to get current app [{location:?}]")]
    GetCurrentApp {
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

    #[error("failed to send rename request [{location:?}]")]
    SendRenameRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse rename response [{location:?}]")]
    ParseRenameResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to rename app (status {status}): {error} [{location:?}]")]
    RenameApp {
        status: reqwest::StatusCode,

        error: String,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) async fn rename(
    client: &ApiClient,
    id: Option<String>,
    new_name: String,
) -> Result<(), RenameError> {
    use RenameErrorCtx as Ctx;

    let app = match id {
        Some(id) => client.fetch_app(&id).await.with_context(Ctx::fetch_app())?,
        None => client
            .get_current_app()
            .await
            .with_context(Ctx::get_current_app())?,
    };

    let old_name = app.resource_name.as_deref().unwrap_or("unnamed");

    output::status(format!("Renaming app '{}' to '{}'...", old_name, new_name));

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let body = serde_json::json!({
        "name": new_name
    });

    // Note: This is a PATCH mutation. get_protected_json only handles GETs,
    // so we still use the raw client call here since it's not idempotent.
    // The username_required check happens during fetch_app above.
    let response = client
        .client
        .patch(format!("{}/api/resources/{}", client.base_url, app.id))
        .header("X-Session-ID", config.session_id)
        .json(&body)
        .send()
        .await
        .with_context(Ctx::send_rename_request())?;

    if response.status().is_success() {
        let updated_app: App = response
            .json()
            .await
            .with_context(Ctx::parse_rename_response())?;
        let updated_name = updated_app.resource_name.as_deref().unwrap_or("unnamed");
        output::success(format!("App renamed: {} -> {}", old_name, updated_name));

        Ok(())
    } else {
        let status = response.status();
        let error = client.api_error_message(response).await;
        Err(RenameError::RenameApp {
            status,
            error,
            location: std::panic::Location::caller(),
            source: None,
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TryRelinkError {
    #[error("failed to determine re-link candidate [{location:?}]")]
    RelinkCandidate {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "unable to verify linked app {resource_id}; refusing to create a successor. Preserve the caution remote and restore authentication or connectivity before retrying. [{location:?}]"
    )]
    VerifyApp {
        resource_id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "api returned app {api_app_id} while verifying {expected_app_id}; refusing to change the checkout link [{location:?}]"
    )]
    IdMismatch {
        api_app_id: String,

        expected_app_id: String,

        #[location]
        location: Location,
    },

    #[error(
        "app {app_id} was verified but the API returned no Git URL; refusing to report a successful re-link [{location:?}]"
    )]
    MissingGitUrl {
        app_id: String,

        #[location]
        location: Location,
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

/// Attempt to re-link an existing app based on local checkout state.
///
/// A valid resource ID in `.caution/deployment.json` takes precedence;
/// otherwise a UUID is read from the `caution` SSH remote. The selected app
/// is verified through the API before local state or the remote is changed.
///
/// Returns `Ok(true)` when the checkout was successfully re-linked (the
/// caller should short-circuit), `Ok(false)` when no linkage state exists at
/// all (proceed with creation), or returns an error for unverifiable state.
pub(crate) async fn try_relink(
    client: &ApiClient,
    checkout_link: &CheckoutLink,
) -> Result<bool, TryRelinkError> {
    use TryRelinkErrorCtx as Ctx;

    let Some((resource_id, from_remote)) =
        relink_candidate(checkout_link).with_context(Ctx::relink_candidate())?
    else {
        return Ok(false);
    };

    if from_remote {
        output::status(format!(
            "Attempting to re-link app from git remote (ID: {})...",
            resource_id
        ));
    } else {
        output::verbose(
            client.verbose,
            ["Found existing deployment with ID: ", &resource_id].concat(),
        );
    }

    let app = client
        .fetch_app(&resource_id)
        .await
        .with_context(Ctx::verify_app(&resource_id))?;
    if app.id != resource_id {
        return Err(TryRelinkError::IdMismatch {
            api_app_id: app.id.clone(),
            expected_app_id: resource_id.clone(),
            location: std::panic::Location::caller(),
        });
    }
    if app.git_url.is_empty() {
        return Err(TryRelinkError::MissingGitUrl {
            app_id: app.id.clone(),
            location: std::panic::Location::caller(),
        });
    }

    let name = app.resource_name.as_deref().unwrap_or("unnamed");
    output::status(if from_remote {
        "App re-linked successfully!"
    } else {
        "App already exists!"
    });
    output::status(format!("ID: {}", app.id));
    output::status(format!("Name: {}", name));
    output::status(format!("State: {}", app.state));
    output::status(format!("Git URL: {}", app.git_url));

    client
        .save_deployment(&app.id)
        .with_context(Ctx::save_deployment())?;
    output::verbose(client.verbose, "Updating git remote...");
    client
        .set_git_remote(&app.git_url)
        .with_context(Ctx::set_git_remote())?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        DeploymentView, VerifyTargetError, api_error_text, bare_target_allowed, canonical_id,
        destroy_deployment, extract_resource_id_from_git_url, fetch_deployment,
        prepare_deployment_verify, short_sha, switch, verify_target,
    };
    use crate::ApiClient;
    use sha2::{Digest, Sha256};
    use std::error::Error;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const DEPLOYMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
    const APP: &str = "660e8400-e29b-41d4-a716-446655440000";
    const OTHER_APP: &str = "770e8400-e29b-41d4-a716-446655440000";
    const LIVE: &str = "880e8400-e29b-41d4-a716-446655440000";

    fn deployment(public_ip: Option<&str>, commit_sha: Option<&str>) -> DeploymentView {
        serde_json::from_value(serde_json::json!({
            "id": DEPLOYMENT,
            "app_id": APP,
            "role": "candidate",
            "status": "running",
            "commit_sha": commit_sha,
            "public_ip": public_ip,
            "created_at": "2026-10-12T00:00:00Z",
            // Fields the CLI does not read are ignored.
            "instance_id": "i-0123",
            "running_at": null,
        }))
        .unwrap()
    }

    #[test]
    fn api_errors_show_their_error_text() {
        assert_eq!(
            api_error_text(r#"{"error":"The live deployment changed; review and confirm again."}"#),
            "The live deployment changed; review and confirm again."
        );
        assert_eq!(
            api_error_text("HTTP 502 Bad Gateway"),
            "HTTP 502 Bad Gateway"
        );
        assert_eq!(api_error_text(r#"{"detail":"x"}"#), r#"{"detail":"x"}"#);
    }

    #[test]
    fn only_uuids_are_deployment_ids() {
        assert_eq!(canonical_id(DEPLOYMENT).as_deref(), Some(DEPLOYMENT));
        assert_eq!(
            canonical_id(&DEPLOYMENT.to_uppercase()).as_deref(),
            Some(DEPLOYMENT)
        );
        for id in [
            "d2",
            "",
            "../x",
            "550e8400-e29b-41d4-a716-446655440000/switch",
        ] {
            assert_eq!(canonical_id(id), None, "{id:?}");
        }
    }

    #[test]
    fn bare_target_requires_a_deployment_when_several_run() {
        assert!(bare_target_allowed(Some("legacy"), 3));
        assert!(bare_target_allowed(None, 3)); // older API: Legacy behavior
        assert!(bare_target_allowed(Some("deployments"), 0));
        assert!(bare_target_allowed(Some("deployments"), 1));
        assert!(!bare_target_allowed(Some("deployments"), 2));
    }

    #[test]
    fn short_commits_are_seven_characters() {
        assert_eq!(short_sha("ff43fef1234567890"), "ff43fef");
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn verification_targets_the_deployments_current_endpoint_and_own_trust() {
        let target = verify_target(&deployment(Some("203.0.113.9"), Some("abc123")), None).unwrap();
        assert_eq!(target.attestation_url, "http://203.0.113.9/attestation");
        assert_eq!(
            target.trust_path.to_str().unwrap(),
            format!(".caution/deployments/{DEPLOYMENT}/trusted_hashes.json")
        );
    }

    #[test]
    fn verification_needs_an_endpoint() {
        for ip in [None, Some("")] {
            let error = verify_target(&deployment(ip, Some("abc123")), None)
                .err()
                .unwrap();
            assert!(matches!(error, VerifyTargetError::NoEndpoint { .. }));
            assert!(error.to_string().starts_with(&format!(
                "Deployment {DEPLOYMENT} has no reachable endpoint (status: running)"
            )));
        }
    }

    #[test]
    fn rebuilding_verification_needs_the_deployments_commit_checked_out() {
        let deployment = deployment(Some("203.0.113.9"), Some("abc123"));
        assert!(verify_target(&deployment, Some("abc123")).is_ok());
        assert!(verify_target(&deployment, Some("ABC123")).is_ok());
        let error = verify_target(&deployment, Some("def456")).err().unwrap();
        assert!(error.to_string().starts_with(&format!(
            "This checkout is at def456, but deployment {DEPLOYMENT} was built from abc123. \
             Check out that commit and retry."
        )));
        // No rebuild from the checkout, or no recorded commit: nothing to compare.
        assert!(verify_target(&deployment, None).is_ok());
        assert!(
            verify_target(&self::deployment(Some("203.0.113.9"), None), Some("def456")).is_ok()
        );
    }

    #[test]
    fn extract_resource_id_from_git_url_parses_ssh_format() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let url = format!("git@codeberg.org:{}.git", uuid);
        assert_eq!(
            extract_resource_id_from_git_url(&url),
            Some(uuid.to_string())
        );
    }

    #[test]
    fn extract_resource_id_from_git_url_parses_ssh_with_port() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let url = format!("ssh://git@codeberg.org:23/{}.git", uuid);
        assert_eq!(
            extract_resource_id_from_git_url(&url),
            Some(uuid.to_string())
        );
    }

    #[test]
    fn extract_resource_id_from_git_url_rejects_unsupported_formats() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            extract_resource_id_from_git_url(&format!("https://codeberg.org/caution/{}.git", uuid)),
            None
        );
        assert_eq!(
            extract_resource_id_from_git_url(&format!("ssh://deploy@example.test/{}.git", uuid)),
            None
        );
        assert_eq!(
            extract_resource_id_from_git_url(&format!("ssh://git@example.test/apps/{}.git", uuid)),
            None
        );
    }

    #[test]
    fn extract_resource_id_from_git_url_rejects_non_uuid_paths() {
        assert_eq!(
            extract_resource_id_from_git_url("git@codeberg.org:user/repo.git"),
            None
        );
        assert_eq!(
            extract_resource_id_from_git_url("git@example.test:app.git"),
            None
        );
    }

    #[test]
    fn extract_resource_id_from_git_url_handles_missing_dot_git() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            extract_resource_id_from_git_url(&format!("git@codeberg.org:{}", uuid)),
            None
        );
    }

    /// Whether `request` holds the whole head and the body its head announces.
    fn request_complete(request: &[u8]) -> bool {
        let text = String::from_utf8_lossy(request);
        let Some((head, body)) = text.split_once("\r\n\r\n") else {
            return false;
        };
        let length = head
            .lines()
            .find_map(|line| {
                line.to_lowercase()
                    .strip_prefix("content-length:")
                    .map(|length| length.trim().parse::<usize>().unwrap_or(0))
            })
            .unwrap_or(0);
        body.len() >= length
    }

    /// Answers each request with `respond(method, path)` and records the raw requests.
    async fn serve(
        respond: impl Fn(&str, &str) -> (u16, String) + Send + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0_u8; 4096];
                    let read = socket.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if read == 0 || request_complete(&request) {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request).to_string();
                let mut line = request.split(' ');
                let (method, path) = (line.next().unwrap(), line.next().unwrap());
                let (status, body) = respond(method, path);
                seen.lock().unwrap().push(request.clone());
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (url, requests)
    }

    /// A logged-in client for the server at `url`, linked to `linked_app`.
    fn client(url: &str, dir: &Path, linked_app: Option<&str>) -> ApiClient {
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            serde_json::json!({
                "session_id": "test-session",
                "expires_at": "2099-01-01T00:00:00Z",
                "server_url": url,
            })
            .to_string(),
        )
        .unwrap();
        let deployment_path = linked_app.map(|app| {
            let path = dir.join("deployment.json");
            std::fs::write(&path, format!(r#"{{"resource_id":"{app}"}}"#)).unwrap();
            path
        });
        ApiClient {
            base_url: url.to_string(),
            client: reqwest::Client::new(),
            config_path,
            deployment_path,
            verbose: false,
            qr: false,
            workdir: None,
        }
    }

    /// The platform's answer for a deployment of `app`.
    fn view_json(id: &str, app: &str, role: &str) -> String {
        serde_json::json!({
            "id": id,
            "app_id": app,
            "role": role,
            "status": "running",
            "public_ip": "203.0.113.9",
            "created_at": "2026-10-12T00:00:00Z",
        })
        .to_string()
    }

    fn view_body() -> String {
        view_json(DEPLOYMENT, APP, "candidate")
    }

    fn request_lines(requests: &Mutex<Vec<String>>) -> Vec<String> {
        let requests = requests.lock().unwrap();
        requests
            .iter()
            .map(|request| request.lines().next().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn a_deployment_is_read_by_id_whatever_the_checkout_is_linked_to() {
        let dir = tempdir().unwrap();
        let (url, requests) = serve(|_, _| (200, view_body())).await;

        let unlinked = client(&url, dir.path(), None);
        let found = fetch_deployment(&unlinked, None, DEPLOYMENT, false)
            .await
            .unwrap();
        assert_eq!(found.app_id, APP);
        // Another app's checkout does not matter: the deployment names its app.
        let linked = client(&url, dir.path(), Some(OTHER_APP));
        let found = fetch_deployment(&linked, None, &DEPLOYMENT.to_uppercase(), false)
            .await
            .unwrap();
        assert_eq!(
            (found.id.as_str(), found.app_id.as_str()),
            (DEPLOYMENT, APP)
        );
        // An explicit app is checked against it.
        fetch_deployment(&linked, Some(APP.to_string()), DEPLOYMENT, false)
            .await
            .unwrap();
        let error = fetch_deployment(&linked, Some(OTHER_APP.to_string()), DEPLOYMENT, false)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().starts_with(&format!(
            "Deployment {DEPLOYMENT} belongs to app {APP}, not {OTHER_APP}. Pass the right app ID."
        )));

        assert_eq!(
            request_lines(&requests),
            vec![format!("GET /api/deployments/{DEPLOYMENT} HTTP/1.1"); 4]
        );
    }

    #[tokio::test]
    async fn a_ci_machine_reads_through_an_app_and_a_miss_names_it() {
        let dir = tempdir().unwrap();
        let (url, requests) =
            serve(|_, _| (404, r#"{"error":"Deployment not found."}"#.to_string())).await;

        // The explicit app, else the linked checkout's.
        let unlinked = client(&url, dir.path(), None);
        let linked = client(&url, dir.path(), Some(APP));
        for (client, app) in [(&unlinked, Some(APP.to_string())), (&linked, None)] {
            let error = fetch_deployment(client, app, DEPLOYMENT, true)
                .await
                .err()
                .unwrap();
            assert!(error.to_string().starts_with(&format!(
                "Deployment {DEPLOYMENT} was not found in app {APP}. Pass the right app ID."
            )));
        }
        // Without an app there is nothing to authorize the key against.
        let error = fetch_deployment(&unlinked, None, DEPLOYMENT, true)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().starts_with(
            "Pass the app ID or run from a linked checkout when using --this-is-a-ci-machine."
        ));
        assert_eq!(
            request_lines(&requests),
            vec![format!("GET /api/resources/{APP}/deployments/{DEPLOYMENT} HTTP/1.1"); 2]
        );
    }

    #[tokio::test]
    async fn read_failures_show_the_apis_error_text() {
        let dir = tempdir().unwrap();
        let (url, _) =
            serve(|_, _| (404, r#"{"error":"Deployment not found."}"#.to_string())).await;
        let client = client(&url, dir.path(), None);

        let error = fetch_deployment(&client, None, DEPLOYMENT, false)
            .await
            .err()
            .unwrap();
        let cause = error.source().unwrap().to_string();
        assert!(
            cause.contains("(status 404 Not Found): Deployment not found. ["),
            "{cause}"
        );
    }

    #[tokio::test]
    async fn deployment_ids_are_uuids_and_the_platform_cannot_rename_one() {
        let dir = tempdir().unwrap();
        let (url, requests) = serve(|_, path| match path {
            // Valid UUIDs the platform might substitute, and a path escape.
            p if p.ends_with(DEPLOYMENT) => (200, view_json(LIVE, APP, "candidate")),
            _ => (200, view_json("..", APP, "candidate")),
        })
        .await;
        let client = client(&url, dir.path(), None);

        for id in ["d2", "../x"] {
            assert!(
                fetch_deployment(&client, None, id, false).await.is_err(),
                "{id}"
            );
        }
        assert!(
            fetch_deployment(&client, Some("../x".to_string()), DEPLOYMENT, false)
                .await
                .is_err()
        );
        assert!(request_lines(&requests).is_empty());

        // A different valid UUID would file this deployment's trust under another's.
        let error = fetch_deployment(&client, None, DEPLOYMENT, false)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().starts_with(&format!(
            "The platform answered with deployment \"{LIVE}\" for {DEPLOYMENT}"
        )));
        // `..` would write the app's own trust file.
        let other = "990e8400-e29b-41d4-a716-446655440000";
        let error = fetch_deployment(&client, None, other, false)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().starts_with(&format!(
            "The platform answered with deployment \"..\" for {other}"
        )));
        assert!(
            prepare_deployment_verify(&client, DEPLOYMENT, false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verification_keeps_trust_under_the_requested_deployment() {
        let dir = tempdir().unwrap();
        let (url, _) = serve(|_, path| {
            let role = if path.ends_with("live") {
                "live"
            } else {
                "candidate"
            };
            (200, view_json(DEPLOYMENT, APP, role))
        })
        .await;
        let client = client(&url, dir.path(), None);

        let target = prepare_deployment_verify(&client, &DEPLOYMENT.to_uppercase(), false)
            .await
            .unwrap();
        assert_eq!(
            target.trust_path.to_str().unwrap(),
            format!(".caution/deployments/{DEPLOYMENT}/trusted_hashes.json")
        );
        assert_eq!(target.attestation_url, "http://203.0.113.9/attestation");
        assert!(target.candidate);
    }

    #[tokio::test]
    async fn switching_to_a_tls_after_switch_target_signs_the_acknowledgement() {
        let dir = tempdir().unwrap();
        let (url, requests) = serve(|method, path| match (method, path) {
            ("GET", p) if p.starts_with("/api/deployments/") => (
                200,
                serde_json::json!({
                    "id": DEPLOYMENT,
                    "app_id": APP,
                    "role": "candidate",
                    "status": "running",
                    "public_ip": "203.0.113.9",
                    "created_at": "2026-10-12T00:00:00Z",
                    "tls_after_switch": true,
                })
                .to_string(),
            ),
            ("GET", _) => (
                200,
                serde_json::json!({
                    "id": APP,
                    "state": "running",
                    "provider_resource_id": "i-0123",
                    "public_ip": "198.51.100.42",
                    "live_deployment_id": LIVE,
                })
                .to_string(),
            ),
            _ => (400, r#"{"error":"no authenticator in tests"}"#.to_string()),
        })
        .await;
        let client = client(&url, dir.path(), Some(OTHER_APP));

        switch(&client, None, DEPLOYMENT, true).await.unwrap_err();

        let challenge = requests.lock().unwrap()[2].clone();
        let body: serde_json::Value =
            serde_json::from_str(challenge.split_once("\r\n\r\n").unwrap().1).unwrap();
        let switch_body = serde_json::to_vec(&serde_json::json!({
            "expected_live_deployment_id": LIVE,
            "acknowledged_verification": true,
            "acknowledged_tls_pending": true,
        }))
        .unwrap();
        assert_eq!(body["body_hash"], hex::encode(Sha256::digest(&switch_body)));
    }

    #[tokio::test]
    async fn switching_asks_for_a_signature_over_the_fresh_live_expectation() {
        let dir = tempdir().unwrap();
        let (url, requests) = serve(|method, path| match (method, path) {
            ("GET", p) if p.starts_with("/api/deployments/") => (200, view_body()),
            ("GET", _) => (
                200,
                serde_json::json!({
                    "id": APP,
                    "state": "running",
                    "provider_resource_id": "i-0123",
                    "public_ip": "198.51.100.42",
                    "live_deployment_id": LIVE,
                })
                .to_string(),
            ),
            // The signature itself needs a security key: refuse the challenge.
            _ => (400, r#"{"error":"no authenticator in tests"}"#.to_string()),
        })
        .await;
        let client = client(&url, dir.path(), Some(OTHER_APP));

        let error = switch(&client, None, DEPLOYMENT, true).await.unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("failed to send the signed switch request")
        );

        assert_eq!(
            request_lines(&requests),
            [
                format!("GET /api/deployments/{DEPLOYMENT} HTTP/1.1"),
                format!("GET /api/resources/{APP} HTTP/1.1"),
                "POST /auth/sign-request HTTP/1.1".to_string(),
            ]
        );
        let challenge = requests.lock().unwrap()[2].clone();
        assert!(
            challenge
                .to_lowercase()
                .contains("x-session-id: test-session")
        );
        let body: serde_json::Value =
            serde_json::from_str(challenge.split_once("\r\n\r\n").unwrap().1).unwrap();
        // The `/api` prefix is stripped from the signed path, and the signed
        // body names the live deployment the app has now.
        let switch_body = serde_json::to_vec(&serde_json::json!({
            "expected_live_deployment_id": LIVE,
            "acknowledged_verification": true,
        }))
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "method": "POST",
                "path": format!("/resources/{APP}/deployments/{DEPLOYMENT}/switch"),
                "body_hash": hex::encode(Sha256::digest(&switch_body)),
            })
        );
    }

    #[tokio::test]
    async fn destroying_a_deployment_shows_the_apis_refusal() {
        let dir = tempdir().unwrap();
        let (url, requests) = serve(|method, _| match method {
            "GET" => (200, view_body()),
            _ => (
                409,
                r#"{"error":"The live deployment cannot be destroyed; switch to another deployment first."}"#
                    .to_string(),
            ),
        })
        .await;
        let client = client(&url, dir.path(), None);

        let error = destroy_deployment(&client, Some(APP.to_string()), DEPLOYMENT, true, false)
            .await
            .unwrap_err();
        assert!(error.to_string().starts_with(
            "failed to destroy deployment (status 409 Conflict): The live deployment cannot be destroyed; switch to another deployment first."
        ));
        assert_eq!(
            request_lines(&requests),
            [
                format!("GET /api/deployments/{DEPLOYMENT} HTTP/1.1"),
                format!("DELETE /api/resources/{APP}/deployments/{DEPLOYMENT} HTTP/1.1"),
            ],
            "the deployment is read, then destroyed through its app"
        );
        assert!(
            requests.lock().unwrap()[1]
                .to_lowercase()
                .contains("x-session-id: test-session")
        );
    }

    #[tokio::test]
    async fn destroying_a_deployment_succeeds_on_no_content() {
        let dir = tempdir().unwrap();
        let (url, requests) = serve(|method, _| match method {
            "GET" => (200, view_body()),
            _ => (204, String::new()),
        })
        .await;
        // The checkout's link to another app does not stop it.
        let client = client(&url, dir.path(), Some(OTHER_APP));

        destroy_deployment(&client, None, DEPLOYMENT, true, false)
            .await
            .unwrap();
        assert_eq!(request_lines(&requests).len(), 2);
    }
}
