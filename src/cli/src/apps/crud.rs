// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::Path;

use dterror::{BoxError, CtxError, Location, ResultExt};

use crate::output;
use crate::output::{Spinner, SpinnerStyle};
use crate::prompt;
use crate::resolve_local_build_command_from_dir;
use crate::{ApiClient, App, CheckoutLink, CreateAppResponse};

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
                    ) {
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
        && let Some(enclave_config) = config.get("enclave_config") {
            if let Some(memory) = enclave_config.get("memory_mb").and_then(|v| v.as_u64()) {
                output::status(format!("  Memory: {} MB", memory));
            }
            if let Some(cpus) = enclave_config.get("cpus").and_then(|v| v.as_u64()) {
                output::status(format!("  CPUs: {}", cpus));
            }
            if let Some(debug) = enclave_config.get("debug").and_then(|v| v.as_bool())
                && debug {
                    output::status("  Debug Mode: enabled");
                }
            if let Some(ports) = enclave_config.get("ports").and_then(|v| v.as_array())
                && !ports.is_empty() {
                    let ports_str: Vec<String> = ports
                        .iter()
                        .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                        .collect();
                    output::status(format!("  Ports: {}", ports_str.join(", ")));
                }
            if let Some(http_port) = enclave_config.get("http_port").and_then(|v| v.as_u64())
                && http_port > 0 {
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
    use super::extract_resource_id_from_git_url;

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
}
