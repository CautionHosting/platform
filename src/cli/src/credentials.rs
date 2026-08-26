// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;

use dterror::{BoxError, CtxError, Location, ResultExt};

use crate::{ApiClient, CredentialPlatform, output, prompt};

const CREDENTIALS_API_PATH: &str = "/api/credentials";

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CredentialsAddError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// Prompt label from the failing `prompt::*` call site.
    #[error("failed to read credential input '{prompt_label}' [{location:?}]")]
    PromptInput {
        #[context(borrow = str)]
        prompt_label: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The GCP service account key file could not be read.
    #[error("Failed to read service account key file [{location:?}]")]
    GcpKeyFileRead {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The GCP service account key file content is not valid JSON.
    #[error("Invalid JSON in service account key file [{location:?}]")]
    GcpKeyFileBadJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The baremetal SSH private key file could not be read.
    #[error("Failed to read SSH key from {key_path} [{location:?}]")]
    SshKeyRead {
        #[context(borrow = str)]
        key_path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// An HTTP request for the add-credential flow failed.
    #[error("HTTP request failed [{location:?}]")]
    Http {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("Failed to add credential: {api_response} [{location:?}]")]
    ServerResponseFailure {
        api_response: String,

        #[location]
        location: Location,
    },
}

/// Add cloud credentials for a platform.
pub async fn add(
    client: &ApiClient,
    platform: CredentialPlatform,
    name: String,
    is_default: bool,
    region: Option<String>,
) -> Result<(), CredentialsAddError> {
    use CredentialsAddErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let request_body = match platform {
        CredentialPlatform::Aws => {
            output::status(format!("Adding AWS credentials for '{}'", name));
            let access_key_id = prompt::text("AWS Access Key ID: ")
                .with_context(Ctx::prompt_input("AWS Access Key ID"))?;

            let secret_access_key = prompt::password("AWS Secret Access Key: ")
                .with_context(Ctx::prompt_input("AWS Secret Access Key"))?;

            serde_json::json!({
                "platform": "aws",
                "name": name,
                "access_key_id": access_key_id,
                "secret_access_key": secret_access_key,
                "default_region": region,
                "is_default": is_default
            })
        }
        CredentialPlatform::Digitalocean
        | CredentialPlatform::Hetzner
        | CredentialPlatform::Linode
        | CredentialPlatform::Vultr
        | CredentialPlatform::Ovh => {
            output::status(format!("Adding {} credentials for '{}'", platform, name));
            let api_token =
                prompt::password("API Token: ").with_context(Ctx::prompt_input("API token"))?;

            serde_json::json!({
                "platform": platform.to_string(),
                "name": name,
                "api_token": api_token,
                "default_region": region,
                "is_default": is_default
            })
        }
        CredentialPlatform::Gcp => {
            output::status(format!("Adding GCP credentials for '{}'", name));
            let email = prompt::text("Service Account Email: ")
                .with_context(Ctx::prompt_input("service account email"))?;

            let key_path = prompt::text("Path to service account JSON key file: ")
                .with_context(Ctx::prompt_input("path to service account JSON key file"))?;

            let key_content =
                fs::read_to_string(&key_path).with_context(Ctx::gcp_key_file_read())?;
            let key_json: serde_json::Value =
                serde_json::from_str(&key_content).with_context(Ctx::gcp_key_file_bad_json())?;

            serde_json::json!({
                "platform": "gcp",
                "name": name,
                "service_account_email": email,
                "service_account_key": key_json,
                "default_region": region,
                "is_default": is_default
            })
        }
        CredentialPlatform::Azure => {
            output::status(format!("Adding Azure credentials for '{}'", name));
            let tenant_id =
                prompt::text("Tenant ID: ").with_context(Ctx::prompt_input("tenant id"))?;

            let client_id =
                prompt::text("Client ID: ").with_context(Ctx::prompt_input("client id"))?;

            let client_secret = prompt::password("Client Secret: ")
                .with_context(Ctx::prompt_input("client secret"))?;

            let subscription_id = prompt::text("Subscription ID: ")
                .with_context(Ctx::prompt_input("subscription id"))?;

            serde_json::json!({
                "platform": "azure",
                "name": name,
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
                "subscription_id": subscription_id,
                "default_region": region,
                "is_default": is_default
            })
        }
        CredentialPlatform::Baremetal => {
            output::status(format!("Adding bare metal credentials for '{}'", name));
            let host =
                prompt::text("Host address: ").with_context(Ctx::prompt_input("host address"))?;

            let port = prompt::text_or_default("SSH Port [22]: ", 22)
                .with_context(Ctx::prompt_input("ssh port"))?;

            let username =
                prompt::text("Username: ").with_context(Ctx::prompt_input("username"))?;

            let auth_type =
                prompt::text_or_default("Use SSH key (k) or password (p)? [k]: ", "k".to_string())
                    .with_context(Ctx::prompt_input("ssh authentication type"))?
                    .to_lowercase();

            let (ssh_private_key, ssh_password) = if auth_type == "p" {
                let password = prompt::password("SSH Password: ")
                    .with_context(Ctx::prompt_input("ssh password"))?;
                (None, Some(password))
            } else {
                let default_key_path = dirs::home_dir()
                    .map(|h| h.join(".ssh/id_ed25519"))
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "~/.ssh/id_ed25519".to_string());
                let key_path = prompt::text_or_default(
                    "Path to SSH private key [~/.ssh/id_ed25519]: ",
                    default_key_path,
                )
                .with_context(Ctx::prompt_input("path to ssh private key"))?;

                let key_content =
                    fs::read_to_string(&key_path).with_context(Ctx::ssh_key_read(&key_path))?;
                (Some(key_content), None)
            };

            serde_json::json!({
                "platform": "baremetal",
                "name": name,
                "host": host,
                "port": port,
                "username": username,
                "ssh_private_key": ssh_private_key,
                "ssh_password": ssh_password,
                "is_default": is_default
            })
        }
    };

    let response = client
        .client
        .post(format!("{}{}", client.base_url, CREDENTIALS_API_PATH))
        .header("X-Session-ID", &config.session_id)
        .json(&request_body)
        .send()
        .await
        .with_context(Ctx::http())?;

    if response.status().is_success() {
        let cred: serde_json::Value = response.json().await.with_context(Ctx::http())?;
        output::success(format!(
            "Credential '{}' added successfully (ID: {})",
            name, cred["id"]
        ));
        if is_default {
            output::status(format!("Set as default for {}", platform));
        }
        Ok(())
    } else {
        let error_text = client.api_error_message(response).await;
        Err(CredentialsAddError::ServerResponseFailure {
            api_response: error_text,
            location: std::panic::Location::caller(),
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CredentialsListError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// `get_protected_json` still returns an anyhow error boundary; its context text ("Failed to list credentials") is preserved on the chain.
    #[error("Failed to list credentials [{location:?}]")]
    ListCredentials {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// List cloud credentials.
pub async fn list(client: &ApiClient) -> Result<(), CredentialsListError> {
    use CredentialsListErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let credentials: Vec<serde_json::Value> = client
        .get_protected_json(
            &config.session_id,
            CREDENTIALS_API_PATH,
            "Failed to list credentials",
        )
        .await
        .with_context(Ctx::list_credentials())?;

    if credentials.is_empty() {
        output::status(
            "No cloud credentials found. Add one with 'caution credentials add <platform> <name>'",
        );
    } else {
        output::data_header("Cloud Credentials:");
        output::status("");
        for cred in credentials {
            let id = cred["id"].as_str().unwrap_or("unknown");
            let name = cred["name"].as_str().unwrap_or("untitled");
            let platform = cred["platform"].as_str().unwrap_or("unknown");
            let identifier = cred["identifier"].as_str().unwrap_or("");
            let is_default = cred["is_default"].as_bool().unwrap_or(false);
            let region = cred["default_region"].as_str();

            let default_marker = if is_default { " (default)" } else { "" };
            let region_str = region.map(|r| format!(" [{}]", r)).unwrap_or_default();

            output::status(format!(
                "  [{}] {} - {}{}{}",
                id, name, platform, default_marker, region_str
            ));
            output::status(format!("       Identifier: {}", identifier));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CredentialsRemoveError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The credential ID argument is not a valid UUID.
    #[error("Invalid credential ID '{credential_id}' must be a valid UUID [{location:?}]")]
    ParseCredentialId {
        #[context(borrow = str)]
        credential_id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// `get_protected_json` still returns an anyhow error boundary; its context text ("Failed to fetch credential") is preserved on the chain.
    #[error("Failed to fetch credential [{location:?}]")]
    FetchCredential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The confirmation prompt could not be read.
    #[error("could not confirm credential removal [{location:?}]")]
    ConfirmDeletion {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// An HTTP request for the remove-credential flow failed.
    #[error("HTTP request failed [{location:?}]")]
    Http {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("Failed to remove credential: {api_response} [{location:?}]")]
    ServerResponseFailure {
        api_response: String,

        #[location]
        location: Location,
    },
}

/// Remove a cloud credential, optionally skipping the confirmation prompt.
pub async fn remove(
    client: &ApiClient,
    id: &str,
    force: bool,
) -> Result<(), CredentialsRemoveError> {
    use CredentialsRemoveErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let credential_id = uuid::Uuid::parse_str(id).with_context(Ctx::parse_credential_id(id))?;

    let cred: serde_json::Value = client
        .get_protected_json(
            &config.session_id,
            &format!("{}/{}", CREDENTIALS_API_PATH, credential_id),
            "Failed to fetch credential",
        )
        .await
        .with_context(Ctx::fetch_credential())?;

    let name = cred["name"].as_str().unwrap_or("unknown");
    let platform = cred["platform"].as_str().unwrap_or("unknown");

    if !force {
        output::status("About to delete credential:");
        output::status(format!("  Name: {}", name));
        output::status(format!("  Platform: {}", platform));
        output::status("");
        let confirmed =
            prompt::confirm("Are you sure? [y/N] ").with_context(Ctx::confirm_deletion())?;
        if !confirmed {
            output::status("Aborted.");
            return Ok(());
        }
    }

    let response = client
        .client
        .delete(format!(
            "{}{}/{}",
            client.base_url, CREDENTIALS_API_PATH, credential_id
        ))
        .header("X-Session-ID", &config.session_id)
        .send()
        .await
        .with_context(Ctx::http())?;

    if response.status().is_success() {
        output::success(format!("Credential '{}' removed", name));
        Ok(())
    } else {
        let error = client.api_error_message(response).await;
        Err(CredentialsRemoveError::ServerResponseFailure {
            api_response: error,
            location: std::panic::Location::caller(),
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CredentialsSetDefaultError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The credential ID argument is not a valid UUID.
    #[error("Invalid credential ID '{credential_id}' must be a valid UUID [{location:?}]")]
    ParseCredentialId {
        #[context(borrow = str)]
        credential_id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// An HTTP request for the set-default flow failed.
    #[error("HTTP request failed [{location:?}]")]
    Http {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API reported a 404 for the credential.
    #[error("Credential '{credential_id}' not found [{location:?}]")]
    CredentialNotFound {
        credential_id: String,

        #[location]
        location: Location,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("Failed to set default: {api_response} [{location:?}]")]
    ServerResponseFailure {
        api_response: String,

        #[location]
        location: Location,
    },
}

/// Set a cloud credential as the default for its platform.
pub async fn set_default(client: &ApiClient, id: &str) -> Result<(), CredentialsSetDefaultError> {
    use CredentialsSetDefaultErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let credential_id = uuid::Uuid::parse_str(id).with_context(Ctx::parse_credential_id(id))?;

    let response = client
        .client
        .post(format!(
            "{}{}/{}/default",
            client.base_url, CREDENTIALS_API_PATH, credential_id
        ))
        .header("X-Session-ID", &config.session_id)
        .send()
        .await
        .with_context(Ctx::http())?;

    if response.status().is_success() {
        output::success("Credential set as default");
        Ok(())
    } else if response.status() == reqwest::StatusCode::NOT_FOUND {
        Err(CredentialsSetDefaultError::CredentialNotFound {
            credential_id: id.to_string(),
            location: std::panic::Location::caller(),
        })
    } else {
        let error = client.api_error_message(response).await;
        Err(CredentialsSetDefaultError::ServerResponseFailure {
            api_response: error,
            location: std::panic::Location::caller(),
        })
    }
}
