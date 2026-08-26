// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{Engine as _, engine::general_purpose};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sha2::{Digest, Sha256};

use crate::{ApiClient, output, prompt};

#[derive(Debug, thiserror::Error, CtxError)]
pub enum FetchExistingSshKeysError {
    /// `get_protected_json` still returns an anyhow error boundary; its context text ("Failed to fetch existing SSH keys") is preserved on the chain.
    #[error("Failed to fetch existing SSH keys [{location:?}]")]
    GetProtectedJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API response did not contain an array of keys.
    #[error("Invalid response format [{location:?}]")]
    InvalidResponseFormat {
        #[location]
        location: Location,
    },
}

/// Fetch existing SSH keys for a session from the API.
async fn fetch_existing_ssh_keys(
    client: &ApiClient,
    session_id: &str,
) -> Result<Vec<(String, String)>, FetchExistingSshKeysError> {
    use FetchExistingSshKeysErrorCtx as Ctx;

    let response_data: serde_json::Value = client
        .get_protected_json(session_id, "/ssh-keys", "Failed to fetch existing SSH keys")
        .await
        .with_context(Ctx::get_protected_json())?;

    let Some(keys) = response_data["keys"].as_array() else {
        return Err(FetchExistingSshKeysError::InvalidResponseFormat {
            location: std::panic::Location::caller(),
        });
    };

    Ok(keys
        .iter()
        .filter_map(|key| {
            let name = key["name"].as_str()?.to_string();
            let public_key = key["public_key"].as_str()?.to_string();
            Some((name, public_key))
        })
        .collect())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum AddSingleKeyError {
    /// An SSH-signed (or plain fallback) POST while registering the key failed; `signed_post` still returns errors from its legacy boundary.
    #[error("Failed to submit key [{location:?}]")]
    SubmitKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API rejected the key as a duplicate.
    #[error("Key already exists [{location:?}]")]
    KeyAlreadyExists {
        #[location]
        location: Location,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("{api_response} [{location:?}]")]
    ServerResponse {
        api_response: String,

        #[location]
        location: Location,
    },
}

/// Send a single key to the API for registration.
async fn add_single_key(
    client: &ApiClient,
    session_id: &str,
    name: &str,
    key: &str,
) -> Result<(), AddSingleKeyError> {
    use AddSingleKeyErrorCtx as Ctx;

    let body = serde_json::json!({ "name": name, "public_key": key });

    let response = client
        .signed_post(session_id, "/ssh-keys", &body)
        .await
        .with_context(Ctx::submit_key())?;

    if !response.status().is_success() {
        let error = client.api_error_message(response).await;
        if error.contains("insert SSH key")
            || error.contains("duplicate")
            || error.contains("23505")
        {
            return Err(AddSingleKeyError::KeyAlreadyExists {
                location: std::panic::Location::caller(),
            });
        }
        return Err(AddSingleKeyError::ServerResponse {
            api_response: error,
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum SshKeysAddError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The initial fetch of existing SSH keys for duplicate checking failed.
    #[error("Failed to fetch existing SSH keys [{location:?}]")]
    FetchExistingSshKeys {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// `ssh-add -L` reported no loaded keys.
    #[error("No keys found in ssh-agent. Run 'ssh-add' first. [{location:?}]")]
    NoAgentKeys {
        #[location]
        location: Location,
    },

    /// Prompt label from the failing `prompt::text` call site.
    #[error("failed to read input '{prompt_label}' [{location:?}]")]
    PromptInput {
        #[context(borrow = str)]
        prompt_label: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The selected agent-key index was out of range or unparsable.
    #[error("Invalid number, please select a number between 1 and {key_count} [{location:?}]")]
    InvalidAgentSelection {
        key_count: usize,

        #[location]
        location: Location,
    },

    /// A local duplicate check found the key already registered under another name.
    #[error("This SSH key is already added as '{existing_key_name}'. [{location:?}]")]
    KeyAlreadyAdded {
        existing_key_name: String,

        #[location]
        location: Location,
    },

    /// The supplied or read public key does not look like an OpenSSH formatted key.
    #[error("Invalid SSH key format [{location:?}]")]
    InvalidKeyFormat {
        #[location]
        location: Location,
    },

    /// The public key file could not be read.
    #[error("Failed to read SSH key file [{location:?}]")]
    KeyFileRead {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// Registering the key with the API failed.
    #[error("Failed to add SSH key [{location:?}]")]
    AddSingleKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// No way was provided to supply a key.
    #[error("Provide a key file, --key, or --from-agent [{location:?}]")]
    MissingKeySource {
        #[location]
        location: Location,
    },
}

/// Add an SSH public key to the account.
pub async fn add(
    client: &ApiClient,
    key_file: Option<PathBuf>,
    from_agent: bool,
    key: Option<String>,
    name: Option<String>,
) -> Result<(), SshKeysAddError> {
    use SshKeysAddErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    // Fetch existing keys to check for duplicates
    let existing_keys = fetch_existing_ssh_keys(client, &config.session_id)
        .await
        .with_context(Ctx::fetch_existing_ssh_keys())?;

    if from_agent {
        let keys = get_ssh_agent_keys();
        if keys.is_empty() {
            return Err(SshKeysAddError::NoAgentKeys {
                location: std::panic::Location::caller(),
            });
        }

        let index = if keys.len() > 1 {
            for (i, (k, comment)) in keys.iter().enumerate() {
                let key_name = name.clone().unwrap_or_else(|| comment.clone());
                let fingerprint = ssh_fingerprint(k);
                output::status(format!("{}. [{}], [{}]", i + 1, key_name, fingerprint));
            }

            let selection_label = format!("Which key would you like to add? (1-{}): ", keys.len());
            let selection = prompt::text(&selection_label)
                .with_context(Ctx::prompt_input(selection_label.as_str()))?;

            match selection.parse::<usize>() {
                Ok(n) if n >= 1 && n <= keys.len() => n - 1,
                _ => {
                    return Err(SshKeysAddError::InvalidAgentSelection {
                        key_count: keys.len(),
                        location: std::panic::Location::caller(),
                    });
                }
            }
        } else {
            let (k, comment) = &keys[0];
            let key_name = name.clone().unwrap_or(comment.clone());
            let fingerprint = ssh_fingerprint(k);
            output::status(format!("Adding SSH key: {} ({})", key_name, fingerprint));
            0
        };

        let (k, comment) = &keys[index];
        let fingerprint = ssh_fingerprint(k);
        let key_name = name.clone().unwrap_or(comment.clone());

        // Check for duplicate before adding
        if let Some(new_identity) = ApiClient::ssh_key_identity(k) {
            for (existing_name, existing_key) in &existing_keys {
                if let Some(existing_identity) = ApiClient::ssh_key_identity(existing_key)
                    && new_identity == existing_identity
                {
                    return Err(SshKeysAddError::KeyAlreadyAdded {
                        existing_key_name: existing_name.clone(),
                        location: std::panic::Location::caller(),
                    });
                }
            }
        }

        add_single_key(client, &config.session_id, &key_name, k)
            .await
            .with_context(Ctx::add_single_key())?;
        output::success(format!("Added SSH key: [{}] [{}]", key_name, fingerprint));
    } else if let Some(key_str) = key {
        let key_content = key_str.trim();
        if !key_content.starts_with("ssh-") {
            return Err(SshKeysAddError::InvalidKeyFormat {
                location: std::panic::Location::caller(),
            });
        }
        let key_name = name.unwrap_or_else(|| "key".to_string());

        // Check for duplicate before adding
        if let Some(new_identity) = ApiClient::ssh_key_identity(key_content) {
            for (existing_name, existing_key) in &existing_keys {
                if let Some(existing_identity) = ApiClient::ssh_key_identity(existing_key)
                    && new_identity == existing_identity
                {
                    return Err(SshKeysAddError::KeyAlreadyAdded {
                        existing_key_name: existing_name.clone(),
                        location: std::panic::Location::caller(),
                    });
                }
            }
        }

        add_single_key(client, &config.session_id, &key_name, key_content)
            .await
            .with_context(Ctx::add_single_key())?;
        output::success(format!("Added: {}", key_name));
        output::status(format!("  {}", key_content));
    } else if let Some(path) = key_file {
        let key_content = fs::read_to_string(&path)
            .with_context(Ctx::key_file_read(Path::new(&path)))?
            .trim()
            .to_string();

        if !key_content.starts_with("ssh-") {
            return Err(SshKeysAddError::InvalidKeyFormat {
                location: std::panic::Location::caller(),
            });
        }

        let key_name = name.unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("key")
                .to_string()
        });

        // Check for duplicate before adding
        if let Some(new_identity) = ApiClient::ssh_key_identity(&key_content) {
            for (existing_name, existing_key) in &existing_keys {
                if let Some(existing_identity) = ApiClient::ssh_key_identity(existing_key)
                    && new_identity == existing_identity
                {
                    return Err(SshKeysAddError::KeyAlreadyAdded {
                        existing_key_name: existing_name.clone(),
                        location: std::panic::Location::caller(),
                    });
                }
            }
        }

        add_single_key(client, &config.session_id, &key_name, &key_content)
            .await
            .with_context(Ctx::add_single_key())?;
        output::success(format!("Added: {}", key_name));
        output::status(format!("  {}", key_content));
    } else {
        return Err(SshKeysAddError::MissingKeySource {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum SshKeysRemoveError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The HTTP delete request for the key failed.
    #[error("HTTP request failed [{location:?}]")]
    Http {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("Failed to remove key: {api_response} [{location:?}]")]
    ServerResponseFailure {
        api_response: String,

        #[location]
        location: Location,
    },
}

/// Remove an SSH key by fingerprint.
pub async fn remove(client: &ApiClient, fingerprint: &str) -> Result<(), SshKeysRemoveError> {
    use SshKeysRemoveErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    // Note: This is a DELETE mutation. get_protected_json only handles GETs.
    // Username claim gate check relies on the server returning username_required error
    // which we don't handle here - mutations would need a separate delete_protected helper.
    let response = client
        .client
        .delete(format!("{}/ssh-keys/{}", client.base_url, fingerprint))
        .header("X-Session-ID", config.session_id)
        .send()
        .await
        .with_context(Ctx::http())?;

    if !response.status().is_success() {
        let error = client.api_error_message(response).await;
        return Err(SshKeysRemoveError::ServerResponseFailure {
            api_response: error,
            location: std::panic::Location::caller(),
        });
    }

    output::success("Key removed.");
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum SshKeysListError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// `get_protected_json` still returns an anyhow error boundary; its context text ("Failed to list SSH keys") is preserved on the chain.
    #[error("Failed to list SSH keys [{location:?}]")]
    ListSshKeys {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API response did not contain an array of keys.
    #[error("Invalid response format [{location:?}]")]
    InvalidResponseFormat {
        #[location]
        location: Location,
    },
}

/// List all SSH keys.
pub async fn list(client: &ApiClient) -> Result<(), SshKeysListError> {
    use SshKeysListErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let response_data: serde_json::Value = client
        .get_protected_json(&config.session_id, "/ssh-keys", "Failed to list SSH keys")
        .await
        .with_context(Ctx::list_ssh_keys())?;

    let Some(keys) = response_data["keys"].as_array() else {
        return Err(SshKeysListError::InvalidResponseFormat {
            location: std::panic::Location::caller(),
        });
    };

    if keys.is_empty() {
        output::status("No SSH keys found. Add one with 'caution ssh-keys add'");
    } else {
        output::data_header("SSH Keys:");
        for key in keys {
            let name = key["name"].as_str().unwrap_or("untitled");
            let public_key = key["public_key"].as_str().unwrap_or("");
            let fingerprint = ssh_fingerprint(public_key);
            output::status(format!("  {} ({})", name, fingerprint));
        }
    }
    Ok(())
}

/// Read the keys currently loaded into `ssh-agent` via `ssh-add -L`.
fn get_ssh_agent_keys() -> Vec<(String, String)> {
    let output = Command::new("ssh-add").arg("-L").output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|line| line.starts_with("ssh-"))
            .map(|line| {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                let comment = parts.get(2).unwrap_or(&"unnamed").to_string();
                (line.to_string(), comment)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Compute a display fingerprint for an SSH public key, or "unknown" if unparsable.
fn ssh_fingerprint(key: &str) -> String {
    let parts: Vec<&str> = key.split_whitespace().collect();
    parts
        .get(1)
        .and_then(|key_data| general_purpose::STANDARD.decode(key_data).ok())
        .map(|decoded| {
            format!(
                "SHA256:{}",
                general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&decoded))
            )
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_BARE: &str = "ssh-ed25519 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEY_WITH_COMMENT: &str =
        "ssh-ed25519 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= my laptop";
    // SHA-256 of the decoded key data, base64-encoded without padding.
    const EXPECTED_KEY_FINGERPRINT: &str = "SHA256:Yw3NKWbEM2aRElRIu7JbT/QSpJxzLbLIq8G4WBvXEN0";

    #[test]
    fn fingerprint_ignores_comment_and_is_stable() {
        assert_eq!(ssh_fingerprint(KEY_WITH_COMMENT), EXPECTED_KEY_FINGERPRINT);
        assert_eq!(ssh_fingerprint(KEY_BARE), EXPECTED_KEY_FINGERPRINT);
    }

    #[test]
    fn fingerprint_rejects_unparsable_input() {
        assert_eq!(ssh_fingerprint(""), "unknown");
        // Type only, no base64 payload.
        assert_eq!(ssh_fingerprint("ssh-ed25519"), "unknown");
        // Payload present but not decodable as standard base64.
        assert_eq!(
            ssh_fingerprint("ssh-ed25519 !!!not-base64!!! comment"),
            "unknown"
        );
    }
}
