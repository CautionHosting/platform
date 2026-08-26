// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::Deserialize;

use crate::{
    ApiClient, PGP_KEY_NAME_MAX_CHARS, PGP_PUBLIC_KEY_MAX_BYTES, output,
    prepare_pgp_public_key_for_upload,
};

#[derive(Deserialize)]
struct AddPgpKeyResponse {
    fingerprint: String,
}

#[derive(Deserialize)]
struct PgpKeyInfo {
    id: uuid::Uuid,
    fingerprint: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct ListPgpKeysResponse {
    keys: Vec<PgpKeyInfo>,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum FetchPgpKeysError {
    /// `get_protected_json` still returns an anyhow error boundary; its context text ("Failed to fetch PGP public keys") is preserved on the chain.
    #[error("Failed to fetch PGP public keys [{location:?}]")]
    GetProtectedJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Fetch active PGP public keys for a session from the API.
async fn fetch_pgp_keys(
    client: &ApiClient,
    session_id: &str,
) -> Result<Vec<PgpKeyInfo>, FetchPgpKeysError> {
    use FetchPgpKeysErrorCtx as Ctx;

    let response: ListPgpKeysResponse = client
        .get_protected_json(session_id, "/pgp-keys", "Failed to fetch PGP public keys")
        .await
        .with_context(Ctx::get_protected_json())?;
    Ok(response.keys)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum PgpKeysAddError {
    /// The public key file could not be opened.
    #[error("Failed to open PGP public key file: {key_file} [{location:?}]")]
    KeyFileOpen {
        #[context(borrow = Path)]
        key_file: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The public key file could not be read.
    #[error("Failed to read PGP public key file: {key_file} [{location:?}]")]
    KeyFileRead {
        #[context(borrow = Path)]
        key_file: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The public key file exceeds the size limit. Replays the constant value at construction so text and bound cannot drift apart.
    #[error("PGP public key is too large (maximum {max_bytes} bytes) [{location:?}]")]
    KeyTooLarge {
        max_bytes: usize,

        #[location]
        location: Location,
    },

    /// The public key file does not contain UTF-8 armored text.
    #[error("PGP public key file must contain UTF-8 armored text [{location:?}]")]
    KeyNotUtf8 {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// `prepare_pgp_public_key_for_upload` still returns an anyhow error boundary; its validation contexts are preserved on the chain.
    #[error("Failed to prepare PGP public key [{location:?}]")]
    UploadPreparation {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The derived or supplied name exceeds the length limit. Replays the constant value at construction so text and bound cannot drift apart.
    #[error("PGP key name must be at most {max_chars} characters [{location:?}]")]
    NameTooLong {
        max_chars: usize,

        #[location]
        location: Location,
    },

    /// The derived or supplied name contains control characters.
    #[error("PGP key name cannot contain control characters [{location:?}]")]
    NameControlChars {
        #[location]
        location: Location,
    },

    /// The trimmed name is empty.
    #[error("PGP key name cannot be empty [{location:?}]")]
    NameEmptyAfterTrim {
        #[location]
        location: Location,
    },

    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The fetch of existing keys for duplicate checking failed; wraps the module-private helper's typed error.
    #[error("Failed to fetch PGP public keys [{location:?}]")]
    FetchPgpKeys {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// A key with the same fingerprint is already registered to the account.
    #[error("This PGP public key is already registered to your account [{location:?}]")]
    AlreadyRegistered {
        #[location]
        location: Location,
    },

    /// An HTTP request for the add-key flow failed; `signed_post` still returns errors from its legacy boundary.
    #[error("Failed to submit PGP public key [{location:?}]")]
    SubmitKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("Failed to add PGP public key: {api_response} [{location:?}]")]
    ServerResponseFailure {
        api_response: String,

        #[location]
        location: Location,
    },

    /// The API success response did not decode into the add-key shape.
    #[error("Failed to parse add PGP public key response [{location:?}]")]
    ParseAddResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Add an armored OpenPGP public key from a file.
pub async fn add(
    client: &ApiClient,
    key_file: PathBuf,
    name: Option<String>,
) -> Result<(), PgpKeysAddError> {
    use PgpKeysAddErrorCtx as Ctx;

    let key_file_handle =
        fs::File::open(&key_file).with_context(Ctx::key_file_open(Path::new(&key_file)))?;
    let mut key_bytes = Vec::new();
    key_file_handle
        .take((PGP_PUBLIC_KEY_MAX_BYTES + 1) as u64)
        .read_to_end(&mut key_bytes)
        .with_context(Ctx::key_file_read(Path::new(&key_file)))?;
    if key_bytes.len() > PGP_PUBLIC_KEY_MAX_BYTES {
        return Err(PgpKeysAddError::KeyTooLarge {
            max_bytes: PGP_PUBLIC_KEY_MAX_BYTES,
            location: std::panic::Location::caller(),
        });
    }
    let key_text = String::from_utf8(key_bytes).with_context(Ctx::key_not_utf8())?;
    let (public_key, fingerprint) =
        prepare_pgp_public_key_for_upload(&key_text).with_context(Ctx::upload_preparation())?;

    let name = name.unwrap_or_else(|| {
        key_file
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("PGP key")
            .to_string()
    });
    if name.chars().count() > PGP_KEY_NAME_MAX_CHARS {
        return Err(PgpKeysAddError::NameTooLong {
            max_chars: PGP_KEY_NAME_MAX_CHARS,
            location: std::panic::Location::caller(),
        });
    }
    if name.chars().any(char::is_control) {
        return Err(PgpKeysAddError::NameControlChars {
            location: std::panic::Location::caller(),
        });
    }
    let name = name.trim();
    if name.is_empty() {
        return Err(PgpKeysAddError::NameEmptyAfterTrim {
            location: std::panic::Location::caller(),
        });
    }

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;
    let existing_keys = fetch_pgp_keys(client, &config.session_id)
        .await
        .with_context(Ctx::fetch_pgp_keys())?;
    if existing_keys
        .iter()
        .any(|key| key.fingerprint == fingerprint)
    {
        return Err(PgpKeysAddError::AlreadyRegistered {
            location: std::panic::Location::caller(),
        });
    }

    let body = serde_json::json!({
        "public_key": public_key,
        "name": name,
    });
    let response = client
        .signed_post(&config.session_id, "/pgp-keys", &body)
        .await
        .with_context(Ctx::submit_key())?;

    if !response.status().is_success() {
        let error = client.api_error_message(response).await;
        return Err(PgpKeysAddError::ServerResponseFailure {
            api_response: error,
            location: std::panic::Location::caller(),
        });
    }

    let added: AddPgpKeyResponse = response
        .json()
        .await
        .with_context(Ctx::parse_add_response())?;
    output::success(format!("Added PGP key: {} ({})", name, added.fingerprint));
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum PgpKeysListError {
    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The fetch of active keys for the listing failed; wraps the module-private helper's typed error.
    #[error("Failed to fetch PGP public keys [{location:?}]")]
    FetchPgpKeys {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// List all active OpenPGP public keys.
pub async fn list(client: &ApiClient) -> Result<(), PgpKeysListError> {
    use PgpKeysListErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;
    let keys = fetch_pgp_keys(client, &config.session_id)
        .await
        .with_context(Ctx::fetch_pgp_keys())?;

    if keys.is_empty() {
        output::status("No PGP keys found. Add one with 'caution pgp-keys add <key-file>'");
        return Ok(());
    }

    output::data_header("PGP Keys:");
    for key in keys {
        output::status(format!(
            "  {} ({})",
            key.name.as_deref().unwrap_or("untitled"),
            key.fingerprint
        ));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum PgpKeysRemoveError {
    /// The fingerprint argument is not 40 or 64 hexadecimal characters once whitespace and case are normalized.
    #[error("PGP key fingerprint must contain 40 or 64 hexadecimal characters [{location:?}]")]
    FingerprintInvalid {
        #[location]
        location: Location,
    },

    /// `ensure_authenticated` still returns an anyhow error boundary; the source is boxed until that method converts.
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The fetch of active keys for the lookup failed; wraps the module-private helper's typed error.
    #[error("Failed to fetch PGP public keys [{location:?}]")]
    FetchPgpKeys {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// No active key matches the normalized fingerprint; the matched lookup value is captured for diagnosis.
    #[error("No active PGP public key matches fingerprint {key_fingerprint} [{location:?}]")]
    KeyNotFound {
        key_fingerprint: String,

        #[location]
        location: Location,
    },

    /// The HTTP delete request for the key failed; `signed_delete` still returns errors from its legacy boundary.
    #[error("HTTP request failed [{location:?}]")]
    Http {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    /// The API returned a non-success response; the text is what `api_error_message` extracted from it.
    #[error("Failed to remove PGP public key: {api_response} [{location:?}]")]
    ServerResponseFailure {
        api_response: String,

        #[location]
        location: Location,
    },
}

/// Remove an active OpenPGP public key by its fingerprint.
pub async fn remove(client: &ApiClient, fingerprint: &str) -> Result<(), PgpKeysRemoveError> {
    use PgpKeysRemoveErrorCtx as Ctx;

    let normalized_fingerprint: String = fingerprint
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if !(matches!(normalized_fingerprint.len(), 40 | 64)
        && normalized_fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit()))
    {
        return Err(PgpKeysRemoveError::FingerprintInvalid {
            location: std::panic::Location::caller(),
        });
    }

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;
    let keys = fetch_pgp_keys(client, &config.session_id)
        .await
        .with_context(Ctx::fetch_pgp_keys())?;
    let Some(key) = keys.iter().find(|key| {
        key.fingerprint
            .eq_ignore_ascii_case(&normalized_fingerprint)
    }) else {
        return Err(PgpKeysRemoveError::KeyNotFound {
            key_fingerprint: normalized_fingerprint,
            location: std::panic::Location::caller(),
        });
    };

    let path = format!("/pgp-keys/{}", key.id);
    let response = client
        .signed_delete(&config.session_id, &path)
        .await
        .with_context(Ctx::http())?;
    if !response.status().is_success() {
        let error = client.api_error_message(response).await;
        return Err(PgpKeysRemoveError::ServerResponseFailure {
            api_response: error,
            location: std::panic::Location::caller(),
        });
    }

    output::success(format!("Removed PGP key: {}", key.fingerprint));
    Ok(())
}
