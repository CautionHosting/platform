// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! The `caution` auth domain: FIDO2/WebAuthn registration and login, QR
//! cross-device login/signing, session helpers, and the username-claim gate.
//! Extracted from the monolith; see also `secrets`, `verify`, `cache`,
//! `ssh_keys`, and `pgp_keys`.

use authenticator::{
    Pin, RegisterResult, SignResult, StatusPinUv, StatusUpdate,
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        PublicKeyCredentialUserEntity, RelyingParty, Transport,
    },
    errors::AuthenticatorError,
    statecallback::StateCallback,
};
use base64::{Engine as _, engine::general_purpose};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::ApiClient;
use crate::output;
use crate::output::{Spinner, SpinnerStyle};
use crate::prompt;

#[derive(Debug, thiserror::Error, CtxError)]
enum PromptForPinError {
    #[error("failed to read PIN [{location:?}]")]
    ReadPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn prompt_for_pin() -> Result<Option<String>, PromptForPinError> {
    use PromptForPinErrorCtx as Ctx;
    let pin = prompt::password("Enter your security key PIN (or press Enter if no PIN is set): ")
        .with_context(Ctx::read_pin())?;

    if pin.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(pin))
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PromptLineError {
    #[error("failed to read input from stdin [{location:?}]")]
    Io {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Prints `prompt`, reads a single non-empty trimmed line from stdin, and
/// keeps re-prompting with `retry_message` until the user provides one.
fn prompt_line(prompt: &str, retry_message: &str) -> Result<String, PromptLineError> {
    prompt_line_from(&mut io::stdin().lock(), prompt, retry_message)
}

/// Testable core of [`prompt_line`]: reads non-empty trimmed lines from any
/// `BufRead` instead of always going to real stdin.
fn prompt_line_from<R: std::io::BufRead>(
    reader: &mut R,
    prompt: &str,
    retry_message: &str,
) -> Result<String, PromptLineError> {
    use PromptLineErrorCtx as Ctx;

    loop {
        eprint!("{}", prompt);
        io::stderr().flush().with_context(Ctx::io())?;

        let mut input = String::new();
        let len = reader.read_line(&mut input).with_context(Ctx::io())?;
        if len == 0 {
            // EOF: nothing left to read, stop looping.
            return Ok(String::new());
        }
        let trimmed = input.trim();

        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }

        output::status(retry_message);
    }
}

/// Prompts for the username to log in with when `--username` was not passed.
/// Unlike [`prompt_for_claimed_username`], an empty line here is valid input
/// (not just EOF): leaving it blank opts into the discoverable/broadcast
/// login path for accounts that don't have a username yet.
const LOGIN_USERNAME_PROMPT: &str = "Username (leave blank if you don't have one): ";

#[derive(Debug, thiserror::Error, CtxError)]
enum LoginUsernameError {
    #[error(
        "Session expired and no username was provided. \
         Re-authenticate with `caution login --username <name>`."
    )]
    NonInteractive,
    #[error("failed to prompt for username [{location:?}]")]
    Prompt {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Resolves the username used for login. Returns the explicitly provided
/// username as-is; otherwise prompts (reading from `reader`) only when a human
/// terminal is attached. Non-interactive callers with no username — e.g. an
/// `ensure_authenticated` auto-relogin fired from a CI/cron invocation — get a
/// fail-fast error instead of a blocking stdin read that would hang forever.
fn resolve_login_username<R: std::io::BufRead>(
    provided: Option<String>,
    is_terminal: bool,
    reader: &mut R,
) -> Result<String, LoginUsernameError> {
    match provided {
        Some(username) => Ok(username),
        None if is_terminal => Ok(prompt_optional_line_from(reader, LOGIN_USERNAME_PROMPT)
            .with_context(LoginUsernameErrorCtx::prompt())?),
        None => Err(LoginUsernameError::NonInteractive),
    }
}

/// Reads a single trimmed line from `reader`, returning it as-is (including
/// empty). No retry loop: an empty line is a valid answer here.
fn prompt_optional_line_from<R: std::io::BufRead>(
    reader: &mut R,
    prompt: &str,
) -> Result<String, PromptLineError> {
    use PromptLineErrorCtx as Ctx;

    eprint!("{}", prompt);
    io::stderr().flush().with_context(Ctx::io())?;

    let mut input = String::new();
    reader.read_line(&mut input).with_context(Ctx::io())?;
    Ok(input.trim().to_string())
}

/// Prompts for a new username when claiming one is required post-login
/// (the `username_required` gate).
fn prompt_for_claimed_username() -> Result<String, PromptLineError> {
    prompt_line(
        "Choose a username: ",
        "Username cannot be empty, please try again.",
    )
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RegisterUsernameError {
    #[error(
        "No username was provided and stdin is not interactive. \
         Re-run with `caution register --username <name>`."
    )]
    NonInteractive,
    #[error("failed to prompt for a username [{location:?}]")]
    Prompt {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Resolves the username used for `register`. Returns the explicitly
/// provided username as-is (blank/whitespace-only treated as not provided);
/// otherwise prompts (reading from `reader`, re-prompting on empty input)
/// only when a human terminal is attached. Non-interactive callers with no
/// username get a fail-fast error instead of silently registering with an
/// empty username (mirrors `resolve_login_username`'s guard).
pub(crate) fn resolve_register_username<R: std::io::BufRead>(
    provided: Option<String>,
    is_terminal: bool,
    reader: &mut R,
) -> Result<String, RegisterUsernameError> {
    use RegisterUsernameErrorCtx as Ctx;

    match provided {
        Some(username) if !username.trim().is_empty() => Ok(username),
        _ if is_terminal => Ok(prompt_line_from(
            reader,
            "Choose a username: ",
            "Username cannot be empty, please try again.",
        )
        .with_context(Ctx::prompt())?),
        _ => Err(RegisterUsernameError::NonInteractive),
    }
}

/// Wrapper that zeroizes the PIN string on drop.
struct ZeroizePin(String);

impl Drop for ZeroizePin {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

fn is_pin_related_error(error: &dyn std::error::Error) -> bool {
    let error_msg = format!("{:?}", error).to_lowercase();
    error_msg.contains("pin")
        || error_msg.contains("pinuv")
        || error_msg.contains("pin required")
        || error_msg.contains("pin_required")
        || error_msg.contains("pin invalid")
        || error_msg.contains("pininvalid")
}

#[derive(Debug, thiserror::Error, CtxError)]
enum RenderQrCodeError {
    #[error("failed to generate QR code [{location:?}]")]
    Generate {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn render_qr_code(url: &str) -> Result<(), RenderQrCodeError> {
    use RenderQrCodeErrorCtx as Ctx;
    // When not attached to a terminal, skip QR art and print only the URL
    if !output::is_tty_stdout() {
        output::status(&format!("QR URL: {url}"));
        return Ok(());
    }

    use qrcode::{EcLevel, QrCode};

    let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::L)
        .with_context(Ctx::generate())?;
    let modules = code.to_colors();
    let width = code.width();
    let height = modules.len() / width;

    // Quiet zone: 1 module each side (minimal but sufficient for scanning)
    let quiet = 1;
    let total_width = width + quiet * 2;
    let total_height = height + quiet * 2;

    // Inverted rendering for dark terminal backgrounds:
    // dark module = space (blends with background), light module = █
    // Half-block chars pack 2 rows per terminal line
    let is_dark = |row: usize, col: usize| -> bool {
        if row < quiet || row >= quiet + height || col < quiet || col >= quiet + width {
            false
        } else {
            modules[(row - quiet) * width + (col - quiet)] == qrcode::types::Color::Dark
        }
    };

    let mut row = 0;
    while row < total_height {
        let mut line = String::new();
        for col in 0..total_width {
            let top = is_dark(row, col);
            let bottom = if row + 1 < total_height {
                is_dark(row + 1, col)
            } else {
                false
            };

            match (top, bottom) {
                (true, true) => line.push(' '),
                (true, false) => line.push('▄'),
                (false, true) => line.push('▀'),
                (false, false) => line.push('█'),
            }
        }
        println!("{}", line);
        row += 2;
    }

    Ok(())
}

#[derive(Deserialize)]
struct RegisterBeginResponse {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCredentialCreationOptions,
    session: String,
}

#[derive(Deserialize)]
struct RegisterFinishResponse {
    expires_at: String,
}

#[derive(Deserialize)]
struct PublicKeyCredentialCreationOptions {
    challenge: String,
    rp: RelyingPartyInfo,
    user: UserInfo,
    #[serde(rename = "pubKeyCredParams")]
    pub_key_cred_params: Vec<PubKeyCredParam>,
    timeout: u64,
}

#[derive(Deserialize)]
pub(crate) struct LoginBeginResponse {
    #[serde(rename = "publicKey")]
    pub(crate) public_key: PublicKeyCredentialRequestOptions,
    pub(crate) session: String,
}

/// JSON body for `POST /auth/login/begin`. The CLI drives USB security keys
/// directly (no conditional UI), so it always sends this field — but `username`
/// may be an empty string (the user left the login prompt blank), which the
/// server's `normalize_login_username` treats as absent, falling back to the
/// broadcast/discoverable no-username path rather than a scoped `allowCredentials`.
fn login_begin_request_body(username: &str) -> serde_json::Value {
    serde_json::json!({ "username": username })
}

#[derive(Deserialize)]
pub(crate) struct Fido2SignResponse {
    #[serde(rename = "publicKey")]
    pub(crate) public_key: PublicKeyCredentialRequestOptions,
    pub(crate) challenge_id: String,
}

#[derive(Deserialize)]
pub(crate) struct PublicKeyCredentialRequestOptions {
    challenge: String,
    #[serde(rename = "rpId")]
    rp_id: String,
    timeout: u64,
    #[serde(rename = "allowCredentials", default)]
    allow_credentials: Vec<AllowCredential>,
}

#[derive(Deserialize, Clone)]
struct AllowCredential {
    id: String,
}

#[derive(Deserialize)]
struct RelyingPartyInfo {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct UserInfo {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Deserialize)]
struct PubKeyCredParam {
    alg: i32,
}

#[derive(Deserialize)]
struct LoginFinishResponse {
    expires_at: String,
}

#[derive(Deserialize)]
struct QrLoginBeginResponse {
    token: String,
    url: String,
    #[allow(dead_code)]
    expires_at: String,
}

#[derive(Deserialize)]
struct QrLoginStatusResponse {
    status: String,
    session_id: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct QrSignBeginResponse {
    challenge_id: String,
    token: String,
    url: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct QrSignStatusResponse {
    status: String,
    fido2_response: Option<String>,
    challenge_id: Option<String>,
}

/// Extract session ID from Set-Cookie header
fn extract_session_from_cookies(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("caution_session="))
        .and_then(|cookie| {
            // Parse "caution_session=VALUE; path=/; ..."
            cookie
                .strip_prefix("caution_session=")
                .and_then(|rest| rest.split(';').next())
                .map(|s| s.to_string())
        })
}

#[derive(Deserialize)]
struct UserStatus {
    email_verified: bool,
    payment_method_added: bool,
    onboarding_complete: bool,
}

#[derive(Deserialize)]
struct OrgSettings {
    require_pin: bool,
}

#[derive(Deserialize)]
struct Organization {
    id: String,
}

pub(crate) struct AssertionResult {
    pub(crate) response_json: Vec<u8>,
}

/// Prompts for a username and claims it via `POST /user/username`
/// (a FIDO2-signed protected mutation), reprompting on 409 (taken).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ClaimUsernameError {
    #[error(
        "This account needs a username set before continuing, but stdin is not \
         interactive. Re-run this command from a terminal to choose one. [{location:?}]"
    )]
    NonInteractive {
        #[location]
        location: Location,
    },

    #[error("failed to prompt for a username [{location:?}]")]
    Prompt {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to submit username claim [{location:?}]")]
    SignedPost {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "Your account already has a username set: {message:?}. Re-run the command \
         that required a username. [{location:?}]"
    )]
    UsernameAlreadySet {
        message: String,

        #[location]
        location: Location,
    },

    #[error("Failed to claim username: {message} [{location:?}]")]
    Failed {
        message: String,

        #[location]
        location: Location,
    },
}

pub(crate) async fn claim_username_interactively(
    client: &ApiClient,
    session_id: &str,
) -> Result<(), ClaimUsernameError> {
    use ClaimUsernameErrorCtx as Ctx;

    // This prompts on stdin in a loop; without a terminal a non-interactive
    // caller (CI/cron reaching a placeholder account) would block forever on
    // the read, or hit EOF and spin on empty input. Fail fast instead — the
    // same guard `resolve_login_username` applies to the login prompt.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(ClaimUsernameError::NonInteractive {
            location: std::panic::Location::caller(),
        });
    }

    loop {
        let username = prompt_for_claimed_username().with_context(Ctx::prompt())?;
        let body = serde_json::json!({ "username": username });

        let response = client
            .signed_post(session_id, "/user/username", &body)
            .await
            .with_context(Ctx::signed_post())?;

        if response.status().is_success() {
            output::success(format!("Username '{}' claimed.", username));
            return Ok(());
        }

        if response.status() == reqwest::StatusCode::CONFLICT {
            let error = client.api_error_message(response).await;
            // The gateway returns 409 for two distinct cases with the
            // same status code: the chosen name is taken (retry with a
            // different name), or the account already has a real
            // username (e.g. a concurrent claim raced this one). Only
            // the former is worth re-prompting for; looping on the
            // latter would spin forever since no name would ever work.
            // Match on the handler's `#[error(...)]` Display text
            // (see UsernameClaimError in gateway/src/handlers.rs).
            if error.contains("already set your username") {
                return Err(ClaimUsernameError::UsernameAlreadySet {
                    message: error,
                    location: std::panic::Location::caller(),
                });
            }

            output::status(format!(
                "Username '{}' is already taken. Please choose another.",
                username
            ));
            continue;
        }

        // A 400 is a validation failure (too short/long, illegal chars):
        // user-fixable, so surface the server's message and reprompt rather
        // than aborting the whole command over a typo.
        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let error = client.api_error_message(response).await;
            output::status(error);
            continue;
        }

        let error = client.api_error_message(response).await;
        return Err(ClaimUsernameError::Failed {
            message: error,
            location: std::panic::Location::caller(),
        });
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RegisterError {
    #[error("failed to build HTTP client [{location:?}]")]
    BuildClient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to send registration begin request [{location:?}]")]
    SendBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read registration error body [{location:?}]")]
    ReadErrorBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Registration begin failed: {message} [{location:?}]")]
    BeginFailed {
        message: String,

        #[location]
        location: Location,
    },

    #[error("Failed to parse registration begin response [{location:?}]")]
    ParseBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create credential on security key [{location:?}]")]
    MakeCredential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to send registration finish request [{location:?}]")]
    SendFinish {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("No session cookie in response [{location:?}]")]
    NoSessionCookie {
        #[location]
        location: Location,
    },

    #[error("failed to parse registration finish response [{location:?}]")]
    ParseFinish {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to save config [{location:?}]")]
    SaveConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Registration failed: {message} [{location:?}]")]
    Failed {
        message: String,

        #[location]
        location: Location,
    },
}

pub(crate) async fn register(
    client: &ApiClient,
    alpha_code: &str,
    username: &str,
) -> Result<(), RegisterError> {
    use RegisterErrorCtx as Ctx;
    output::verbose(client.verbose, "Starting FIDO2 registration...");
    output::verbose(client.verbose, &format!("Target URL: {}", client.base_url));

    let cookie_store = reqwest::cookie::Jar::default();
    let client_local = reqwest::Client::builder()
        .cookie_provider(Arc::new(cookie_store))
        .build()
        .with_context(Ctx::build_client())?;

    output::verbose(
        client.verbose,
        "Sending registration begin request with alpha code...",
    );
    let response = client_local
        .post(format!("{}/auth/register/begin", client.base_url))
        .json(&serde_json::json!({ "alpha_code": alpha_code, "username": username }))
        .send()
        .await
        .with_context(Ctx::send_begin())?;

    output::verbose(
        client.verbose,
        &format!("Response status: {}", response.status()),
    );

    if !response.status().is_success() {
        let error = response.text().await.with_context(Ctx::read_error_body())?;
        return Err(RegisterError::BeginFailed {
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    let begin_resp: RegisterBeginResponse =
        response.json().await.with_context(Ctx::parse_begin())?;
    output::verbose(client.verbose, "Registration challenge received");
    output::verbose(
        client.verbose,
        &format!("Challenge: {}", begin_resp.public_key.challenge),
    );

    output::verbose(client.verbose, "Creating credential on security key...");

    let mut attestation = make_credential(client, &begin_resp, &client.base_url)
        .with_context(Ctx::make_credential())?;

    output::success("Credential created on device");

    if let Some(obj) = attestation.as_object_mut() {
        obj.insert("session".to_string(), serde_json::json!(begin_resp.session));
    }

    output::verbose(client.verbose, "Sending registration finish request...");
    let response = client_local
        .post(format!("{}/auth/register/finish", client.base_url))
        .json(&attestation)
        .send()
        .await
        .with_context(Ctx::send_finish())?;

    output::verbose(
        client.verbose,
        &format!("Response status: {}", response.status()),
    );

    if response.status().is_success() {
        // Extract session from Set-Cookie header (not response body)
        let session_id = extract_session_from_cookies(&response).ok_or_else(|| {
            RegisterError::NoSessionCookie {
                location: std::panic::Location::caller(),
            }
        })?;

        let finish_resp: RegisterFinishResponse =
            response.json().await.with_context(Ctx::parse_finish())?;

        output::success("FIDO2 registration successful");
        output::success(&format!(
            "Logged in. Account expires: {}",
            finish_resp.expires_at
        ));

        client
            .save_config(session_id.clone(), finish_resp.expires_at.clone())
            .with_context(Ctx::save_config())?;

        output::success("\nALPHA ACCESS GRANTED");
        output::status("You're registered as an alpha user. You can now:");
        output::status("  • Create apps with 'caution init'");
        output::status("  • Deploy with 'git push caution main'");
        output::status(&format!("Dashboard: {}/dashboard", client.frontend_url()));

        Ok(())
    } else {
        let error = response.text().await.with_context(Ctx::read_error_body())?;
        Err(RegisterError::Failed {
            message: error,
            location: std::panic::Location::caller(),
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoginError {
    #[error("failed to resolve login username [{location:?}]")]
    ResolveUsername {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to perform login [{location:?}]")]
    PerformLogin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn login(client: &ApiClient, username: Option<String>) -> Result<(), LoginError> {
    use LoginErrorCtx as Ctx;
    output::verbose(client.verbose, "Starting FIDO2 login...");

    let username = resolve_login_username(
        username,
        std::io::IsTerminal::is_terminal(&std::io::stdin()),
        &mut std::io::stdin().lock(),
    )
    .with_context(Ctx::resolve_username())?;

    let (session_id, _expires_at) = perform_login(client, &username)
        .await
        .with_context(Ctx::perform_login())?;
    output::success("Login successful");

    match check_onboarding_status(client, &session_id).await {
        Ok(status) => {
            if !status.onboarding_complete {
                output::warning("=======================================================");
                output::warning("COMPLETE YOUR ONBOARDING");
                output::warning("=======================================================");
                output::warning("You need to complete onboarding to use this service:");
                output::warning(format!(
                    "  1. Verify your email address {}",
                    if status.email_verified { "✓" } else { "✗" }
                ));
                output::warning(format!(
                    "  2. Add payment information {}",
                    if status.payment_method_added {
                        "✓"
                    } else {
                        "✗"
                    }
                ));
                output::warning("Onboarding URL:");
                output::warning(format!("  {}/onboarding", client.frontend_url()));
                output::warning("You must complete onboarding before you can create apps.");
                output::warning("=======================================================");
            }
        }
        Err(e) => {
            output::verbose(
                client.verbose,
                &format!("Could not check onboarding status: {}", e),
            );
        }
    }

    // Check if PIN requirement is disabled and warn the user
    match check_org_security_settings(client, &session_id).await {
        Ok(settings) => {
            if !settings.require_pin {
                output::warning("⚠️  WARNING: PIN verification is disabled for your organization.");
                output::warning("   For production use, enable PIN requirement.");
            }
        }
        Err(e) => {
            output::verbose(
                client.verbose,
                &format!("Could not check security settings: {}", e),
            );
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoginQrError {
    #[error("failed to request QR login token [{location:?}]")]
    SendBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read QR login error body [{location:?}]")]
    ReadErrorBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to start QR login: {message} [{location:?}]")]
    BeginFailed {
        message: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse QR login begin response [{location:?}]")]
    ParseBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to render QR code [{location:?}]")]
    RenderQr {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("QR login timed out. Please try again. [{location:?}]")]
    TimedOut {
        #[location]
        location: Location,
    },

    #[error("failed to poll QR login status [{location:?}]")]
    PollSend {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse QR login status response [{location:?}]")]
    PollParse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Completed but no session_id returned [{location:?}]")]
    MissingSessionId {
        #[location]
        location: Location,
    },

    #[error("Completed but no expires_at returned [{location:?}]")]
    MissingExpiresAt {
        #[location]
        location: Location,
    },

    #[error("failed to save config [{location:?}]")]
    SaveConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("QR login token expired. Please try again. [{location:?}]")]
    TokenExpired {
        #[location]
        location: Location,
    },
}

pub(crate) async fn login_qr(
    client: &ApiClient,
    username: Option<&str>,
) -> Result<(), LoginQrError> {
    use LoginQrErrorCtx as Ctx;
    output::verbose(client.verbose, "Starting QR code cross-device login...");

    // Step 1: Request a QR login token from the gateway. An optional
    // username scopes the eventual allowCredentials to that user's own
    // credentials, needed for non-resident/legacy keys the scanning
    // device can't otherwise offer via a discoverable challenge.
    let response = client
        .client
        .post(format!("{}/auth/qr-login/begin", client.base_url))
        .json(&serde_json::json!({ "username": username }))
        .send()
        .await
        .with_context(Ctx::send_begin())?;

    if !response.status().is_success() {
        let error = response.text().await.with_context(Ctx::read_error_body())?;
        return Err(LoginQrError::BeginFailed {
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    let begin_resp: QrLoginBeginResponse = response.json().await.with_context(Ctx::parse_begin())?;
    output::verbose(client.verbose, &format!("QR token: {}", begin_resp.token));
    output::verbose(client.verbose, &format!("QR URL: {}", begin_resp.url));

    // Step 2: Render the QR code in the terminal
    output::status("");
    render_qr_code(&begin_resp.url).with_context(Ctx::render_qr())?;
    output::status("");
    output::status("Scan the QR code with your phone, or open this URL:");
    output::status(&format!("  {}", begin_resp.url));

    // Step 3: Poll for completion
    let loader = Spinner::new("Waiting for authentication...", SpinnerStyle::Processing);

    let poll_result = async {
        let timeout = Duration::from_secs(180); // 3 minutes
        let start = std::time::Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed > timeout {
                return Err(LoginQrError::TimedOut {
                    location: std::panic::Location::caller(),
                });
            }

            let remaining = timeout.saturating_sub(elapsed).as_secs();
            loader.set_message(&format!(
                "Waiting for authentication... QR code expires in {}:{:02}",
                remaining / 60,
                remaining % 60
            ));

            tokio::time::sleep(Duration::from_secs(2)).await;

            let status_resp = client
                .client
                .get(format!("{}/auth/qr-login/status", client.base_url))
                .query(&[("token", &begin_resp.token)])
                .send()
                .await
                .with_context(Ctx::poll_send())?;

            if !status_resp.status().is_success() {
                output::verbose(client.verbose, "Status poll failed, retrying...");
                continue;
            }

            let status: QrLoginStatusResponse =
                status_resp.json().await.with_context(Ctx::poll_parse())?;
            output::verbose(client.verbose, &format!("Poll status: {}", status.status));

            match status.status.as_str() {
                "completed" => {
                    let session_id =
                        status
                            .session_id
                            .ok_or_else(|| LoginQrError::MissingSessionId {
                                location: std::panic::Location::caller(),
                            })?;
                    let expires_at =
                        status
                            .expires_at
                            .ok_or_else(|| LoginQrError::MissingExpiresAt {
                                location: std::panic::Location::caller(),
                            })?;

                    client
                        .save_config(session_id.clone(), expires_at)
                        .with_context(Ctx::save_config())?;
                    return Ok(session_id);
                }
                "expired" => {
                    return Err(LoginQrError::TokenExpired {
                        location: std::panic::Location::caller(),
                    });
                }
                // "pending" or "authenticated" — keep polling
                _ => continue,
            }
        }
    }
    .await;

    loader.finish();

    let session_id = poll_result?;
    output::success("Login successful");

    match check_org_security_settings(client, &session_id).await {
        Ok(settings) => {
            if !settings.require_pin {
                output::warning("\nWARNING: PIN verification is disabled for your organization.");
                output::warning("For production use, enable PIN requirement.");
            }
        }
        Err(e) => {
            output::verbose(
                client.verbose,
                &format!("Could not check security settings: {}", e),
            );
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LogoutError {
    #[error("failed to remove local config [{location:?}]")]
    RemoveConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn logout(client: &ApiClient) -> Result<(), LogoutError> {
    use LogoutErrorCtx as Ctx;
    // Try to invalidate session on server if we have a config
    if let Ok(config) = client.load_config() {
        output::verbose(client.verbose, "Invalidating session on server...");
        match client
            .client
            .post(format!("{}/auth/logout", client.base_url))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                output::verbose(client.verbose, "Session invalidated on server");
            }
            Ok(response) => {
                output::verbose(
                    client.verbose,
                    &format!("Server returned {}", response.status()),
                );
            }
            Err(e) => {
                output::verbose(client.verbose, &format!("Could not reach server: {}", e));
            }
        }
    }

    // Delete local config
    if client.config_path.exists() {
        std::fs::remove_file(&client.config_path).with_context(Ctx::remove_config())?;
        output::success("Logged out successfully");
    } else {
        output::status("Not logged in");
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum CheckOnboardingStatusError {
    #[error("failed to get user status [{location:?}]")]
    GetStatus {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn check_onboarding_status(
    client: &ApiClient,
    session_id: &str,
) -> Result<UserStatus, CheckOnboardingStatusError> {
    use CheckOnboardingStatusErrorCtx as Ctx;
    client
        .get_protected_json(session_id, "/api/user/status", "Failed to get user status")
        .await
        .with_context(Ctx::get_status())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PrimaryOrganizationIdError {
    #[error("failed to get organizations [{location:?}]")]
    GetOrganizations {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("no organizations found [{location:?}]")]
    NoOrganizations {
        #[location]
        location: Location,
    },
}

pub(crate) async fn primary_organization_id(
    client: &ApiClient,
    session_id: &str,
) -> Result<String, PrimaryOrganizationIdError> {
    use PrimaryOrganizationIdErrorCtx as Ctx;
    let orgs: Vec<Organization> = client
        .get_protected_json(
            session_id,
            "/api/organizations",
            "Failed to get organizations",
        )
        .await
        .with_context(Ctx::get_organizations())?;

    if orgs.is_empty() {
        return Err(PrimaryOrganizationIdError::NoOrganizations {
            location: std::panic::Location::caller(),
        });
    }

    Ok(orgs[0].id.clone())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PrintAccountIdError {
    #[error("failed to load authenticated config [{location:?}]")]
    LoadConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to determine primary organization id [{location:?}]")]
    PrimaryOrganizationId {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to print account id [{location:?}]")]
    Print {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn print_account_id(client: &ApiClient) -> Result<(), PrintAccountIdError> {
    use PrintAccountIdErrorCtx as Ctx;

    let config = client
        .require_existing_authenticated_config()
        .with_context(Ctx::load_config())?;
    let account_id = primary_organization_id(client, config.session_id())
        .await
        .with_context(Ctx::primary_organization_id())?;
    output::data_ln(account_id).with_context(Ctx::print())?;
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum CheckOrgSecuritySettingsError {
    #[error("failed to determine primary organization id [{location:?}]")]
    PrimaryOrganizationId {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to get security settings [{location:?}]")]
    GetSettings {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn check_org_security_settings(
    client: &ApiClient,
    session_id: &str,
) -> Result<OrgSettings, CheckOrgSecuritySettingsError> {
    use CheckOrgSecuritySettingsErrorCtx as Ctx;
    let org_id = primary_organization_id(client, session_id)
        .await
        .with_context(Ctx::primary_organization_id())?;

    client
        .get_protected_json(
            session_id,
            &format!("/api/organizations/{}/settings", org_id),
            "Failed to get security settings",
        )
        .await
        .with_context(Ctx::get_settings())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum MakeCredentialError {
    #[error("failed to create credential on security key [{location:?}]")]
    Credential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to prompt for PIN [{location:?}]")]
    PromptForPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn make_credential(
    client: &ApiClient,
    options: &RegisterBeginResponse,
    base_url: &str,
) -> Result<serde_json::Value, MakeCredentialError> {
    use MakeCredentialErrorCtx as Ctx;

    output::verbose(
        client.verbose,
        "Attempting registration without PIN first...",
    );
    match try_make_credential(client, options, base_url, None) {
        Ok(result) => {
            output::verbose(client.verbose, "Registration succeeded without PIN");
            Ok(result)
        }
        Err(e) => {
            output::verbose(client.verbose, &format!("First attempt failed: {:?}", e));
            output::verbose(client.verbose, &format!("Full error details: {:#?}", e));

            // Only ask for PIN if the error is PIN-related
            if is_pin_related_error(&e) {
                output::status("Your security key requires a PIN.");
                match prompt_for_pin().with_context(Ctx::prompt_for_pin())? {
                    Some(pin_string) => {
                        let pin_string = ZeroizePin(pin_string);
                        let pin = Pin::new(&pin_string.0);
                        output::verbose(client.verbose, "Retrying registration with PIN...");
                        try_make_credential(client, options, base_url, Some(pin))
                            .with_context(Ctx::credential())
                    }
                    None => {
                        output::verbose(
                            client.verbose,
                            "No PIN provided, returning original error",
                        );
                        Err(e).with_context(Ctx::credential())
                    }
                }
            } else {
                // Not a PIN error, return the original error
                output::verbose(
                    client.verbose,
                    "Error is not PIN-related, not prompting for PIN",
                );
                Err(e).with_context(Ctx::credential())
            }
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum TryMakeCredentialError {
    #[error("failed to decode user ID [{location:?}]")]
    DecodeUserId {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to decode challenge [{location:?}]")]
    DecodeChallenge {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create authenticator service [{location:?}]")]
    AuthenticatorService {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize client data JSON [{location:?}]")]
    SerializeClientData {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to start registration [{location:?}]")]
    StartRegistration {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to prompt for a credential selection [{location:?}]")]
    PromptSelection {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("credential selection out of range [{location:?}]")]
    SelectionOutOfRange {
        #[location]
        location: Location,
    },

    #[error("failed to report credential selection [{location:?}]")]
    SendSelection {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to prompt for PIN [{location:?}]")]
    PromptForPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send PIN to authenticator [{location:?}]")]
    SendPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("PIN is required but none provided [{location:?}]")]
    PinRequiredNoneProvided {
        #[location]
        location: Location,
    },

    #[error("PIN/UV error: {error:?} [{location:?}]")]
    PinUvError {
        error: StatusPinUv,

        #[location]
        location: Location,
    },

    #[error("registration failed [{location:?}]")]
    RegistrationFailed {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("invalid authenticator data length: {length} [{location:?}]")]
    InvalidAuthenticatorDataLength {
        length: usize,

        #[location]
        location: Location,
    },

    #[error("authenticator data too short for credential ID [{location:?}]")]
    AuthenticatorDataTooShort {
        #[location]
        location: Location,
    },

    #[error("failed to serialize attestation object [{location:?}]")]
    SerializeAttestationObject {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn try_make_credential(
    client: &ApiClient,
    options: &RegisterBeginResponse,
    base_url: &str,
    pin: Option<Pin>,
) -> Result<serde_json::Value, TryMakeCredentialError> {
    use TryMakeCredentialErrorCtx as Ctx;

    let opts = &options.public_key;

    output::verbose(client.verbose, "Creating FIDO2 credential...");

    let user_id = general_purpose::URL_SAFE_NO_PAD
        .decode(&opts.user.id)
        .with_context(Ctx::decode_user_id())?;

    let challenge = general_purpose::URL_SAFE_NO_PAD
        .decode(&opts.challenge)
        .with_context(Ctx::decode_challenge())?;

    output::verbose(client.verbose, &format!("user_id bytes: {:?}", user_id));
    output::verbose(client.verbose, &format!("challenge bytes: {:?}", challenge));
    output::verbose(client.verbose, &format!("rpId: {}", opts.rp.id));

    let user = PublicKeyCredentialUserEntity {
        id: user_id.clone(),
        name: Some(opts.user.name.clone()),
        display_name: Some(opts.user.display_name.clone()),
    };

    let rp = RelyingParty {
        id: opts.rp.id.clone(),
        name: Some(opts.rp.name.clone()),
    };

    let pub_key_params: Vec<PublicKeyCredentialParameters> = opts
        .pub_key_cred_params
        .iter()
        .filter_map(|p| match p.alg {
            -7 => Some(PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }),
            -257 => Some(PublicKeyCredentialParameters {
                alg: COSEAlgorithm::RS256,
            }),
            _ => None,
        })
        .collect();

    output::verbose(
        client.verbose,
        &format!("pub_key_params count: {}", pub_key_params.len()),
    );
    output::verbose(
        client.verbose,
        &format!("timeout from server: {} ms", opts.timeout),
    );

    let mut manager = AuthenticatorService::new().with_context(Ctx::authenticator_service())?;

    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (callback_tx, callback_rx) = channel::<Result<RegisterResult, AuthenticatorError>>();

    let callback = StateCallback::new(Box::new(move |result| {
        let _ = callback_tx.send(result);
    }));

    let args = RegisterArgs {
        client_data_hash: Sha256::digest(
            serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create",
            "challenge": opts.challenge,
            "origin": base_url,
            }))
            .with_context(Ctx::serialize_client_data())?,
        )
        .into(),
        relying_party: rp,
        origin: base_url.to_string(),
        user,
        pub_cred_params: pub_key_params,
        exclude_list: vec![],
        user_verification_req: authenticator::ctap2::server::UserVerificationRequirement::Preferred,
        resident_key_req: authenticator::ctap2::server::ResidentKeyRequirement::Required,
        extensions: Default::default(),
        pin,
        use_ctap1_fallback: false,
    };

    output::verbose(
        client.verbose,
        "Sending register request to authenticator...",
    );
    manager
        .register(opts.timeout, args, status_tx, callback)
        .with_context(Ctx::start_registration())?;

    output::verbose(
        client.verbose,
        "Waiting for callback result (up to 60 seconds)...",
    );

    let mut loader = Spinner::new("Tap your security key to continue", SpinnerStyle::KeyTap);

    loop {
        // Check for status updates
        while let Ok(status) = status_rx.try_recv() {
            match status {
                StatusUpdate::SelectResultNotice(sender, users) => {
                    loader.abandon();
                    output::status("Multiple credentials found. Please select one:");
                    for (idx, user) in users.iter().enumerate() {
                        let display = user
                            .display_name
                            .as_deref()
                            .or(user.name.as_deref())
                            .unwrap_or("Unknown");
                        output::status(format!("[{}] {}", idx, display));
                    }

                    let selection = crate::prompt::select(&format!(
                        "Enter selection (0-{}): ",
                        users.len() - 1
                    ))
                    .with_context(Ctx::prompt_selection())?;

                    if selection >= users.len() {
                        return Err(TryMakeCredentialError::SelectionOutOfRange {
                            location: std::panic::Location::caller(),
                        });
                    }

                    output::status(format!(
                        "Selected: {}",
                        users[selection].name.as_deref().unwrap_or("Unknown")
                    ));
                    sender
                        .send(Some(selection))
                        .with_context(Ctx::send_selection())?;
                }
                StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                    loader.abandon();
                    output::verbose(client.verbose, "PIN required by authenticator");
                    match prompt_for_pin().with_context(Ctx::prompt_for_pin())? {
                        Some(pin_string) => {
                            let pin = Pin::new(&pin_string);
                            sender.send(pin).with_context(Ctx::send_pin())?;
                            loader = Spinner::new(
                                "Tap your security key to continue",
                                SpinnerStyle::KeyTap,
                            );
                        }
                        None => {
                            return Err(TryMakeCredentialError::PinRequiredNoneProvided {
                                location: std::panic::Location::caller(),
                            });
                        }
                    }
                }
                StatusUpdate::PinUvError(e) => {
                    loader.abandon();
                    output::verbose(client.verbose, &format!("PIN/UV error: {:?}", e));
                    return Err(TryMakeCredentialError::PinUvError {
                        error: e,
                        location: std::panic::Location::caller(),
                    });
                }
                _ => {
                    output::verbose(
                        client.verbose,
                        &format!("Authenticator status: {:?}", status),
                    );
                }
            }
        }

        if let Ok(result) = callback_rx.try_recv() {
            loader.finish();
            output::verbose(client.verbose, "Got registration result");
            let register_result = result.with_context(Ctx::registration_failed())?;

            let att_obj = &register_result.att_obj;

            let client_data_json = serde_json::json!({
                "type": "webauthn.create",
                "challenge": opts.challenge,
                "origin": base_url,
            });
            let client_data_json_bytes =
                serde_json::to_vec(&client_data_json).with_context(Ctx::serialize_client_data())?;

            let auth_data_bytes = att_obj.auth_data.to_vec();

            if auth_data_bytes.len() < 37 {
                return Err(TryMakeCredentialError::InvalidAuthenticatorDataLength {
                    length: auth_data_bytes.len(),
                    location: std::panic::Location::caller(),
                });
            }

            let credential_id_len =
                u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;

            let credential_id_start = 55;
            let credential_id_end = credential_id_start + credential_id_len;

            if auth_data_bytes.len() < credential_id_end {
                return Err(TryMakeCredentialError::AuthenticatorDataTooShort {
                    location: std::panic::Location::caller(),
                });
            }

            let credential_id = &auth_data_bytes[credential_id_start..credential_id_end];

            output::verbose(
                client.verbose,
                &format!("credential_id len: {}", credential_id.len()),
            );
            output::verbose(
                client.verbose,
                &format!("credential_id: {}", hex::encode(credential_id)),
            );

            let att_obj_bytes = serde_cbor::to_vec(&register_result.att_obj)
                .with_context(Ctx::serialize_attestation_object())?;

            let response_json = serde_json::json!({
                "id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                "rawId": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                "response": {
                    "clientDataJSON": general_purpose::URL_SAFE_NO_PAD.encode(&client_data_json_bytes),
                    "attestationObject": general_purpose::URL_SAFE_NO_PAD.encode(&att_obj_bytes),
                },
                "type": "public-key"
            });

            return Ok(response_json);
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum PerformLoginError {
    #[error("failed to build HTTP client [{location:?}]")]
    BuildClient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send login begin request [{location:?}]")]
    SendBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read login error body [{location:?}]")]
    ReadErrorBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Login begin failed: {message} [{location:?}]")]
    BeginFailed {
        message: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse login begin response [{location:?}]")]
    ParseBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to get assertion [{location:?}]")]
    GetAssertion {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse credential from assertion [{location:?}]")]
    ParseCredential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize credential [{location:?}]")]
    SerializeCredential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send login finish request [{location:?}]")]
    SendFinish {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("no session cookie in response [{location:?}]")]
    NoSessionCookie {
        #[location]
        location: Location,
    },

    #[error("failed to parse login finish response [{location:?}]")]
    ParseFinish {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to save config [{location:?}]")]
    SaveConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Login failed: {message} [{location:?}]")]
    Failed {
        message: String,

        #[location]
        location: Location,
    },
}

async fn perform_login(
    client: &ApiClient,
    username: &str,
) -> Result<(String, String), PerformLoginError> {
    use PerformLoginErrorCtx as Ctx;

    let cookie_store = reqwest::cookie::Jar::default();
    let client_local = reqwest::Client::builder()
        .cookie_provider(Arc::new(cookie_store))
        .build()
        .with_context(Ctx::build_client())?;

    output::verbose(client.verbose, "Sending login begin request...");
    // The CLI drives USB security keys directly and has no conditional UI,
    // so it always sends this field — but an empty `username` (blank login
    // prompt, see prompt_for_login_username) opts into the no-username
    // broadcast/discoverable path instead of a scoped allow-list.
    let response = client_local
        .post(format!("{}/auth/login/begin", client.base_url))
        .json(&login_begin_request_body(username))
        .send()
        .await
        .with_context(Ctx::send_begin())?;

    if !response.status().is_success() {
        let error = response.text().await.with_context(Ctx::read_error_body())?;
        return Err(PerformLoginError::BeginFailed {
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    let begin_resp: LoginBeginResponse = response.json().await.with_context(Ctx::parse_begin())?;
    output::verbose(client.verbose, "Login challenge received");
    output::verbose(
        client.verbose,
        &format!("Session from server: {:?}", begin_resp.session),
    );

    let assertion =
        get_assertion(client, &begin_resp, &client.base_url).with_context(Ctx::get_assertion())?;

    output::status("Assertion created");

    let mut credential: serde_json::Value =
        serde_json::from_slice(&assertion.response_json).with_context(Ctx::parse_credential())?;

    output::verbose(client.verbose, "Credential before adding session:");
    output::verbose(
        client.verbose,
        &serde_json::to_string_pretty(&credential).with_context(Ctx::serialize_credential())?,
    );

    if let Some(obj) = credential.as_object_mut() {
        obj.insert("session".to_string(), serde_json::json!(begin_resp.session));
    }

    output::verbose(
        client.verbose,
        "Final payload being sent to /auth/login/finish:",
    );
    output::verbose(
        client.verbose,
        &serde_json::to_string_pretty(&credential).with_context(Ctx::serialize_credential())?,
    );

    let response = client_local
        .post(format!("{}/auth/login/finish", client.base_url))
        .json(&credential)
        .send()
        .await
        .with_context(Ctx::send_finish())?;

    if response.status().is_success() {
        // Extract session from Set-Cookie header (not response body)
        let session_id = extract_session_from_cookies(&response).ok_or_else(|| {
            PerformLoginError::NoSessionCookie {
                location: std::panic::Location::caller(),
            }
        })?;

        let finish_resp: LoginFinishResponse =
            response.json().await.with_context(Ctx::parse_finish())?;

        client
            .save_config(session_id.clone(), finish_resp.expires_at.clone())
            .with_context(Ctx::save_config())?;

        Ok((session_id, finish_resp.expires_at))
    } else {
        let status = response.status();
        let error = response.text().await.with_context(Ctx::read_error_body())?;
        output::verbose(
            client.verbose,
            &format!("Server error response (status {}): {}", status, error),
        );
        Err(PerformLoginError::Failed {
            message: error,
            location: std::panic::Location::caller(),
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignedRequestQrError {
    #[error("failed to send QR sign begin request [{location:?}]")]
    SendBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read QR sign error body [{location:?}]")]
    ReadErrorBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to start QR signing: {message} [{location:?}]")]
    BeginFailed {
        message: String,

        #[location]
        location: Location,
    },

    #[error("failed to parse QR sign begin response [{location:?}]")]
    ParseBegin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to render QR code [{location:?}]")]
    RenderQr {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("QR signing timed out. Please try again. [{location:?}]")]
    TimedOut {
        #[location]
        location: Location,
    },

    #[error("failed to poll QR sign status [{location:?}]")]
    PollSend {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse QR sign status response [{location:?}]")]
    PollParse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("completed but no fido2_response returned [{location:?}]")]
    MissingFido2Response {
        #[location]
        location: Location,
    },

    #[error("completed but no challenge_id returned [{location:?}]")]
    MissingChallengeId {
        #[location]
        location: Location,
    },

    #[error("QR signing token expired. Please try again. [{location:?}]")]
    TokenExpired {
        #[location]
        location: Location,
    },

    #[error("failed to send signed request [{location:?}]")]
    SendRequest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) async fn signed_request_qr(
    client: &ApiClient,
    session_id: &str,
    path: &str,
    method: reqwest::Method,
    body_json: Vec<u8>,
) -> Result<reqwest::Response, SignedRequestQrError> {
    use SignedRequestQrErrorCtx as Ctx;

    let body_hash = hex::encode(Sha256::digest(&body_json));
    let method_name = method.as_str();

    // The gateway nests /api routes, so the sign middleware sees paths with /api stripped
    let challenge_path = path.strip_prefix("/api").unwrap_or(path);

    output::verbose(client.verbose, "Starting QR code cross-device signing...");

    // Step 1: Request a QR sign token from the gateway
    let body_str = String::from_utf8_lossy(&body_json);
    let sign_req = serde_json::json!({
        "method": method_name,
        "path": challenge_path,
        "body": body_str,
        "body_hash": body_hash,
    });

    let response = client
        .client
        .post(format!("{}/auth/qr-sign/begin", client.base_url))
        .header("X-Session-ID", session_id)
        .json(&sign_req)
        .send()
        .await
        .with_context(Ctx::send_begin())?;

    if !response.status().is_success() {
        let error = response.text().await.with_context(Ctx::read_error_body())?;
        return Err(SignedRequestQrError::BeginFailed {
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    let begin_resp: QrSignBeginResponse = response.json().await.with_context(Ctx::parse_begin())?;
    output::verbose(
        client.verbose,
        &format!("QR sign token: {}", begin_resp.token),
    );

    // Step 2: Render QR code
    output::status("");
    render_qr_code(&begin_resp.url).with_context(Ctx::render_qr())?;
    output::status("");
    output::status("Scan the QR code with your phone to approve the operation, or open:");
    output::status(format!("  {}", begin_resp.url));
    output::status("");

    // Step 3: Poll for completion
    let loader = Spinner::new("Waiting for approval...", SpinnerStyle::Processing);

    let poll_result = async {
        let timeout = Duration::from_secs(180);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(SignedRequestQrError::TimedOut {
                    location: std::panic::Location::caller(),
                });
            }

            tokio::time::sleep(Duration::from_secs(2)).await;

            let status_resp = client
                .client
                .get(format!("{}/auth/qr-sign/status", client.base_url))
                .query(&[("token", &begin_resp.token)])
                .send()
                .await
                .with_context(Ctx::poll_send())?;

            if !status_resp.status().is_success() {
                output::verbose(client.verbose, "Status poll failed, retrying...");
                continue;
            }

            let status: QrSignStatusResponse =
                status_resp.json().await.with_context(Ctx::poll_parse())?;
            output::verbose(client.verbose, &format!("Poll status: {}", status.status));

            match status.status.as_str() {
                "completed" => {
                    let fido2_response = status.fido2_response.ok_or_else(|| {
                        SignedRequestQrError::MissingFido2Response {
                            location: std::panic::Location::caller(),
                        }
                    })?;
                    let challenge_id = status.challenge_id.ok_or_else(|| {
                        SignedRequestQrError::MissingChallengeId {
                            location: std::panic::Location::caller(),
                        }
                    })?;
                    return Ok((fido2_response, challenge_id));
                }
                "expired" => {
                    return Err(SignedRequestQrError::TokenExpired {
                        location: std::panic::Location::caller(),
                    });
                }
                // "pending" or "authenticated" — keep polling
                _ => continue,
            }
        }
    }
    .await;

    loader.finish();

    let (fido2_response, challenge_id) = poll_result?;
    output::verbose(client.verbose, "Sending QR-signed request");

    // Step 4: Send the actual request with the FIDO2 assertion from the phone
    let response = client
        .client
        .request(method, format!("{}{}", client.base_url, path))
        .header("X-Fido2-Challenge-Id", &challenge_id)
        .header("X-Fido2-Response", &fido2_response)
        .header("Content-Type", "application/json")
        .body(body_json)
        .send()
        .await
        .with_context(Ctx::send_request())?;

    Ok(response)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAssertionError {
    #[error("failed to get assertion [{location:?}]")]
    Assertion {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to prompt for PIN [{location:?}]")]
    PromptForPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) fn get_assertion(
    client: &ApiClient,
    options: &LoginBeginResponse,
    base_url: &str,
) -> Result<AssertionResult, GetAssertionError> {
    use GetAssertionErrorCtx as Ctx;

    output::verbose(client.verbose, "Attempting assertion without PIN first...");
    match try_get_assertion(client, options, base_url, None) {
        Ok(result) => {
            output::verbose(client.verbose, "Assertion succeeded without PIN");
            Ok(result)
        }
        Err(e) => {
            output::verbose(client.verbose, &format!("First attempt failed: {:?}", e));
            output::verbose(client.verbose, &format!("Full error details: {:#?}", e));

            // Only ask for PIN if the error is PIN-related
            if is_pin_related_error(&e) {
                output::status("Your security key requires a PIN.");
                match prompt_for_pin().with_context(Ctx::prompt_for_pin())? {
                    Some(pin_string) => {
                        let pin_string = ZeroizePin(pin_string);
                        let pin = Pin::new(&pin_string.0);
                        output::verbose(client.verbose, "Retrying assertion with PIN...");
                        try_get_assertion(client, options, base_url, Some(pin))
                            .with_context(Ctx::assertion())
                    }
                    None => {
                        output::verbose(
                            client.verbose,
                            "No PIN provided, returning original error",
                        );
                        Err(GetAssertionError::Assertion {
                            location: std::panic::Location::caller(),
                            source: e.into(),
                        })
                    }
                }
            } else {
                // Not a PIN error, return the original error
                output::verbose(
                    client.verbose,
                    "Error is not PIN-related, not prompting for PIN",
                );
                Err(GetAssertionError::Assertion {
                    location: std::panic::Location::caller(),
                    source: e.into(),
                })
            }
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum TryGetAssertionError {
    #[error("failed to decode challenge [{location:?}]")]
    DecodeChallenge {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create authenticator service [{location:?}]")]
    AuthenticatorService {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize client data JSON [{location:?}]")]
    SerializeClientData {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to start assertion [{location:?}]")]
    StartAssertion {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to prompt for a credential selection [{location:?}]")]
    PromptSelection {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("credential selection out of range [{location:?}]")]
    SelectionOutOfRange {
        #[location]
        location: Location,
    },

    #[error("failed to report credential selection [{location:?}]")]
    SendSelection {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to prompt for PIN [{location:?}]")]
    PromptForPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to send PIN to authenticator [{location:?}]")]
    SendPin {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("PIN is required but none provided [{location:?}]")]
    PinRequiredNoneProvided {
        #[location]
        location: Location,
    },

    #[error("PIN/UV error: {error:?} [{location:?}]")]
    PinUvError {
        error: StatusPinUv,

        #[location]
        location: Location,
    },

    #[error(
        "no passkey found on this device for this server. If you haven't registered yet, run: caution register. If you registered with a different key, try that one instead. [{location:?}]"
    )]
    NoCredentials {
        #[location]
        location: Location,
    },

    #[error("assertion failed [{location:?}]")]
    AssertionFailed {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("no credential returned from assertion [{location:?}]")]
    NoCredential {
        #[location]
        location: Location,
    },

    #[error("failed to serialize response JSON [{location:?}]")]
    SerializeResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn try_get_assertion(
    client: &ApiClient,
    options: &LoginBeginResponse,
    base_url: &str,
    pin: Option<Pin>,
) -> Result<AssertionResult, TryGetAssertionError> {
    use TryGetAssertionErrorCtx as Ctx;

    let opts = &options.public_key;

    output::verbose(client.verbose, "Getting assertion from authenticator...");

    let challenge = general_purpose::URL_SAFE_NO_PAD
        .decode(&opts.challenge)
        .with_context(Ctx::decode_challenge())?;

    output::verbose(client.verbose, &format!("challenge bytes: {:?}", challenge));
    output::verbose(client.verbose, &format!("rpId: {}", opts.rp_id));

    let mut manager = AuthenticatorService::new().with_context(Ctx::authenticator_service())?;

    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (callback_tx, callback_rx) = channel::<Result<SignResult, AuthenticatorError>>();

    let callback = StateCallback::new(Box::new(move |result| {
        let _ = callback_tx.send(result);
    }));

    let allow_list: Vec<PublicKeyCredentialDescriptor> = opts
        .allow_credentials
        .iter()
        .filter_map(|cred| {
            general_purpose::URL_SAFE_NO_PAD
                .decode(&cred.id)
                .ok()
                .map(|id_bytes| PublicKeyCredentialDescriptor {
                    id: id_bytes,
                    transports: vec![Transport::USB],
                })
        })
        .collect();

    output::verbose(
        client.verbose,
        &format!("Allow list has {} credentials", allow_list.len()),
    );

    let args = SignArgs {
        client_data_hash: Sha256::digest(
            serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": opts.challenge,
            "origin": base_url,
            }))
            .with_context(Ctx::serialize_client_data())?,
        )
        .into(),
        origin: base_url.to_string(),
        relying_party_id: opts.rp_id.clone(),
        allow_list,
        user_verification_req: authenticator::ctap2::server::UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: Default::default(),
        pin,
        use_ctap1_fallback: false,
    };

    output::verbose(client.verbose, "Sending sign request to authenticator...");
    manager
        .sign(opts.timeout, args, status_tx, callback)
        .with_context(Ctx::start_assertion())?;

    output::verbose(
        client.verbose,
        "Waiting for callback result (up to 60 seconds)...",
    );

    let mut loader = Spinner::new("Tap your security key to continue", SpinnerStyle::KeyTap);

    loop {
        // Check for status updates
        while let Ok(status) = status_rx.try_recv() {
            match status {
                StatusUpdate::SelectResultNotice(sender, users) => {
                    loader.abandon();
                    output::status("Multiple credentials found. Please select one:");
                    for (idx, user) in users.iter().enumerate() {
                        let display = user
                            .display_name
                            .as_deref()
                            .or(user.name.as_deref())
                            .unwrap_or("Unknown");
                        output::status(format!("[{}] {}", idx, display));
                    }

                    let selection = crate::prompt::select(&format!(
                        "Enter selection (0-{}): ",
                        users.len() - 1
                    ))
                    .with_context(Ctx::prompt_selection())?;

                    if selection >= users.len() {
                        return Err(TryGetAssertionError::SelectionOutOfRange {
                            location: std::panic::Location::caller(),
                        });
                    }

                    output::status(format!(
                        "Selected: {}",
                        users[selection].name.as_deref().unwrap_or("Unknown")
                    ));
                    sender
                        .send(Some(selection))
                        .with_context(Ctx::send_selection())?;
                }
                StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                    loader.abandon();
                    output::verbose(client.verbose, "PIN required by authenticator");
                    match prompt_for_pin().with_context(Ctx::prompt_for_pin())? {
                        Some(pin_string) => {
                            let pin = Pin::new(&pin_string);
                            sender.send(pin).with_context(Ctx::send_pin())?;
                            loader = Spinner::new(
                                "Tap your security key to continue",
                                SpinnerStyle::KeyTap,
                            );
                        }
                        None => {
                            return Err(TryGetAssertionError::PinRequiredNoneProvided {
                                location: std::panic::Location::caller(),
                            });
                        }
                    }
                }
                StatusUpdate::PinUvError(e) => {
                    loader.abandon();
                    output::verbose(client.verbose, &format!("PIN/UV error: {:?}", e));
                    return Err(TryGetAssertionError::PinUvError {
                        error: e,
                        location: std::panic::Location::caller(),
                    });
                }
                _ => {
                    output::verbose(
                        client.verbose,
                        &format!("Authenticator status: {:?}", status),
                    );
                }
            }
        }

        if let Ok(result) = callback_rx.try_recv() {
            loader.finish();
            output::verbose(client.verbose, "Got assertion result");
            // The authenticator surfaces "no credentials" as an error whose message names
            // `NoCredentials`; detect that by inspecting the message so we can surface a
            // helpful hint, otherwise wrap the raw error through the typed Ctx constructor.
            let sign_result = if result
                .as_ref()
                .err()
                .is_some_and(|e| format!("{:?}", e).contains("NoCredentials"))
            {
                Err::<_, TryGetAssertionError>(TryGetAssertionError::NoCredentials {
                    location: std::panic::Location::caller(),
                })
            } else {
                result.with_context(Ctx::assertion_failed())
            }?;

            let client_data_json = serde_json::json!({
                "type": "webauthn.get",
                "challenge": opts.challenge,
                "origin": client.base_url.clone(),
            });
            let client_data_json_bytes =
                serde_json::to_vec(&client_data_json).with_context(Ctx::serialize_client_data())?;

            let cred_id_bytes = &sign_result
                .assertion
                .credentials
                .as_ref()
                .ok_or_else(|| TryGetAssertionError::NoCredential {
                    location: std::panic::Location::caller(),
                })?
                .id;

            let response_json = serde_json::json!({
                "id": general_purpose::URL_SAFE_NO_PAD.encode(cred_id_bytes),
                "rawId": general_purpose::URL_SAFE_NO_PAD.encode(cred_id_bytes),
                "response": {
                    "authenticatorData": general_purpose::URL_SAFE_NO_PAD.encode(&sign_result.assertion.auth_data.to_vec()),
                    "clientDataJSON": general_purpose::URL_SAFE_NO_PAD.encode(&client_data_json_bytes),
                    "signature": general_purpose::URL_SAFE_NO_PAD.encode(&sign_result.assertion.signature),
                    "userHandle": sign_result.assertion.user.as_ref()
                        .map(|u| general_purpose::URL_SAFE_NO_PAD.encode(&u.id))
                        .unwrap_or_default(),
                },
                "type": "public-key"
            });

            output::verbose(client.verbose, "Response JSON structure:");
            output::verbose(
                client.verbose,
                &serde_json::to_string_pretty(&response_json)
                    .with_context(Ctx::serialize_response())?,
            );

            return Ok(AssertionResult {
                response_json: serde_json::to_vec(&response_json)
                    .with_context(Ctx::serialize_response())?,
            });
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn prompt_line_from_returns_typed_line() {
        let mut input = Cursor::new(b"carol\n".to_vec());
        let username = prompt_line_from(&mut input, "Username: ", "cannot be empty").unwrap();
        assert_eq!(username, "carol");
    }

    #[test]
    fn prompt_line_from_trims_whitespace() {
        let mut input = Cursor::new(b"  dave  \n".to_vec());
        let username = prompt_line_from(&mut input, "Username: ", "cannot be empty").unwrap();
        assert_eq!(username, "dave");
    }

    #[test]
    fn prompt_line_from_reprompts_on_blank_lines() {
        // Two blank lines, then a real answer: simulates the user hitting
        // Enter accidentally before typing a username.
        let mut input = Cursor::new(b"\n\nerin\n".to_vec());
        let username = prompt_line_from(&mut input, "Username: ", "cannot be empty").unwrap();
        assert_eq!(username, "erin");
    }

    #[test]
    fn prompt_optional_line_from_returns_typed_line() {
        let mut input = Cursor::new(b"frank\n".to_vec());
        let username = prompt_optional_line_from(&mut input, "Username: ").unwrap();
        assert_eq!(username, "frank");
    }

    #[test]
    fn prompt_optional_line_from_accepts_blank_line_on_first_try() {
        // A plain Enter keypress (not just EOF) must resolve to an empty
        // string immediately — this is the legacy/no-username login path,
        // and it must not loop asking the user to try again.
        let mut input = Cursor::new(b"\n".to_vec());
        let username = prompt_optional_line_from(&mut input, "Username: ").unwrap();
        assert_eq!(username, "");
    }

    #[test]
    fn prompt_optional_line_from_accepts_immediate_eof() {
        let mut input = Cursor::new(b"".to_vec());
        let username = prompt_optional_line_from(&mut input, "Username: ").unwrap();
        assert_eq!(username, "");
    }

    #[test]
    fn resolve_login_username_returns_provided_username_without_prompting() {
        // An explicit --username wins regardless of terminal state; the reader
        // must never be touched (empty input would otherwise yield "").
        let mut input = Cursor::new(b"".to_vec());
        let username =
            resolve_login_username(Some("alice".to_string()), false, &mut input).unwrap();
        assert_eq!(username, "alice");
    }

    #[test]
    fn resolve_login_username_prompts_when_interactive() {
        let mut input = Cursor::new(b"bob\n".to_vec());
        let username = resolve_login_username(None, true, &mut input).unwrap();
        assert_eq!(username, "bob");
    }

    #[test]
    fn resolve_login_username_errors_non_interactive_instead_of_hanging() {
        // The #3 regression guard: a headless auto-relogin (no username, no TTY)
        // must fail fast rather than block on a stdin read that never returns.
        let mut input = Cursor::new(b"".to_vec());
        let err = resolve_login_username(None, false, &mut input).unwrap_err();
        assert!(matches!(err, LoginUsernameError::NonInteractive));
    }

    #[test]
    fn resolve_register_username_returns_provided_username_without_prompting() {
        let mut input = Cursor::new(b"".to_vec());
        let username =
            resolve_register_username(Some("alice".to_string()), false, &mut input).unwrap();
        assert_eq!(username, "alice");
    }

    #[test]
    fn resolve_register_username_prompts_when_interactive() {
        let mut input = Cursor::new(b"bob\n".to_vec());
        let username = resolve_register_username(None, true, &mut input).unwrap();
        assert_eq!(username, "bob");
    }

    #[test]
    fn resolve_register_username_errors_non_interactive_instead_of_hanging() {
        // Finding 4: register lacked the noninteractive guard that login has
        // (`resolve_login_username_errors_non_interactive_instead_of_hanging`
        // above) — a noninteractive caller with no --username must fail fast
        // instead of getting an empty username silently sent to the server.
        let mut input = Cursor::new(b"".to_vec());
        let err = resolve_register_username(None, false, &mut input).unwrap_err();
        assert!(matches!(err, RegisterUsernameError::NonInteractive));
    }

    #[test]
    fn resolve_register_username_treats_blank_provided_as_absent() {
        let mut input = Cursor::new(b"bob\n".to_vec());
        let username =
            resolve_register_username(Some("   ".to_string()), true, &mut input).unwrap();
        assert_eq!(username, "bob");
    }

    #[test]
    fn login_begin_request_body_carries_username() {
        let body = login_begin_request_body("frank");
        assert_eq!(body, serde_json::json!({ "username": "frank" }));
    }

    #[test]
    fn login_begin_request_body_does_not_leak_other_fields() {
        let body = login_begin_request_body("grace");
        let obj = body.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert_eq!(obj.get("username").and_then(|v| v.as_str()), Some("grace"));
    }
}
