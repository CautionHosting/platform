// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//
// Software WebAuthn authenticator for e2e. Performs the assertion ceremony that
// test_webauthn_login.sh can't (it only covers the deterministic begin-side
// shapes): a real register + login round-trip whose challenges are signed by an
// in-process SoftPasskey and verified for real by the gateway's webauthn-rs.
//
// SoftPasskey holds one non-resident credential in memory, so the SAME instance
// registers then authenticates. This exercises the scoped/broadcast SecurityKey
// path (residentKey is forced to "preferred" by the register handler); the
// discoverable-only path (resident key + userHandle) is out of scope — SoftPasskey
// can't mint resident credentials.
//
// Env: GATEWAY_URL, RP_ORIGIN (must be an allowed origin), ALPHA_CODE (required,
// an unredeemed beta_codes.code), USERNAME.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use url::Url;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs_proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() -> Result<()> {
    let base = env_or("GATEWAY_URL", "http://localhost:8000");
    let origin = Url::parse(&env_or("RP_ORIGIN", "http://localhost:8000"))
        .context("RP_ORIGIN is not a valid URL")?;
    let alpha_code = std::env::var("ALPHA_CODE").context("ALPHA_CODE env var required")?;
    let username = env_or("USERNAME", "softauth");

    let http = reqwest::blocking::Client::new();
    // One authenticator for the whole run: registration stores the credential
    // in-process, authentication looks it up by allowCredentials id.
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // ── Register ──────────────────────────────────────────────────────────
    // begin -> { publicKey: {...creation options...}, session: "<uuid>" }
    let begin: Value = http
        .post(format!("{base}/auth/register/begin"))
        .json(&json!({ "alpha_code": alpha_code, "username": username }))
        .send()?
        .error_for_status()
        .context("register/begin (bad alpha code or duplicate username?)")?
        .json()?;
    let reg_session = begin["session"]
        .as_str()
        .context("register/begin response missing `session`")?
        .to_string();
    // The `publicKey` field flattened alongside `session` IS a CreationChallengeResponse.
    let ccr: CreationChallengeResponse = serde_json::from_value(begin)
        .context("register/begin body is not a CreationChallengeResponse")?;

    let reg_cred: RegisterPublicKeyCredential = authenticator
        .do_registration(origin.clone(), ccr)
        .map_err(|e| anyhow::anyhow!("SoftPasskey do_registration failed: {e:?}"))?;

    // finish body = the proto credential JSON + the correlating `session` string.
    let mut reg_body = serde_json::to_value(&reg_cred)?;
    reg_body["session"] = json!(reg_session);
    let resp = http
        .post(format!("{base}/auth/register/finish"))
        .json(&reg_body)
        .send()?;
    if !resp.status().is_success() {
        bail!("register/finish -> {}: {}", resp.status(), resp.text()?);
    }
    println!("✓ registered '{username}' (attestation verified by gateway)");

    // ── Login ─────────────────────────────────────────────────────────────
    // Scoped (username) path -> allowCredentials contains our credential.
    let begin: Value = http
        .post(format!("{base}/auth/login/begin"))
        .json(&json!({ "username": username }))
        .send()?
        .error_for_status()
        .context("login/begin failed")?
        .json()?;
    let auth_session = begin["session"]
        .as_str()
        .context("login/begin response missing `session`")?
        .to_string();
    let rcr: RequestChallengeResponse = serde_json::from_value(begin)
        .context("login/begin body is not a RequestChallengeResponse")?;

    let auth_cred: PublicKeyCredential = authenticator
        .do_authentication(origin, rcr)
        .map_err(|e| anyhow::anyhow!("SoftPasskey do_authentication failed: {e:?}"))?;

    let mut auth_body = serde_json::to_value(&auth_cred)?;
    auth_body["session"] = json!(auth_session);
    let resp = http
        .post(format!("{base}/auth/login/finish"))
        .json(&auth_body)
        .send()?;
    if !resp.status().is_success() {
        bail!("login/finish -> {}: {}", resp.status(), resp.text()?);
    }
    // Successful finish issues the authenticated session as a Set-Cookie; grab it
    // so we can prove the session actually works on a protected route.
    let session_id = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|c| {
            c.strip_prefix("caution_session=")
                .map(|v| v.split(';').next().unwrap_or_default().to_string())
        })
        .context("login/finish did not set a caution_session cookie")?;
    println!("✓ login assertion verified (signature checked by gateway)");

    // ── Prove the issued session is authenticated ─────────────────────────
    let resp = http
        .get(format!("{base}/passkeys"))
        .header("X-Session-ID", &session_id)
        .send()?;
    if !resp.status().is_success() {
        bail!(
            "GET /passkeys with issued session -> {} (want 200; session not authenticated)",
            resp.status()
        );
    }
    let count = resp
        .json::<Value>()
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    println!("✓ authenticated session lists {count} passkey(s)");

    println!("\nPASS: software-passkey register + login round-trip");
    Ok(())
}
