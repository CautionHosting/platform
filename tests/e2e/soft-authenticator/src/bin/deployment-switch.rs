// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//
// Signs one deployment switch with an in-process software passkey, for the
// app deployments lifecycle e2e (tests/e2e/test_app_deployments.sh). The switch
// stays FIDO2-signed in e2e builds, but an `e2e-login` user has only a dummy
// credential, so this process, which holds the soft passkey in memory:
//
//   1. adds a soft passkey to the session's user (`/passkeys/register/*`; that
//      route is session-only in e2e builds, as in `add_passkey` of
//      quorum_caution.rs),
//   2. logs in with it (username-scoped) to get a session bound to that
//      passkey: `/auth/sign-request` challenges only the *session's* credential,
//      which for the `e2e-login` session is the dummy one,
//   3. signs `POST /api{SWITCH_PATH}` through `/auth/sign-request` and sends it
//      with X-Fido2-Challenge-Id / X-Fido2-Response, as `Session::signed_at` in
//      quorum.rs (the challenge path is SWITCH_PATH; the request goes to
//      `/api{SWITCH_PATH}`),
//   4. prints the response body on stdout and `HTTP <status>` on stderr; exits
//      non-zero unless the status is 2xx.
//
// Env: GATEWAY_URL, RP_ORIGIN (an allowed origin), SESSION_ID (an `e2e-login`
// session), SWITCH_PATH (e.g. /resources/<app>/deployments/<dep>/switch),
// SWITCH_BODY (the exact JSON body).

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::blocking::{Client, Response};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs_proto::{PublicKeyCredential, RequestChallengeResponse};

fn required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("{key} env var required"))
}

fn checked(what: &str, response: Response) -> Result<Response> {
    if !response.status().is_success() {
        bail!("{what} -> {}: {}", response.status(), response.text()?);
    }
    Ok(response)
}

fn main() -> Result<()> {
    let base = required("GATEWAY_URL")?;
    let origin = Url::parse(&required("RP_ORIGIN")?).context("RP_ORIGIN is not a valid URL")?;
    let session_id = required("SESSION_ID")?;
    let switch_path = required("SWITCH_PATH")?;
    let switch_body = required("SWITCH_BODY")?;

    let http = Client::new();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // The session's user, by name, for the username-scoped login below.
    let status: Value = checked(
        "GET /user/username",
        http.get(format!("{base}/user/username"))
            .header("X-Session-ID", &session_id)
            .send()?,
    )?
    .json()?;
    let username = status["username"]
        .as_str()
        .context("GET /user/username: missing `username`")?;

    // 1. Add the soft passkey to that user.
    let begin: Value = checked(
        "passkey register/begin",
        http.post(format!("{base}/passkeys/register/begin"))
            .header("X-Session-ID", &session_id)
            .json(&json!({ "name": format!("e2e-switch-{}", uuid::Uuid::new_v4()) }))
            .send()?,
    )?
    .json()?;
    let credential = authenticator
        .do_registration(origin.clone(), serde_json::from_value(begin.clone())?)
        .map_err(|e| anyhow::anyhow!("passkey registration: {e:?}"))?;
    let mut finish = serde_json::to_value(credential)?;
    finish["session"] = begin["session"].clone();
    checked(
        "passkey register/finish",
        http.post(format!("{base}/passkeys/register/finish"))
            .header("X-Session-ID", &session_id)
            .json(&finish)
            .send()?,
    )?;

    // 2. A session bound to the soft passkey (the sign-request credential).
    let begin: Value = checked(
        "login/begin",
        http.post(format!("{base}/auth/login/begin"))
            .json(&json!({ "username": username }))
            .send()?,
    )?
    .json()?;
    let login_state = begin["session"]
        .as_str()
        .context("login/begin: missing `session`")?
        .to_string();
    let request: RequestChallengeResponse =
        serde_json::from_value(begin).context("login/begin is not a RequestChallengeResponse")?;
    let assertion: PublicKeyCredential = authenticator
        .do_authentication(origin.clone(), request)
        .map_err(|e| anyhow::anyhow!("login assertion: {e:?}"))?;
    let mut finish = serde_json::to_value(&assertion)?;
    finish["session"] = json!(login_state);
    let finished = checked(
        "login/finish",
        http.post(format!("{base}/auth/login/finish"))
            .json(&finish)
            .send()?,
    )?;
    // The session ID is issued as a cookie, never in the body.
    let signing_session = finished
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            cookie
                .strip_prefix("caution_session=")
                .map(|value| value.split(';').next().unwrap_or_default().to_string())
        })
        .context("login/finish did not set a caution_session cookie")?;

    // 3. Sign and send the switch.
    let body_hash = hex::encode(Sha256::digest(switch_body.as_bytes()));
    let challenge: Value = checked(
        "auth/sign-request",
        http.post(format!("{base}/auth/sign-request"))
            .header("X-Session-ID", &signing_session)
            .json(&json!({ "method": "POST", "path": switch_path, "body_hash": body_hash }))
            .send()?,
    )?
    .json()?;
    let assertion = authenticator
        .do_authentication(origin, serde_json::from_value(challenge.clone())?)
        .map_err(|e| anyhow::anyhow!("request signing: {e:?}"))?;
    let response = http
        .post(format!("{base}/api{switch_path}"))
        .header("X-Session-ID", &signing_session)
        .header(
            "X-Fido2-Challenge-Id",
            challenge["challenge_id"]
                .as_str()
                .context("auth/sign-request: missing `challenge_id`")?,
        )
        .header(
            "X-Fido2-Response",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion)?),
        )
        .header("Content-Type", "application/json")
        .body(switch_body)
        .send()?;

    // 4. Body on stdout, status on stderr, non-zero unless 2xx.
    let status = response.status();
    let body = response.text()?;
    println!("{body}");
    eprintln!("HTTP {}", status.as_u16());
    if !status.is_success() {
        std::process::exit(1);
    }
    Ok(())
}
