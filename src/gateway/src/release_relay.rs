// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
//! Relay only key-service-authenticated approval challenges. The enclave authorizes release.
use crate::types::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use locksmith::release::{self, Attested, Measurements, Prepared};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime},
};
use uuid::Uuid;

#[path = "release_relay_metadata.rs"]
mod metadata;

struct Pending {
    user: Uuid,
    // Key-service session of the attested Prepared; one approval page per release attempt.
    session: String,
    browser: String,
    deadline: Instant,
    request: Value,
    result: Option<Value>,
}
const CAPACITY: usize = 128;
const PER_USER_PENDING: usize = 4;
static PENDING: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
fn store() -> &'static Mutex<HashMap<String, Pending>> {
    PENDING.get_or_init(Default::default)
}

// A passkey re-registered by another user after deletion rejects rather than admits.
fn sole_owner(owners: &[Uuid], user: Uuid) -> bool {
    owners == [user]
}

fn admit_pending(
    pending: &mut HashMap<String, Pending>,
    token: String,
    entry: Pending,
) -> Result<(), StatusCode> {
    pending.retain(|_, p| p.deadline > Instant::now());
    if pending.values().any(|p| p.session == entry.session) {
        return Err(StatusCode::CONFLICT);
    }
    if pending.len() >= CAPACITY
        || pending.values().filter(|p| p.user == entry.user).count() >= PER_USER_PENDING
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    pending.insert(token, entry);
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    token: String,
    assertion: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    prepared: Attested<Prepared>,
    nonce: String,
    #[serde(default)]
    display: Option<metadata::DisplayContext>,
}

// Trust is configured by the operator, never supplied by the relay requester.
fn trusted_measurements() -> Result<Measurements, StatusCode> {
    let path =
        std::env::var("RECRYPTOR_PCR_POLICY_PATH").map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let text = std::fs::read_to_string(path).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let policy = locksmith::bundle::KeymakerPcrPolicy::from_json(&text)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if policy.sets.len() != 1 || policy.sets[0].expires_at_unix_seconds.is_some() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let pcrs = policy.sets[0]
        .pcrs
        .iter()
        .map(|(&i, bytes)| (i, hex::encode(bytes)))
        .collect();
    release::pcrs(&pcrs).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(pcrs)
}

fn verified_request(
    approval: &Approval,
    trusted: &Measurements,
    rp_id: &str,
) -> Result<(Value, Duration), StatusCode> {
    release::verify_response(&approval.prepared, trusted, &approval.nonce)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let prepared = &approval.prepared.data;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_secs();
    let remaining = prepared
        .context
        .expires_at_unix_seconds
        .checked_sub(now)
        .filter(|&seconds| seconds > 0 && seconds <= 180)
        .ok_or(StatusCode::GONE)?;
    let options = serde_json::to_value(&prepared.options).map_err(|_| StatusCode::BAD_REQUEST)?;
    if options["publicKey"]["userVerification"] != "required"
        || options["publicKey"]["rpId"] != rp_id
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let context_hash = release::hash(prepared).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok((
        json!({"options": options, "context": prepared.context,
        "destination_key": prepared.destination_key, "context_hash": context_hash,
        "destination_attestation_hash":prepared.destination_attestation_hash,
        "custody_policy":trusted, "approval_origin":crate::handlers::get_rp_origin()}),
        Duration::from_secs(remaining),
    ))
}

pub async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(approval): Json<Approval>,
) -> Result<Json<Value>, StatusCode> {
    let credential = crate::handlers::authenticate_session(&state, &headers)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if approval.display.as_ref().is_some_and(|display| !display.valid()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let started = Instant::now();
    let (mut request, lifetime) =
        verified_request(&approval, &trusted_measurements()?, &state.relying_party_id)?;
    let user = crate::db::get_user_id_by_credential(&state.db, &credential)
        .await
        .map_err(|error| match error.kind {
            crate::db::DbErrorKind::CredentialNotFound => StatusCode::UNAUTHORIZED,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        })?;
    // Only the holder may open an approval page. The attested options list exactly the
    // holder's snapshot passkeys, the only credentials that can approve this release.
    let holder_credentials: Vec<Vec<u8>> = approval
        .prepared
        .data
        .options
        .public_key
        .allow_credentials
        .iter()
        .map(|credential| credential.id.to_vec())
        .collect();
    let owners = crate::db::get_credential_owners(&state.db, &holder_credentials)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !sole_owner(&owners, user) {
        tracing::warn!("release relay requester does not own the holder's passkeys");
        return Err(StatusCode::FORBIDDEN);
    }
    request["metadata"] = metadata::load(
        &state,
        user,
        &approval.prepared.data,
        approval.display.as_ref(),
    )
    .await;
    request["reported"] = serde_json::to_value(&approval.display).map_err(|_| StatusCode::BAD_REQUEST)?;
    if started.elapsed() >= lifetime { return Err(StatusCode::GONE); }
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let browser = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let metadata = request.get("metadata").cloned();
    let entry = Pending {
        user,
        session: approval.prepared.data.session_id.clone(),
        browser: browser.clone(),
        deadline: started + lifetime,
        request,
        result: None,
    };
    let mut pending = store()
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    admit_pending(&mut pending, token.clone(), entry)?;
    // Browser and requester capabilities are distinct. Assertions are delivered only to the requester.
    Ok(Json(
        json!({"token":token,"url":format!("{}/qr-release#{}",crate::handlers::get_rp_origin(),browser),"metadata":metadata}),
    ))
}
pub async fn read(Json(token): Json<Token>) -> Result<Json<Value>, StatusCode> {
    let pending = store()
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let p = pending
        .values()
        .find(|p| p.browser == token.token && p.deadline > Instant::now() && p.result.is_none())
        .ok_or(StatusCode::GONE)?;
    Ok(Json(p.request.clone()))
}
pub async fn finish(Json(finish): Json<Finish>) -> Result<Json<Value>, StatusCode> {
    let mut pending = store()
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let p = pending
        .values_mut()
        .find(|p| p.browser == finish.token && p.deadline > Instant::now() && p.result.is_none())
        .ok_or(StatusCode::GONE)?;
    p.result = Some(match finish.assertion {
        Some(assertion) => json!({"status":"complete","assertion":assertion}),
        None => json!({"status":"cancelled"}),
    });
    Ok(Json(json!({"status":"relayed"})))
}
pub async fn status(Json(token): Json<Token>) -> Result<Json<Value>, StatusCode> {
    let mut pending = store()
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let p = pending.get(&token.token).ok_or(StatusCode::GONE)?;
    if p.deadline <= Instant::now() {
        pending.remove(&token.token);
        return Err(StatusCode::GONE);
    }
    if p.result.is_some() {
        return Ok(Json(pending.remove(&token.token).unwrap().result.unwrap()));
    }
    Ok(Json(json!({"status":"pending"})))
}
pub async fn cancel(Json(token): Json<Token>) -> StatusCode {
    if let Ok(mut pending) = store().lock() {
        pending.remove(&token.token);
    }
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending() -> (String, String) {
        let requester = Uuid::new_v4().to_string();
        let browser = Uuid::new_v4().to_string();
        store()
            .lock()
            .unwrap()
            .insert(requester.clone(), entry(Uuid::new_v4(), &browser));
        (requester, browser)
    }
    fn entry(user: Uuid, browser: &str) -> Pending {
        Pending {
            user,
            session: Uuid::new_v4().to_string(),
            browser: browser.to_owned(),
            deadline: Instant::now() + Duration::from_secs(180),
            request: json!({"context":{"holder":"test"}}),
            result: None,
        }
    }
    #[test]
    fn admission_limits_each_user_and_rejects_replayed_sessions() {
        let mut pending = HashMap::new();
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        let first = entry(alice, "first");
        let mut replay = entry(bob, "replay");
        replay.session = first.session.clone();
        admit_pending(&mut pending, "first".into(), first).unwrap();
        assert_eq!(
            admit_pending(&mut pending, "replay".into(), replay),
            Err(StatusCode::CONFLICT)
        );
        for index in 1..PER_USER_PENDING {
            admit_pending(&mut pending, index.to_string(), entry(alice, "alice")).unwrap();
        }
        assert_eq!(
            admit_pending(&mut pending, "over".into(), entry(alice, "over")),
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
        admit_pending(&mut pending, "bob".into(), entry(bob, "bob")).unwrap();
        // Expired attempts free their slot and their session.
        pending.get_mut("first").unwrap().deadline = Instant::now();
        admit_pending(&mut pending, "again".into(), entry(alice, "again")).unwrap();
        assert!(!pending.contains_key("first"));
    }
    #[test]
    fn only_the_sole_owner_of_the_holder_passkeys_is_admitted() {
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(sole_owner(&[alice], alice));
        assert!(!sole_owner(&[bob], alice));
        assert!(!sole_owner(&[alice, bob], alice));
        assert!(!sole_owner(&[], alice));
    }
    #[test]
    fn admission_keeps_the_global_capacity() {
        let mut pending = HashMap::new();
        for index in 0..CAPACITY {
            admit_pending(
                &mut pending,
                index.to_string(),
                entry(Uuid::new_v4(), "full"),
            )
            .unwrap();
        }
        assert_eq!(
            admit_pending(&mut pending, "over".into(), entry(Uuid::new_v4(), "over")),
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
    }
    #[tokio::test]
    async fn capabilities_are_separate_and_assertion_is_delivered_once() {
        let (requester, browser) = pending();
        assert!(status(Json(Token {
            token: browser.clone()
        }))
        .await
        .is_err());
        assert!(read(Json(Token {
            token: requester.clone()
        }))
        .await
        .is_err());
        assert!(read(Json(Token {
            token: browser.clone()
        }))
        .await
        .is_ok());
        let response = finish(Json(Finish {
            token: browser.clone(),
            assertion: Some(json!({"raw":"assertion"})),
        }))
        .await
        .unwrap();
        assert_eq!(response.0, json!({"status":"relayed"}));
        assert!(finish(Json(Finish {
            token: browser,
            assertion: Some(json!({}))
        }))
        .await
        .is_err());
        let result = status(Json(Token {
            token: requester.clone(),
        }))
        .await
        .unwrap()
        .0;
        assert_eq!(result["assertion"]["raw"], "assertion");
        assert!(status(Json(Token { token: requester })).await.is_err());
    }
    #[tokio::test]
    async fn requester_cancellation_rejects_late_browser_submission() {
        let (requester, browser) = pending();
        assert_eq!(cancel(Json(Token { token: requester.clone() })).await, StatusCode::NO_CONTENT);
        assert!(read(Json(Token { token: browser.clone() })).await.is_err());
        assert!(finish(Json(Finish {
            token: browser,
            assertion: Some(json!({"late": "assertion"})),
        })).await.is_err());
        assert!(status(Json(Token { token: requester })).await.is_err());
    }

    #[tokio::test]
    async fn cancellation_and_expiry_are_terminal() {
        let (requester, browser) = pending();
        let response = finish(Json(Finish {
            token: browser,
            assertion: None,
        }))
        .await
        .unwrap();
        assert_eq!(response.0, json!({"status":"relayed"}));
        assert_eq!(
            status(Json(Token { token: requester })).await.unwrap().0["status"],
            "cancelled"
        );
        let (requester, browser) = pending();
        store()
            .lock()
            .unwrap()
            .get_mut(&requester)
            .unwrap()
            .deadline = Instant::now();
        assert!(read(Json(Token { token: browser })).await.is_err());
        assert!(status(Json(Token { token: requester })).await.is_err());
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;

    pub(super) fn fixture() -> (Approval, Measurements) {
        let expiry = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120;
        let prepared: Prepared = serde_json::from_value(json!({
            "request_hash": "request", "session_id": "custody-session",
            "context": {"version":"V1", "bundle_hash":"bundle", "bundle_id":vec![1;16],
                "organization_id":vec![2;16], "holder":"holder", "holder_position":0,
                "certificate_index":0, "destination_policy":{"0":"ab".repeat(48),"1":"ab".repeat(48),"2":"ab".repeat(48)},
                "transport_nonce":"12".repeat(32), "expires_at_unix_seconds":expiry},
            "destination_attestation_hash":"destination", "destination_key":vec![3;32],
            "options":{"publicKey":{"challenge":"Y3VzdG9keS1jaGFsbGVuZ2U", "rpId":"example.com",
                "allowCredentials":[], "userVerification":"required", "timeout":120000}}
        })).unwrap();
        let mut approval = Approval {
            prepared: Attested {
                data: prepared,
                attestation: vec![],
            },
            nonce: "34".repeat(32),
            display: None,
        };
        synthetic_proof(&mut approval);
        (approval, (0..=2).map(|i| (i, "ab".repeat(48))).collect())
    }
    fn synthetic_proof(approval: &mut Approval) {
        let mut proof = b"caution-release-test-v1:".to_vec();
        proof.extend(
            serde_json::to_vec(&(
                &approval.nonce,
                release::hash(&approval.prepared.data).unwrap().as_bytes(),
            ))
            .unwrap(),
        );
        approval.prepared.attestation = proof;
    }
    #[test]
    fn login_options_and_invented_context_cannot_enter_relay() {
        let login = json!({"options":{"publicKey":{"challenge":"login-challenge","userVerification":"required"}},
            "context":{"holder":"victim"}, "context_hash":"invented"});
        assert!(serde_json::from_value::<Approval>(login).is_err());
        let (mut approval, pcrs) = fixture();
        approval.prepared.attestation.clear();
        assert!(verified_request(&approval, &pcrs, "example.com").is_err());
    }
    #[test]
    fn attestation_binds_challenge_display_and_expiry_with_all_synthetic_gates() {
        let enabled = cfg!(feature = "e2e-testing-unsafe")
            && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
        let (approval, pcrs) = fixture();
        let result = verified_request(&approval, &pcrs, "example.com");
        if !enabled {
            assert!(result.is_err());
            return;
        }
        let (display, ttl) = result.unwrap();
        assert_eq!(
            display["context_hash"],
            release::hash(&approval.prepared.data).unwrap()
        );
        assert_eq!(display["context"]["holder"], "holder");
        assert!(ttl.as_secs() <= 120);
        assert_eq!(display["destination_attestation_hash"], "destination");
        assert_eq!(display["custody_policy"], serde_json::to_value(&pcrs).unwrap());
        let (mut descriptive, _) = fixture();
        descriptive.display = Some(metadata::DisplayContext { application_id: Uuid::new_v4(),
            destination_address: "203.0.113.42:49504".parse().unwrap(), custody_url: "https://custody.example.test".into() });
        let original = verified_request(&descriptive, &pcrs, "example.com").unwrap().0;
        descriptive.display.as_mut().unwrap().application_id = Uuid::new_v4();
        assert_eq!(verified_request(&descriptive, &pcrs, "example.com").unwrap().0, original);
        for field in [
            "challenge",
            "holder",
            "destination",
            "nonce",
            "proof",
            "expiry",
            "rp",
            "uv",
        ] {
            let (mut changed, pcrs) = fixture();
            match field {
                "challenge" => {
                    let mut options = serde_json::to_value(&changed.prepared.data.options).unwrap();
                    options["publicKey"]["challenge"] = json!("bG9naW4tY2hhbGxlbmdl");
                    changed.prepared.data.options = serde_json::from_value(options).unwrap();
                }
                "holder" => changed.prepared.data.context.holder = "victim".into(),
                "destination" => changed.prepared.data.destination_key = [4; 32],
                "nonce" => changed.nonce = "56".repeat(32),
                "proof" => changed.prepared.attestation[0] ^= 1,
                "expiry" => {
                    changed.prepared.data.context.expires_at_unix_seconds = 0;
                    synthetic_proof(&mut changed);
                }
                "rp" | "uv" => {
                    let mut options = serde_json::to_value(&changed.prepared.data.options).unwrap();
                    options["publicKey"][if field == "rp" {
                        "rpId"
                    } else {
                        "userVerification"
                    }] = json!(if field == "rp" {
                        "wrong.example"
                    } else {
                        "preferred"
                    });
                    changed.prepared.data.options = serde_json::from_value(options).unwrap();
                    synthetic_proof(&mut changed);
                }
                _ => unreachable!(),
            }
            assert!(
                verified_request(&changed, &pcrs, "example.com").is_err(),
                "{field}"
            );
        }
        let wrong = (0..=2).map(|i| (i, "cd".repeat(48))).collect();
        assert!(verified_request(&approval, &wrong, "example.com").is_err());
    }
}
