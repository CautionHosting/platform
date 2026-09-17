// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
//! Opaque browser assertion relay. This service cannot authorize or perform share release.
use crate::types::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

struct Pending {
    browser: String,
    deadline: Instant,
    request: Value,
    result: Option<Value>,
}
static PENDING: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
fn store() -> &'static Mutex<HashMap<String, Pending>> {
    PENDING.get_or_init(Default::default)
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

pub async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    crate::handlers::authenticate_session(&state, &headers)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if request["options"]["publicKey"]["userVerification"] != "required"
        || !request["options"]["publicKey"]["challenge"].is_string()
        || !request["context"].is_object()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let browser = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let mut pending = store()
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    pending.retain(|_, p| p.deadline > Instant::now());
    if pending.len() >= 128 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    pending.insert(
        token.clone(),
        Pending {
            browser: browser.clone(),
            deadline: Instant::now() + Duration::from_secs(180),
            request,
            result: None,
        },
    );
    // Browser and requester capabilities are distinct. Assertions are delivered only to the requester.
    Ok(Json(
        json!({"token":token,"url":format!("{}/qr-release#{}",crate::handlers::get_rp_origin(),browser)}),
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
        store().lock().unwrap().insert(
            requester.clone(),
            Pending {
                browser: browser.clone(),
                deadline: Instant::now() + Duration::from_secs(180),
                request: json!({"context":{"holder":"test"}}),
                result: None,
            },
        );
        (requester, browser)
    }
    #[tokio::test]
    async fn capabilities_are_separate_and_assertion_is_delivered_once() {
        let (requester, browser) = pending();
        assert!(
            status(Json(Token {
                token: browser.clone()
            }))
            .await
            .is_err()
        );
        assert!(
            read(Json(Token {
                token: requester.clone()
            }))
            .await
            .is_err()
        );
        assert!(
            read(Json(Token {
                token: browser.clone()
            }))
            .await
            .is_ok()
        );
        finish(Json(Finish {
            token: browser.clone(),
            assertion: Some(json!({"raw":"assertion"})),
        }))
        .await
        .unwrap();
        assert!(
            finish(Json(Finish {
                token: browser,
                assertion: Some(json!({}))
            }))
            .await
            .is_err()
        );
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
    async fn cancellation_and_expiry_are_terminal() {
        let (requester, browser) = pending();
        finish(Json(Finish {
            token: browser,
            assertion: None,
        }))
        .await
        .unwrap();
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
