//! A one-time UV ceremony for an existing credential; never changes login policy.
use super::passkey::PasskeyError;
use crate::{handlers::MAX_PENDING_CHALLENGES, types::*};
use axum::{
    extract::{Extension, Path, State},
    Json,
};
use dterror::ResultExt;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

#[derive(Serialize)]
pub struct BeginResponse {
    #[serde(flatten)]
    challenge: RequestChallengeResponse,
    session: String,
}

#[derive(Deserialize)]
pub struct FinishRequest {
    session: String,
    #[serde(flatten)]
    assertion: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct FinishResponse {
    uv_verified: bool,
}

pub async fn begin_recovery_verification(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Path(id): Path<Uuid>,
) -> Result<Json<BeginResponse>, PasskeyError> {
    use super::passkey::PasskeyErrorCtx as Ctx;
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT public_key FROM fido2_credentials WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::internal())?
    .ok_or_else(|| PasskeyError::CredentialNotFound {
        location: std::panic::Location::caller(),
    })?;
    let key: SecurityKey = serde_json::from_slice(&bytes).with_context(Ctx::internal())?;
    let credential_id = key.cred_id().as_ref().to_vec();
    let (mut challenge, auth_state) = state
        .webauthn
        .start_securitykey_authentication(&[key])
        .with_context(Ctx::internal())?;
    challenge.public_key.user_verification = UserVerificationPolicy::Required;
    let now = OffsetDateTime::now_utc();
    let mut pending = state.recovery_verifications.write().await;
    pending.retain(|_, item| item.expires_at > now);
    if pending.len() >= MAX_PENDING_CHALLENGES {
        return Err(PasskeyError::TooManyPending {
            location: std::panic::Location::caller(),
        });
    }
    let session = Uuid::new_v4().to_string();
    pending.insert(
        session.clone(),
        PendingRecoveryVerification {
            auth_state,
            user_id,
            credential_row_id: id,
            credential_id,
            expires_at: now + Duration::minutes(2),
        },
    );
    Ok(Json(BeginResponse { challenge, session }))
}

fn verify_assertion(
    webauthn: &Webauthn,
    pending: &PendingRecoveryVerification,
    user_id: Uuid,
    id: Uuid,
    assertion: &PublicKeyCredential,
) -> Result<AuthenticationResult, PasskeyError> {
    use super::passkey::PasskeyErrorCtx as Ctx;
    if pending.user_id != user_id || pending.credential_row_id != id {
        return Err(PasskeyError::Forbidden {
            location: std::panic::Location::caller(),
        });
    }
    if pending.expires_at <= OffsetDateTime::now_utc() {
        return Err(PasskeyError::ChallengeExpired {
            location: std::panic::Location::caller(),
        });
    }
    let result = webauthn
        .finish_securitykey_authentication(assertion, &pending.auth_state)
        .with_context(Ctx::bad_request())?;
    if !result.user_verified() {
        return Err(PasskeyError::UserVerificationRequired {
            location: std::panic::Location::caller(),
        });
    }
    Ok(result)
}

pub async fn finish_recovery_verification(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Path(id): Path<Uuid>,
    Json(request): Json<FinishRequest>,
) -> Result<Json<FinishResponse>, PasskeyError> {
    use super::passkey::PasskeyErrorCtx as Ctx;
    // Consume before validating so errors, expiry and concurrent finishes cannot replay.
    let pending = state
        .recovery_verifications
        .write()
        .await
        .remove(&request.session)
        .ok_or_else(|| PasskeyError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?;
    let result = verify_assertion(&state.webauthn, &pending, user_id, id, &request.assertion)?;
    let mut tx = state.db.begin().await.with_context(Ctx::internal())?;
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT public_key FROM fido2_credentials WHERE id = $1 AND user_id = $2 AND credential_id = $3 FOR UPDATE",
    ).bind(id).bind(user_id).bind(&pending.credential_id).fetch_optional(&mut *tx).await
        .with_context(Ctx::internal())?
        .ok_or_else(|| PasskeyError::CredentialNotFound { location: std::panic::Location::caller() })?;
    let mut key: SecurityKey = serde_json::from_slice(&bytes).with_context(Ctx::internal())?;
    if key.update_credential(&result).is_none() {
        return Err(PasskeyError::Forbidden {
            location: std::panic::Location::caller(),
        });
    }
    let updated = serde_json::to_vec(&key).with_context(Ctx::internal())?;
    sqlx::query(
        "UPDATE fido2_credentials SET uv_verified = true, public_key = $1,
        sign_count = GREATEST(sign_count, $2), updated_at = NOW() WHERE id = $3 AND user_id = $4",
    )
    .bind(updated)
    .bind(i64::from(result.counter()))
    .bind(id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::internal())?;
    tx.commit().await.with_context(Ctx::internal())?;
    Ok(Json(FinishResponse { uv_verified: true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_target_and_expiry_are_checked_before_verifying_the_assertion() {
        let origin = Url::parse("http://localhost:8000").unwrap();
        let webauthn = WebauthnBuilder::new("localhost", &origin)
            .unwrap()
            .build()
            .unwrap();
        let key: SecurityKey = serde_json::from_str(include_str!(
            "../../../../api/src/org_quorum/test-credential.json"
        ))
        .unwrap();
        let (_, auth_state) = webauthn
            .start_securitykey_authentication(&[key.clone()])
            .unwrap();
        let user_id = Uuid::new_v4();
        let id = Uuid::new_v4();
        let mut pending = PendingRecoveryVerification {
            auth_state,
            user_id,
            credential_row_id: id,
            credential_id: key.cred_id().as_ref().to_vec(),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(2),
        };
        let assertion = serde_json::from_value(serde_json::json!({
            "id":"AQ", "rawId":"AQ", "type":"public-key", "extensions":{},
            "response":{"authenticatorData":"AQ", "clientDataJSON":"AQ", "signature":"AQ", "userHandle":null}
        })).unwrap();
        assert!(matches!(
            verify_assertion(&webauthn, &pending, Uuid::new_v4(), id, &assertion),
            Err(PasskeyError::Forbidden { .. })
        ));
        assert!(matches!(
            verify_assertion(&webauthn, &pending, user_id, Uuid::new_v4(), &assertion),
            Err(PasskeyError::Forbidden { .. })
        ));
        pending.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        assert!(matches!(
            verify_assertion(&webauthn, &pending, user_id, id, &assertion),
            Err(PasskeyError::ChallengeExpired { .. })
        ));
    }
}
