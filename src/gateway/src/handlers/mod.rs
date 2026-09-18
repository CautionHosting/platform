// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{response::IntoResponse, Json};

mod common;
mod credentials;
#[cfg(feature = "e2e-testing-unsafe")]
mod e2e;
pub(crate) mod frontend;
mod proxy;
mod qr_auth;
mod user_profile;
mod webauthn;

pub(crate) use proxy::{build_api_target_url, metering_proxy_handler, proxy_handler};
pub(crate) use webauthn::reset as reset_webauthn;

#[cfg(feature = "e2e-testing-unsafe")]
pub(crate) use e2e::e2e_login_handler;

pub(crate) use user_profile::{claim_username_handler, get_username_status_handler};

pub(crate) use credentials::{
    add_pgp_key_handler, add_ssh_key_handler, begin_add_passkey_handler, delete_passkey_handler,
    delete_ssh_key_handler, finish_add_passkey_handler, list_passkeys_handler,
    list_pgp_keys_handler, list_ssh_keys_handler, remove_pgp_key_handler,
};

pub(crate) use qr_auth::{
    authenticate_session, begin_sign_request_handler, get_rp_origin,
    qr_login_authenticate_finish_handler, qr_login_authenticate_handler, qr_login_begin_handler,
    qr_login_status_handler, qr_sign_authenticate_finish_handler, qr_sign_authenticate_handler,
    qr_sign_begin_handler, qr_sign_status_handler,
};

pub(crate) use common::{
    build_auth_cookies, generic_auth_failure_response, read_credprops_rk,
    relax_registration_extensions, DomainError, LoginError, LoginErrorCtx, RegisterBeginResponse,
    RegisterError, RegisterErrorCtx, SignRequestError, SignRequestErrorCtx, MAX_PENDING_CHALLENGES,
};

pub(crate) use webauthn::{
    begin_invite_register_handler, begin_login_handler, begin_register_handler,
    check_username_scope, finish_login_handler, finish_register_handler, invite_preview_handler,
    logout_handler, normalize_login_username, scoped_or_decoy_challenge,
    validate_decoy_timing_fixtures, UsernameScope,
};

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}
