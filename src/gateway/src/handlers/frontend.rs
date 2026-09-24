// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{Path as RoutePath, Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use std::path::{Path, PathBuf};
use tower::Service;
use tower_http::services::ServeFile;

const VERIFY_E2EE_CLIENT_PATH: &str =
    "/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137";

#[tracing::instrument(skip_all)]
async fn redirect_verify_e2ee() -> Redirect {
    Redirect::permanent("/verify-e2ee/")
}

#[tracing::instrument(skip_all)]
async fn serve_verify_e2ee_target(
    RoutePath(scope): RoutePath<String>,
    State(frontend_index): State<PathBuf>,
    request: Request,
) -> Response {
    if scope.len() != 64
        || !scope
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || request.uri().path() != format!("{VERIFY_E2EE_CLIENT_PATH}/targets/{scope}/")
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    ServeFile::new(frontend_index)
        .call(request)
        .await
        .expect("ServeFile is infallible")
        .map(Body::new)
}

pub(crate) fn build_frontend_routes(frontend_dir: &Path) -> Router {
    let frontend_index = frontend_dir.join("index.html");
    let target_route = format!("{VERIFY_E2EE_CLIENT_PATH}/targets/{{scope}}/");

    Router::new()
        .route_service("/login", ServeFile::new(frontend_index.clone()))
        .route_service("/onboarding", ServeFile::new(frontend_index.clone()))
        .route_service("/invite", ServeFile::new(frontend_index.clone()))
        .route_service("/reset", ServeFile::new(frontend_index.clone()))
        .route_service("/dashboard", ServeFile::new(frontend_index.clone()))
        .route_service("/qr-login", ServeFile::new(frontend_index.clone()))
        .route_service("/qr-release", ServeFile::new(frontend_index.clone()))
        .route_service("/qr-sign", ServeFile::new(frontend_index.clone()))
        .route_service("/components", ServeFile::new(frontend_index.clone()))
        .route_service("/verify", ServeFile::new(frontend_index.clone()))
        .route("/verify-e2ee", get(redirect_verify_e2ee))
        .route_service("/verify-e2ee/", ServeFile::new(frontend_index.clone()))
        .route(&target_route, get(serve_verify_e2ee_target))
        .with_state(frontend_index)
}

#[cfg(test)]
mod tests {
    use super::{build_frontend_routes, VERIFY_E2EE_CLIENT_PATH};
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        middleware,
    };
    use tower::Service;
    use tower_http::services::ServeDir;

    async fn get(app: &mut axum::Router, path: &str) -> axum::response::Response {
        app.call(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn components_is_public_html() {
        let (_dir, mut app) = test_frontend();
        let response = get(&mut app, "/components").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .contains("text/html")
        );
    }

    fn test_frontend() -> (tempfile::TempDir, axum::Router) {
        let dir = tempfile::tempdir().unwrap();
        let client_dir = dir
            .path()
            .join(VERIFY_E2EE_CLIENT_PATH.trim_start_matches('/'));
        std::fs::create_dir_all(client_dir.join("xwing")).unwrap();
        std::fs::write(dir.path().join("index.html"), "<main>verifier</main>").unwrap();
        std::fs::write(client_dir.join("register.js"), "export {};").unwrap();
        std::fs::write(client_dir.join("enclave-sw.js"), "self.onfetch = null;").unwrap();
        std::fs::write(client_dir.join("xwing/steve_xwing_wasm_bg.wasm"), b"\0asm").unwrap();

        let app = build_frontend_routes(dir.path())
            .fallback_service(ServeDir::new(dir.path()).append_index_html_on_directories(true))
            .layer(middleware::from_fn(
                crate::security_headers::security_headers_middleware,
            ));

        (dir, app)
    }

    #[tokio::test]
    async fn verify_e2ee_routes_are_public_and_canonical() {
        let (_dir, mut app) = test_frontend();

        let redirect = get(&mut app, "/verify-e2ee").await;
        assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(redirect.headers()[header::LOCATION], "/verify-e2ee/");

        let index = get(&mut app, "/verify-e2ee/").await;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(index.headers()[header::CONTENT_TYPE], "text/html");
    }

    #[tokio::test]
    async fn verify_e2ee_only_serves_deterministic_target_pages() {
        let (_dir, mut app) = test_frontend();
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let target = format!(
            "{VERIFY_E2EE_CLIENT_PATH}/targets/{hash}/?origin=https%3A%2F%2Fexample.com&suite=X25519"
        );

        let response = get(&mut app, &target).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");

        for invalid in [
            "/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/targets/not-a-sha256/",
            "/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/targets/ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789/",
            "/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/targets/%610123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde/",
            "/verify-e2ee/client/wrong/targets/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/",
            "/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/targets/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let response = get(&mut app, invalid).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{invalid}");
        }
    }

    #[tokio::test]
    async fn verify_e2ee_artifacts_have_safe_content_types() {
        let (_dir, mut app) = test_frontend();

        for (relative_path, content_type) in [
            ("register.js", "text/javascript"),
            ("enclave-sw.js", "text/javascript"),
            ("xwing/steve_xwing_wasm_bg.wasm", "application/wasm"),
        ] {
            let path = format!("{VERIFY_E2EE_CLIENT_PATH}/{relative_path}");
            let response = get(&mut app, &path).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("worker-src 'self'"));
        }
    }
}
