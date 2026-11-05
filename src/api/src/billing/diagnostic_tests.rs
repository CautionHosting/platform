// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use tracing::instrument::WithSubscriber;

#[tokio::test]
#[ignore = "requires disposable DIAGNOSTICS_TEST_DATABASE_URL (PostgreSQL on loopback)"]
async fn paddle_error_bodies_never_reach_billing_diagnostics() {
    let url = std::env::var("DIAGNOSTICS_TEST_DATABASE_URL").unwrap();
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_diagnostics_test");
    // Session-local tables: do not alter any shared schema or existing records.
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE organization_members (id UUID, organization_id UUID, user_id UUID, created_at TIMESTAMPTZ DEFAULT NOW());
        CREATE TEMP TABLE billing_config (organization_id UUID, paddle_customer_id TEXT);
        CREATE TEMP TABLE payment_methods (id UUID, organization_id UUID, is_primary BOOL, paddle_payment_method_id TEXT, is_active BOOL);")
        .execute(&db).await.unwrap();
    let org = Uuid::new_v4();
    let user = Uuid::new_v4();
    let method = Uuid::new_v4();
    sqlx::query("INSERT INTO organization_members VALUES ($1, $2, $3, NOW())")
        .bind(Uuid::new_v4())
        .bind(org)
        .bind(user)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO payment_methods VALUES ($1, $2, false, 'paymtd_fixture', true), ($3, $2, true, 'paymtd_other', true)")
        .bind(method).bind(org).bind(Uuid::new_v4()).execute(&db).await.unwrap();
    sqlx::query("INSERT INTO billing_config VALUES ($1, 'ctm_fixture')")
        .bind(org)
        .execute(&db)
        .await
        .unwrap();

    let marker = "synthetic-private-provider-response";
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = requests.clone();
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        seen.lock().unwrap().push((request.method().clone(), request.uri().path().to_owned()));
        async move {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": {"detail": marker, "email": "synthetic-private-billing@example.invalid"}
            })))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    let log_path = temp.path().join("billing.log");
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(std::sync::Mutex::new(
            std::fs::File::create(&log_path).unwrap(),
        ))
        .finish();
    let state = Arc::new(AppState {
        db: db.clone(),
        database_url: String::new(),
        teardown_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        git_hostname: "git.example.invalid".into(),
        git_ssh_port: None,
        data_dir: temp.path().to_str().unwrap().into(),
        encryptor: None,
        internal_service_secret: None,
        paddle_client_token: Some("fixture-client-token".into()),
        paddle_setup_price_id: None,
        paddle_credits_price_ids: [None, None, None],
        paddle_api_url: endpoint,
        paddle_api_key: Some("fixture-api-key".into()),
        pricing: crate::PricingConfig {
            compute_margin_percent: 0.0,
            subscription_tiers: caution_config::pricing::DuplicateCheckedTiers(Default::default()),
            credit_packages: Default::default(),
            paddle_catalog: None,
        },
        builder_config: crate::builder::BuilderConfig {
            ami_id: String::new(),
            security_group_id: String::new(),
            subnet_id: String::new(),
            instance_profile: String::new(),
            region: "us-west-2".into(),
            timeout_secs: 1,
            eif_s3_bucket: String::new(),
            git_hostname: String::new(),
            additional_instance_tags: Vec::new(),
        },
        builder_sizes: crate::builder::BuilderSizesConfig {
            builder_sizes: Vec::new(),
            max_resources_per_org: 1,
        },
        eif_download_cache: crate::eif_download::EifDownloadCache::new(
            temp.path().to_str().unwrap(),
            1,
        ),
        managed_dns: None,
    });
    async {
        let error = delete_payment_method(
            State(state.clone()),
            Extension(AuthContext::session(user)),
            Path(method),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            DeletePaymentMethodError::PaddleAgreement { .. }
        ));
        assert!(!format!("{error:?}").contains(marker));
        // No customer avoids the unrelated customer-auth-token request.
        sqlx::query("UPDATE billing_config SET paddle_customer_id = NULL")
            .execute(&db)
            .await
            .unwrap();
        let request = serde_json::from_value(serde_json::json!({"amount_cents": 10000})).unwrap();
        let error = purchase_credits(
            State(state),
            Extension(AuthContext::session(user)),
            Json(request),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PurchaseCreditsError::PaddleStatus { .. }));
        assert!(!format!("{error:?}").contains(marker));
    }
    .with_subscriber(subscriber)
    .await;
    server.abort();
    db.close().await;
    assert_eq!(
        *requests.lock().unwrap(),
        [
            (
                axum::http::Method::DELETE,
                "/customers/ctm_fixture/payment-methods/paymtd_fixture".into()
            ),
            (axum::http::Method::POST, "/transactions".into()),
        ]
    );
    let logs = std::fs::read_to_string(log_path).unwrap();
    assert!(logs.contains("Failed to delete Paddle payment method"));
    assert!(logs.contains("Paddle transaction failed"));
    assert!(logs.contains("400"));
    assert!(!logs.contains(marker));
    assert!(!logs.contains("synthetic-private-billing@example.invalid"));
}
