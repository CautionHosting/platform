// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed tests of BYOC (linked account) apps on the deployments lifecycle.

use super::*;
use crate::app_deployments::account::{AppAccount, AppAccountError, app_account};
use serde_json::json;

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn byoc() {
    let pool = test_pool().await;
    let state = test_state(&pool, "/nonexistent");
    unlinked_apps_use_the_platform_account(&state).await;
    linked_networks_use_their_linked_account(&state).await;
    unreadable_linked_access_never_uses_platform_credentials(&state).await;
    relinking_another_environment_is_refused(&state).await;
    byoc_apps_follow_the_byoc_flag(&state).await;
    app_destroy_never_uses_platform_keys_on_a_linked_state(&pool).await;
    pool.close().await;
}

/// Seals `secrets` as `create_credential` does.
fn sealed(state: &AppState, secrets: serde_json::Value) -> Vec<u8> {
    state
        .encryptor
        .as_ref()
        .unwrap()
        .encrypt_json(&secrets)
        .unwrap()
}

/// Links `app` to the provisioner environment `dep-test` in us-east-1.
async fn link(state: &AppState, org: Uuid, app: Uuid, secrets: Vec<u8>) {
    let user = member(&state.db, org).await;
    sqlx::query(
        "INSERT INTO cloud_credentials
             (organization_id, resource_id, platform, managed_on_prem, identifier,
              secrets_encrypted, config, is_default, created_by)
         VALUES ($1, $2, 'aws', true, 'AKIATEST', $3, $4, false, $5)",
    )
    .bind(org)
    .bind(app)
    .bind(secrets)
    .bind(json!({
        "deployment_id": "dep-test", "aws_region": "us-east-1", "vpc_id": "vpc-test",
        "subnet_ids": ["subnet-a"], "eif_bucket": "bucket",
        "instance_profile_name": "profile", "aws_account_id": "210987654321",
    }))
    .bind(user)
    .execute(&state.db)
    .await
    .unwrap();
}

async fn set_network(pool: &PgPool, app: Uuid, network: serde_json::Value) {
    sqlx::query("UPDATE compute_resources SET app_network = $2 WHERE id = $1")
        .bind(app)
        .bind(network)
        .execute(pool)
        .await
        .unwrap();
}

fn keys() -> serde_json::Value {
    json!({"aws_access_key_id": "AKIALINKED", "aws_secret_access_key": "secret"})
}

async fn unlinked_apps_use_the_platform_account(state: &AppState) {
    let org = organization(&state.db).await;
    let app = deployments_app(&state.db, org).await;
    let account = app_account(state, app, "us-east-1").await.unwrap();
    assert!(matches!(account, AppAccount::Platform { ref region } if region == "us-east-1"));
    // A credential linked to an app whose network is in Caution's account
    // never moves its operations.
    set_network(&state.db, app, json!({"vpc_id": "vpc-managed"})).await;
    link(state, org, app, sealed(state, keys())).await;
    assert!(
        app_account(state, app, "us-east-1")
            .await
            .unwrap()
            .provider_credentials()
            .is_none()
    );
}

async fn linked_networks_use_their_linked_account(state: &AppState) {
    let org = organization(&state.db).await;
    let app = deployments_app(&state.db, org).await;
    link(state, org, app, sealed(state, keys())).await;
    set_network(
        &state.db,
        app,
        json!({"scope_tag": "dep-test", "vpc_id": "vpc-test"}),
    )
    .await;
    let account = app_account(state, app, "us-east-1").await.unwrap();
    assert_eq!(
        account.provider_credentials().unwrap().access_key_id,
        "AKIALINKED"
    );
    assert!(matches!(
        app_account(state, app, "us-west-2").await,
        Err(AppAccountError::EnvironmentChanged { .. })
    ));
    // Relinked to another environment since the network was created.
    set_network(
        &state.db,
        app,
        json!({"scope_tag": "dep-other", "vpc_id": "vpc-test"}),
    )
    .await;
    assert!(matches!(
        app_account(state, app, "us-east-1").await,
        Err(AppAccountError::EnvironmentChanged { .. })
    ));
}

async fn unreadable_linked_access_never_uses_platform_credentials(state: &AppState) {
    let pool = &state.db;
    let org = organization(pool).await;
    let network = json!({"scope_tag": "dep-test", "vpc_id": "vpc-test"});

    // Secrets that do not decrypt (rotated key, corruption).
    let corrupt = deployments_app(pool, org).await;
    link(state, org, corrupt, vec![0u8; 48]).await;
    set_network(pool, corrupt, network.clone()).await;
    assert!(matches!(
        app_account(state, corrupt, "us-east-1").await,
        Err(AppAccountError::Credential { .. })
    ));

    // Keys missing from the secrets.
    let keyless = deployments_app(pool, org).await;
    link(state, org, keyless, sealed(state, json!({}))).await;
    set_network(pool, keyless, network.clone()).await;
    assert!(matches!(
        app_account(state, keyless, "us-east-1").await,
        Err(AppAccountError::Unavailable { .. })
    ));

    // The credential was deleted while the network remains.
    let unlinked = deployments_app(pool, org).await;
    set_network(pool, unlinked, network).await;
    assert!(matches!(
        app_account(state, unlinked, "us-east-1").await,
        Err(AppAccountError::Unavailable { .. })
    ));

    // A linked app without a network (never pushed, a first push that failed
    // before its network, or a forced app destroy) uses its credential's account,
    // in the credential's region whatever the caller's.
    let networkless = deployments_app(pool, org).await;
    link(state, org, networkless, sealed(state, keys())).await;
    let account = app_account(state, networkless, "us-west-2").await.unwrap();
    let credentials = account.provider_credentials().unwrap();
    assert_eq!(
        (credentials.access_key_id.as_str(), account.region()),
        ("AKIALINKED", "us-east-1")
    );
    // Its unreadable access still fails, never Caution's account.
    let reseal = async |secrets: Vec<u8>| {
        sqlx::query("UPDATE cloud_credentials SET secrets_encrypted = $2 WHERE resource_id = $1")
            .bind(networkless)
            .bind(secrets)
            .execute(pool)
            .await
            .unwrap();
    };
    reseal(vec![0u8; 48]).await;
    assert!(matches!(
        app_account(state, networkless, "us-east-1").await,
        Err(AppAccountError::Credential { .. })
    ));
    reseal(sealed(state, json!({}))).await;
    assert!(matches!(
        app_account(state, networkless, "us-east-1").await,
        Err(AppAccountError::Unavailable { .. })
    ));
}

/// `caution init --byoc`'s link of an existing app (the update branch of
/// `create_managed_onprem_resource`), by `user`.
async fn relink(
    state: &Arc<AppState>,
    user: Uuid,
    app: Uuid,
    deployment_id: &str,
    vpc_id: &str,
    region: &str,
) -> Result<axum::Json<serde_json::Value>, crate::CreateManagedOnpremResourceError> {
    use axum::{Extension, extract::State};

    let body = json!({
        "platform": "aws", "managed_on_prem": true, "resource_id": app,
        "deployment_id": deployment_id, "vpc_id": vpc_id, "subnet_ids": ["subnet-a"],
        "eif_bucket": "bucket", "instance_profile_name": "profile",
        "asg_name": "asg", "launch_template_name": "template", "launch_template_id": "lt-1",
        "iam_user": "caution-user", "scope_tag": format!("caution:deployment-id={deployment_id}"),
        "aws_access_key_id": "AKIAROTATED", "aws_secret_access_key": "secret",
        "aws_region": region, "aws_account_id": "210987654321",
    })
    .to_string();
    crate::create_managed_onprem_resource(
        State(state.clone()),
        Extension(crate::AuthContext::session(user)),
        body,
    )
    .await
}

/// Relinking keeps the environment (provisioner deployment and region) an app
/// network lives in; rotating its keys works.
async fn relinking_another_environment_is_refused(state: &Arc<AppState>) {
    let pool = &state.db;
    let org = organization(pool).await;
    let user = member(pool, org).await;

    let app = deployments_app(pool, org).await;
    link(state, org, app, sealed(state, keys())).await;
    set_network(
        pool,
        app,
        json!({"scope_tag": "dep-test", "vpc_id": "vpc-test", "region": "us-east-1"}),
    )
    .await;
    for (deployment_id, region) in [("dep-other", "us-east-1"), ("dep-test", "us-west-2")] {
        let error = relink(state, user, app, deployment_id, "vpc-test", region)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                crate::CreateManagedOnpremResourceError::LinkedNetworkChanged { .. }
            ),
            "{deployment_id} in {region}: {error:?}"
        );
    }
    // A relink does not compare VPCs: a `provider` block may have given the
    // network another one than the provisioner's.
    for vpc_id in ["vpc-test", "vpc-other"] {
        let _ = relink(state, user, app, "dep-test", vpc_id, "us-east-1")
            .await
            .expect("rotating the keys of the same environment");
    }

    // A fully managed network never takes a linked account.
    let managed = deployments_app(pool, org).await;
    set_network(
        pool,
        managed,
        json!({"vpc_id": "vpc-managed", "region": "us-east-1"}),
    )
    .await;
    assert!(matches!(
        relink(state, user, managed, "dep-test", "vpc-test", "us-east-1").await,
        Err(crate::CreateManagedOnpremResourceError::LinkedNetworkChanged { .. })
    ));
}

async fn lifecycle(pool: &PgPool, app: Uuid) -> String {
    crate::app_deployments::app_lifecycle(pool, app)
        .await
        .unwrap()
        .unwrap()
}

/// Interactive `caution init --byoc` creates the app through `POST /resources`,
/// then links it: that first link of a pristine app applies the BYOC flag. Any
/// other link keeps the app's lifecycle.
async fn byoc_apps_follow_the_byoc_flag(state: &Arc<AppState>) {
    use crate::app_deployments::{
        LIFECYCLE_DEPLOYMENTS, LIFECYCLE_LEGACY, assign_byoc_lifecycle, byoc_enabled_for_new_apps,
        lifecycle_for_new_app,
    };

    let pool = &state.db;
    let org = organization(pool).await;
    let set_lifecycle = async |app: Uuid, value: &str| {
        sqlx::query("UPDATE compute_resources SET lifecycle = $2 WHERE id = $1")
            .bind(app)
            .bind(value)
            .execute(pool)
            .await
            .unwrap();
    };

    // Pristine apps take the flag, whatever `POST /resources` gave them.
    let app = deployments_app(pool, org).await;
    assert!(assign_byoc_lifecycle(pool, app, false).await.unwrap());
    assert_eq!(lifecycle(pool, app).await, LIFECYCLE_LEGACY);
    let app = deployments_app(pool, org).await;
    set_lifecycle(app, LIFECYCLE_LEGACY).await;
    assert!(assign_byoc_lifecycle(pool, app, true).await.unwrap());
    assert_eq!(lifecycle(pool, app).await, LIFECYCLE_DEPLOYMENTS);

    // Any other app keeps its lifecycle, whatever the flag.
    let with_region = deployments_app(pool, org).await;
    sqlx::query("UPDATE compute_resources SET region = 'us-east-1' WHERE id = $1")
        .bind(with_region)
        .execute(pool)
        .await
        .unwrap();
    let with_network = deployments_app(pool, org).await;
    set_network(
        pool,
        with_network,
        json!({"vpc_id": "vpc-managed", "region": "us-east-1"}),
    )
    .await;
    let with_deployment = deployments_app(pool, org).await;
    deployment(pool, org, with_deployment, "failed", None).await;
    let linked = deployments_app(pool, org).await;
    link(state, org, linked, sealed(state, keys())).await;
    for app in [with_region, with_network, with_deployment, linked] {
        for byoc_enabled in [false, true] {
            assert!(
                !assign_byoc_lifecycle(pool, app, byoc_enabled)
                    .await
                    .unwrap(),
                "{app} with the flag {byoc_enabled}"
            );
            assert_eq!(lifecycle(pool, app).await, LIFECYCLE_DEPLOYMENTS);
        }
    }

    // Through the handler, a relink keeps the lifecycle: the app is on the
    // lifecycle the flag would not give it.
    let kept = if lifecycle_for_new_app(byoc_enabled_for_new_apps()) == LIFECYCLE_LEGACY {
        LIFECYCLE_DEPLOYMENTS
    } else {
        LIFECYCLE_LEGACY
    };
    let user = member(pool, org).await;
    let relinked = deployments_app(pool, org).await;
    set_lifecycle(relinked, kept).await;
    link(state, org, relinked, sealed(state, keys())).await;
    let _ = relink(state, user, relinked, "dep-test", "vpc-test", "us-east-1")
        .await
        .expect("relinking the same environment");
    assert_eq!(lifecycle(pool, relinked).await, kept);
}

/// App destroy resolves a deployments app's account: a linked app state whose
/// access is gone is kept (the destroy fails and is retried), never destroyed
/// with Caution's keys, which would drop its Elastic IP from the state.
async fn app_destroy_never_uses_platform_keys_on_a_linked_state(pool: &PgPool) {
    // App destroy takes its teardown lock on a connection of its own.
    let mut state = Arc::into_inner(test_state(pool, "/nonexistent")).unwrap();
    state.database_url = std::env::var("APP_DEPLOYMENTS_TEST_DATABASE_URL").unwrap();
    let state = Arc::new(state);

    let org = organization(pool).await;
    let app = deployments_app(pool, org).await;
    sqlx::query("UPDATE compute_resources SET region = 'us-east-1' WHERE id = $1")
        .bind(app)
        .execute(pool)
        .await
        .unwrap();
    // The credential was deleted while the network remains.
    set_network(
        pool,
        app,
        json!({"scope_tag": "dep-test", "vpc_id": "vpc-test", "region": "us-east-1"}),
    )
    .await;

    let error = crate::resources::destroy_resource_by_id(&state, app, false)
        .await
        .unwrap_err();
    let source = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<AppAccountError>());
    assert!(
        matches!(source, Some(AppAccountError::Unavailable { .. })),
        "{error:?}"
    );
    let (app_state, has_network): (String, bool) = sqlx::query_as(
        "SELECT state::text, app_network IS NOT NULL FROM compute_resources WHERE id = $1",
    )
    .bind(app)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((app_state.as_str(), has_network), ("terminating", true));
}
