// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use super::*;

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn builders_do_not_consume_legacy_instance_meter_slot() {
    let pool = test_pool().await;
    let f = fixture(&pool, "running").await;
    let insert = |resource: String, metadata: serde_json::Value| {
        sqlx::query(
            "INSERT INTO tracked_resources
                 (resource_id, organization_id, application_id, provider, status, metadata)
             VALUES ($1, $2, $3, 'aws', 'running', $4)",
        )
        .bind(resource)
        .bind(f.org)
        .bind(f.app)
        .bind(metadata)
    };
    insert(format!("i-legacy-{}", f.app), serde_json::json!({}))
        .execute(&pool)
        .await
        .unwrap();
    // Both current and historical builder metadata must coexist with a live instance.
    for metadata in [
        serde_json::json!({"resource_type": "builder"}),
        serde_json::json!({"build_id": Uuid::new_v4()}),
    ] {
        insert(format!("i-builder-{}", Uuid::new_v4()), metadata)
            .execute(&pool)
            .await
            .expect("a running builder must not conflict with the live instance meter");
    }
    // API startup replays these migrations over running applications and builders.
    for migration in [
        include_str!("../../../../migrations/030_tracked_resource_application_id.sql"),
        include_str!("../../../../migrations/056_app_deployments.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    }
    let error = insert(format!("i-second-legacy-{}", f.app), serde_json::json!({}))
        .execute(&pool)
        .await
        .expect_err("two live legacy instance meters still conflict");
    assert_eq!(
        error.as_database_error().unwrap().constraint(),
        Some("idx_tracked_resources_active_legacy_application")
    );
    pool.close().await;
}
