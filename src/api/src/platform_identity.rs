//! Persistent identity shared by the API processes using one platform database.

use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use uuid::Uuid;

/// Failure to read the identity installed by the platform migration.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadPlatformIdError {
    #[error("could not load platform identity [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Load the existing identity; never generate a replacement during API startup.
#[tracing::instrument(skip_all, err)]
pub(crate) async fn load(db: &PgPool) -> Result<Uuid, LoadPlatformIdError> {
    use LoadPlatformIdErrorCtx as Ctx;
    sqlx::query_scalar("SELECT id FROM platform_identity WHERE singleton AND id <> '00000000-0000-0000-0000-000000000000'::uuid")
        .fetch_one(db)
        .await
        .with_context(Ctx::query())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = false)]
    #[ignore = "requires disposable PostgreSQL via DATABASE_URL"]
    async fn identity_survives_replay_and_missing_identity_fails_closed(db: PgPool) {
        let migration = include_str!("../migrations/054_platform_identity.sql");
        assert!(load(&db).await.is_err());
        sqlx::raw_sql(migration).execute(&db).await.unwrap();
        let first = load(&db).await.unwrap();
        assert!(!first.is_nil());
        sqlx::raw_sql(migration).execute(&db).await.unwrap();
        let (replica_a, replica_b) = tokio::join!(load(&db), load(&db));
        assert_eq!(first, replica_a.unwrap());
        assert_eq!(first, replica_b.unwrap());
        assert!(
            sqlx::query("UPDATE platform_identity SET id = '00000000-0000-0000-0000-000000000000'")
                .execute(&db)
                .await
                .is_err()
        );
        sqlx::query("DELETE FROM platform_identity")
            .execute(&db)
            .await
            .unwrap();
        assert!(load(&db).await.is_err());
    }
}
