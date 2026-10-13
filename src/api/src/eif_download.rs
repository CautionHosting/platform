use axum::{
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::SystemTime};
use tokio::{fs, io::AsyncWriteExt, sync::Semaphore};
use tower::Service;
use tower_http::services::fs::ServeFile;
use uuid::Uuid;

use crate::{AppState, AuthContext, cloud_credentials, deployment};

const SUBDIR: &str = "eif-cache";

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum EnsureCachedError {
    #[error("failed to acquire download lock [{location}]")]
    AcquirePermit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to download EIF from S3 [{location}]")]
    S3Download {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create cache directory [{location}]")]
    CreateCacheDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create temp file [{location}]")]
    CreateTempFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read EIF data from S3 stream [{location}]")]
    ReadStream {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to write EIF data to temp file [{location}]")]
    WriteFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to flush temp file [{location}]")]
    FlushFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to rename temp file to final cache path [{location}]")]
    RenameFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to evict LRU cache entries [{location}]")]
    EvictLru {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum EvictLruError {
    #[error("failed to remove cached EIF file '{path}' [{location}]")]
    RemoveFile {
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DownloadEifError {
    #[error("insufficient permissions [{location}]")]
    Forbidden { location: Location },

    #[error("database error [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no completed builds found for this resource [{location}]")]
    BuildNotFound { location: Location },

    #[error("this app does not use deployments [{location}]")]
    DeploymentsNotUsed { location: Location },

    #[error("credential error [{location}]")]
    CredentialError {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("encryption not configured [{location}]")]
    EncryptionNotConfigured { location: Location },

    #[error("failed to decrypt managed on-prem credential [{location}]")]
    ManagedCredentialDecrypt {
        #[location]
        location: Location,
        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },

    #[error("failed to prepare cached EIF for serving [{location}]")]
    CachedEifNotAvailable {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DownloadEifError {
    fn into_response(self) -> Response<Body> {
        let (status, body) = match &self {
            DownloadEifError::Forbidden { .. } => {
                (StatusCode::FORBIDDEN, "insufficient permissions")
            }
            DownloadEifError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database error")
            }
            DownloadEifError::BuildNotFound { .. } => (
                StatusCode::NOT_FOUND,
                "no completed builds found for this resource",
            ),
            DownloadEifError::DeploymentsNotUsed { .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "This app does not use deployments.",
            ),
            DownloadEifError::CredentialError { .. } => {
                (StatusCode::BAD_REQUEST, "credential error")
            }
            DownloadEifError::EncryptionNotConfigured { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "encryption not configured")
            }
            DownloadEifError::ManagedCredentialDecrypt { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to decrypt managed on-prem credential",
            ),
            DownloadEifError::CachedEifNotAvailable { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to prepare cached EIF",
            ),
        };
        (status, body).into_response()
    }
}

#[derive(Clone)]
pub(crate) struct EifDownloadCache {
    data_dir: PathBuf,
    max_cache_size: u64,
    in_flight: Arc<tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>>,
}

impl EifDownloadCache {
    pub(crate) fn new(data_dir: &str, max_cache_size_gb: u64) -> Self {
        Self {
            data_dir: PathBuf::from(data_dir),
            max_cache_size: max_cache_size_gb * 1024 * 1024 * 1024,
            in_flight: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    fn cache_path(&self, s3_key: &str) -> PathBuf {
        let sanitized: String = s3_key
            .chars()
            .map(|c| if c == '/' { '_' } else { c })
            .collect();
        self.data_dir.join(SUBDIR).join(sanitized)
    }

    #[tracing::instrument(skip_all, err)]
    pub(crate) async fn ensure_cached(
        &self,
        s3_client: &aws_sdk_s3::Client,
        bucket: &str,
        s3_key: &str,
    ) -> Result<PathBuf, EnsureCachedError> {
        use EnsureCachedErrorCtx as Ctx;

        let cache_path = self.cache_path(s3_key);

        if cache_path.exists() {
            return Ok(cache_path);
        }

        let semaphore = {
            let mut map = self.in_flight.lock().await;
            map.entry(s3_key.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(1)))
                .clone()
        };

        let permit = semaphore
            .acquire()
            .await
            .with_context(Ctx::acquire_permit())?;

        if cache_path.exists() {
            return Ok(cache_path);
        }

        tracing::info!("Downloading EIF from s3://{}/{}", bucket, s3_key);

        let response = s3_client
            .get_object()
            .bucket(bucket)
            .key(s3_key)
            .send()
            .await
            .with_context(Ctx::s3_download())?;

        let mut stream = response.body;
        let temp_dir = self.data_dir.join(SUBDIR);
        fs::create_dir_all(&temp_dir)
            .await
            .with_context(Ctx::create_cache_dir())?;

        let temp_path = temp_dir.join(format!(
            ".{}.tmp",
            cache_path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let mut file = fs::File::create(&temp_path)
            .await
            .with_context(Ctx::create_temp_file())?;

        while let Some(chunk) = stream.try_next().await.with_context(Ctx::read_stream())? {
            file.write_all(&chunk)
                .await
                .with_context(Ctx::write_file())?;
        }
        file.flush().await.with_context(Ctx::flush_file())?;
        drop(permit);

        fs::rename(&temp_path, &cache_path)
            .await
            .with_context(Ctx::rename_file())?;

        self.evict_lru().await.with_context(Ctx::evict_lru())?;

        tracing::info!("Cached EIF to {}", cache_path.display());
        Ok(cache_path)
    }

    #[tracing::instrument(skip_all, err)]
    async fn evict_lru(&self) -> Result<(), EvictLruError> {
        use EvictLruErrorCtx as Ctx;

        let cache_dir = self.data_dir.join(SUBDIR);
        let Ok(mut entries) = fs::read_dir(&cache_dir).await else {
            return Ok(());
        };

        let mut files: Vec<(PathBuf, SystemTime)> = Vec::new();
        let mut total_size: u64 = 0;

        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(meta) = entry.metadata().await
                && meta.is_file()
            {
                let accessed = meta
                    .accessed()
                    .unwrap_or_else(|_| meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
                total_size += meta.len();
                files.push((entry.path(), accessed));
            }
        }

        if total_size <= self.max_cache_size {
            return Ok(());
        }

        let target = self.max_cache_size - self.max_cache_size / 10;
        files.sort_by_key(|(_, accessed)| *accessed);

        for (path, _) in files {
            if total_size <= target {
                break;
            }
            if let Ok(meta) = fs::metadata(&path).await {
                total_size -= meta.len();
            }
            match fs::remove_file(&path).await {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                result => result.with_context(Ctx::remove_file(path))?,
            }
        }

        Ok(())
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct BuildDownloadRow {
    pub(crate) eif_s3_key: String,
    pub(crate) eif_sha256: String,
    #[allow(dead_code)]
    eif_size_bytes: i64,
    pub(crate) resource_name: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct DownloadEifParams {
    /// A deployment of the app; the live one when omitted.
    deployment: Option<Uuid>,
}

/// Which EIF to serve.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EifSource {
    /// Legacy app: the latest completed build.
    LatestBuild,
    /// Deployments app: the build stored under this S3 key.
    Key(String),
}

/// `(lifecycle, deployment id, deployment EIF key, app configuration EIF key)`
/// of the requested deployment, or of the live one.
type EifSourceRow = (String, Option<Uuid>, Option<String>, Option<String>);

/// A requested deployment never falls back to the live EIF.
fn decide_eif_source(
    row: Option<EifSourceRow>,
    requested: Option<Uuid>,
) -> Result<EifSource, DownloadEifError> {
    let not_found = || DownloadEifError::BuildNotFound {
        location: std::panic::Location::caller(),
    };
    let (lifecycle, deployment_id, deployment_key, configuration_key) =
        row.ok_or_else(not_found)?;
    if lifecycle != crate::app_deployments::LIFECYCLE_DEPLOYMENTS {
        return match requested {
            Some(_) => Err(DownloadEifError::DeploymentsNotUsed {
                location: std::panic::Location::caller(),
            }),
            None => Ok(EifSource::LatestBuild),
        };
    }
    // Unknown or another app's deployment, or nothing live.
    deployment_id.ok_or_else(not_found)?;
    let key = match requested {
        Some(_) => deployment_key,
        None => deployment_key.or(configuration_key),
    };
    key.map(EifSource::Key).ok_or_else(not_found)
}

pub(crate) async fn resolve_eif_source(
    db: &sqlx::PgPool,
    org_id: Uuid,
    resource_id: Uuid,
    requested: Option<Uuid>,
) -> Result<EifSource, DownloadEifError> {
    let row: Option<EifSourceRow> = sqlx::query_as(
        r"SELECT cr.lifecycle, d.id, d.eif_s3_key, cr.configuration->>'eif_s3_key'
          FROM compute_resources cr
          LEFT JOIN app_deployments d
            ON d.app_id = cr.id AND d.id = COALESCE($3, cr.live_deployment_id)
          WHERE cr.id = $1 AND cr.organization_id = $2",
    )
    .bind(resource_id)
    .bind(org_id)
    .bind(requested)
    .fetch_optional(db)
    .await
    .with_context(DownloadEifErrorCtx::database())?;
    decide_eif_source(row, requested)
}

type BuildTuple = (String, String, i64, Option<String>);

fn build_row(
    (eif_s3_key, eif_sha256, eif_size_bytes, resource_name): BuildTuple,
) -> BuildDownloadRow {
    BuildDownloadRow {
        eif_s3_key,
        eif_sha256,
        eif_size_bytes,
        resource_name,
    }
}

/// Legacy: the app's latest completed build.
async fn latest_build(
    db: &sqlx::PgPool,
    org_id: Uuid,
    resource_id: Uuid,
) -> Result<Option<BuildDownloadRow>, sqlx::Error> {
    sqlx::query_as::<_, BuildTuple>(
        r"SELECT eb.eif_s3_key, eb.eif_sha256, eb.eif_size_bytes, cr.resource_name
          FROM eif_builds eb
          JOIN compute_resources cr ON cr.id = eb.app_id
          WHERE eb.app_id = $1 AND eb.organization_id = $2 AND eb.status = 'completed'
          ORDER BY eb.completed_at DESC NULLS LAST
          LIMIT 1",
    )
    .bind(resource_id)
    .bind(org_id)
    .fetch_optional(db)
    .await
    .map(|row| row.map(build_row))
}

/// The completed build stored under `eif_s3_key`, named after the app.
pub(crate) async fn build_for_key(
    db: &sqlx::PgPool,
    org_id: Uuid,
    resource_id: Uuid,
    eif_s3_key: &str,
) -> Result<Option<BuildDownloadRow>, sqlx::Error> {
    sqlx::query_as::<_, BuildTuple>(
        r"SELECT eb.eif_s3_key, eb.eif_sha256, eb.eif_size_bytes, cr.resource_name
          FROM eif_builds eb
          JOIN compute_resources cr ON cr.id = $1 AND cr.organization_id = eb.organization_id
          WHERE eb.eif_s3_key = $3 AND eb.organization_id = $2 AND eb.status = 'completed'
          ORDER BY eb.completed_at DESC NULLS LAST
          LIMIT 1",
    )
    .bind(resource_id)
    .bind(org_id)
    .bind(eif_s3_key)
    .fetch_optional(db)
    .await
    .map(|row| row.map(build_row))
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub(crate) async fn download_eif(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    Query(params): Query<DownloadEifParams>,
    req: axum::extract::Request,
) -> Result<Response<Body>, DownloadEifError> {
    use DownloadEifErrorCtx as Ctx;

    let org_id = crate::get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::database())?;

    let role = crate::check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::database())?;

    if !crate::can_manage_org(&role) && !crate::is_owner(&role) {
        return Err(DownloadEifError::Forbidden {
            location: std::panic::Location::caller(),
        });
    }

    let build =
        match resolve_eif_source(&state.db, org_id, resource_id, params.deployment).await? {
            EifSource::Key(eif_s3_key) => {
                build_for_key(&state.db, org_id, resource_id, &eif_s3_key).await
            }
            EifSource::LatestBuild => latest_build(&state.db, org_id, resource_id).await,
        }
        .with_context(Ctx::database())?;

    let build = build.ok_or_else(|| DownloadEifError::BuildNotFound {
        location: std::panic::Location::caller(),
    })?;

    let app_name = build
        .resource_name
        .unwrap_or_else(|| resource_id.to_string());

    let credential = cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id)
        .await
        .with_context(Ctx::credential_error())?;

    let (s3_client, bucket) =
        if let Some(cred) = credential.as_ref().filter(|c| c.managed_on_prem) {
            let encryptor = state.encryptor.as_ref().ok_or_else(|| {
                DownloadEifError::EncryptionNotConfigured {
                    location: std::panic::Location::caller(),
                }
            })?;

            let managed_cred = cloud_credentials::get_managed_onprem_credential(
                &state.db, encryptor, org_id, cred.id,
            )
            .await
            .with_context(Ctx::managed_credential_decrypt())?
            .ok_or_else(|| DownloadEifError::ManagedCredentialDecrypt {
                location: std::panic::Location::caller(),
                source: None,
            })?;

            let aws_creds = deployment::AwsCredentials {
                access_key_id: managed_cred.aws_access_key_id,
                secret_access_key: managed_cred.aws_secret_access_key,
                region: managed_cred.aws_region,
            };

            let client = crate::s3_client_for_credentials(&aws_creds).await;
            let bucket = managed_cred.eif_bucket;
            (client, bucket)
        } else {
            let aws_creds = deployment::AwsCredentials {
                access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
            };

            let client = crate::s3_client_for_credentials(&aws_creds).await;
            let bucket = state.builder_config.eif_s3_bucket.clone();
            (client, bucket)
        };

    let cache_path = state
        .eif_download_cache
        .ensure_cached(&s3_client, &bucket, &build.eif_s3_key)
        .await
        .with_context(Ctx::cached_eif_not_available())?;

    let mut serve_file = ServeFile::new(&cache_path);

    let response = serve_file.call(req).await.expect("ServeFile is infallible");
    let (parts, body) = response.into_parts();
    let body = Body::new(body);
    let mut response = Response::from_parts(parts, body);

    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{app_name}.eif\"")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "private, max-age=31536000".parse().unwrap(),
    );
    headers.insert(
        header::ETAG,
        format!("\"{}\"", build.eif_sha256).parse().unwrap(),
    );

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployments_row(
        deployment: Option<Uuid>,
        deployment_key: Option<&str>,
        configuration_key: Option<&str>,
    ) -> Option<EifSourceRow> {
        Some((
            "deployments".to_string(),
            deployment,
            deployment_key.map(str::to_string),
            configuration_key.map(str::to_string),
        ))
    }

    fn key(value: &str) -> EifSource {
        EifSource::Key(value.to_string())
    }

    #[test]
    fn legacy_app_keeps_the_latest_build_and_rejects_a_deployment() {
        let legacy = || Some(("legacy".to_string(), None, None, None));
        assert_eq!(
            decide_eif_source(legacy(), None).unwrap(),
            EifSource::LatestBuild
        );
        assert!(matches!(
            decide_eif_source(legacy(), Some(Uuid::new_v4())),
            Err(DownloadEifError::DeploymentsNotUsed { .. })
        ));
    }

    #[test]
    fn requested_deployment_never_falls_back_to_the_live_eif() {
        let id = Uuid::new_v4();
        assert_eq!(
            decide_eif_source(deployments_row(Some(id), Some("k"), Some("live")), Some(id))
                .unwrap(),
            key("k")
        );
        // Unknown or another app's deployment: the join finds no row.
        assert!(matches!(
            decide_eif_source(deployments_row(None, None, Some("live")), Some(id)),
            Err(DownloadEifError::BuildNotFound { .. })
        ));
        // No EIF recorded: not the app configuration's either.
        assert!(matches!(
            decide_eif_source(deployments_row(Some(id), None, Some("live")), Some(id)),
            Err(DownloadEifError::BuildNotFound { .. })
        ));
    }

    #[test]
    fn default_download_is_the_live_deployment() {
        let live = Uuid::new_v4();
        assert_eq!(
            decide_eif_source(deployments_row(Some(live), Some("k"), Some("c")), None).unwrap(),
            key("k")
        );
        assert_eq!(
            decide_eif_source(deployments_row(Some(live), None, Some("c")), None).unwrap(),
            key("c")
        );
        assert!(matches!(
            decide_eif_source(deployments_row(Some(live), None, None), None),
            Err(DownloadEifError::BuildNotFound { .. })
        ));
        // Nothing live: the configuration of a not-yet-live app is not served.
        assert!(matches!(
            decide_eif_source(deployments_row(None, None, Some("c")), None),
            Err(DownloadEifError::BuildNotFound { .. })
        ));
    }

    #[test]
    fn missing_app_is_not_found() {
        assert!(matches!(
            decide_eif_source(None, None),
            Err(DownloadEifError::BuildNotFound { .. })
        ));
    }
}
