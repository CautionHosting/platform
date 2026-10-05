use axum::{
    body::Body,
    extract::{Extension, Path, State},
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
struct BuildDownloadRow {
    eif_s3_key: String,
    eif_sha256: String,
    #[allow(dead_code)]
    eif_size_bytes: i64,
    resource_name: Option<String>,
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub(crate) async fn download_eif(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
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

    let build: Option<BuildDownloadRow> =
        sqlx::query_as::<_, (String, String, i64, Option<String>)>(
            r"SELECT eb.eif_s3_key, eb.eif_sha256, eb.eif_size_bytes, cr.resource_name
              FROM eif_builds eb
              JOIN compute_resources cr ON cr.id = eb.app_id
              WHERE eb.app_id = $1 AND eb.organization_id = $2 AND eb.status = 'completed'
              ORDER BY eb.completed_at DESC NULLS LAST
              LIMIT 1",
        )
        .bind(resource_id)
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?
        .map(|(s3_key, sha256, size, name)| BuildDownloadRow {
            eif_s3_key: s3_key,
            eif_sha256: sha256,
            eif_size_bytes: size,
            resource_name: name,
        });

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
