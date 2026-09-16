// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt};
use std::env;
use url::Url;

#[derive(Debug, thiserror::Error, CtxError)]
enum ApiServiceUrlError {
    #[error("Invalid API_SERVICE_URL [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("API_SERVICE_URL must be a root URL without a path prefix [{location}]")]
    PathPrefix {
        #[location]
        location: Location,
    },
}

fn validate_api_service_url(value: &str) -> Result<(), ApiServiceUrlError> {
    use ApiServiceUrlErrorCtx as Ctx;
    let url = Url::parse(value).with_context(Ctx::parse())?;
    if !matches!(url.path(), "" | "/") {
        return Err(ApiServiceUrlError::PathPrefix {
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub api_service_url: String,
    pub metering_service_url: String,
    pub rp_id: String,
    pub rp_display_name: String,
    pub rp_origins: Vec<String>,
    pub port: u16,
    pub ssh_port: u16,
    pub ssh_host_key_path: String,
    pub session_timeout_hours: i64,
    pub data_dir: String,
    pub csrf_secret: String,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ConfigError {
    #[error("invalid API_SERVICE_URL [{location}]")]
    InvalidApiServiceUrl {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("invalid origin in RP_ORIGINS: {origin} [{location}]")]
    InvalidOrigin {
        #[context(borrow = str)]
        origin: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("invalid PORT [{location}]")]
    InvalidPort {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("invalid SSH_PORT [{location}]")]
    InvalidSshPort {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("invalid SESSION_TIMEOUT_HOURS [{location}]")]
    InvalidSessionTimeoutHours {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("CSRF_SECRET environment variable must be set [{location}]")]
    CsrfSecretMissing {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        use ConfigErrorCtx as Ctx;

        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://apiuser:apipass@localhost:5432/apidb?sslmode=disable".to_string()
        });

        // Trailing slashes would produce "//"-prefixed backend paths when the
        // request path is appended, defeating the gateway's internal-route
        // check — normalize them away before validating.
        let api_service_url = env::var("API_SERVICE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string())
            .trim_end_matches('/')
            .to_string();

        // Validate API service URL
        validate_api_service_url(&api_service_url).with_context(Ctx::invalid_api_service_url())?;

        let metering_service_url =
            env::var("METERING_SERVICE_URL").unwrap_or_else(|_| "http://metering:8083".to_string());

        let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());

        let rp_display_name =
            env::var("RP_DISPLAY_NAME").unwrap_or_else(|_| "Hybrid API".to_string());

        let rp_origins: Vec<String> = env::var("RP_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:8080,http://localhost:8000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Validate RP origins
        for origin in rp_origins.iter() {
            Url::parse(origin.as_str()).with_context(Ctx::invalid_origin(origin.as_str()))?;
        }

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .with_context(Ctx::invalid_port())?;

        let ssh_port = env::var("SSH_PORT")
            .unwrap_or_else(|_| "2222".to_string())
            .parse()
            .with_context(Ctx::invalid_ssh_port())?;

        let ssh_host_key_path = env::var("SSH_HOST_KEY_PATH")
            .unwrap_or_else(|_| "/var/cache/caution/ssh_host_ed25519_key".to_string());

        let session_timeout_hours: i64 = env::var("SESSION_TIMEOUT_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .with_context(Ctx::invalid_session_timeout_hours())?;

        let data_dir =
            env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());

        let csrf_secret = env::var("CSRF_SECRET").with_context(Ctx::csrf_secret_missing())?;

        Ok(Config {
            database_url,
            api_service_url,
            metering_service_url,
            rp_id,
            rp_display_name,
            rp_origins,
            port,
            ssh_port,
            ssh_host_key_path,
            session_timeout_hours,
            data_dir,
            csrf_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_service_url_requires_root_path() {
        for value in ["http://api:8080", "http://api:8080/", "http://api:8080///"] {
            assert!(validate_api_service_url(value.trim_end_matches('/')).is_ok());
        }
        for value in ["http://api:8080/v1", "http://api:8080/v1/"] {
            let error = validate_api_service_url(value.trim_end_matches('/')).unwrap_err();
            assert!(matches!(error, ApiServiceUrlError::PathPrefix { .. }));
            assert!(error
                .to_string()
                .contains("API_SERVICE_URL must be a root URL"));
        }
        assert!(matches!(
            validate_api_service_url("not a URL"),
            Err(ApiServiceUrlError::Parse { .. })
        ));
    }
}
