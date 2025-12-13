// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use std::env;
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub api_service_url: String,
    pub rp_id: String,
    pub rp_display_name: String,
    pub rp_origins: Vec<String>,
    pub port: u16,
    pub ssh_port: u16,
    pub ssh_host_key_path: String,
    pub session_timeout_hours: i64,
    pub data_dir: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://apiuser:apipass@localhost:5432/apidb?sslmode=disable".to_string());

        let api_service_url = env::var("API_SERVICE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        // Validate API service URL
        Url::parse(&api_service_url)
            .context("Invalid API_SERVICE_URL")?;

        let rp_id = env::var("RP_ID")
            .unwrap_or_else(|_| "localhost".to_string());

        let rp_display_name = env::var("RP_DISPLAY_NAME")
            .unwrap_or_else(|_| "Hybrid API".to_string());

        let rp_origins: Vec<String> = env::var("RP_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:8080,http://localhost:8000,http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Validate RP origins
        for origin in rp_origins.iter() {
            Url::parse(origin.as_str())
                .with_context(|| format!("Invalid origin in RP_ORIGINS: {}", origin))?;
        }

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .context("Invalid PORT")?;

        let ssh_port = env::var("SSH_PORT")
            .unwrap_or_else(|_| "2222".to_string())
            .parse()
            .context("Invalid SSH_PORT")?;

        let ssh_host_key_path = env::var("SSH_HOST_KEY_PATH")
            .unwrap_or_else(|_| "/etc/caution/ssh_host_ed25519_key".to_string());

        let session_timeout_hours: i64 = env::var("SESSION_TIMEOUT_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .context("Invalid SESSION_TIMEOUT_HOURS")?;

        let data_dir = env::var("CAUTION_DATA_DIR")
            .unwrap_or_else(|_| "/var/cache/caution".to_string());

        Ok(Config {
            database_url,
            api_service_url,
            rp_id,
            rp_display_name,
            rp_origins,
            port,
            ssh_port,
            ssh_host_key_path,
            session_timeout_hours,
            data_dir,
        })
    }
}
