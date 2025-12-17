// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveManifest {
    pub version: String,
    pub powered_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_source: Option<AppSource>,
    pub enclave_source: EnclaveSource,
    pub framework_source: FrameworkSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSource {
    pub urls: Vec<String>,
    pub commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EnclaveSource {
    GitArchive {
        urls: Vec<String>,
        commit: Option<String>,
    },
    GitRepository {
        url: String,
        branch: String,
        commit: Option<String>,
    },
    Local {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FrameworkSource {
    GitArchive {
        url: String,
    },
}

impl EnclaveManifest {
    pub fn new(
        app_source: Option<AppSource>,
        enclave_source: EnclaveSource,
        framework_source: FrameworkSource,
        binary: Option<String>,
        run_command: Option<String>,
        metadata: Option<String>,
    ) -> Self {
        Self {
            version: "1.0".to_string(),
            powered_by: "https://caution.co".to_string(),
            app_source,
            enclave_source,
            framework_source,
            binary,
            run_command,
            metadata,
        }
    }

    pub async fn write_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).await?;
        Ok(())
    }

    pub async fn read_from_file(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path).await?;
        let manifest = serde_json::from_str(&json)?;
        Ok(manifest)
    }
}
