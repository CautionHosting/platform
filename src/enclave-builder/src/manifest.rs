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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclaveos_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootproof_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steve_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locksmith_commit: Option<String>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        commit: Option<String>,
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
            enclaveos_commit: None,
            bootproof_commit: None,
            steve_commit: None,
            locksmith_commit: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manifest(
        app_source: Option<AppSource>,
        binary: Option<String>,
        run_command: Option<String>,
        metadata: Option<String>,
    ) -> EnclaveManifest {
        EnclaveManifest::new(
            app_source,
            EnclaveSource::GitArchive {
                urls: vec!["https://example.com/enclave.tar.gz".to_string()],
                commit: Some("abc123".to_string()),
            },
            FrameworkSource::GitArchive {
                url: "https://example.com/framework.tar.gz".to_string(),
                commit: Some("def456".to_string()),
            },
            binary,
            run_command,
            metadata,
        )
    }

    #[test]
    fn test_manifest_new_defaults() {
        let manifest = make_manifest(None, None, None, None);
        assert_eq!(manifest.version, "1.0");
        assert_eq!(manifest.powered_by, "https://caution.co");
        assert!(manifest.app_source.is_none());
        assert!(manifest.binary.is_none());
        assert!(manifest.run_command.is_none());
        assert!(manifest.metadata.is_none());
    }

    #[test]
    fn test_manifest_serialization_round_trip() {
        let manifest = make_manifest(
            Some(AppSource {
                urls: vec!["https://github.com/user/repo.git".to_string()],
                commit: "abc123def456".to_string(),
                branch: Some("main".to_string()),
            }),
            Some("/app/server".to_string()),
            Some("/app/server --port 8080".to_string()),
            Some("test metadata".to_string()),
        );

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let deserialized: EnclaveManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, manifest.version);
        assert_eq!(deserialized.powered_by, manifest.powered_by);
        assert_eq!(deserialized.binary, manifest.binary);
        assert_eq!(deserialized.run_command, manifest.run_command);
        assert_eq!(deserialized.metadata, manifest.metadata);

        let app_src = deserialized.app_source.unwrap();
        assert_eq!(app_src.commit, "abc123def456");
        assert_eq!(app_src.branch, Some("main".to_string()));
        assert_eq!(app_src.urls.len(), 1);
    }

    #[test]
    fn test_manifest_optional_fields_omitted() {
        let manifest = make_manifest(None, None, None, None);
        let json = serde_json::to_string(&manifest).unwrap();

        // Optional None fields should be omitted from JSON
        assert!(!json.contains("app_source"));
        assert!(!json.contains("binary"));
        assert!(!json.contains("run_command"));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn test_manifest_optional_fields_present() {
        let manifest = make_manifest(
            None,
            Some("/app/bin".to_string()),
            Some("/app/bin --flag".to_string()),
            Some("meta".to_string()),
        );
        let json = serde_json::to_string(&manifest).unwrap();

        assert!(json.contains("binary"));
        assert!(json.contains("run_command"));
        assert!(json.contains("metadata"));
    }

    #[test]
    fn test_enclave_source_git_archive() {
        let source = EnclaveSource::GitArchive {
            urls: vec![
                "https://example.com/a.tar.gz".to_string(),
                "https://mirror.com/a.tar.gz".to_string(),
            ],
            commit: Some("abc123".to_string()),
        };

        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"type\":\"git_archive\""));

        let deserialized: EnclaveSource = serde_json::from_str(&json).unwrap();
        match deserialized {
            EnclaveSource::GitArchive { urls, commit } => {
                assert_eq!(urls.len(), 2);
                assert_eq!(commit, Some("abc123".to_string()));
            }
            _ => panic!("Expected GitArchive"),
        }
    }

    #[test]
    fn test_enclave_source_git_repository() {
        let source = EnclaveSource::GitRepository {
            url: "https://github.com/org/repo.git".to_string(),
            branch: "main".to_string(),
            commit: None,
        };

        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"type\":\"git_repository\""));

        let deserialized: EnclaveSource = serde_json::from_str(&json).unwrap();
        match deserialized {
            EnclaveSource::GitRepository { url, branch, commit } => {
                assert_eq!(url, "https://github.com/org/repo.git");
                assert_eq!(branch, "main");
                assert!(commit.is_none());
            }
            _ => panic!("Expected GitRepository"),
        }
    }

    #[test]
    fn test_enclave_source_local() {
        let source = EnclaveSource::Local {
            path: "/home/user/enclave".to_string(),
        };

        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"type\":\"local\""));
    }

    #[test]
    fn test_framework_source_git_archive() {
        let source = FrameworkSource::GitArchive {
            url: "https://example.com/framework.tar.gz".to_string(),
            commit: None,
        };

        let json = serde_json::to_string(&source).unwrap();
        let deserialized: FrameworkSource = serde_json::from_str(&json).unwrap();

        match deserialized {
            FrameworkSource::GitArchive { url, commit } => {
                assert_eq!(url, "https://example.com/framework.tar.gz");
                assert!(commit.is_none());
            }
        }
    }

    #[test]
    fn test_framework_source_commit_omitted_when_none() {
        let source = FrameworkSource::GitArchive {
            url: "https://example.com/framework.tar.gz".to_string(),
            commit: None,
        };

        let json = serde_json::to_string(&source).unwrap();
        assert!(!json.contains("commit"));
    }

    #[test]
    fn test_app_source_serialization() {
        let source = AppSource {
            urls: vec!["https://github.com/user/repo.git".to_string()],
            commit: "deadbeef".to_string(),
            branch: None,
        };

        let json = serde_json::to_string(&source).unwrap();
        assert!(!json.contains("branch")); // None branch should not be serialized

        let source_with_branch = AppSource {
            urls: vec!["https://github.com/user/repo.git".to_string()],
            commit: "deadbeef".to_string(),
            branch: Some("develop".to_string()),
        };

        let json = serde_json::to_string(&source_with_branch).unwrap();
        assert!(json.contains("develop"));
    }

    #[tokio::test]
    async fn test_manifest_write_and_read() {
        let manifest = make_manifest(None, None, None, None);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        manifest.write_to_file(&path).await.unwrap();
        let loaded = EnclaveManifest::read_from_file(&path).await.unwrap();

        assert_eq!(loaded.version, "1.0");
        assert_eq!(loaded.powered_by, "https://caution.co");
    }

    #[test]
    fn test_manifest_locksmith_commit_none_by_default() {
        let manifest = make_manifest(None, None, None, None);
        assert!(manifest.locksmith_commit.is_none());
        assert!(manifest.steve_commit.is_none());
    }

    #[test]
    fn test_manifest_locksmith_commit_omitted_when_none() {
        let manifest = make_manifest(None, None, None, None);
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("locksmith_commit"));
    }

    #[test]
    fn test_manifest_locksmith_commit_present_when_set() {
        let mut manifest = make_manifest(None, None, None, None);
        manifest.locksmith_commit = Some("abc123".to_string());
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("locksmith_commit"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_manifest_locksmith_commit_round_trip() {
        let mut manifest = make_manifest(None, None, None, None);
        manifest.locksmith_commit = Some("d16b74c6b3fd".to_string());
        manifest.steve_commit = Some("ed38a190cd5d".to_string());

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let loaded: EnclaveManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.locksmith_commit, Some("d16b74c6b3fd".to_string()));
        assert_eq!(loaded.steve_commit, Some("ed38a190cd5d".to_string()));
    }

    #[test]
    fn test_manifest_deserializes_without_locksmith_commit() {
        // Old manifests without locksmith_commit field should still deserialize
        let json = r#"{
            "version": "1.0",
            "powered_by": "https://caution.co",
            "enclave_source": {"type": "git_archive", "urls": ["https://example.com/a.tar.gz"], "commit": "abc"},
            "framework_source": {"type": "git_archive", "url": "https://example.com/f.tar.gz"}
        }"#;
        let manifest: EnclaveManifest = serde_json::from_str(json).unwrap();
        assert!(manifest.locksmith_commit.is_none());
        assert!(manifest.steve_commit.is_none());
    }
}
