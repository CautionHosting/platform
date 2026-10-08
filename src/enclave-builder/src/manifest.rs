// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::ResultExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::Path;
use tokio::fs;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnclaveManifest {
    pub version: String,
    pub powered_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_source: Option<AppSource>,
    pub enclave_source: EnclaveSource,
    pub framework_source: FrameworkSource,
    /// Pinned component inputs and binary digests; absent on historical source builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_set: Option<crate::components::ComponentSet>,
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
    /// STEVE key exchange, recorded only when it differs from STEVE's default,
    /// so manifests for existing deployments stay byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steve_key_exchange: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub steve_allow_plaintext_fallback: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub locksmith: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locksmith_commit: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Preserve the measured #464 wire format: named fields retain their historical
/// order, while component_set is a recursively sorted Value among sorted extras.
/// This must not change ComponentSet serialization or its publication identity.
impl Serialize for EnclaveManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct WireManifest<'a> {
            version: &'a str,
            powered_by: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            app_source: &'a Option<AppSource>,
            enclave_source: &'a EnclaveSource,
            framework_source: &'a FrameworkSource,
            #[serde(skip_serializing_if = "Option::is_none")]
            binary: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            run_command: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            metadata: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            enclaveos_commit: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            bootproof_commit: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            steve_commit: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            steve_key_exchange: &'a Option<String>,
            #[serde(skip_serializing_if = "is_false")]
            steve_allow_plaintext_fallback: bool,
            #[serde(skip_serializing_if = "is_false")]
            locksmith: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            locksmith_commit: &'a Option<String>,
            #[serde(flatten)]
            extra: Map<String, Value>,
        }

        let mut extra = self.extra.clone();
        if let Some(set) = &self.component_set {
            extra.insert(
                "component_set".to_owned(),
                serde_json::to_value(set).map_err(serde::ser::Error::custom)?,
            );
        }
        extra.sort_keys();
        for value in extra.values_mut() {
            value.sort_all_objects();
        }
        WireManifest {
            version: &self.version,
            powered_by: &self.powered_by,
            app_source: &self.app_source,
            enclave_source: &self.enclave_source,
            framework_source: &self.framework_source,
            binary: &self.binary,
            run_command: &self.run_command,
            metadata: &self.metadata,
            enclaveos_commit: &self.enclaveos_commit,
            bootproof_commit: &self.bootproof_commit,
            steve_commit: &self.steve_commit,
            steve_key_exchange: &self.steve_key_exchange,
            steve_allow_plaintext_fallback: self.steve_allow_plaintext_fallback,
            locksmith: self.locksmith,
            locksmith_commit: &self.locksmith_commit,
            extra,
        }
        .serialize(serializer)
    }
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

/// Error type for [`EnclaveManifest::write_to_file`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum WriteToFileError {
    #[error("could not serialize manifest to JSON [{location}]")]
    Serialize {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("could not write manifest file '{path}' [{location}]")]
    WriteFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`EnclaveManifest::read_from_file`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ReadFromFileError {
    #[error("could not read manifest file '{path}' [{location}]")]
    ReadFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("could not deserialize manifest JSON [{location}]")]
    Deserialize {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
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
            component_set: None,
            binary,
            run_command,
            metadata,
            enclaveos_commit: None,
            bootproof_commit: None,
            steve_commit: None,
            steve_key_exchange: None,
            steve_allow_plaintext_fallback: false,
            locksmith: false,
            locksmith_commit: None,
            extra: Map::new(),
        }
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn write_to_file(&self, path: &Path) -> Result<(), WriteToFileError> {
        use WriteToFileErrorCtx as Ctx;

        let json = serde_json::to_string_pretty(self).with_context(Ctx::serialize(path))?;
        fs::write(path, json)
            .await
            .with_context(Ctx::write_file(path))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn read_from_file(path: &Path) -> Result<Self, ReadFromFileError> {
        use ReadFromFileErrorCtx as Ctx;

        let json = fs::read_to_string(path)
            .await
            .with_context(Ctx::read_file(path))?;
        let manifest = serde_json::from_str(&json).with_context(Ctx::deserialize(path))?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The #464 manifest at 2d18b25: retain the exact fields, serde attributes and
    /// declaration order so this reader cannot accidentally learn component_set.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Pr464EnclaveManifest {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub steve_key_exchange: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        pub steve_allow_plaintext_fallback: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        pub locksmith: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub locksmith_commit: Option<String>,
        #[serde(flatten)]
        pub extra: Map<String, Value>,
    }

    fn component_set_fixture() -> crate::components::ComponentSet {
        use crate::components::{
            ArtifactFile, Component, ComponentArtifact, ComponentSet, ComponentSpec,
        };
        ComponentSet::new(
            Component::ALL
                .into_iter()
                .map(|component| {
                    let spec = ComponentSpec::new(
                        component,
                        "a".repeat(40),
                        "b".repeat(64),
                        component.source_subdir().map(|_| "c".repeat(64)),
                    )
                    .unwrap();
                    let files = component
                        .filenames()
                        .iter()
                        .map(|name| {
                            (
                                name.to_string(),
                                ArtifactFile::from_bytes(name.as_bytes()).unwrap(),
                            )
                        })
                        .collect();
                    (component, ComponentArtifact::new(spec, files).unwrap())
                })
                .collect(),
        )
        .unwrap()
    }

    fn populated_manifest() -> EnclaveManifest {
        let mut manifest = make_manifest(
            Some(AppSource {
                urls: vec!["https://example.com/app.tar.gz".to_owned()],
                commit: "d".repeat(40),
                branch: Some("main".to_owned()),
            }),
            Some("/app/server".to_owned()),
            Some("/app/server --port 8080".to_owned()),
            Some("measured metadata".to_owned()),
        );
        manifest.enclaveos_commit = Some("a".repeat(40));
        manifest.bootproof_commit = Some("a".repeat(40));
        manifest.steve_commit = Some("a".repeat(40));
        manifest.steve_key_exchange = Some("XWING-DRAFT10".to_owned());
        manifest.steve_allow_plaintext_fallback = true;
        manifest.locksmith = true;
        manifest.locksmith_commit = Some("a".repeat(40));
        for key in ["zzz_future", "aaa_future"] {
            manifest.extra.insert(
                key.to_owned(),
                serde_json::json!({"z": [{"z": 1, "a": {"z": false, "a": true}}], "a": 2}),
            );
        }
        manifest
    }

    #[test]
    fn component_manifest_pretty_bytes_survive_pr464_round_trip() {
        let mut manifest = populated_manifest();
        let set = component_set_fixture();
        let canonical = set.canonical_bytes().unwrap();
        let typed = serde_json::to_vec(&set).unwrap();
        manifest.component_set = Some(set.clone());

        let measured = serde_json::to_vec_pretty(&manifest).unwrap();
        let old: Pr464EnclaveManifest = serde_json::from_slice(&measured).unwrap();
        assert_eq!(
            old.extra["component_set"],
            serde_json::to_value(&set).unwrap()
        );
        let old_bytes = serde_json::to_vec_pretty(&old).unwrap();
        assert_eq!(
            measured, old_bytes,
            "#464 must reproduce the exact measured manifest bytes"
        );

        let loaded: EnclaveManifest = serde_json::from_slice(&old_bytes).unwrap();
        assert_eq!(serde_json::to_vec_pretty(&loaded).unwrap(), measured);
        assert_eq!(loaded.extra, manifest.extra);
        let loaded_set = loaded.component_set.unwrap();
        assert_eq!(loaded_set, set);
        assert_eq!(loaded_set.canonical_bytes().unwrap(), canonical);
        assert_eq!(serde_json::to_vec(&loaded_set).unwrap(), typed);
    }

    #[test]
    fn component_set_none_preserves_pr464_pretty_bytes() {
        for manifest in [make_manifest(None, None, None, None), populated_manifest()] {
            let measured = serde_json::to_vec_pretty(&manifest).unwrap();
            let old: Pr464EnclaveManifest = serde_json::from_slice(&measured).unwrap();
            assert!(!old.extra.contains_key("component_set"));
            assert_eq!(measured, serde_json::to_vec_pretty(&old).unwrap());
            let loaded: EnclaveManifest = serde_json::from_slice(&measured).unwrap();
            assert!(loaded.component_set.is_none());
            assert_eq!(serde_json::to_vec_pretty(&loaded).unwrap(), measured);
        }
    }

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
        assert!(!json.contains("steve_allow_plaintext_fallback"));
    }

    #[test]
    fn test_manifest_plaintext_fallback_round_trip() {
        let mut manifest = make_manifest(None, None, None, None);
        manifest.steve_allow_plaintext_fallback = true;

        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("\"steve_allow_plaintext_fallback\":true"));

        let deserialized: EnclaveManifest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.steve_allow_plaintext_fallback);
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
            EnclaveSource::GitRepository {
                url,
                branch,
                commit,
            } => {
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
        assert!(!manifest.locksmith);
        assert!(manifest.locksmith_commit.is_none());
        assert!(manifest.steve_commit.is_none());
    }

    #[test]
    fn test_manifest_locksmith_commit_omitted_when_none() {
        let manifest = make_manifest(None, None, None, None);
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("locksmith"));
        assert!(!json.contains("locksmith_commit"));
    }

    #[test]
    fn test_manifest_locksmith_commit_present_when_set() {
        let mut manifest = make_manifest(None, None, None, None);
        manifest.locksmith = true;
        manifest.locksmith_commit = Some("abc123".to_string());
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("\"locksmith\":true"));
        assert!(json.contains("locksmith_commit"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_manifest_locksmith_commit_round_trip() {
        let mut manifest = make_manifest(None, None, None, None);
        manifest.locksmith = true;
        manifest.locksmith_commit = Some("d16b74c6b3fd".to_string());
        manifest.steve_commit = Some("ed38a190cd5d".to_string());

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let loaded: EnclaveManifest = serde_json::from_str(&json).unwrap();

        assert!(loaded.locksmith);
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
        assert!(!manifest.locksmith);
        assert!(manifest.locksmith_commit.is_none());
        assert!(manifest.steve_commit.is_none());
    }
}
