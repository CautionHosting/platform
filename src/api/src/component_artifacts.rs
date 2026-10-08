// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::ResultExt;
use enclave_builder::components::{Component, ComponentSet};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub(crate) enum SelectionError {
    #[error("COMPONENTS_S3_BUCKET requires COMPONENT_SET_SHA256 [{location}]")]
    MissingDigest { location: dterror::Location },
    #[error("COMPONENT_SET_SHA256 must be a lowercase SHA-256 digest [{location}]")]
    InvalidDigest { location: dterror::Location },
    #[error("invalid component bucket name [{location}]")]
    InvalidBucket { location: dterror::Location },
}

#[derive(Debug, Clone)]
pub(crate) struct ComponentSelection {
    digest: String,
    bucket: String,
}

impl ComponentSelection {
    pub(crate) fn parse(
        digest: Option<String>,
        bucket: Option<String>,
        default_bucket: &str,
    ) -> Result<Option<Self>, SelectionError> {
        let Some(digest) = digest else {
            return if bucket.is_some() {
                Err(SelectionError::MissingDigest {
                    location: std::panic::Location::caller(),
                })
            } else {
                Ok(None)
            };
        };
        if enclave_builder::components::validate_digest(&digest).is_err() {
            return Err(SelectionError::InvalidDigest {
                location: std::panic::Location::caller(),
            });
        }
        let bucket = bucket.unwrap_or_else(|| default_bucket.to_owned());
        if !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
            || !bucket.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !bucket.ends_with(|c: char| c.is_ascii_alphanumeric())
        {
            return Err(SelectionError::InvalidBucket {
                location: std::panic::Location::caller(),
            });
        }
        Ok(Some(Self { digest, bucket }))
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn bucket(&self) -> &str {
        &self.bucket
    }
}

#[tracing::instrument(skip_all)]
pub(crate) fn cache_key_with_components(base: &str, digest: Option<&str>) -> String {
    match digest {
        None => base.to_owned(),
        Some(digest) => {
            let mut hash = Sha256::new();
            hash.update(b"caution-eif-components-v1\0");
            hash.update(base.as_bytes());
            hash.update(b"\0");
            hash.update(digest.as_bytes());
            hex::encode(hash.finalize())
        }
    }
}

#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub(crate) enum ComponentPinsError {
    #[error("invalid component set [{location}]")]
    InvalidSet {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    #[error("component set does not match the selected {component} source revision [{location}]")]
    Mismatch {
        component: String,
        location: dterror::Location,
    },
    #[error("component set does not match the active {component} build recipe [{location}]")]
    RecipeMismatch {
        component: String,
        location: dterror::Location,
    },
}

#[tracing::instrument(skip_all, err)]
pub(crate) fn validate_source_pins(
    set: &ComponentSet,
    enclaveos: &str,
    bootproof: &str,
    framework: &str,
    steve: Option<&str>,
    locksmith: Option<&str>,
) -> Result<(), ComponentPinsError> {
    use ComponentPinsErrorCtx as Ctx;
    set.validate().with_context(Ctx::invalid_set())?;
    for (component, expected) in [
        (Component::Init, Some(enclaveos)),
        (Component::Bootproof, Some(bootproof)),
        (Component::TapFramer, Some(framework)),
        (Component::Steve, steve),
        (Component::Locksmith, locksmith),
    ] {
        if let Some(expected) = expected
            && !set
                .get(component)
                .is_some_and(|artifact| artifact.spec().source_commit() == expected)
        {
            return Err(ComponentPinsError::Mismatch {
                component: component.as_str().to_owned(),
                location: std::panic::Location::caller(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error(
    "could not {operation} at component startup; prepare compatible set then activate image/pins together [{location}]"
)]
pub(crate) struct StartupComponentsError {
    operation: &'static str,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

/// Validate the complete API selection against active source pins and the canonical
/// recipe embedded in this API image. Both optional services are active API
/// capabilities, even before an app requests E2E or vault. Staged source-tree
/// fingerprints are still independently verified by component staging.
#[tracing::instrument(skip_all, err)]
fn validate_startup_pins(
    set: &ComponentSet,
    platform_git_sha: Option<&str>,
    tools: &enclave_builder::build::ToolCommits,
) -> Result<(), StartupComponentsError> {
    use StartupComponentsErrorCtx as Ctx;
    let framework = crate::builder::require_platform_framework_commit(platform_git_sha)
        .with_context(Ctx::new("validate PLATFORM_GIT_SHA"))?;
    validate_source_pins(
        set,
        &tools.enclaveos.commit,
        &tools.bootproof.commit,
        &framework,
        Some(&tools.steve.commit),
        Some(&tools.locksmith.commit),
    )
    .with_context(Ctx::new("validate active source pins"))?;
    for (component, commit) in [
        (Component::Init, &tools.enclaveos.commit),
        (Component::Bootproof, &tools.bootproof.commit),
        (Component::TapFramer, &framework),
        (Component::Steve, &tools.steve.commit),
        (Component::Locksmith, &tools.locksmith.commit),
    ] {
        let recipe = enclave_builder::components::recipe::render_component(
            include_str!("../../enclave-builder/templates/Containerfile.eif"),
            component,
            commit,
            Some(component.embedded_containerfile()),
        )
        .with_context(Ctx::new("render active component recipe"))?;
        let expected = enclave_builder::components::sha256(recipe.as_bytes());
        if !set
            .get(component)
            .is_some_and(|artifact| artifact.spec().recipe_sha256() == expected)
        {
            return Err(ComponentPinsError::RecipeMismatch {
                component: component.as_str().to_owned(),
                location: std::panic::Location::caller(),
            })
            .with_context(Ctx::new("validate active recipes"));
        }
    }
    Ok(())
}

/// Load the digest-pinned manifest and reject incompatible active inputs before
/// application background work or listeners start. Source-only mode performs no I/O.
/// Per-deployment validation remains necessary and is deliberately not replaced.
#[tracing::instrument(skip_all, err)]
pub(crate) async fn validate_startup(
    digest: Option<String>,
    bucket: Option<String>,
    default_bucket: &str,
    platform_git_sha: Option<&str>,
    tools: &enclave_builder::build::ToolCommits,
) -> Result<(), StartupComponentsError> {
    use StartupComponentsErrorCtx as Ctx;
    let Some(selection) = ComponentSelection::parse(digest, bucket, default_bucket)
        .with_context(Ctx::new("parse selection"))?
    else {
        return Ok(());
    };
    let selected = SelectedComponents::load(selection)
        .await
        .with_context(Ctx::new("load pinned set"))?;
    validate_startup_pins(selected.set(), platform_git_sha, tools)
}

#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("could not {operation} selected component artifacts [{location}]")]
pub(crate) struct SelectedComponentsError {
    operation: &'static str,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

/// Immutable component provenance retained by builds and deployments, including cache hits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildComponentArtifacts {
    component_set_sha256: String,
    tap_framer_s3_key: String,
    tap_framer_sha256: String,
}

impl BuildComponentArtifacts {
    pub(crate) fn from_set(
        set: &ComponentSet,
        eif_s3_key: &str,
    ) -> Result<Self, SelectedComponentsError> {
        use SelectedComponentsErrorCtx as Ctx;
        let canonical = set.canonical_bytes().with_context(Ctx::new("pin build"))?;
        let file = set
            .get(Component::TapFramer)
            .and_then(|artifact| artifact.files().get("tap-framer"))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "tap-framer is absent")
            })
            .with_context(Ctx::new("pin host helper for"))?;
        Ok(Self {
            component_set_sha256: enclave_builder::components::sha256(&canonical),
            tap_framer_s3_key: format!("{eif_s3_key}.tap-framer"),
            tap_framer_sha256: file.sha256().to_owned(),
        })
    }

    pub(crate) fn component_set_sha256(&self) -> &str {
        &self.component_set_sha256
    }
    pub(crate) fn tap_framer_s3_key(&self) -> &str {
        &self.tap_framer_s3_key
    }
    pub(crate) fn tap_framer_sha256(&self) -> &str {
        &self.tap_framer_sha256
    }
}

#[tracing::instrument(skip_all)]
pub(crate) fn required_components(steve: bool, locksmith: bool, egress: bool) -> Vec<Component> {
    Component::ALL
        .into_iter()
        .filter(|component| match component {
            Component::Steve => steve,
            Component::Locksmith => locksmith,
            Component::TapFramer => egress,
            _ => true,
        })
        .collect()
}

pub(crate) struct SelectedComponents {
    selection: ComponentSelection,
    set: ComponentSet,
    source: enclave_builder::components::store::S3ComponentStore,
}

impl SelectedComponents {
    #[tracing::instrument(skip_all, err)]
    pub(crate) async fn load(
        selection: ComponentSelection,
    ) -> Result<Self, SelectedComponentsError> {
        use SelectedComponentsErrorCtx as Ctx;
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let source = enclave_builder::components::store::S3ComponentStore::new(
            aws_sdk_s3::Client::new(&config),
            selection.bucket().to_owned(),
        );
        let set = source
            .load_set(selection.digest())
            .await
            .with_context(Ctx::new("load"))?;
        Ok(Self {
            selection,
            set,
            source,
        })
    }

    pub(crate) fn set(&self) -> &ComponentSet {
        &self.set
    }
    pub(crate) fn digest(&self) -> &str {
        self.selection.digest()
    }

    #[tracing::instrument(skip_all, err)]
    pub(crate) async fn stage_for_builder(
        &self,
        destination_client: aws_sdk_s3::Client,
        destination_bucket: String,
        required: &[Component],
    ) -> Result<(), SelectedComponentsError> {
        use SelectedComponentsErrorCtx as Ctx;
        if destination_bucket == self.selection.bucket() {
            for component in required {
                let artifact = self
                    .set
                    .get(*component)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "required component is absent",
                        )
                    })
                    .with_context(Ctx::new("select platform"))?;
                for (name, file) in artifact.files() {
                    let key = enclave_builder::components::artifact_key(file.sha256(), name)
                        .with_context(Ctx::new("resolve artifact key for"))?;
                    self.source
                        .get_verified(&key, file)
                        .await
                        .with_context(Ctx::new("verify platform"))?
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "selected component object is missing",
                            )
                        })
                        .with_context(Ctx::new("find platform"))?;
                }
            }
            return Ok(());
        }
        let destination = enclave_builder::components::store::S3ComponentStore::new(
            destination_client,
            destination_bucket,
        );
        destination
            .ensure_components_from(&self.source, &self.set, required)
            .await
            .with_context(Ctx::new("stage for builder"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture() -> (ComponentSet, BTreeMap<String, Vec<u8>>) {
        use enclave_builder::components::{ArtifactFile, ComponentArtifact, ComponentSpec};
        let mut objects = BTreeMap::new();
        let artifacts = Component::ALL
            .into_iter()
            .map(|component| {
                let recipe = enclave_builder::components::recipe::render_component(
                    include_str!("../../enclave-builder/templates/Containerfile.eif"),
                    component,
                    &"a".repeat(40),
                    Some(component.embedded_containerfile()),
                )
                .unwrap();
                let spec = ComponentSpec::new(
                    component,
                    "a".repeat(40),
                    enclave_builder::components::sha256(recipe.as_bytes()),
                    component.source_subdir().map(|_| "c".repeat(64)),
                )
                .unwrap();
                let files = component
                    .filenames()
                    .iter()
                    .map(|name| {
                        let file = ArtifactFile::from_bytes(name.as_bytes()).unwrap();
                        objects.insert(
                            format!(
                                "/platform-bucket/components/v1/blobs/sha256/{}/{name}",
                                file.sha256()
                            ),
                            name.as_bytes().to_vec(),
                        );
                        (name.to_string(), file)
                    })
                    .collect();
                (component, ComponentArtifact::new(spec, files).unwrap())
            })
            .collect();
        (ComponentSet::new(artifacts).unwrap(), objects)
    }

    fn startup_tools() -> enclave_builder::build::ToolCommits {
        use enclave_builder::build::{ToolCommits, ToolSource};
        ToolCommits {
            enclaveos: ToolSource {
                commit: "a".repeat(40),
                repo: enclave_builder::build::ENCLAVEOS_REPO,
            },
            bootproof: ToolSource {
                commit: "a".repeat(40),
                repo: enclave_builder::build::BOOTPROOF_REPO,
            },
            steve: ToolSource {
                commit: "a".repeat(40),
                repo: enclave_builder::build::STEVE_REPO,
            },
            locksmith: ToolSource {
                commit: "a".repeat(40),
                repo: enclave_builder::build::LOCKSMITH_REPO,
            },
        }
    }

    #[tokio::test]
    async fn startup_source_mode_needs_neither_platform_pin_nor_storage() {
        validate_startup(None, None, "", None, &startup_tools())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn startup_rejects_partial_selection_before_loading_a_set() {
        let error = validate_startup(
            None,
            Some("platform-bucket".to_owned()),
            "platform-bucket",
            None,
            &startup_tools(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.operation, "parse selection");
        assert!(matches!(
            error.source.downcast_ref::<SelectionError>(),
            Some(SelectionError::MissingDigest { .. })
        ));
    }

    #[test]
    fn startup_accepts_exact_active_pins_and_canonical_recipes() {
        let (set, _) = fixture();
        let mut tools = startup_tools();
        tools.bootproof.commit = "b".repeat(40);
        tools.steve.commit = "c".repeat(40);
        tools.locksmith.commit = "d".repeat(40);
        let framework = "e".repeat(40);
        let mut value = serde_json::to_value(&set).unwrap();
        for (component, commit) in [
            (Component::Init, &tools.enclaveos.commit),
            (Component::Bootproof, &tools.bootproof.commit),
            (Component::Steve, &tools.steve.commit),
            (Component::Locksmith, &tools.locksmith.commit),
            (Component::TapFramer, &framework),
        ] {
            value["components"][component.as_str()]["spec"]["source_commit"] =
                serde_json::json!(commit);
            let recipe = enclave_builder::components::recipe::render_component(
                include_str!("../../enclave-builder/templates/Containerfile.eif"),
                component,
                commit,
                Some(component.embedded_containerfile()),
            )
            .unwrap();
            value["components"][component.as_str()]["spec"]["recipe_sha256"] =
                serde_json::json!(enclave_builder::components::sha256(recipe.as_bytes()));
        }
        let set: ComponentSet = serde_json::from_value(value).unwrap();
        validate_startup_pins(&set, Some(&framework), &tools).unwrap();
    }

    #[test]
    fn startup_rejects_each_incompatible_recipe_with_matching_source_pins() {
        let (set, _) = fixture();
        let tools = startup_tools();
        let framework = "a".repeat(40);
        validate_startup_pins(&set, Some(&framework), &tools).unwrap();
        for component in Component::ALL {
            let mut value = serde_json::to_value(&set).unwrap();
            let recipe = &mut value["components"][component.as_str()]["spec"]["recipe_sha256"];
            let incompatible_digest = serde_json::json!("0".repeat(64));
            assert_ne!(*recipe, incompatible_digest);
            *recipe = incompatible_digest;
            let incompatible: ComponentSet = serde_json::from_value(value).unwrap();
            validate_source_pins(
                &incompatible,
                &tools.enclaveos.commit,
                &tools.bootproof.commit,
                &framework,
                Some(&tools.steve.commit),
                Some(&tools.locksmith.commit),
            )
            .unwrap();
            let error = validate_startup_pins(&incompatible, Some(&framework), &tools).unwrap_err();
            assert_eq!(error.operation, "validate active recipes");
            assert!(matches!(
                error.source.downcast_ref::<ComponentPinsError>(),
                Some(ComponentPinsError::RecipeMismatch { component: name, .. })
                    if name == component.as_str()
            ));
        }
    }

    #[test]
    fn startup_rejects_each_incompatible_source_revision() {
        let (set, _) = fixture();
        for component in Component::ALL {
            let mut value = serde_json::to_value(&set).unwrap();
            value["components"][component.as_str()]["spec"]["source_commit"] =
                serde_json::json!("b".repeat(40));
            let incompatible: ComponentSet = serde_json::from_value(value).unwrap();
            incompatible.validate().unwrap();
            let error =
                validate_startup_pins(&incompatible, Some(&"a".repeat(40)), &startup_tools())
                    .unwrap_err();
            assert_eq!(error.operation, "validate active source pins");
            assert!(matches!(
                error.source.downcast_ref::<ComponentPinsError>(),
                Some(ComponentPinsError::Mismatch { component: name, .. })
                    if name == component.as_str()
            ));
            assert!(
                error
                    .to_string()
                    .contains("prepare compatible set then activate image/pins together")
            );
        }
    }

    #[test]
    fn startup_rejects_missing_or_invalid_platform_revision() {
        let (set, _) = fixture();
        for framework in [None, Some(""), Some("main"), Some("abc123")] {
            let error = validate_startup_pins(&set, framework, &startup_tools()).unwrap_err();
            assert_eq!(error.operation, "validate PLATFORM_GIT_SHA");
            assert!(
                error
                    .source
                    .downcast_ref::<crate::builder::RequirePlatformFrameworkCommitError>()
                    .is_some()
            );
        }
    }

    #[test]
    fn startup_requires_optional_services_before_accepting_deployments() {
        let (set, _) = fixture();
        for component in [Component::Steve, Component::Locksmith] {
            let mut value = serde_json::to_value(&set).unwrap();
            value["components"]
                .as_object_mut()
                .unwrap()
                .remove(component.as_str());
            let incomplete: ComponentSet = serde_json::from_value(value).unwrap();
            incomplete.validate().unwrap();
            let error = validate_startup_pins(&incomplete, Some(&"a".repeat(40)), &startup_tools())
                .unwrap_err();
            assert!(matches!(
                error.source.downcast_ref::<ComponentPinsError>(),
                Some(ComponentPinsError::Mismatch { component: name, .. })
                    if name == component.as_str()
            ));
        }
    }

    #[test]
    fn startup_rejects_malformed_sets_before_comparing_pins() {
        let (set, _) = fixture();
        let mut value = serde_json::to_value(&set).unwrap();
        value["schema_version"] = serde_json::json!(0);
        let malformed: ComponentSet = serde_json::from_value(value).unwrap();
        let error =
            validate_startup_pins(&malformed, Some(&"a".repeat(40)), &startup_tools()).unwrap_err();
        assert!(matches!(
            error.source.downcast_ref::<ComponentPinsError>(),
            Some(ComponentPinsError::InvalidSet { .. })
        ));
    }

    #[test]
    fn build_provenance_pins_the_exact_set_and_eif_paired_helper() {
        let (set, _) = fixture();
        let record = BuildComponentArtifacts::from_set(&set, "eifs/org/release.eif").unwrap();
        assert_eq!(
            record.component_set_sha256(),
            enclave_builder::components::sha256(&set.canonical_bytes().unwrap())
        );
        assert_eq!(
            record.tap_framer_s3_key(),
            "eifs/org/release.eif.tap-framer"
        );
        assert_eq!(
            record.tap_framer_sha256(),
            enclave_builder::components::sha256(b"tap-framer")
        );
        let persisted = serde_json::to_vec(&record).unwrap();
        assert_eq!(
            serde_json::from_slice::<BuildComponentArtifacts>(&persisted).unwrap(),
            record
        );
        assert_ne!(
            BuildComponentArtifacts::from_set(&set, "eifs/org/other.eif").unwrap(),
            record
        );
        let mut changed = serde_json::to_value(&set).unwrap();
        changed["components"]["init"]["files"]["init"]["sha256"] =
            serde_json::json!("d".repeat(64));
        let changed: ComponentSet = serde_json::from_value(changed).unwrap();
        let new_record =
            BuildComponentArtifacts::from_set(&changed, "eifs/org/release.eif").unwrap();
        assert_ne!(
            record.component_set_sha256(),
            new_record.component_set_sha256()
        );
    }

    #[test]
    fn required_component_matrix_excludes_only_disabled_optional_components() {
        let (set, _) = fixture();
        for steve in [false, true] {
            for locksmith in [false, true] {
                let required = required_components(steve, locksmith, true);
                assert!(Component::REQUIRED.iter().all(|c| required.contains(c)));
                assert_eq!(required.contains(&Component::Steve), steve);
                assert_eq!(required.contains(&Component::Locksmith), locksmith);
                validate_source_pins(
                    &set,
                    &"a".repeat(40),
                    &"a".repeat(40),
                    &"a".repeat(40),
                    steve.then_some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    locksmith.then_some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn no_egress_component_selection_omits_only_the_host_guest_tunnel() {
        for steve in [false, true] {
            for locksmith in [false, true] {
                let required = required_components(steve, locksmith, false);
                assert!(required.contains(&Component::Init));
                assert!(required.contains(&Component::Bootproof));
                assert!(!required.contains(&Component::TapFramer));
                assert_eq!(required.contains(&Component::Steve), steve);
                assert_eq!(required.contains(&Component::Locksmith), locksmith);
            }
        }
    }

    #[tokio::test]
    async fn managed_components_need_only_read_permissions_and_fail_closed() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
            response::IntoResponse,
        };
        use std::sync::{Arc, Mutex};
        let (set, objects) = fixture();
        for (fault, egress) in [
            ("none", true),
            ("none", false),
            ("missing", true),
            ("corrupt", true),
            ("size", true),
            ("unused-missing", true),
            ("unused-corrupt", true),
            ("unused-tap-missing", false),
            ("unused-tap-corrupt", false),
        ] {
            let mut set = set.clone();
            if fault == "size" {
                let mut value = serde_json::to_value(&set).unwrap();
                value["components"]["init"]["files"]["init"]["size"] =
                    serde_json::json!(b"init".len() + 1);
                set = serde_json::from_value(value).unwrap();
            }
            let mut objects = objects.clone();
            let name = if fault.starts_with("unused-tap-") {
                "/tap-framer"
            } else if fault.starts_with("unused-") {
                "/steve"
            } else {
                "/init"
            };
            let key = objects
                .keys()
                .find(|key| key.ends_with(name))
                .unwrap()
                .clone();
            if fault.ends_with("missing") {
                objects.remove(&key);
            }
            if fault.ends_with("corrupt") {
                objects.get_mut(&key).unwrap()[0] ^= 1;
            }
            let objects = Arc::new(objects);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen_requests = requests.clone();
            let app = axum::Router::new().fallback(move |request: Request<Body>| {
                let objects = objects.clone();
                let requests = seen_requests.clone();
                async move {
                    requests.lock().unwrap().push(format!(
                        "{} {}",
                        request.method(),
                        request.uri().path()
                    ));
                    if request.method() != axum::http::Method::GET {
                        return (
                            StatusCode::FORBIDDEN,
                            "<Error><Code>AccessDenied</Code></Error>",
                        )
                            .into_response();
                    }
                    match objects.get(request.uri().path()) {
                        Some(bytes) => bytes.clone().into_response(),
                        None => (
                            StatusCode::NOT_FOUND,
                            "<Error><Code>NoSuchKey</Code></Error>",
                        )
                            .into_response(),
                    }
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let config = aws_sdk_s3::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-west-2"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "fixture", "fixture", None, None, "test",
                ))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build();
            let client = aws_sdk_s3::Client::from_conf(config);
            let selection = ComponentSelection::parse(
                Some(enclave_builder::components::sha256(
                    &set.canonical_bytes().unwrap(),
                )),
                None,
                "platform-bucket",
            )
            .unwrap()
            .unwrap();
            let selected = SelectedComponents {
                selection,
                set,
                source: enclave_builder::components::store::S3ComponentStore::new(
                    client.clone(),
                    "platform-bucket".into(),
                ),
            };
            let result = selected
                .stage_for_builder(
                    client,
                    "platform-bucket".into(),
                    &required_components(false, false, egress),
                )
                .await;
            server.abort();
            let succeeds = fault == "none" || fault.starts_with("unused-");
            assert_eq!(result.is_ok(), succeeds, "fault={fault}: {result:?}");
            if !succeeds {
                assert_eq!(
                    result.unwrap_err().operation,
                    if fault == "missing" {
                        "find platform"
                    } else {
                        "verify platform"
                    }
                );
            }
            let expected_names: &[&str] = if succeeds && egress {
                &["init", "bootproofd", "tap-framer"]
            } else if succeeds {
                &["init", "bootproofd"]
            } else {
                &["init"]
            };
            let mut expected_requests = expected_names
                .iter()
                .map(|name| {
                    format!(
                        "GET /platform-bucket/components/v1/blobs/sha256/{}/{name}",
                        enclave_builder::components::sha256(name.as_bytes())
                    )
                })
                .collect::<Vec<_>>();
            expected_requests.sort();
            let mut requests = requests.lock().unwrap().clone();
            requests.sort();
            assert_eq!(requests, expected_requests, "fault={fault}");
        }
    }

    #[test]
    fn selection_preserves_source_builds_and_pins_digest_and_bucket() {
        for (digest, bucket, expected_bucket) in [
            (None, None, None),
            (Some("a".repeat(64)), None, Some("platform-bucket")),
            (
                Some("b".repeat(64)),
                Some("component-bucket".to_owned()),
                Some("component-bucket"),
            ),
        ] {
            let selection =
                ComponentSelection::parse(digest.clone(), bucket, "platform-bucket").unwrap();
            assert_eq!(
                selection.as_ref().map(ComponentSelection::digest),
                digest.as_deref()
            );
            assert_eq!(
                selection.as_ref().map(ComponentSelection::bucket),
                expected_bucket
            );
        }
    }

    #[test]
    fn partial_or_mutable_configuration_fails_closed() {
        assert!(ComponentSelection::parse(None, Some("bucket".into()), "platform-bucket").is_err());
        for digest in [
            "".to_owned(),
            "latest".into(),
            "A".repeat(64),
            "a".repeat(63),
            "a/".repeat(32),
        ] {
            assert!(ComponentSelection::parse(Some(digest), None, "platform-bucket").is_err());
        }
        for bucket in [
            "",
            "x",
            "not/a/bucket",
            "bucket\n",
            "$(command)",
            "-bucket",
            "bucket-",
            "Bucket",
        ] {
            assert!(
                ComponentSelection::parse(
                    Some("a".repeat(64)),
                    Some(bucket.into()),
                    "platform-bucket"
                )
                .is_err(),
                "accepted {bucket:?}"
            );
        }
    }

    #[test]
    fn selection_is_part_of_eif_cache_identity_but_legacy_keys_are_preserved() {
        let base = "old-key";
        assert_eq!(cache_key_with_components(base, None), base);
        let first = cache_key_with_components(base, Some(&"a".repeat(64)));
        let second = cache_key_with_components(base, Some(&"b".repeat(64)));
        assert_ne!(first, base);
        assert_ne!(first, second);
        assert_ne!(
            first,
            cache_key_with_components("other-key", Some(&"a".repeat(64)))
        );
        assert_eq!(
            first,
            cache_key_with_components(base, Some(&"a".repeat(64)))
        );
    }
}
