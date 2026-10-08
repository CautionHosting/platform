// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Validated, digest-addressed prebuilt components and their immutable inputs.

pub mod recipe;
#[cfg(feature = "s3-components")]
pub mod store;

use dterror::ResultExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Only supported artifact target; part of every build identity.
pub const TARGET: &str = "x86_64-unknown-linux-musl";
/// Current component-set wire schema.
pub const SCHEMA_VERSION: u32 = 1;
/// Bound each descriptor before a consumer allocates or downloads an artifact.
pub const MAX_ARTIFACT_SIZE: u64 = 256 * 1024 * 1024;
/// Recommended maximum raw manifest size for transport readers, before parsing.
pub const MAX_MANIFEST_SIZE: usize = 64 * 1024;

/// Components shared across application builds. Wire names are stable kebab-case.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    /// EnclaveOS PID 1.
    Init,
    /// Attestation daemon.
    Bootproof,
    /// Optional STEVE daemon.
    Steve,
    /// Optional Locksmith daemon and its inseparable oneshot companion.
    Locksmith,
    /// Frame-preserving guest and host tunnel helper.
    TapFramer,
}

impl Component {
    /// Every supported component.
    pub const ALL: [Self; 5] = [
        Self::Init,
        Self::Bootproof,
        Self::Steve,
        Self::Locksmith,
        Self::TapFramer,
    ];
    /// Components present in every supported component set.
    pub const REQUIRED: [Self; 3] = [Self::Init, Self::Bootproof, Self::TapFramer];

    /// Stable manifest name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Bootproof => "bootproof",
            Self::Steve => "steve",
            Self::Locksmith => "locksmith",
            Self::TapFramer => "tap-framer",
        }
    }

    /// Exact compiler stage name in the canonical EIF template.
    pub fn stage_name(self) -> &'static str {
        match self {
            Self::Init => "enclave-builder",
            Self::Bootproof => "bootproof-builder",
            Self::Steve => "steve-builder",
            Self::Locksmith => "locksmith-builder",
            Self::TapFramer => "tap-framer-builder",
        }
    }

    /// Inclusion marker in the selected framework's EIF template.
    pub fn containerfile_marker(self) -> &'static str {
        match self {
            Self::Init => "{{INIT_CONTAINERFILE}}",
            Self::Bootproof => "{{BOOTPROOF_CONTAINERFILE}}",
            Self::Steve => "{{STEVE_CONTAINERFILE}}",
            Self::Locksmith => "{{LOCKSMITH_CONTAINERFILE}}",
            Self::TapFramer => "{{TAP_FRAMER_CONTAINERFILE}}",
        }
    }

    /// Recipe path relative to the selected framework checkout.
    pub fn containerfile_path(self) -> String {
        format!("containerfiles/Containerfile.{self}")
    }

    /// Recipe embedded in this binary's checkout, for active API startup checks.
    /// Historical publication and reproduction must read the selected revision instead.
    pub fn embedded_containerfile(self) -> &'static str {
        match self {
            Self::Init => include_str!("../../../containerfiles/Containerfile.init"),
            Self::Bootproof => include_str!("../../../containerfiles/Containerfile.bootproof"),
            Self::Steve => include_str!("../../../containerfiles/Containerfile.steve"),
            Self::Locksmith => include_str!("../../../containerfiles/Containerfile.locksmith"),
            Self::TapFramer => include_str!("../../../containerfiles/Containerfile.tap-framer"),
        }
    }

    /// Immutable Git checkout argument for remotely acquired component sources.
    pub fn commit_arg(self) -> Option<&'static str> {
        match self {
            Self::Bootproof => Some("BOOTPROOF_COMMIT"),
            Self::Steve => Some("STEVE_COMMIT"),
            Self::Locksmith => Some("LOCKSMITH_COMMIT"),
            Self::Init | Self::TapFramer => None,
        }
    }

    /// Complete set of permitted output filenames for this component.
    pub fn filenames(self) -> &'static [&'static str] {
        match self {
            Self::Init => &["init"],
            Self::Bootproof => &["bootproofd"],
            Self::Steve => &["steve"],
            Self::Locksmith => &["locksmithd", "locksmith-oneshot"],
            Self::TapFramer => &["tap-framer"],
        }
    }

    /// Source fragment below the build context, or `None` for immutable git clones.
    pub fn source_subdir(self) -> Option<&'static str> {
        match self {
            Self::Init => Some("enclave"),
            Self::TapFramer => Some("src/tap-framer"),
            Self::Bootproof | Self::Steve | Self::Locksmith => None,
        }
    }
}

impl std::fmt::Display for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Invalid component metadata or bytes. Deserialization alone is not validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid component {field}: {reason} [{location}]")]
pub struct ValidationError {
    field: &'static str,
    reason: &'static str,
    location: dterror::Location,
}

#[track_caller]
fn invalid(field: &'static str, reason: &'static str) -> ValidationError {
    ValidationError {
        field,
        reason,
        location: std::panic::Location::caller(),
    }
}

/// SHA-256 of exact bytes, encoded as lowercase hexadecimal.
#[tracing::instrument(skip_all)]
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Reject abbreviated, uppercase, or otherwise noncanonical SHA-256 values.
#[tracing::instrument(skip_all, err)]
pub fn validate_digest(value: &str) -> Result<(), ValidationError> {
    if !is_lower_hex(value, 64) {
        return Err(invalid(
            "sha256",
            "expected 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

/// Reject floating refs and abbreviated or noncanonical Git object IDs.
#[tracing::instrument(skip_all, err)]
pub fn validate_commit(value: &str) -> Result<(), ValidationError> {
    if !is_lower_hex(value, 40) {
        return Err(invalid(
            "source_commit",
            "expected 40 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Immutable identity of one compiler invocation and its selected source bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSpec {
    component: Component,
    source_commit: String,
    recipe_sha256: String,
    source_tree_sha256: Option<String>,
    target: String,
}

impl ComponentSpec {
    /// Construct validated metadata. Prefer `from_inputs` when publishing new builds.
    pub fn new(
        component: Component,
        source_commit: String,
        recipe_sha256: String,
        source_tree_sha256: Option<String>,
    ) -> Result<Self, ValidationError> {
        let spec = Self {
            component,
            source_commit,
            recipe_sha256,
            source_tree_sha256,
            target: TARGET.to_owned(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Component described by this spec.
    pub fn component(&self) -> Component {
        self.component
    }
    /// Immutable revision of the component's owning repository.
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    /// Digest of the rendered standalone compiler recipe.
    pub fn recipe_sha256(&self) -> &str {
        &self.recipe_sha256
    }
    /// Digest of the staged fragment, required for Init and TapFramer.
    pub fn source_tree_sha256(&self) -> Option<&str> {
        self.source_tree_sha256.as_deref()
    }
    /// Compilation target.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Validate metadata; this does not establish correspondence to source bytes.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_commit(&self.source_commit)?;
        validate_digest(&self.recipe_sha256)?;
        if let Some(digest) = &self.source_tree_sha256 {
            validate_digest(digest)?;
        } else if self.component.source_subdir().is_some() {
            return Err(invalid(
                "source_tree_sha256",
                "staged source component requires a tree digest",
            ));
        }
        if self.target != TARGET {
            return Err(invalid("target", "unsupported compilation target"));
        }
        Ok(())
    }

    /// Compute identity from the selected template and staged source fragment.
    ///
    /// `source_dir` is the fragment itself (for example `stage/enclave`), never
    /// the whole application build context. Git-clone components may omit it:
    /// their immutable checkout and locked dependency recipe cover those inputs.
    #[tracing::instrument(skip_all, err)]
    pub fn from_inputs(
        component: Component,
        source_commit: &str,
        template: &str,
        source_dir: Option<&Path>,
        component_recipe: Option<&str>,
    ) -> Result<Self, SpecInputsError> {
        use SpecInputsErrorCtx as Ctx;
        let rendered =
            recipe::render_component(template, component, source_commit, component_recipe)
                .with_context(Ctx::new(component, "render recipe"))?;
        let source_tree_sha256 = source_dir
            .map(recipe::source_tree_sha256)
            .transpose()
            .with_context(Ctx::new(component, "fingerprint source"))?;
        Self::new(
            component,
            source_commit.to_owned(),
            sha256(rendered.as_bytes()),
            source_tree_sha256,
        )
        .with_context(Ctx::new(component, "validate inputs"))
    }
}

/// Could not compute a component's identity from its selected inputs.
#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("could not {operation} for component '{component}' [{location}]")]
pub struct SpecInputsError {
    component: Component,
    operation: &'static str,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

/// Integrity descriptor of one nonempty regular executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    sha256: String,
    size: u64,
}

impl ArtifactFile {
    /// Construct a checked descriptor; byte verification remains mandatory on read.
    pub fn new(sha256: String, size: u64) -> Result<Self, ValidationError> {
        let file = Self { sha256, size };
        file.validate()?;
        Ok(file)
    }
    /// Derive a checked descriptor from the actual artifact.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::new(sha256(bytes), bytes.len() as u64)
    }
    /// Lowercase SHA-256 of the artifact bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    /// Exact artifact length in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Validate the descriptor before allocating or downloading.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_digest(&self.sha256)?;
        if self.size == 0 || self.size > MAX_ARTIFACT_SIZE {
            return Err(invalid(
                "size",
                "artifact must be nonempty and at most 256 MiB",
            ));
        }
        Ok(())
    }
    /// Check exact length and digest of downloaded or independently rebuilt bytes.
    #[tracing::instrument(skip_all, err)]
    pub fn verify(&self, bytes: &[u8]) -> Result<(), ValidationError> {
        self.validate()?;
        if self.size != bytes.len() as u64 || self.sha256 != sha256(bytes) {
            return Err(invalid(
                "artifact",
                "bytes do not match the pinned size and digest",
            ));
        }
        Ok(())
    }
}

/// A compiler identity and its complete immutable output set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentArtifact {
    spec: ComponentSpec,
    #[serde(deserialize_with = "deserialize_unique_map")]
    files: BTreeMap<String, ArtifactFile>,
}

impl ComponentArtifact {
    /// Construct an artifact, requiring every expected filename exactly once.
    pub fn new(
        spec: ComponentSpec,
        files: BTreeMap<String, ArtifactFile>,
    ) -> Result<Self, ValidationError> {
        let artifact = Self { spec, files };
        artifact.validate()?;
        Ok(artifact)
    }
    /// Selected compiler/source identity.
    pub fn spec(&self) -> &ComponentSpec {
        &self.spec
    }
    /// Deterministically ordered artifact descriptors.
    pub fn files(&self) -> &BTreeMap<String, ArtifactFile> {
        &self.files
    }
    /// Validate spec, filenames, complete Locksmith pairing, and descriptor bounds.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.spec.validate()?;
        let expected = self.spec.component.filenames();
        if self.files.len() != expected.len()
            || expected.iter().any(|name| !self.files.contains_key(*name))
        {
            return Err(invalid(
                "files",
                "expected exactly the component's complete allowed filenames",
            ));
        }
        for file in self.files.values() {
            file.validate()?;
        }
        Ok(())
    }
}

/// Pinned set of shared compiler outputs. Verify raw bytes against a separately
/// trusted manifest digest **before** serde parsing; call `validate` after parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSet {
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_unique_map")]
    components: BTreeMap<Component, ComponentArtifact>,
}

impl ComponentSet {
    /// Construct the current schema, requiring Init, Bootproof and TapFramer.
    pub fn new(
        components: BTreeMap<Component, ComponentArtifact>,
    ) -> Result<Self, ValidationError> {
        let set = Self {
            schema_version: SCHEMA_VERSION,
            components,
        };
        set.validate()?;
        Ok(set)
    }
    /// Wire schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    /// The set's artifact map.
    pub fn components(&self) -> &BTreeMap<Component, ComponentArtifact> {
        &self.components
    }
    /// One component, if included in this set.
    pub fn get(&self, component: Component) -> Option<&ComponentArtifact> {
        self.components.get(&component)
    }
    /// Validate the entire set, including unselected optional components.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(invalid("schema_version", "unsupported schema"));
        }
        if Component::REQUIRED
            .iter()
            .any(|c| !self.components.contains_key(c))
        {
            return Err(invalid("components", "required component is missing"));
        }
        for (component, artifact) in &self.components {
            if *component != artifact.spec.component {
                return Err(invalid("component", "map key and spec disagree"));
            }
            artifact.validate()?;
        }
        Ok(())
    }

    /// Validated compact JSON with every object sorted lexicographically.
    /// Hash these exact bytes for publication, not an arbitrary serde rendering.
    #[tracing::instrument(skip_all, err)]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalBytesError> {
        use CanonicalBytesErrorCtx as Ctx;
        self.validate().with_context(Ctx::new("validate"))?;
        let mut value = serde_json::to_value(self).with_context(Ctx::new("serialize"))?;
        value.sort_all_objects();
        serde_json::to_vec(&value).with_context(Ctx::new("encode"))
    }

    /// Recompute selected recipe/source identities against the commits from the
    /// deployment manifest. Never pass the component set's own claimed commits
    /// as a substitute for those independently selected source revisions.
    #[tracing::instrument(skip_all, err)]
    pub fn validate_selected(
        &self,
        template: &str,
        selected: &[SelectedComponent<'_>],
        recipes: &BTreeMap<Component, String>,
    ) -> Result<(), SelectionError> {
        use SelectionErrorCtx as Ctx;
        self.validate().with_context(Ctx::new("validate set"))?;
        if selected.is_empty() {
            return Err(invalid("selection", "empty selection"))
                .with_context(Ctx::new("validate selection"));
        }
        let mut seen = BTreeSet::new();
        for input in selected {
            if !seen.insert(input.component) {
                return Err(invalid("selection", "duplicate selected component"))
                    .with_context(Ctx::new("validate selection"));
            }
            let artifact = self
                .get(input.component)
                .ok_or_else(|| invalid("selection", "selected component is absent"))
                .with_context(Ctx::new("select artifact"))?;
            let expected = ComponentSpec::from_inputs(
                input.component,
                input.source_commit,
                template,
                input.source_dir,
                recipes.get(&input.component).map(String::as_str),
            )
            .with_context(Ctx::new("recompute selected inputs"))?;
            if artifact.spec != expected {
                return Err(invalid(
                    "selection",
                    "source revision, recipe or staged source differs",
                ))
                .with_context(Ctx::new("compare selected inputs"));
            }
        }
        Ok(())
    }
}

/// Actual source inputs selected by a deployment or historical reproduction.
#[derive(Debug, Clone, Copy)]
pub struct SelectedComponent<'a> {
    component: Component,
    source_commit: &'a str,
    source_dir: Option<&'a Path>,
}

impl<'a> SelectedComponent<'a> {
    /// Describe a selected commit and optional staged source fragment.
    pub fn new(component: Component, source_commit: &'a str, source_dir: Option<&'a Path>) -> Self {
        Self {
            component,
            source_commit,
            source_dir,
        }
    }
    /// Selected component.
    pub fn component(&self) -> Component {
        self.component
    }
    /// Revision independently selected by the deployment manifest.
    pub fn source_commit(&self) -> &str {
        self.source_commit
    }
    /// Selected staged source fragment, not the whole application context.
    pub fn source_dir(&self) -> Option<&Path> {
        self.source_dir
    }
}

/// Could not validate or encode a manifest for publication.
#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("could not {operation} component manifest [{location}]")]
pub struct CanonicalBytesError {
    operation: &'static str,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

/// Selected real inputs are unavailable or disagree with the pinned set.
#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("could not {operation} [{location}]")]
pub struct SelectionError {
    operation: &'static str,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

/// Digest-addressed artifact object key; filenames cannot introduce path traversal.
#[tracing::instrument(skip_all, err)]
pub fn artifact_key(digest: &str, filename: &str) -> Result<String, ValidationError> {
    validate_digest(digest)?;
    if !Component::ALL
        .iter()
        .any(|c| c.filenames().contains(&filename))
    {
        return Err(invalid("filename", "unknown artifact filename"));
    }
    Ok(format!("components/v1/blobs/sha256/{digest}/{filename}"))
}

/// Digest-addressed key of canonical manifest bytes.
#[tracing::instrument(skip_all, err)]
pub fn manifest_key(digest: &str) -> Result<String, ValidationError> {
    validate_digest(digest)?;
    Ok(format!("components/v1/manifests/sha256/{digest}.json"))
}

fn deserialize_unique_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct UniqueMap<K, V>(std::marker::PhantomData<(K, V)>);
    impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> serde::de::Visitor<'de>
        for UniqueMap<K, V>
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map without duplicate keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry()? {
                if map.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate component manifest map key",
                    ));
                }
            }
            Ok(map)
        }
    }
    deserializer.deserialize_map(UniqueMap(std::marker::PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn artifact(component: Component) -> ComponentArtifact {
        let spec = ComponentSpec::new(
            component,
            COMMIT.to_owned(),
            sha256(b"recipe"),
            component.source_subdir().map(|_| sha256(b"source")),
        )
        .unwrap();
        let files = component
            .filenames()
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    ArtifactFile::from_bytes(name.as_bytes()).unwrap(),
                )
            })
            .collect();
        ComponentArtifact::new(spec, files).unwrap()
    }

    fn set() -> ComponentSet {
        ComponentSet::new(
            Component::ALL
                .into_iter()
                .map(|c| (c, artifact(c)))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_canonical_manifest_and_content_keys() {
        let set = set();
        let bytes = set.canonical_bytes().unwrap();
        let restored: ComponentSet = serde_json::from_slice(&bytes).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored, set);
        assert_eq!(restored.canonical_bytes().unwrap(), bytes);
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            manifest_key(&sha256(&bytes)).unwrap(),
            format!("components/v1/manifests/sha256/{}.json", sha256(&bytes))
        );
        let file = ArtifactFile::from_bytes(b"abc").unwrap();
        assert_eq!(
            artifact_key(file.sha256(), "init").unwrap(),
            format!("components/v1/blobs/sha256/{}/init", file.sha256())
        );
        assert!(artifact_key(file.sha256(), "../init").is_err());
        assert!(manifest_key("bad").is_err());
        let object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(object["components"]["tap-framer"]["spec"]["target"], TARGET);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.find("\"bootproof\":").unwrap() < text.find("\"init\":").unwrap());
    }

    #[test]
    fn schema_rejects_missing_required_and_partial_locksmith() {
        for component in Component::REQUIRED {
            let mut value = serde_json::to_value(set()).unwrap();
            value["components"]
                .as_object_mut()
                .unwrap()
                .remove(component.as_str());
            assert!(serde_json::from_value::<ComponentSet>(value)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut value = serde_json::to_value(set()).unwrap();
        value["components"]["locksmith"]["files"]
            .as_object_mut()
            .unwrap()
            .remove("locksmith-oneshot");
        assert!(serde_json::from_value::<ComponentSet>(value)
            .unwrap()
            .validate()
            .is_err());
        assert!(ComponentSet::new(BTreeMap::new()).is_err());
    }

    #[test]
    fn schema_rejects_corrupt_and_unreasonable_descriptors() {
        for (pointer, replacement) in [
            ("/schema_version", serde_json::json!(2)),
            (
                "/components/init/spec/source_commit",
                serde_json::json!("main"),
            ),
            (
                "/components/init/spec/source_commit",
                serde_json::json!("A".repeat(40)),
            ),
            (
                "/components/init/spec/recipe_sha256",
                serde_json::json!("0".repeat(63)),
            ),
            (
                "/components/init/spec/source_tree_sha256",
                serde_json::Value::Null,
            ),
            (
                "/components/tap-framer/spec/source_tree_sha256",
                serde_json::json!("Z".repeat(64)),
            ),
            (
                "/components/init/spec/target",
                serde_json::json!("aarch64-unknown-linux-musl"),
            ),
            (
                "/components/init/spec/component",
                serde_json::json!("steve"),
            ),
            (
                "/components/init/files/init/sha256",
                serde_json::json!("F".repeat(64)),
            ),
            ("/components/init/files/init/size", serde_json::json!(0)),
            (
                "/components/init/files/init/size",
                serde_json::json!(MAX_ARTIFACT_SIZE + 1),
            ),
        ] {
            let mut value = serde_json::to_value(set()).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                serde_json::from_value::<ComponentSet>(value)
                    .unwrap()
                    .validate()
                    .is_err(),
                "accepted {pointer}"
            );
        }
        let mut value = serde_json::to_value(set()).unwrap();
        value["components"]["init"]["files"]["../init"] =
            serde_json::to_value(ArtifactFile::from_bytes(b"bad").unwrap()).unwrap();
        assert!(serde_json::from_value::<ComponentSet>(value)
            .unwrap()
            .validate()
            .is_err());
    }

    #[test]
    fn rejects_unknown_fields_components_and_duplicate_map_entries() {
        assert!(serde_json::from_str::<Component>("\"future-component\"").is_err());
        let mut value = serde_json::to_value(set()).unwrap();
        value["ignored"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ComponentSet>(value).is_err());
        let descriptor = format!("{{\"sha256\":\"{}\",\"size\":1}}", sha256(b"x"));
        let spec = serde_json::to_string(artifact(Component::Init).spec()).unwrap();
        let duplicate = format!(
            "{{\"spec\":{spec},\"files\":{{\"init\":{descriptor},\"init\":{descriptor}}}}}"
        );
        assert!(serde_json::from_str::<ComponentArtifact>(&duplicate).is_err());
    }

    #[test]
    fn artifact_bytes_must_match_both_size_and_digest() {
        let file = ArtifactFile::from_bytes(b"good").unwrap();
        file.verify(b"good").unwrap();
        assert_eq!(file.size(), b"evil".len() as u64);
        assert_ne!(file.sha256(), sha256(b"evil"));
        assert!(matches!(
            file.verify(b"evil"),
            Err(ValidationError {
                field: "artifact",
                ..
            })
        ));
        let wrong_size = ArtifactFile::new(file.sha256().to_owned(), file.size() + 1).unwrap();
        assert_eq!(wrong_size.sha256(), sha256(b"good"));
        assert_ne!(wrong_size.size(), b"good".len() as u64);
        assert!(matches!(
            wrong_size.verify(b"good"),
            Err(ValidationError {
                field: "artifact",
                ..
            })
        ));
    }
}
