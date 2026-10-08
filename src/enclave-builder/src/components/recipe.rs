// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Canonical selected-revision component recipes, with historical inline compatibility.

use super::{validate_commit, validate_digest, Component, ComponentArtifact};
use dterror::ResultExt;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The selected template cannot be safely split or rewritten.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum RecipeError {
    /// A standalone recipe required by the selected framework is unavailable.
    #[error("could not read selected component Containerfile '{path}' [{location}]")]
    Read {
        /// Path inside the selected framework checkout.
        #[context(borrow = Path)]
        path: PathBuf,
        /// Internal caller location.
        #[location]
        location: dterror::Location,
        /// Underlying file error.
        #[source]
        source: dterror::BoxError,
    },
    /// A required stage is absent, duplicated, or structurally unsupported.
    #[error("invalid component recipe stage '{stage}': {reason} [{location}]")]
    Invalid {
        /// Stage name or input label.
        stage: String,
        /// Fixed diagnostic reason.
        reason: &'static str,
        /// Internal caller location.
        location: dterror::Location,
    },
    /// A selected revision or artifact descriptor is invalid.
    #[error("invalid component recipe {input} [{location}]")]
    Input {
        /// Input being checked.
        input: &'static str,
        /// Internal caller location.
        #[location]
        location: dterror::Location,
        /// Underlying validation failure.
        #[source]
        source: dterror::BoxError,
    },
}

#[track_caller]
fn invalid_recipe(stage: &str, reason: &'static str) -> RecipeError {
    RecipeError::Invalid {
        stage: stage.to_owned(),
        reason,
        location: std::panic::Location::caller(),
    }
}

#[derive(Debug)]
struct Stage<'a> {
    name: &'a str,
    base: &'a str,
    start: usize,
    end: usize,
}

#[tracing::instrument(skip_all, err)]
fn parse_stages(template: &str) -> Result<Vec<Stage<'_>>, RecipeError> {
    let mut stages: Vec<Stage<'_>> = Vec::new();
    let mut names = BTreeSet::new();
    let mut offset = 0;
    for line in template.split_inclusive('\n') {
        let words: Vec<_> = line.split_whitespace().collect();
        if words
            .first()
            .is_some_and(|word| word.eq_ignore_ascii_case("FROM"))
        {
            if words.len() != 4 || words[0] != "FROM" || words[2] != "AS" {
                return Err(invalid_recipe(
                    "FROM",
                    "expected exact FROM <base> AS <name> declaration",
                ));
            }
            let name = words[3];
            if !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !names.insert(name)
            {
                return Err(invalid_recipe(name, "invalid or duplicate stage name"));
            }
            if let Some(previous) = stages.last_mut() {
                previous.end = offset;
            }
            stages.push(Stage {
                name,
                base: words[1],
                start: offset,
                end: template.len(),
            });
        }
        offset += line.len();
    }
    if stages.is_empty() {
        return Err(invalid_recipe("FROM", "template has no stages"));
    }
    Ok(stages)
}

#[tracing::instrument(skip_all)]
fn is_conditional_marker(line: &str) -> bool {
    let text = line.trim();
    text.strip_prefix("# {")
        .or_else(|| text.strip_prefix("# }"))
        .is_some_and(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        })
}

#[tracing::instrument(skip_all, err)]
fn selected_stage<'a, 'b>(
    stages: &'b [Stage<'a>],
    component: Component,
) -> Result<&'b Stage<'a>, RecipeError> {
    stages
        .iter()
        .find(|s| s.name == component.stage_name())
        .ok_or_else(|| invalid_recipe(component.stage_name(), "required stage is missing"))
}

/// Source location in current and historical selected compiler recipes.
/// This never falls back to a different framework checkout.
pub fn source_subdir(template: &str, component: Component) -> Option<&'static str> {
    if component == Component::TapFramer {
        for path in ["src/tap-framer", "components/tap-framer", "tap-framer"] {
            if template
                .lines()
                .any(|line| line.starts_with(&format!("COPY {path}/ ")))
            {
                return Some(path);
            }
        }
    }
    component.source_subdir()
}

/// Read only the selected recipes requested by surviving inclusion markers.
/// Neither a disabled component nor an old inline template requires a standalone file.
#[tracing::instrument(skip_all, err)]
pub async fn read_selected(
    templates: &Path,
    template: &str,
    components: &[Component],
) -> Result<BTreeMap<Component, String>, RecipeError> {
    use RecipeErrorCtx as Ctx;
    let mut recipes = BTreeMap::new();
    for &component in components {
        if template.contains(component.containerfile_marker()) {
            let path = templates
                .join("../../..")
                .join(component.containerfile_path());
            let recipe = tokio::fs::read_to_string(&path)
                .await
                .with_context(Ctx::read(&path))?;
            recipes.insert(component, recipe);
        }
    }
    Ok(recipes)
}

/// Keep canonical import names local to each component when composing an EIF.
#[tracing::instrument(skip_all)]
pub(crate) fn scope_imports(recipe: &str, component: Component) -> String {
    let prefix = format!("{component}-");
    let mut scoped = recipe.to_owned();
    for line in recipe.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if let ["FROM", base, "AS", name] = words.as_slice() {
            if base.contains("@sha256:") && !name.starts_with(&prefix) {
                let alias = format!("{prefix}{name}");
                scoped = scoped
                    .replace(&format!("{line}\n"), &format!("FROM {base} AS {alias}\n"))
                    .replace(&format!("FROM {name} AS "), &format!("FROM {alias} AS "))
                    .replace(&format!("--from={name} "), &format!("--from={alias} "));
            }
        }
    }
    scoped
}

/// Bind the same source revision in standalone recipes and composed EIF builds.
/// Historical inline templates use commit tokens rather than Docker build arguments.
#[tracing::instrument(skip_all)]
pub fn pin_source_revision(recipe: &str, component: Component, commit: &str) -> String {
    match component.commit_arg() {
        Some(arg) => recipe
            .replace(&format!("{{{{{arg}}}}}"), commit)
            .replace(&format!("ARG {arg}\n"), &format!("ARG {arg}={commit}\n"))
            // Release/source builds bind a literal checkout, so Docker ARG overrides
            // or recipe ENV shadows cannot alter the selected source revision.
            .replace(
                &format!("git checkout \"${arg}\""),
                &format!("git checkout {commit}"),
            ),
        None => recipe.to_owned(),
    }
}

/// Render the entire selected canonical recipe, binding its immutable source revision
/// and adding an `output` alias to its export stage. Only historical templates without
/// this component's inclusion marker use the original inline stage extraction.
#[tracing::instrument(skip_all, err)]
pub fn render_component(
    template: &str,
    component: Component,
    source_commit: &str,
    component_recipe: Option<&str>,
) -> Result<String, RecipeError> {
    use RecipeErrorCtx as Ctx;
    validate_commit(source_commit).with_context(Ctx::input("source commit"))?;
    let standalone = template.contains(component.containerfile_marker());
    let template = if standalone {
        component_recipe.ok_or_else(|| {
            invalid_recipe(
                component.stage_name(),
                "selected standalone component recipe is missing",
            )
        })?
    } else {
        template
    };
    let stages = parse_stages(template)?;
    let chosen = selected_stage(&stages, component)?;
    let first_compiler = stages
        .iter()
        .position(|s| Component::ALL.iter().any(|c| s.name == c.stage_name()))
        .ok_or_else(|| invalid_recipe(component.stage_name(), "no compiler stages"))?;
    let globals = &stages[..first_compiler];
    if globals.is_empty() || !globals.iter().any(|s| s.name == chosen.base) {
        return Err(invalid_recipe(
            chosen.name,
            "compiler must derive from a pinned global image",
        ));
    }
    let mut output = String::new();
    for stage in globals {
        let digest = stage
            .base
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .ok_or_else(|| invalid_recipe(stage.name, "global image is not digest pinned"))?;
        validate_digest(digest).with_context(Ctx::input("global image digest"))?;
        if template[stage.start..stage.end]
            .lines()
            .skip(1)
            .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        {
            return Err(invalid_recipe(
                stage.name,
                "global image declaration contains build instructions",
            ));
        }
        output.push_str(&format!("FROM {} AS {}\n", stage.base, stage.name));
    }
    output.push('\n');
    let mut body = template[chosen.start..chosen.end]
        .lines()
        .filter(|line| {
            !is_conditional_marker(line)
                && !Component::ALL
                    .iter()
                    .any(|c| line.trim() == c.containerfile_marker())
        })
        .collect::<Vec<_>>()
        .join("\n");
    validate_source_imports(&body, component, globals)?;
    if let Some(arg) = component.commit_arg() {
        let token = format!("{{{{{arg}}}}}");
        let checkout = if standalone {
            format!("git checkout \"${arg}\"")
        } else {
            format!("git checkout {token}")
        };
        let pinned_input = if standalone {
            body.lines()
                .filter(|line| *line == format!("ARG {arg}"))
                .count()
                == 1
                && body.matches(&format!("ARG {arg}")).count() == 1
        } else {
            body.matches(&token).count() == 1
        };
        if !pinned_input
            || body.matches("git checkout").count() != 1
            || !body.lines().any(|line| line.trim() == checkout)
        {
            return Err(invalid_recipe(
                chosen.name,
                "expected a single immutable checkout without branch fallback",
            ));
        }
        body = pin_source_revision(&body, component, source_commit);
    }
    if body.contains("{{") || body.contains("}}") {
        return Err(invalid_recipe(
            chosen.name,
            "unresolved or unrelated template token",
        ));
    }
    if standalone {
        let export = format!("{component}-export");
        if !stages
            .iter()
            .any(|stage| stage.name == export && stage.base == "scratch")
        {
            return Err(invalid_recipe(&export, "canonical export stage is missing"));
        }
        let recipe = pin_source_revision(template, component, source_commit);
        return Ok(format!("{recipe}\nFROM {export} AS output\n"));
    }
    output.push_str(body.trim_end());
    output.push_str("\n\nFROM scratch AS output\n");
    for name in component.filenames() {
        output.push_str(&format!(
            "COPY --from={} /binaries/{name} /{name}\n",
            component.stage_name()
        ));
    }
    Ok(output)
}

#[tracing::instrument(skip_all, err)]
fn validate_source_imports(
    body: &str,
    component: Component,
    globals: &[Stage<'_>],
) -> Result<(), RecipeError> {
    for line in body.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        match words
            .first()
            .map(|word| word.to_ascii_uppercase())
            .as_deref()
        {
            Some("ADD") => {
                return Err(invalid_recipe(
                    component.stage_name(),
                    "ADD inputs are outside the source identity contract",
                ));
            }
            Some("COPY") => {
                if let Some(from) = words.get(1).and_then(|word| word.strip_prefix("--from=")) {
                    if !globals.iter().any(|stage| stage.name == from) {
                        return Err(invalid_recipe(
                            component.stage_name(),
                            "COPY must reference a pinned global stage",
                        ));
                    }
                } else if component == Component::TapFramer
                    && matches!(
                        words.as_slice(),
                        [
                            "COPY",
                            "src/tap-framer/Cargo.toml",
                            "src/tap-framer/Cargo.lock",
                            _
                        ] | ["COPY", "src/tap-framer/src/", _]
                    )
                {
                    // The canonical standalone recipe copies only this fingerprinted fragment.
                } else if words.len() != 3
                    || component.source_subdir().is_none_or(|directory| {
                        words[1] != format!("{directory}/")
                            && !(component == Component::TapFramer
                                && matches!(words[1], "components/tap-framer/" | "tap-framer/"))
                    })
                {
                    return Err(invalid_recipe(
                        component.stage_name(),
                        "COPY input is not the fingerprinted component source fragment",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Replace only selected compiler stages, retaining every unselected stage and
/// the EIF assembly/output paths. Run on the original or feature-filtered template,
/// before ordinary template substitutions. Missing/duplicate stages are errors.
/// Consumers must verify and stage the exact files below `prebuilt/` first.
#[tracing::instrument(skip_all, err)]
pub fn rewrite_prebuilt(template: &str, selected: &[Component]) -> Result<String, RecipeError> {
    let stages = parse_stages(template)?;
    let mut replacements = BTreeMap::new();
    for component in selected {
        let stage = selected_stage(&stages, *component)?;
        let mut body = format!("FROM scratch AS {}\n", component.stage_name());
        for name in component.filenames() {
            body.push_str(&format!("COPY prebuilt/{name} /binaries/{name}\n"));
        }
        for marker in template[stage.start..stage.end]
            .lines()
            .filter(|line| is_conditional_marker(line))
        {
            body.push_str(marker);
            body.push('\n');
        }
        body.push('\n');
        if replacements
            .insert(stage.start, (stage.end, body))
            .is_some()
        {
            return Err(invalid_recipe(stage.name, "duplicate selected component"));
        }
    }
    Ok(replace_ranges(template, replacements))
}

/// Add SHA-256 assertions to the *source compiler stages*, never substitute cached
/// binaries. Call after checking selected inputs, before rendering/filtering the
/// full EIF template. The Docker build must independently execute these source
/// stages (use a clean builder/`--no-cache` for independent reproduction).
#[tracing::instrument(skip_all, err)]
pub fn append_source_verification(
    template: &str,
    artifacts: &BTreeMap<Component, ComponentArtifact>,
) -> Result<String, RecipeError> {
    use RecipeErrorCtx as Ctx;
    let stages = parse_stages(template)?;
    let mut replacements = BTreeMap::new();
    for (component, artifact) in artifacts {
        artifact.validate().with_context(Ctx::input("artifact"))?;
        if artifact.spec().component() != *component {
            return Err(invalid_recipe(
                component.stage_name(),
                "artifact belongs to a different component",
            ));
        }
        let stage = selected_stage(&stages, *component)?;
        let original = &template[stage.start..stage.end];
        if stage.base == "scratch"
            || original.contains("COPY prebuilt/")
            || !original.contains("cargo build")
        {
            return Err(invalid_recipe(
                stage.name,
                "verification requires a source compiler stage",
            ));
        }
        let mut body = String::new();
        let mut markers = String::new();
        for line in original.lines() {
            let destination = if is_conditional_marker(line) {
                &mut markers
            } else {
                &mut body
            };
            destination.push_str(line);
            destination.push('\n');
        }
        body.push_str("RUN printf '%s\\n'");
        for (name, file) in artifact.files() {
            body.push_str(&format!(" '{}  /binaries/{name}'", file.sha256()));
        }
        body.push_str(" | sha256sum -c -\n");
        body.push_str(&markers);
        body.push('\n');
        replacements.insert(stage.start, (stage.end, body));
    }
    Ok(replace_ranges(template, replacements))
}

#[tracing::instrument(skip_all)]
fn replace_ranges(template: &str, replacements: BTreeMap<usize, (usize, String)>) -> String {
    let mut output = String::with_capacity(template.len());
    let mut copied = 0;
    for (start, (end, replacement)) in replacements {
        output.push_str(&template[copied..start]);
        output.push_str(&replacement);
        copied = end;
    }
    output.push_str(&template[copied..]);
    output
}

/// Source tree cannot be fingerprinted deterministically and safely.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum SourceTreeError {
    /// A source file or directory could not be read.
    #[error("could not read component source '{path}' [{location}]")]
    Read {
        /// Source path.
        #[context(borrow = Path)]
        path: PathBuf,
        /// Internal caller location.
        #[location]
        location: dterror::Location,
        /// Underlying filesystem error.
        #[source]
        source: dterror::BoxError,
    },
    /// Links, special files, and non-UTF-8 paths are outside the source contract.
    #[error("unsupported component source '{path}': {reason} [{location}]")]
    Unsupported {
        /// Source path.
        path: PathBuf,
        /// Fixed diagnostic reason.
        reason: &'static str,
        /// Internal caller location.
        location: dterror::Location,
    },
}

#[track_caller]
fn unsupported_source(path: &Path, reason: &'static str) -> SourceTreeError {
    SourceTreeError::Unsupported {
        path: path.to_owned(),
        reason,
        location: std::panic::Location::caller(),
    }
}

/// Fingerprint one immutable staged source fragment, not an application's entire
/// build context. Sorted relative paths, node types, executable bits and exact
/// file bytes are length framed and domain separated. Only `.git` and `target`
/// entries are ignored, at any depth. Symlinks (including the root), special
/// files, and non-UTF-8 paths are rejected; timestamps/ownership/umask are ignored.
/// The caller must keep the staged tree unchanged while hashing and building.
#[tracing::instrument(skip_all, err)]
pub fn source_tree_sha256(root: &Path) -> Result<String, SourceTreeError> {
    use SourceTreeErrorCtx as Ctx;
    let metadata = std::fs::symlink_metadata(root).with_context(Ctx::read(root))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(unsupported_source(
            root,
            "source root must be a real directory",
        ));
    }
    let mut entries = BTreeMap::new();
    collect_sources(root, root, &mut entries)?;
    let mut hash = Sha256::new();
    hash.update(b"caution-component-source-tree-v1\0");
    for (relative, (path, metadata)) in entries {
        hash.update((relative.len() as u64).to_be_bytes());
        hash.update(relative.as_bytes());
        hash.update([if metadata.is_dir() { b'd' } else { b'f' }]);
        hash.update([u8::from(metadata.permissions().mode() & 0o111 != 0)]);
        if metadata.is_file() {
            hash.update(metadata.len().to_be_bytes());
            let mut file = std::fs::File::open(&path).with_context(Ctx::read(&path))?;
            let mut buffer = [0u8; 64 * 1024];
            let mut length = 0u64;
            loop {
                let read = file.read(&mut buffer).with_context(Ctx::read(&path))?;
                if read == 0 {
                    break;
                }
                hash.update(&buffer[..read]);
                length += read as u64;
            }
            if length != metadata.len() {
                return Err(unsupported_source(
                    &path,
                    "source changed while fingerprinting",
                ));
            }
        }
    }
    Ok(hex::encode(hash.finalize()))
}

#[tracing::instrument(skip_all, err)]
fn collect_sources(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<String, (PathBuf, std::fs::Metadata)>,
) -> Result<(), SourceTreeError> {
    use SourceTreeErrorCtx as Ctx;
    for entry in std::fs::read_dir(directory).with_context(Ctx::read(directory))? {
        let entry = entry.with_context(Ctx::read(directory))?;
        if entry.file_name() == ".git" || entry.file_name() == "target" {
            continue;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).with_context(Ctx::read(&path))?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(unsupported_source(
                &path,
                "links and special files are forbidden",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .with_context(Ctx::read(&path))?
            .to_str()
            .ok_or_else(|| unsupported_source(&path, "path must be UTF-8"))?
            .to_owned();
        if metadata.is_dir() {
            collect_sources(root, &path, entries)?;
        }
        entries.insert(relative, (path, metadata));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::{
        ArtifactFile, ComponentArtifact, ComponentSet, ComponentSpec, SelectedComponent,
    };

    // Frozen from 4fd6292: historical inline components plus the standalone TAP marker.
    const TEMPLATE: &str = include_str!("../../tests/fixtures/Containerfile.eif.inline-components");
    const TAP_RECIPE: &str = include_str!("../../../../containerfiles/Containerfile.tap-framer");
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn canonical_files_are_shared_whole_and_selected_without_fallback() {
        let template = include_str!("../../templates/Containerfile.eif");
        for component in Component::ALL {
            let recipe = component.embedded_containerfile();
            let scoped = scope_imports(recipe, component);
            assert_eq!(scope_imports(&scoped, component), scoped);
            for stage in parse_stages(recipe).unwrap() {
                if stage.base.contains("@sha256:") {
                    assert!(!stage.name.starts_with(&format!("{component}-")));
                    assert!(scoped.contains(&format!(
                        "FROM {} AS {component}-{}\n",
                        stage.base, stage.name
                    )));
                }
            }
            assert!(render_component(template, component, COMMIT, None).is_err());
            let rendered = render_component(template, component, COMMIT, Some(recipe)).unwrap();
            assert_eq!(
                rendered,
                format!(
                    "{}\nFROM {component}-export AS output\n",
                    pin_source_revision(recipe, component, COMMIT)
                )
            );
            assert!(!rendered.contains("{{"));
            if let Some(arg) = component.commit_arg() {
                assert!(rendered.contains(&format!("ARG {arg}={COMMIT}\n")));
                // Caller build arguments or ENV shadows must not change the selected Git checkout.
                assert!(rendered.contains(&format!("git checkout {COMMIT}\n")));
                assert!(!rendered.contains(&format!("git checkout \"${arg}\"")));
            }
            let changed = format!("{recipe}\n# changed selected recipe\n");
            assert_ne!(
                rendered,
                render_component(template, component, COMMIT, Some(&changed)).unwrap()
            );
            let unrelated = template.replace("COPY app/", "COPY different-app/");
            assert_eq!(
                rendered,
                render_component(&unrelated, component, COMMIT, Some(recipe)).unwrap()
            );
            assert!(!template.contains(&format!(" AS {}", component.stage_name())));
        }
    }

    #[test]
    fn canonical_recipes_reject_unpinned_inputs_and_wrong_export() {
        let template = include_str!("../../templates/Containerfile.eif");
        let original = Component::Bootproof.embedded_containerfile();
        for changed in [
            original.replace("ARG BOOTPROOF_COMMIT\n", "ARG BOOTPROOF_COMMIT=main\n"),
            original.replace(
                "ARG BOOTPROOF_COMMIT\n",
                "ARG BOOTPROOF_COMMIT\nARG BOOTPROOF_COMMIT\n",
            ),
            original.replace(
                "git checkout \"$BOOTPROOF_COMMIT\"",
                "git checkout \"$BOOTPROOF_COMMIT\" || git checkout main",
            ),
            original.replace(
                "COPY --from=git . /",
                "COPY --from=untrusted:latest . /",
            ),
            original.replace("COPY --from=git . /", "COPY app/ /build-bootproof/"),
            original.replace(
                "FROM scratch AS bootproof-export",
                "FROM scratch AS wrong-export",
            ),
        ] {
            assert_ne!(changed, original);
            assert!(
                render_component(template, Component::Bootproof, COMMIT, Some(&changed)).is_err()
            );
        }
        assert!(render_component(template, Component::Bootproof, "main", Some(original)).is_err());
    }

    #[test]
    fn extracts_every_real_component_and_exact_export_paths() {
        for component in Component::ALL {
            let rendered = render_component(TEMPLATE, component, COMMIT, Some(TAP_RECIPE)).unwrap();
            let parsed = parse_stages(&rendered).unwrap();
            assert!(parsed.iter().all(|s| s.base.contains("@sha256:")
                || s.name == component.stage_name()
                || s.name == "tap-framer-export"
                || s.name == "output"));
            let selected = parsed
                .iter()
                .find(|s| s.name == component.stage_name())
                .unwrap();
            assert!(rendered[selected.start..selected.end].contains("cargo build"));
            assert_eq!(parsed.last().unwrap().name, "output");
            for filename in component.filenames() {
                assert!(rendered.contains(
                    &format!(
                        "COPY --from={} /binaries/{filename} /{filename}\n",
                        component.stage_name()
                    )
                    .trim_end()
                ));
            }
            assert!(!rendered.contains("{{"));
            assert!(!rendered.contains("# {"));
            assert!(!rendered.contains("COPY app/"));
            assert!(!rendered.contains("eif_build \\"));
        }
    }

    #[test]
    fn canonical_tap_uses_whole_selected_recipe_and_never_current_fallback() {
        assert!(render_component(TEMPLATE, Component::TapFramer, COMMIT, None).is_err());
        let selected = TAP_RECIPE.replace("codegen-units=1", "codegen-units=2");
        let rendered =
            render_component(TEMPLATE, Component::TapFramer, COMMIT, Some(&selected)).unwrap();
        assert_eq!(
            rendered,
            format!("{selected}\nFROM tap-framer-export AS output\n")
        );
        assert_ne!(
            rendered,
            render_component(TEMPLATE, Component::TapFramer, COMMIT, Some(TAP_RECIPE)).unwrap()
        );
        assert_eq!(
            render_component(TEMPLATE, Component::Init, COMMIT, Some(&selected)).unwrap(),
            render_component(TEMPLATE, Component::Init, COMMIT, None).unwrap(),
        );
        for directory in ["components/tap-framer", "tap-framer"] {
            let historical = TAP_RECIPE.replace(
                "COPY src/tap-framer/Cargo.toml src/tap-framer/Cargo.lock /build-tap-framer/\nCOPY src/tap-framer/src/ /build-tap-framer/src/",
                &format!("COPY {directory}/ /build-tap-framer/"),
            );
            let old = render_component(&historical, Component::TapFramer, COMMIT, None).unwrap();
            assert_eq!(
                old,
                render_component(
                    &historical,
                    Component::TapFramer,
                    COMMIT,
                    Some("invalid current recipe")
                )
                .unwrap()
            );
            assert_eq!(
                source_subdir(&historical, Component::TapFramer),
                Some(directory)
            );
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_unpinned_stages_without_fallback() {
        assert!(render_component(
            "FROM scratch AS output\n",
            Component::Init,
            COMMIT,
            Some(TAP_RECIPE)
        )
        .is_err());
        let duplicate = format!("{TEMPLATE}\nFROM pallet-rust AS enclave-builder\n");
        assert!(render_component(&duplicate, Component::Init, COMMIT, Some(TAP_RECIPE)).is_err());
        assert!(render_component(
            &TEMPLATE.replace(" AS enclave-builder", " AS renamed-builder"),
            Component::Init,
            COMMIT,
            Some(TAP_RECIPE)
        )
        .is_err());
        assert!(render_component(
            &TEMPLATE.replace("{{BOOTPROOF_COMMIT}}", "main"),
            Component::Bootproof,
            COMMIT,
            Some(TAP_RECIPE)
        )
        .is_err());
        let first = TEMPLATE.lines().next().unwrap();
        assert!(render_component(
            &TEMPLATE.replace(first, "FROM stagex/pallet-rust:latest AS pallet-rust"),
            Component::Init,
            COMMIT,
            Some(TAP_RECIPE)
        )
        .is_err());
        assert!(
            render_component(TEMPLATE, Component::Bootproof, "main", Some(TAP_RECIPE)).is_err()
        );
    }

    #[test]
    fn rejects_unpinned_imports_unfingerprinted_sources_and_branch_fallback() {
        for changed in [
            TEMPLATE.replace("COPY --from=git . /", "copy --from=untrusted:latest . /"),
            TEMPLATE.replace("COPY --from=git . /", "COPY --from=untrusted:latest . /"),
            TEMPLATE.replace("COPY --from=git . /", "COPY app/ /build-bootproof/"),
            TEMPLATE.replace(
                "COPY --from=git . /",
                "ADD https://example.test/source.tar /build-bootproof/",
            ),
            TEMPLATE.replace(
                "git checkout {{BOOTPROOF_COMMIT}}",
                "git checkout {{BOOTPROOF_COMMIT}} || git checkout main",
            ),
        ] {
            assert!(
                render_component(&changed, Component::Bootproof, COMMIT, Some(TAP_RECIPE)).is_err()
            );
        }
        assert!(render_component(
            &TEMPLATE.replace("COPY enclave/ /build-enclave/", "COPY app/ /build-enclave/"),
            Component::Init,
            COMMIT,
            Some(TAP_RECIPE)
        )
        .is_err());
    }

    #[test]
    fn recipe_identity_ignores_unrelated_application_and_component_inputs() {
        let expected =
            render_component(TEMPLATE, Component::Init, COMMIT, Some(TAP_RECIPE)).unwrap();
        let unrelated = TEMPLATE
            .replace(
                "COPY app/ /build/initramfs/",
                "COPY other-app/ /build/initramfs/",
            )
            .replace("{{STEVE_COMMIT}}", "unrelated");
        assert_eq!(
            render_component(&unrelated, Component::Init, COMMIT, Some(TAP_RECIPE)).unwrap(),
            expected
        );
        let changed = TEMPLATE.replace("-p init", "-p init --features changed");
        assert_ne!(
            render_component(&changed, Component::Init, COMMIT, Some(TAP_RECIPE)).unwrap(),
            expected
        );
        assert_ne!(
            render_component(TEMPLATE, Component::Bootproof, COMMIT, Some(TAP_RECIPE)).unwrap(),
            render_component(
                TEMPLATE,
                Component::Bootproof,
                &"a".repeat(40),
                Some(TAP_RECIPE)
            )
            .unwrap()
        );
    }

    #[test]
    fn prebuilt_rewrite_preserves_composition_and_conditionals() {
        let template = TEMPLATE.replace("{{TAP_FRAMER_CONTAINERFILE}}", TAP_RECIPE);
        let rewritten =
            rewrite_prebuilt(template.as_str(), &[Component::Init, Component::Locksmith]).unwrap();
        let original_stages = parse_stages(template.as_str()).unwrap();
        let rewritten_stages = parse_stages(&rewritten).unwrap();
        for name in [
            "eif-builder",
            "output",
            "steve-builder",
            "bootproof-builder",
            "tap-framer-builder",
        ] {
            let before = original_stages.iter().find(|s| s.name == name).unwrap();
            let after = rewritten_stages.iter().find(|s| s.name == name).unwrap();
            assert_eq!(
                &template.as_str()[before.start..before.end],
                &rewritten[after.start..after.end]
            );
        }
        for component in [Component::Init, Component::Locksmith] {
            let stage = rewritten_stages
                .iter()
                .find(|s| s.name == component.stage_name())
                .unwrap();
            assert_eq!(stage.base, "scratch");
            let body = &rewritten[stage.start..stage.end];
            assert!(!body.contains("cargo"));
            for filename in component.filenames() {
                assert!(body.contains(&format!("COPY prebuilt/{filename} /binaries/{filename}")));
            }
        }
        let markers = |s: &str| {
            s.lines()
                .filter(|line| is_conditional_marker(line))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(markers(template.as_str()), markers(&rewritten));
        assert!(rewrite_prebuilt("FROM scratch AS output\n", &[Component::Init]).is_err());
        assert!(rewrite_prebuilt(template.as_str(), &[Component::Init, Component::Init]).is_err());
    }

    #[test]
    fn source_rebuild_verifies_hashes_in_original_compiler_stage() {
        let spec = ComponentSpec::new(
            Component::Locksmith,
            COMMIT.to_owned(),
            "a".repeat(64),
            None,
        )
        .unwrap();
        let files = Component::Locksmith
            .filenames()
            .iter()
            .map(|f| {
                (
                    (*f).to_owned(),
                    ArtifactFile::from_bytes(f.as_bytes()).unwrap(),
                )
            })
            .collect();
        let artifact = ComponentArtifact::new(spec, files).unwrap();
        let rewritten = append_source_verification(
            TEMPLATE,
            &BTreeMap::from([(Component::Locksmith, artifact.clone())]),
        )
        .unwrap();
        let parsed = parse_stages(&rewritten).unwrap();
        let stage = parsed
            .iter()
            .find(|s| s.name == "locksmith-builder")
            .unwrap();
        let body = &rewritten[stage.start..stage.end];
        assert!(body.contains("cargo build"));
        assert!(!body.contains("prebuilt/"));
        for (name, file) in artifact.files() {
            assert!(body.contains(&format!("{}  /binaries/{name}", file.sha256())));
        }
        assert!(body.contains("sha256sum -c -"));
        let prebuilt = rewrite_prebuilt(TEMPLATE, &[Component::Locksmith]).unwrap();
        assert!(append_source_verification(
            &prebuilt,
            &BTreeMap::from([(Component::Locksmith, artifact)])
        )
        .is_err());
    }

    #[test]
    fn source_fingerprint_is_order_independent_and_covers_bytes_paths_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for (root, names) in [(first.path(), ["b", "a"]), (second.path(), ["a", "b"])] {
            for name in names {
                std::fs::write(root.join(name), name).unwrap();
                std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
        }
        let original = source_tree_sha256(first.path()).unwrap();
        assert_eq!(original, source_tree_sha256(second.path()).unwrap());
        for name in ["target", ".git"] {
            std::fs::create_dir(first.path().join(name)).unwrap();
            std::fs::write(first.path().join(name).join("ignored"), "ignored").unwrap();
        }
        assert_eq!(original, source_tree_sha256(first.path()).unwrap());
        std::fs::set_permissions(
            first.path().join("a"),
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        assert_eq!(original, source_tree_sha256(first.path()).unwrap());
        std::fs::set_permissions(
            first.path().join("a"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_ne!(original, source_tree_sha256(first.path()).unwrap());
        std::fs::rename(second.path().join("a"), second.path().join("c")).unwrap();
        assert_ne!(original, source_tree_sha256(second.path()).unwrap());
        std::fs::rename(second.path().join("c"), second.path().join("a")).unwrap();
        std::fs::write(second.path().join("a"), "changed").unwrap();
        assert_ne!(original, source_tree_sha256(second.path()).unwrap());
    }

    #[test]
    fn source_fingerprint_rejects_links_and_missing_roots() {
        let root = tempfile::tempdir().unwrap();
        assert!(source_tree_sha256(&root.path().join("missing")).is_err());
        std::os::unix::fs::symlink("/etc/passwd", root.path().join("escape")).unwrap();
        assert!(source_tree_sha256(root.path()).is_err());
    }

    #[test]
    fn selection_recomputes_recipe_and_source_not_just_claimed_metadata() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("Cargo.lock"), "locked").unwrap();
        let mut artifacts = BTreeMap::new();
        for component in Component::REQUIRED {
            let source = component.source_subdir().map(|_| root.path());
            let spec =
                ComponentSpec::from_inputs(component, COMMIT, TEMPLATE, source, Some(TAP_RECIPE))
                    .unwrap();
            let files = component
                .filenames()
                .iter()
                .map(|f| {
                    (
                        (*f).to_owned(),
                        ArtifactFile::from_bytes(f.as_bytes()).unwrap(),
                    )
                })
                .collect();
            artifacts.insert(component, ComponentArtifact::new(spec, files).unwrap());
        }
        let recipes = BTreeMap::from([(Component::TapFramer, TAP_RECIPE.to_owned())]);
        let set = ComponentSet::new(artifacts).unwrap();
        let selected = [SelectedComponent::new(
            Component::Init,
            COMMIT,
            Some(root.path()),
        )];
        set.validate_selected(TEMPLATE, &selected, &recipes)
            .unwrap();
        assert!(set
            .validate_selected(
                &TEMPLATE.replace("-p init", "-p other"),
                &selected,
                &recipes
            )
            .is_err());
        assert!(set
            .validate_selected(
                TEMPLATE,
                &[SelectedComponent::new(
                    Component::Init,
                    &"f".repeat(40),
                    Some(root.path())
                )],
                &recipes
            )
            .is_err());
        assert!(set
            .validate_selected(
                TEMPLATE,
                &[SelectedComponent::new(Component::Init, COMMIT, None)],
                &recipes
            )
            .is_err());
        assert!(set
            .validate_selected(
                TEMPLATE,
                &[SelectedComponent::new(Component::Steve, COMMIT, None)],
                &recipes
            )
            .is_err());
        std::fs::write(root.path().join("Cargo.lock"), "changed").unwrap();
        assert!(set
            .validate_selected(TEMPLATE, &selected, &recipes)
            .is_err());
    }
}
