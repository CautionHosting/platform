// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::AsyncReadExt;

use dterror::ResultExt;

use crate::components::{recipe, Component, ComponentSet, SelectedComponent};
use crate::manifest::{EnclaveManifest, FrameworkSource};

#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("could not {operation} component staging [{location}]")]
pub(crate) struct ComponentStageError {
    operation: &'static str,
    #[location]
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
}

#[derive(Debug, thiserror::Error)]
#[error("{reason} [{location}]")]
struct InvalidInput {
    reason: &'static str,
    location: dterror::Location,
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn configure(
    stage: &Path,
    templates: &Path,
    manifest: Option<&EnclaveManifest>,
    prebuilt: Option<&Path>,
    steve: bool,
    locksmith: bool,
) -> Result<(), ComponentStageError> {
    use ComponentStageErrorCtx as Ctx;
    let Some((manifest, set)) = manifest.and_then(|m| m.component_set.as_ref().map(|s| (m, s)))
    else {
        if prebuilt.is_some() {
            return Err(InvalidInput {
                reason: "prebuilt component consumption requires a pinned component set",
                location: std::panic::Location::caller(),
            })
            .with_context(Ctx::new("select"));
        }
        return Ok(());
    };
    let source_template = tokio::fs::read_to_string(templates.join("Containerfile.eif"))
        .await
        .with_context(Ctx::new("read selected source recipe for"))?;
    let rendered_path = stage.join("Containerfile.eif");
    let rendered = tokio::fs::read_to_string(&rendered_path)
        .await
        .with_context(Ctx::new("read rendered recipe for"))?;
    // The historical template always includes this stage, even without egress.
    let needs_tap_framer = rendered.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        words.len() == 4
            && words[0] == "FROM"
            && words[2] == "AS"
            && words[3] == Component::TapFramer.stage_name()
    });
    let enclave = stage.join("enclave");
    let tap_framer = stage.join(recipe::source_subdir(&rendered, Component::TapFramer).unwrap());
    let FrameworkSource::GitArchive {
        commit: framework_commit,
        ..
    } = &manifest.framework_source;
    fn pinned(value: Option<&str>) -> Result<&str, InvalidInput> {
        value.ok_or(InvalidInput {
            reason: "component set requires immutable manifest source revisions",
            location: std::panic::Location::caller(),
        })
    }
    let mut selected = vec![
        SelectedComponent::new(
            Component::Init,
            pinned(manifest.enclaveos_commit.as_deref())
                .with_context(Ctx::new("resolve init revision for"))?,
            Some(&enclave),
        ),
        SelectedComponent::new(
            Component::Bootproof,
            pinned(manifest.bootproof_commit.as_deref())
                .with_context(Ctx::new("resolve bootproof revision for"))?,
            None,
        ),
    ];
    if needs_tap_framer {
        selected.push(SelectedComponent::new(
            Component::TapFramer,
            pinned(framework_commit.as_deref())
                .with_context(Ctx::new("resolve framework revision for"))?,
            Some(&tap_framer),
        ));
    }
    if steve {
        selected.push(SelectedComponent::new(
            Component::Steve,
            pinned(manifest.steve_commit.as_deref())
                .with_context(Ctx::new("resolve STEVE revision for"))?,
            None,
        ));
    }
    if locksmith {
        selected.push(SelectedComponent::new(
            Component::Locksmith,
            pinned(manifest.locksmith_commit.as_deref())
                .with_context(Ctx::new("resolve Locksmith revision for"))?,
            None,
        ));
    }
    let components: Vec<_> = selected.iter().map(SelectedComponent::component).collect();
    let recipes = recipe::read_selected(templates, &source_template, &components)
        .await
        .with_context(Ctx::new("read selected standalone recipes for"))?;
    set.validate_selected(&source_template, &selected, &recipes)
        .with_context(Ctx::new("validate selected inputs for"))?;
    let configured = if let Some(prebuilt) = prebuilt {
        stage_verified_files(set, &components, prebuilt, stage)
            .await
            .with_context(Ctx::new("verify downloaded files for"))?;
        recipe::rewrite_prebuilt(&rendered, &components)
            .with_context(Ctx::new("replace compiler stages for"))?
    } else {
        let artifacts = set
            .components()
            .iter()
            .filter(|(component, _)| components.contains(component))
            .map(|(component, artifact)| (*component, artifact.clone()))
            .collect::<BTreeMap<_, _>>();
        recipe::append_source_verification(&rendered, &artifacts)
            .with_context(Ctx::new("assert source-built digests for"))?
    };
    tokio::fs::write(&rendered_path, configured)
        .await
        .with_context(Ctx::new("write configured recipe for"))?;
    Ok(())
}

#[tracing::instrument(skip_all, err)]
async fn stage_verified_files(
    set: &ComponentSet,
    selected: &[Component],
    source: &Path,
    stage: &Path,
) -> Result<(), ComponentStageError> {
    use ComponentStageErrorCtx as Ctx;
    let destination = stage.join("prebuilt");
    tokio::fs::create_dir_all(&destination)
        .await
        .with_context(Ctx::new("create directory for"))?;
    for component in selected {
        let artifact = set
            .get(*component)
            .ok_or(InvalidInput {
                reason: "selected component is absent",
                location: std::panic::Location::caller(),
            })
            .with_context(Ctx::new("select artifact for"))?;
        for (name, file) in artifact.files() {
            let path = source.join(name);
            let metadata = tokio::fs::symlink_metadata(&path)
                .await
                .with_context(Ctx::new("inspect downloaded file for"))?;
            if !metadata.is_file() || metadata.len() != file.size() {
                return Err(InvalidInput {
                    reason: "component must be a regular file of the pinned size",
                    location: std::panic::Location::caller(),
                })
                .with_context(Ctx::new("validate downloaded file for"));
            }
            let input = tokio::fs::File::open(&path)
                .await
                .with_context(Ctx::new("open downloaded file for"))?;
            let mut bytes = Vec::new();
            input
                .take(file.size() + 1)
                .read_to_end(&mut bytes)
                .await
                .with_context(Ctx::new("read bounded downloaded file for"))?;
            file.verify(&bytes)
                .with_context(Ctx::new("verify downloaded file for"))?;
            let output = destination.join(name);
            tokio::fs::write(&output, bytes)
                .await
                .with_context(Ctx::new("copy verified file for"))?;
            tokio::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755))
                .await
                .with_context(Ctx::new("make verified file executable for"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::{ArtifactFile, ComponentArtifact, ComponentSpec};
    use crate::manifest::{EnclaveSource, FrameworkSource};

    fn fixture() -> (tempfile::TempDir, EnclaveManifest) {
        let dir = tempfile::tempdir().unwrap();
        let template = include_str!("../templates/Containerfile.eif");
        let mut rendered = template.to_owned();
        for component in Component::ALL {
            rendered = rendered.replace(
                component.containerfile_marker(),
                component.embedded_containerfile(),
            );
        }
        std::fs::write(dir.path().join("Containerfile.eif"), rendered).unwrap();
        std::fs::create_dir_all(dir.path().join("src/enclave-builder/templates")).unwrap();
        std::fs::write(
            dir.path()
                .join("src/enclave-builder/templates/Containerfile.eif"),
            template,
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("containerfiles")).unwrap();
        for component in Component::ALL {
            std::fs::write(
                dir.path().join(component.containerfile_path()),
                component.embedded_containerfile(),
            )
            .unwrap();
        }
        std::fs::create_dir_all(dir.path().join("enclave")).unwrap();
        std::fs::create_dir_all(dir.path().join("src/tap-framer")).unwrap();
        std::fs::create_dir(dir.path().join("downloads")).unwrap();
        for root in ["enclave", "src/tap-framer"] {
            std::fs::write(
                dir.path().join(root).join("Cargo.lock"),
                "fixture locked inputs",
            )
            .unwrap();
        }
        let commit = "a".repeat(40);
        let mut artifacts = BTreeMap::new();
        for component in [
            Component::Init,
            Component::Bootproof,
            Component::TapFramer,
            Component::Steve,
            Component::Locksmith,
        ] {
            let fragment = component.source_subdir().map(|p| dir.path().join(p));
            let spec = ComponentSpec::from_inputs(
                component,
                &commit,
                template,
                fragment.as_deref(),
                Some(component.embedded_containerfile()),
            )
            .unwrap();
            let mut files = BTreeMap::new();
            for name in component.filenames() {
                let bytes = format!("synthetic test binary: {name}").into_bytes();
                std::fs::write(dir.path().join("downloads").join(name), &bytes).unwrap();
                files.insert(name.to_string(), ArtifactFile::from_bytes(&bytes).unwrap());
            }
            artifacts.insert(component, ComponentArtifact::new(spec, files).unwrap());
        }
        let mut manifest = EnclaveManifest::new(
            None,
            EnclaveSource::Local {
                path: "synthetic fixture".into(),
            },
            FrameworkSource::GitArchive {
                url: "https://example.invalid/framework.tar.gz".into(),
                commit: Some(commit.clone()),
            },
            None,
            None,
            None,
        );
        manifest.enclaveos_commit = Some(commit.clone());
        manifest.bootproof_commit = Some(commit.clone());
        manifest.steve_commit = Some(commit.clone());
        manifest.locksmith_commit = Some(commit);
        manifest.component_set = Some(ComponentSet::new(artifacts).unwrap());
        (dir, manifest)
    }

    #[tokio::test]
    async fn no_egress_recipe_needs_neither_tap_source_nor_tap_download() {
        for prebuilt in [false, true] {
            let (dir, manifest) = fixture();
            let path = dir.path().join("Containerfile.eif");
            let mut rendered = std::fs::read_to_string(&path).unwrap();
            assert!(rendered.contains("# {EGRESS"));
            while let Some(start) = rendered.find("# {EGRESS") {
                let end = start + rendered[start..].find("# }EGRESS").unwrap() + "# }EGRESS".len();
                rendered.replace_range(start..end, "");
            }
            std::fs::write(&path, rendered).unwrap();
            std::fs::remove_dir_all(dir.path().join("src/tap-framer")).unwrap();
            std::fs::remove_file(dir.path().join("downloads/tap-framer")).unwrap();
            std::fs::remove_file(dir.path().join("containerfiles/Containerfile.tap-framer"))
                .unwrap();
            let downloads = dir.path().join("downloads");
            configure(
                dir.path(),
                &dir.path().join("src/enclave-builder/templates"),
                Some(&manifest),
                prebuilt.then_some(downloads.as_path()),
                true,
                true,
            )
            .await
            .unwrap();
            let rendered = std::fs::read_to_string(&path).unwrap();
            assert!(!rendered.contains("tap-framer"));
            assert!(!dir.path().join("prebuilt/tap-framer").exists());
            assert_eq!(rendered.contains("COPY prebuilt/"), prebuilt);
        }
    }

    #[tokio::test]
    async fn selected_standalone_recipe_is_required_and_fingerprinted() {
        for (component, replacement) in Component::ALL.into_iter().flat_map(|component| {
            [None, Some("# changed selected recipe\n")]
                .into_iter()
                .map(move |replacement| (component, replacement))
        }) {
            let (dir, manifest) = fixture();
            let recipe = dir.path().join(component.containerfile_path());
            match replacement {
                None => std::fs::remove_file(&recipe).unwrap(),
                Some(extra) => {
                    let original = std::fs::read_to_string(&recipe).unwrap();
                    std::fs::write(&recipe, format!("{original}{extra}")).unwrap();
                }
            }
            assert!(configure(
                dir.path(),
                &dir.path().join("src/enclave-builder/templates"),
                Some(&manifest),
                None,
                true,
                true
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn source_reproduction_does_not_consume_downloaded_components() {
        let (dir, manifest) = fixture();
        std::fs::write(dir.path().join("downloads/tap-framer"), "corrupt").unwrap();
        configure(
            dir.path(),
            &dir.path().join("src/enclave-builder/templates"),
            Some(&manifest),
            None,
            true,
            true,
        )
        .await
        .unwrap();
        let rendered = std::fs::read_to_string(dir.path().join("Containerfile.eif")).unwrap();
        assert!(rendered.contains("cargo build"));
        assert!(rendered.contains("sha256sum -c"));
        assert!(!rendered.contains("COPY prebuilt/"));
        assert!(!dir.path().join("prebuilt").exists());
    }

    #[tokio::test]
    async fn prebuilt_stages_verify_bytes_and_preserve_paired_export() {
        let (dir, manifest) = fixture();
        configure(
            dir.path(),
            &dir.path().join("src/enclave-builder/templates"),
            Some(&manifest),
            Some(&dir.path().join("downloads")),
            true,
            true,
        )
        .await
        .unwrap();
        let rendered = std::fs::read_to_string(dir.path().join("Containerfile.eif")).unwrap();
        assert!(!rendered.contains("cargo build"));
        assert_eq!(
            std::fs::metadata(dir.path().join("prebuilt/tap-framer"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(
            rendered.contains("COPY --from=tap-framer-builder /binaries/tap-framer /tap-framer")
        );
        assert_eq!(
            std::fs::read(dir.path().join("prebuilt/tap-framer")).unwrap(),
            std::fs::read(dir.path().join("downloads/tap-framer")).unwrap()
        );
    }

    #[tokio::test]
    async fn corruption_and_source_drift_fail_before_rewriting() {
        for change in [
            "same-size-binary",
            "source",
            "commit",
            "recipe",
            "tap-recipe",
            "missing-tap-recipe",
        ] {
            let (dir, mut manifest) = fixture();
            match change {
                "same-size-binary" => {
                    let path = dir.path().join("downloads/tap-framer");
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes[0] ^= 1;
                    std::fs::write(path, bytes).unwrap();
                }
                "source" => std::fs::write(
                    dir.path().join("src/tap-framer/Cargo.lock"),
                    "changed dependencies",
                )
                .unwrap(),
                "commit" => manifest.bootproof_commit = Some("b".repeat(40)),
                "recipe" => {
                    let p = dir.path().join("containerfiles/Containerfile.bootproof");
                    let original = std::fs::read_to_string(&p).unwrap();
                    let recipe = original.replace("codegen-units=1", "codegen-units=2");
                    assert_ne!(original, recipe);
                    std::fs::write(p, recipe).unwrap();
                }
                "tap-recipe" => {
                    let p = dir.path().join("containerfiles/Containerfile.tap-framer");
                    let recipe = std::fs::read_to_string(&p)
                        .unwrap()
                        .replace("codegen-units=1", "codegen-units=2");
                    std::fs::write(p, recipe).unwrap();
                }
                "missing-tap-recipe" => {
                    std::fs::remove_file(
                        dir.path().join("containerfiles/Containerfile.tap-framer"),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                configure(
                    dir.path(),
                    &dir.path().join("src/enclave-builder/templates"),
                    Some(&manifest),
                    Some(&dir.path().join("downloads")),
                    true,
                    true
                )
                .await
                .is_err(),
                "accepted {change}"
            );
            let recipe = std::fs::read_to_string(dir.path().join("Containerfile.eif")).unwrap();
            assert!(!recipe.contains("COPY prebuilt/"));
        }
    }

    #[tokio::test]
    async fn optional_components_are_not_required_when_disabled() {
        for steve in [false, true] {
            for locksmith in [false, true] {
                let (dir, manifest) = fixture();
                for (component, enabled) in
                    [(Component::Steve, steve), (Component::Locksmith, locksmith)]
                {
                    if !enabled {
                        std::fs::remove_file(dir.path().join(component.containerfile_path()))
                            .unwrap();
                        for name in component.filenames() {
                            std::fs::remove_file(dir.path().join("downloads").join(name)).unwrap();
                        }
                    }
                }
                configure(
                    dir.path(),
                    &dir.path().join("src/enclave-builder/templates"),
                    Some(&manifest),
                    Some(&dir.path().join("downloads")),
                    steve,
                    locksmith,
                )
                .await
                .unwrap();
                for component in Component::ALL {
                    let expected = match component {
                        Component::Steve => steve,
                        Component::Locksmith => locksmith,
                        _ => true,
                    };
                    for name in component.filenames() {
                        assert_eq!(
                            dir.path().join("prebuilt").join(name).exists(),
                            expected,
                            "selection steve={steve}, locksmith={locksmith}: {name}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn prebuilt_requires_pins_but_legacy_source_behavior_is_unchanged() {
        let (dir, mut manifest) = fixture();
        manifest.component_set = None;
        assert!(configure(
            dir.path(),
            &dir.path().join("src/enclave-builder/templates"),
            Some(&manifest),
            Some(&dir.path().join("downloads")),
            false,
            false
        )
        .await
        .is_err());
        let before = std::fs::read(dir.path().join("Containerfile.eif")).unwrap();
        configure(
            dir.path(),
            &dir.path().join("absent-templates"),
            Some(&manifest),
            None,
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            before,
            std::fs::read(dir.path().join("Containerfile.eif")).unwrap()
        );
    }
}
