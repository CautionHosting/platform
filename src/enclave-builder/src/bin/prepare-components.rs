// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Explicit operator publication; never part of an ordinary per-application build.
//!
//! Retain reviewed release locks outside S3 and pass each via `--accepted-lock`.
//! The output lock is NOT implicitly trusted; pass it explicitly to reuse it.
//! Without an accepted mapping, an S3 index is only a first-use candidate, not
//! independent proof of accepted bytes. Publication never activates a release.

#![recursion_limit = "256"]

use clap::Parser;
use dterror::ResultExt;
use enclave_builder::{
    build,
    components::{
        recipe, sha256,
        store::{build_key, S3ComponentStore},
        validate_commit, ArtifactFile, Component, ComponentArtifact, ComponentSet, ComponentSpec,
        MAX_ARTIFACT_SIZE, MAX_MANIFEST_SIZE,
    },
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const TEMPLATE_PATH: &str = "src/enclave-builder/templates/Containerfile.eif";
const TAP_PATH: &str = "src/tap-framer";
const TAP_FILES: [&str; 4] = ["Cargo.toml", "Cargo.lock", "src/main.rs", "src/vsock.rs"];

#[derive(Debug, Parser)]
#[command(
    about = "Build missing pinned service components and publish an immutable S3 set; does not activate it"
)]
struct Arguments {
    /// Existing destination bucket. No bucket creation, deletion or lifecycle changes.
    #[arg(long)]
    bucket: String,
    /// Selected platform repository root (not the templates subdirectory).
    #[arg(long)]
    framework_source: PathBuf,
    /// Exact lowercase 40-character framework HEAD, never a branch/tag.
    #[arg(long)]
    framework_commit: String,
    /// EnclaveOS repository root checked out at --enclave-commit.
    #[arg(long)]
    enclave_source: PathBuf,
    /// Exact EnclaveOS pin; defaults to ENCLAVEOS_COMMIT or the framework default.
    #[arg(long, default_value_t = build::resolve_enclaveos_commit())]
    enclave_commit: String,
    #[arg(long, default_value_t = build::resolve_bootproof_commit())]
    bootproof_commit: String,
    #[arg(long, default_value_t = build::resolve_steve_commit())]
    steve_commit: String,
    #[arg(long, default_value_t = build::resolve_locksmith_commit())]
    locksmith_commit: String,
    /// Atomic local manifest write after all uploads and verification succeed.
    #[arg(long)]
    output_lock: PathBuf,
    /// Trusted local release manifest; repeat for retained historical releases.
    /// Conflicting accepted outputs for one spec fail before S3 access.
    #[arg(long)]
    accepted_lock: Vec<PathBuf>,
    /// Keep private stdout/stderr build logs here; never print subprocess output.
    #[arg(long, default_value = "component-build-logs")]
    build_log_dir: PathBuf,
    /// Optional explicit AWS region; otherwise use the standard AWS config chain.
    #[arg(long)]
    region: Option<String>,
}

#[derive(Debug, thiserror::Error, dterror::CtxError)]
enum PrepareError {
    #[error("could not {operation} [{location}]")]
    Operation {
        operation: &'static str,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    #[error("component preparation rejected {reason} [{location}]")]
    Invalid {
        reason: &'static str,
        location: dterror::Location,
    },
    #[error("{program} failed with status {status}; inspect {log} [{location}]")]
    Command {
        program: &'static str,
        status: std::process::ExitStatus,
        log: PathBuf,
        location: dterror::Location,
    },
}

#[track_caller]
fn invalid(reason: &'static str) -> PrepareError {
    PrepareError::Invalid {
        reason,
        location: std::panic::Location::caller(),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match prepare(Arguments::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[tracing::instrument(skip_all, err)]
async fn prepare(args: Arguments) -> Result<(), PrepareError> {
    use PrepareErrorCtx as Ctx;
    let accepted = load_accepted_locks(&args.accepted_lock)?;
    for commit in [
        &args.framework_commit,
        &args.enclave_commit,
        &args.bootproof_commit,
        &args.steve_commit,
        &args.locksmith_commit,
    ] {
        validate_commit(commit).with_context(Ctx::operation("validate selected revision"))?;
    }
    if args.bucket.is_empty()
        || args
            .bucket
            .bytes()
            .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'))
    {
        return Err(invalid("bucket name"));
    }
    validate_checkout(
        &args.framework_source,
        &args.framework_commit,
        &[
            "src/enclave-builder/templates",
            "containerfiles/Containerfile.init",
            "containerfiles/Containerfile.bootproof",
            "containerfiles/Containerfile.steve",
            "containerfiles/Containerfile.locksmith",
            "containerfiles/Containerfile.tap-framer",
            TAP_PATH,
        ],
    )?;
    validate_checkout(&args.enclave_source, &args.enclave_commit, &["."])?;
    let workspace =
        tempfile::tempdir().with_context(Ctx::operation("create disposable build workspace"))?;
    let context = workspace.path().join("context");
    std::fs::create_dir(&context).with_context(Ctx::operation("create build context"))?;
    let template = String::from_utf8(git_bytes(
        &args.framework_source,
        &[
            "show",
            &format!("{}:{TEMPLATE_PATH}", args.framework_commit),
        ],
    )?)
    .with_context(Ctx::operation("decode selected template"))?;
    let mut recipes = BTreeMap::new();
    for component in Component::ALL {
        if template.contains(component.containerfile_marker()) {
            let recipe = String::from_utf8(git_bytes(
                &args.framework_source,
                &[
                    "show",
                    &format!(
                        "{}:{}",
                        args.framework_commit,
                        component.containerfile_path()
                    ),
                ],
            )?)
            .with_context(Ctx::operation(
                "decode selected standalone component recipe",
            ))?;
            recipes.insert(component, recipe);
        }
    }
    snapshot_enclave(
        &args.enclave_source,
        &args.enclave_commit,
        &context.join("enclave"),
        workspace.path(),
    )?;
    let tap = context.join(recipe::source_subdir(&template, Component::TapFramer).unwrap());
    for name in TAP_FILES {
        let path = tap.join(name);
        let parent = path.parent().ok_or_else(|| invalid("tap source path"))?;
        std::fs::create_dir_all(parent)
            .with_context(Ctx::operation("create tap source directory"))?;
        let bytes = git_bytes(
            &args.framework_source,
            &[
                "show",
                &format!("{}:{TAP_PATH}/{name}", args.framework_commit),
            ],
        )?;
        std::fs::write(&path, bytes).with_context(Ctx::operation("stage pinned tap source"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .with_context(Ctx::operation("normalize tap source mode"))?;
    }
    let mut specs = BTreeMap::new();
    for (component, commit) in [
        (Component::Init, &args.enclave_commit),
        (Component::Bootproof, &args.bootproof_commit),
        (Component::Steve, &args.steve_commit),
        (Component::Locksmith, &args.locksmith_commit),
        (Component::TapFramer, &args.framework_commit),
    ] {
        let source = recipe::source_subdir(&template, component).map(|path| context.join(path));
        let spec = ComponentSpec::from_inputs(
            component,
            commit,
            &template,
            source.as_deref(),
            recipes.get(&component).map(String::as_str),
        )
        .with_context(Ctx::operation("resolve component inputs"))?;
        specs.insert(component, spec);
    }
    let mut config = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = args.region {
        config = config.region(aws_config::Region::new(region));
    }
    let config = config.load().await;
    let store = S3ComponentStore::new(aws_sdk_s3::Client::new(&config), args.bucket.clone());
    let mut components = BTreeMap::new();
    for (component, spec) in specs {
        let trusted =
            accepted.get(&build_key(&spec).with_context(Ctx::operation("identify selected spec"))?);
        let existing = if let Some(trusted) = trusted {
            store
                .load_accepted_build(trusted)
                .await
                .with_context(Ctx::operation("resolve trusted historical build"))?
                .then(|| trusted.clone())
        } else {
            eprintln!(
                "{component}: no accepted lock mapping; output is a candidate requiring review"
            );
            store
                .load_build(&spec)
                .await
                .with_context(Ctx::operation("resolve candidate existing build"))?
        };
        let artifact = match existing {
            Some(artifact) => {
                eprintln!("{component}: verified reuse (no compilation)");
                artifact
            }
            None => {
                eprintln!("{component}: missing outputs or descriptor; compiling pinned recipe");
                let files = compile_component(
                    &spec,
                    &template,
                    &context,
                    workspace.path(),
                    &args.build_log_dir,
                    recipes.get(&component).map(String::as_str),
                )?;
                let artifact = checked_outputs(spec, &files, trusted)?;
                store
                    .publish_build(&artifact, &files)
                    .await
                    .with_context(Ctx::operation("publish immutable compiler outputs"))?;
                artifact
            }
        };
        components.insert(component, artifact);
    }
    let set = ComponentSet::new(components)
        .with_context(Ctx::operation("validate completed component set"))?;
    let digest = store
        .publish_set(&set)
        .await
        .with_context(Ctx::operation("publish verified component set"))?;
    write_lock(&args.output_lock, &set, &digest)?;
    println!("{digest}");
    println!(
        "Activate explicitly after review: export COMPONENTS_S3_BUCKET={} COMPONENT_SET_SHA256={digest}",
        args.bucket
    );
    Ok(())
}

#[tracing::instrument(skip_all, err)]
fn load_accepted_locks(
    paths: &[PathBuf],
) -> Result<BTreeMap<String, ComponentArtifact>, PrepareError> {
    use PrepareErrorCtx as Ctx;
    let mut accepted = BTreeMap::new();
    for path in paths {
        let file =
            std::fs::File::open(path).with_context(Ctx::operation("open trusted release lock"))?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_SIZE as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(Ctx::operation("read bounded trusted release lock"))?;
        if bytes.len() > MAX_MANIFEST_SIZE {
            return Err(invalid("trusted release lock exceeds size limit"));
        }
        let set: ComponentSet = serde_json::from_slice(&bytes)
            .with_context(Ctx::operation("parse trusted release lock"))?;
        set.validate()
            .with_context(Ctx::operation("validate trusted release lock"))?;
        for artifact in set.components().values() {
            let key = build_key(artifact.spec())
                .with_context(Ctx::operation("identify accepted build spec"))?;
            if let Some(previous) = accepted.insert(key, artifact.clone()) {
                if &previous != artifact {
                    return Err(invalid(
                        "inconsistent accepted outputs for the same build spec",
                    ));
                }
            }
        }
    }
    Ok(accepted)
}

#[tracing::instrument(skip_all, err)]
fn checked_outputs(
    spec: ComponentSpec,
    files: &BTreeMap<String, Vec<u8>>,
    accepted: Option<&ComponentArtifact>,
) -> Result<ComponentArtifact, PrepareError> {
    use PrepareErrorCtx as Ctx;
    let descriptors = files
        .iter()
        .map(|(name, bytes)| ArtifactFile::from_bytes(bytes).map(|file| (name.clone(), file)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .with_context(Ctx::operation("describe compiler outputs"))?;
    let artifact = ComponentArtifact::new(spec, descriptors)
        .with_context(Ctx::operation("validate compiler output set"))?;
    if accepted.is_some_and(|accepted| accepted != &artifact) {
        return Err(invalid(
            "rebuilt bytes differ from trusted accepted outputs",
        ));
    }
    Ok(artifact)
}

#[tracing::instrument(skip_all, err)]
fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>, PrepareError> {
    use PrepareErrorCtx as Ctx;
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .output()
        .with_context(Ctx::operation("run git source inspection"))?;
    if !output.status.success() {
        return Err(invalid("git source inspection failed"));
    }
    Ok(output.stdout)
}

#[tracing::instrument(skip_all, err)]
fn validate_checkout(root: &Path, commit: &str, paths: &[&str]) -> Result<(), PrepareError> {
    use PrepareErrorCtx as Ctx;
    validate_commit(commit).with_context(Ctx::operation("validate checkout pin"))?;
    let actual_root = root
        .canonicalize()
        .with_context(Ctx::operation("resolve checkout root"))?;
    let top = git_bytes(root, &["rev-parse", "--show-toplevel"])?;
    let top = String::from_utf8(top).with_context(Ctx::operation("decode git root"))?;
    if Path::new(top.trim())
        .canonicalize()
        .with_context(Ctx::operation("resolve git root"))?
        != actual_root
    {
        return Err(invalid("source must be a git repository root"));
    }
    if git_bytes(root, &["rev-parse", "HEAD"])?.strip_suffix(b"\n") != Some(commit.as_bytes()) {
        return Err(invalid("checkout HEAD differs from selected revision"));
    }
    let mut args = vec!["status", "--porcelain=v1", "--untracked-files=all", "--"];
    args.extend_from_slice(paths);
    if !git_bytes(root, &args)?.is_empty() {
        return Err(invalid("selected source paths are dirty"));
    }
    Ok(())
}

#[tracing::instrument(skip_all, err)]
fn snapshot_enclave(
    root: &Path,
    commit: &str,
    destination: &Path,
    workspace: &Path,
) -> Result<(), PrepareError> {
    use PrepareErrorCtx as Ctx;
    let archive_path = workspace.join("enclave.tar");
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["archive", "--format=tar", "--output"])
        .arg(&archive_path)
        .arg(commit)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(Ctx::operation("archive pinned enclave source"))?;
    if !status.success() {
        return Err(invalid("git archive failed"));
    }
    std::fs::create_dir_all(destination)
        .with_context(Ctx::operation("create enclave source directory"))?;
    let file = std::fs::File::open(&archive_path)
        .with_context(Ctx::operation("open enclave source snapshot"))?;
    let mut archive = tar::Archive::new(file);
    archive
        .unpack(destination)
        .with_context(Ctx::operation("extract enclave source snapshot"))?;
    Ok(())
}

#[tracing::instrument(skip_all)]
fn docker_arguments(context: &Path, output: &Path) -> Vec<OsString> {
    vec![
        "buildx".into(),
        "build".into(),
        "--platform".into(),
        "linux/amd64".into(),
        "--target".into(),
        "output".into(),
        "--output".into(),
        format!("type=local,dest={}", output.display()).into(),
        "--file".into(),
        context.join("Containerfile").into_os_string(),
        context.as_os_str().to_owned(),
    ]
}

#[tracing::instrument(skip_all, err)]
fn compile_component(
    spec: &ComponentSpec,
    template: &str,
    context: &Path,
    workspace: &Path,
    log_dir: &Path,
    component_recipe: Option<&str>,
) -> Result<BTreeMap<String, Vec<u8>>, PrepareError> {
    use PrepareErrorCtx as Ctx;
    let component = spec.component();
    let rendered =
        recipe::render_component(template, component, spec.source_commit(), component_recipe)
            .with_context(Ctx::operation("render pinned compiler recipe"))?;
    let source = recipe::source_subdir(&template, component).map(|path| context.join(path));
    if &ComponentSpec::from_inputs(
        component,
        spec.source_commit(),
        template,
        source.as_deref(),
        component_recipe,
    )
    .with_context(Ctx::operation("recheck staged compiler inputs"))?
        != spec
    {
        return Err(invalid("staged source changed"));
    }
    std::fs::write(context.join("Containerfile"), rendered)
        .with_context(Ctx::operation("write standalone compiler recipe"))?;
    let output = workspace.join(format!("output-{component}"));
    std::fs::create_dir(&output)
        .with_context(Ctx::operation("create compiler output directory"))?;
    std::fs::create_dir_all(log_dir)
        .with_context(Ctx::operation("create private build log directory"))?;
    let log = tempfile::Builder::new()
        .prefix(&format!("{component}-"))
        .suffix(".log")
        .tempfile_in(log_dir)
        .with_context(Ctx::operation("create private build log"))?;
    let (log_file, log_path) = log
        .keep()
        .with_context(Ctx::operation("retain build log"))?;
    let stderr = log_file
        .try_clone()
        .with_context(Ctx::operation("open compiler stderr log"))?;
    let status = Command::new("docker")
        .args(docker_arguments(context, &output))
        .stdin(Stdio::null())
        .stdout(log_file)
        .stderr(stderr)
        .status()
        .with_context(Ctx::operation("start component compiler"))?;
    eprintln!(
        "{component}: compiler exit {status}; log {}",
        log_path.display()
    );
    if !status.success() {
        return Err(PrepareError::Command {
            program: "docker buildx",
            status,
            log: log_path,
            location: std::panic::Location::caller(),
        });
    }
    if &ComponentSpec::from_inputs(
        component,
        spec.source_commit(),
        template,
        source.as_deref(),
        component_recipe,
    )
    .with_context(Ctx::operation("recheck compiler source snapshot"))?
        != spec
    {
        return Err(invalid("compiler source snapshot changed"));
    }
    let mut files = BTreeMap::new();
    for filename in component.filenames() {
        let path = output.join(filename);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(Ctx::operation("inspect compiled artifact"))?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.len() == 0
            || metadata.len() > MAX_ARTIFACT_SIZE
        {
            return Err(invalid(
                "compiler output must be a bounded nonempty regular executable",
            ));
        }
        let file =
            std::fs::File::open(&path).with_context(Ctx::operation("open compiler output"))?;
        let mut bytes = Vec::new();
        file.take(MAX_ARTIFACT_SIZE + 1)
            .read_to_end(&mut bytes)
            .with_context(Ctx::operation("read bounded compiler output"))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(invalid("compiler output length changed"));
        }
        files.insert((*filename).to_owned(), bytes);
    }
    Ok(files)
}

#[tracing::instrument(skip_all, err)]
fn write_lock(path: &Path, set: &ComponentSet, digest: &str) -> Result<(), PrepareError> {
    use PrepareErrorCtx as Ctx;
    let bytes = set
        .canonical_bytes()
        .with_context(Ctx::operation("validate local lock"))?;
    if sha256(&bytes) != digest {
        return Err(invalid("local lock digest mismatch"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(Ctx::operation("create atomic lock staging file"))?;
    file.write_all(&bytes)
        .with_context(Ctx::operation("write validated lock"))?;
    file.as_file()
        .sync_all()
        .with_context(Ctx::operation("sync validated lock"))?;
    file.persist(path)
        .with_context(Ctx::operation("atomically publish local lock"))?;
    std::fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .with_context(Ctx::operation("sync lock directory"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_set() -> ComponentSet {
        ComponentSet::new(
            Component::REQUIRED
                .into_iter()
                .map(|component| {
                    let spec = ComponentSpec::new(
                        component,
                        "a".repeat(40),
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
                                ArtifactFile::from_bytes(b"binary").unwrap(),
                            )
                        })
                        .collect();
                    (component, ComponentArtifact::new(spec, files).unwrap())
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn accepted_locks_merge_identical_history_and_reject_conflicting_spec_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.json");
        let second = directory.path().join("second.json");
        let set = test_set();
        std::fs::write(&first, set.canonical_bytes().unwrap()).unwrap();
        std::fs::write(&second, set.canonical_bytes().unwrap()).unwrap();
        let paths = [first, second.clone()];
        assert_eq!(
            load_accepted_locks(&paths).unwrap().len(),
            set.components().len()
        );
        let mut components = set.components().clone();
        let init = &components[&Component::Init];
        let replaced = ComponentArtifact::new(
            init.spec().clone(),
            BTreeMap::from([(
                "init".to_owned(),
                ArtifactFile::from_bytes(b"changed").unwrap(),
            )]),
        )
        .unwrap();
        components.insert(Component::Init, replaced);
        std::fs::write(
            &second,
            ComponentSet::new(components)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load_accepted_locks(&paths),
            Err(PrepareError::Invalid {
                reason: "inconsistent accepted outputs for the same build spec",
                ..
            })
        ));
    }

    #[test]
    fn accepted_locks_reject_invalid_missing_and_oversized_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock.json");
        assert!(load_accepted_locks(std::slice::from_ref(&path)).is_err());
        for bytes in [
            b"not json".to_vec(),
            b"{\"schema_version\":99,\"components\":{}}".to_vec(),
            vec![b' '; MAX_MANIFEST_SIZE + 1],
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(load_accepted_locks(std::slice::from_ref(&path)).is_err());
        }
    }

    #[test]
    fn historical_rebuild_must_match_accepted_bytes_before_publication() {
        let set = test_set();
        let accepted = &set.components()[&Component::Init];
        let mut files = BTreeMap::from([("init".to_owned(), b"binary".to_vec())]);
        assert_eq!(
            checked_outputs(accepted.spec().clone(), &files, Some(accepted)).unwrap(),
            *accepted
        );
        files.insert("init".to_owned(), b"different".to_vec());
        assert!(checked_outputs(accepted.spec().clone(), &files, Some(accepted)).is_err());
        assert!(checked_outputs(accepted.spec().clone(), &files, None).is_ok());
    }

    #[test]
    fn output_lock_is_validated_and_atomically_replaced_only_on_success() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected.json");
        std::fs::write(&path, b"previous").unwrap();
        let set = test_set();
        assert!(write_lock(&path, &set, &sha256(b"wrong")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");
        let expected = set.canonical_bytes().unwrap();
        write_lock(&path, &set, &sha256(&expected)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert!(write_lock(&path.join("missing-parent"), &set, &sha256(&expected)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), expected);
    }

    #[test]
    fn cli_requires_explicit_roots_and_framework_revision() {
        assert!(Arguments::try_parse_from(["prepare-components", "--bucket", "bucket"]).is_err());
        let args = Arguments::try_parse_from([
            "prepare-components",
            "--bucket",
            "bucket",
            "--framework-source",
            "/framework",
            "--framework-commit",
            &"a".repeat(40),
            "--enclave-source",
            "/enclave",
            "--output-lock",
            "/output.json",
            "--accepted-lock",
            "/release-a.json",
            "--accepted-lock",
            "/release-b.json",
        ])
        .unwrap();
        assert_eq!(
            args.accepted_lock,
            [
                PathBuf::from("/release-a.json"),
                PathBuf::from("/release-b.json")
            ]
        );
        for pin in [
            &args.framework_commit,
            &args.enclave_commit,
            &args.bootproof_commit,
            &args.steve_commit,
            &args.locksmith_commit,
        ] {
            validate_commit(pin).unwrap();
        }
    }

    #[test]
    fn docker_invocation_uses_independent_output_stage_and_fixed_architecture() {
        let args = docker_arguments(
            Path::new("/tmp/build/context"),
            Path::new("/tmp/build/output"),
        );
        assert_eq!(
            args,
            [
                "buildx",
                "build",
                "--platform",
                "linux/amd64",
                "--target",
                "output",
                "--output",
                "type=local,dest=/tmp/build/output",
                "--file",
                "/tmp/build/context/Containerfile",
                "/tmp/build/context"
            ]
            .map(std::ffi::OsString::from)
        );
    }

    fn git(root: &Path, args: &[&str]) -> Vec<u8> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "git fixture command failed");
        output.stdout
    }

    #[test]
    fn source_roots_require_exact_head_and_clean_relevant_paths() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.name", "Fixture"]);
        git(root, &["config", "user.email", "fixture@example.invalid"]);
        std::fs::write(root.join("input"), b"original").unwrap();
        std::fs::write(root.join("unrelated"), b"original").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "fixture"]);
        let commit = String::from_utf8(git(root, &["rev-parse", "HEAD"])).unwrap();
        let commit = commit.trim();
        validate_checkout(root, commit, &["input"]).unwrap();
        assert!(validate_checkout(root, &"0".repeat(40), &["input"]).is_err());
        std::fs::write(root.join("unrelated"), b"changed").unwrap();
        validate_checkout(root, commit, &["input"]).unwrap();
        std::fs::write(root.join("input"), b"changed").unwrap();
        assert!(validate_checkout(root, commit, &["input"]).is_err());
    }
}
