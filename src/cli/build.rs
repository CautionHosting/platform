use std::process::Command;

fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let heuristics = caution_environment_heuristics::heuristics();
    let heuristics_file = std::fs::File::create(out_dir.join("heuristics.json"))
        .expect("should be able to open heuristics file");

    serde_json::to_writer(heuristics_file, &heuristics)
        .expect("should be able to serialize heuristics to heuristics.json");

    // Build ID keys the one-time environment acknowledgement. Container builds
    // pass the commit explicitly since .git is not in the build context.
    let sha = std::env::var("CAUTION_CLI_GIT_SHA")
        .ok()
        .filter(|sha| !sha.trim().is_empty())
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let sha = sha.trim();
    let short_sha = sha.get(..12).unwrap_or(sha);
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rustc-env=CAUTION_CLI_BUILD_ID={version}+{short_sha}");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CAUTION_CLI_GIT_SHA");

    // Rerun when the checked-out commit changes, without relying on reflogs:
    // HEAD covers checkouts and detached commits, packed-refs and the branch
    // ref cover new commits. A packed branch has no loose ref until the next
    // commit creates one, so watch its closest existing directory under
    // refs/heads instead. Missing paths are never emitted because Cargo treats
    // them as always stale.
    for name in ["HEAD", "packed-refs"] {
        if let Some(path) = git_path(name).filter(|path| path.exists()) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(ref_path) = git_path(head_ref.trim())
        && let Some(heads) = git_path("refs/heads")
        && let Some(watched) = ref_path
            .ancestors()
            .take_while(|path| path.starts_with(&heads))
            .find(|path| path.exists())
    {
        println!("cargo:rerun-if-changed={}", watched.display());
    }
}

fn git_path(name: &str) -> Option<std::path::PathBuf> {
    git(&["rev-parse", "--path-format=absolute", "--git-path", name])
        .map(|path| std::path::PathBuf::from(path.trim()))
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}
