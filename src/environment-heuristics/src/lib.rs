use std::io::{BufRead, BufReader};

// The security guarantees of Caution rely not only on the environment in which it is run, but also
// the environment in which it is built. While we can't cryptographically attest (at this point in
// time) the statements made here, we can do a best-effort marking of all findings assuming such
// compromises don't themselves affect the build output.

fn get_os_name() -> Option<String> {
    let Ok(file) = std::fs::File::open("/etc/os-release") else {
        return None;
    };
    let reader = BufReader::new(file);

    for line_reader in reader.lines() {
        let line = line_reader.expect("/etc/os-release should remain valid");
        if let Some((left, right)) = line.split_once('=')
            && left == "ID"
        {
            return Some(right.to_string());
        }
    }

    None
}

fn has_package_manager(bin_name: &str) -> bool {
    which::which_global(bin_name).is_ok()
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum Heuristic {
    PackageManager(String),
    UnknownOs(Option<String>),
    #[allow(non_camel_case_types)]
    LD_PRELOAD(std::ffi::OsString),
}

impl std::fmt::Display for Heuristic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Heuristic::PackageManager(pkgman) => write!(f, "Found package manager: {pkgman}"),
            Heuristic::UnknownOs(Some(os)) => write!(f, "Untrusted build OS: {os}"),
            Heuristic::UnknownOs(None) => write!(f, "Unknown build OS"),
            Heuristic::LD_PRELOAD(value) => {
                write!(f, "Unsafe variable LD_PRELOAD is set {value:?}")
            }
        }
    }
}

#[must_use]
pub fn heuristics() -> Vec<Heuristic> {
    let mut heuristics = vec![];

    for pkg_manager in [
        // os package managers
        "pacman", "apt-get", "yum", "dnf", "zypper", "nix", "guix", "emerge", "apk", "brew", "port",
        // language-specific package managers
        "npm", "pip", "luarocks",
    ] {
        if has_package_manager(pkg_manager) {
            heuristics.push(Heuristic::PackageManager(pkg_manager.into()));
        }
    }

    if let Some(name) = get_os_name() {
        if name != "stagex" {
            heuristics.push(Heuristic::UnknownOs(Some(name)));
        }
    } else {
        heuristics.push(Heuristic::UnknownOs(None));
    }

    if let Some(var) = std::env::var_os("LD_PRELOAD") {
        heuristics.push(Heuristic::LD_PRELOAD(var));
    }

    heuristics
}
