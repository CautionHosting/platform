// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//! Hosted verification never uses legacy HTTP archive guesses, Git fallbacks or
//! the old URL-keyed download cache. The measured manifest is kept unchanged.
use super::{StagedSource, extract_tarball_bytes_to_dir};
use dterror::{BoxError, CtxError, Location, ResultExt};
use enclave_builder::AppSource;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, thiserror::Error, CtxError)]
#[error("{message} [{location:?}]")]
pub(crate) struct Error {
    #[context(borrow = str)]
    message: String,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}
impl Error {
    #[track_caller]
    fn invalid(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}
use ErrorCtx as Ctx;

fn https_url(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).with_context(Ctx::new("parse hosted source URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "hosted source retrieval requires HTTPS without credentials, query or fragment",
        ));
    }
    Ok(url)
}
fn commit_valid(commit: &str) -> bool {
    commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Archive sources must name their exact approved commit. Reject mutable or
/// unrecognized archive layouts instead of changing the measured manifest.
pub(crate) fn pinned_archive(raw: &str, commit: &str) -> Result<Url, Error> {
    let url = https_url(raw)?;
    let expected = [commit, ".tar.gz"].concat();
    let pinned = url
        .path()
        .rsplit_once("/archive/")
        .is_some_and(|(repo, file)| !repo.is_empty() && !repo.ends_with("/-") && file == expected);
    if !commit_valid(commit) || !pinned {
        return Err(Error::invalid(
            "hosted archive source must use /archive/<approved-40-character-commit>.tar.gz; mutable or unsupported archives are rejected",
        ));
    }
    Ok(url)
}

pub(crate) fn archive_urls(source: &AppSource) -> Result<Vec<Url>, Error> {
    if !commit_valid(&source.commit) || source.urls.len() != 1 {
        return Err(Error::invalid(
            "hosted application source requires one HTTPS repository and a full immutable commit",
        ));
    }
    let url = https_url(&source.urls[0])?;
    let path = url.path().trim_end_matches('/');
    // Do not interpret an archive (including unsupported formats) as a Git repository.
    if path.contains("/archive/")
        || path.contains("/get/")
        || path.contains("/tar.gz/")
        || path.ends_with(".tar.gz")
        || path.ends_with(".tar")
        || path.ends_with(".zip")
        || path.ends_with(".tgz")
    {
        return Ok(vec![pinned_archive(&source.urls[0], &source.commit)?]);
    }
    let repo = path.trim_end_matches(".git");
    let name = repo
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::invalid("hosted source repository path is missing"))?;
    let mut urls = Vec::new();
    for suffix in [
        ["/archive/", &source.commit, ".tar.gz"].concat(),
        [
            "/-/archive/",
            &source.commit,
            "/",
            name,
            "-",
            &source.commit,
            ".tar.gz",
        ]
        .concat(),
        ["/get/", &source.commit, ".tar.gz"].concat(),
    ] {
        let mut candidate = url.clone();
        candidate.set_path(&[repo, &suffix].concat());
        urls.push(candidate);
    }
    Ok(urls)
}

fn http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(enclave_builder::source_transport::redirect_policy())
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .build()
        .with_context(Ctx::new("create HTTPS-only hosted source client"))
}

pub(super) async fn stage(source: &AppSource) -> Result<StagedSource, Error> {
    // Validate every candidate before issuing any request.
    let urls = archive_urls(source)?;
    let http = http_client()?;
    let mut failure = None;
    for url in urls {
        let fetched = async {
            let response = http
                .get(url)
                .send()
                .await
                .with_context(Ctx::new("fetch pinned hosted application source"))?
                .error_for_status()
                .with_context(Ctx::new("hosted source archive unavailable"))?;
            if !response.status().is_success() {
                return Err(Error::invalid(
                    "hosted source archive did not return success",
                ));
            }
            response
                .bytes()
                .await
                .with_context(Ctx::new("read hosted source archive"))
        }
        .await;
        match fetched {
            Ok(bytes) => return stage_bytes(&bytes, &source.commit),
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or_else(|| Error::invalid("no hosted source archive candidates")))
}
fn stage_bytes(bytes: &[u8], commit: &str) -> Result<StagedSource, Error> {
    let temp_dir = tempfile::TempDir::new().with_context(Ctx::new("stage hosted source"))?;
    extract_tarball_bytes_to_dir(bytes, temp_dir.path())
        .with_context(Ctx::new("extract hosted source"))?;
    // Forge archives usually wrap the repository in one directory; plain Git
    // archives may contain the source directly at the extraction root.
    let entries = std::fs::read_dir(temp_dir.path())
        .with_context(Ctx::new("read staged source directory"))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(Ctx::new("read staged source entries"))?;
    if entries.is_empty() {
        return Err(Error::invalid("hosted source archive is empty"));
    }
    let path = if entries.len() == 1
        && entries[0]
            .file_type()
            .with_context(Ctx::new("inspect source root"))?
            .is_dir()
    {
        entries[0].path()
    } else {
        temp_dir.path().to_owned()
    };
    // Segregate EIF cache entries from builds that used the legacy downloader;
    // different fetched content must also produce a different cache identity.
    let cache_key = ["hosted-https-v1-", &hex::encode(Sha256::digest(bytes))].concat();
    Ok(StagedSource {
        path,
        cache_key,
        app_commit: Some(commit.to_owned()),
        _temp_dir: temp_dir,
    })
}

#[cfg(test)]
#[path = "verify_hosted_source_tests.rs"]
mod tests;
