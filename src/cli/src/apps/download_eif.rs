// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::Args;
use dterror::{BoxError, CtxError, Location, ResultExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crate::ApiClient;
use crate::output;

#[derive(Args, Debug)]
pub(crate) struct DownloadEif {
    #[arg(help = "App ID (default: from .caution/deployment)")]
    pub(crate) id: Option<String>,

    #[arg(short, long, help = "Output file path")]
    pub(crate) output: Option<PathBuf>,

    #[arg(short, long, help = "Overwrite existing file")]
    pub(crate) force: bool,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DownloadEifError {
    #[error("no deployment found; run 'init' first or provide an app ID [{location:?}]")]
    NoDeployment {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("authentication failed [{location:?}]")]
    Auth {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("HTTP request failed [{location:?}]")]
    Http {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("unauthorized [{location:?}]")]
    Unauthorized {
        #[location]
        location: Location,
    },

    #[error("forbidden [{location:?}]")]
    Forbidden {
        #[location]
        location: Location,
    },

    #[error("resource not found [{location:?}]")]
    NotFound {
        #[location]
        location: Location,
    },

    #[error("HTTP status {status} [{location:?}]")]
    HttpStatus {
        status: u16,

        #[location]
        location: Location,
    },

    #[error("output file already exists: {path}; use --force to overwrite [{location:?}]")]
    FileExists {
        path: PathBuf,

        #[location]
        location: Location,
    },

    #[error("failed to write to file [{location:?}]")]
    WriteError {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("stream error [{location:?}]")]
    StreamError {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("download idle timeout (no data received for 30s) [{location:?}]")]
    IdleTimeout {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

struct PartFileGuard {
    path: Option<PathBuf>,
}

impl PartFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path.take();
    }
}

impl Drop for PartFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = fs::remove_file(path);
        }
    }
}

fn parse_content_disposition(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let value = headers
        .get(reqwest::header::CONTENT_DISPOSITION)?
        .to_str()
        .ok()?;
    for part in value.split(';') {
        let part = part.trim();
        if let Some(filename) = part.strip_prefix("filename=") {
            let filename = filename.trim_matches('"').trim_matches('\'');
            if !filename.is_empty() {
                return Some(filename.to_string());
            }
        }
    }
    None
}

pub(crate) async fn download_eif(
    client: &ApiClient,
    args: &DownloadEif,
) -> Result<(), DownloadEifError> {
    use DownloadEifErrorCtx as Ctx;

    let resource_id = match &args.id {
        Some(id) => id.clone(),
        None => {
            client
                .load_deployment()
                .with_context(Ctx::no_deployment())?
                .resource_id
        }
    };

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::auth())?;

    let mut response = client
        .http_client()
        .get(format!(
            "{}/api/resources/{}/eif/download",
            client.api_base_url(),
            resource_id
        ))
        .header("X-Session-ID", config.session_id())
        .send()
        .await
        .with_context(Ctx::http())?;

    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 => DownloadEifError::Unauthorized {
                location: std::panic::Location::caller(),
            },
            403 => DownloadEifError::Forbidden {
                location: std::panic::Location::caller(),
            },
            404 => DownloadEifError::NotFound {
                location: std::panic::Location::caller(),
            },
            code => DownloadEifError::HttpStatus {
                status: code,
                location: std::panic::Location::caller(),
            },
        });
    }

    let content_length = response.content_length();

    let default_filename = parse_content_disposition(response.headers())
        .unwrap_or_else(|| format!("{resource_id}.eif"));

    let output_path = match &args.output {
        Some(path) => path.clone(),
        None => PathBuf::from(&default_filename),
    };

    if output_path.exists() && !args.force {
        return Err(DownloadEifError::FileExists {
            path: output_path,
            location: std::panic::Location::caller(),
        });
    }

    let part_path = {
        let parent = output_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let file_name = output_path.file_name().map_or_else(
            || {
                let mut name = output_path.to_string_lossy().to_string();
                name.push_str(".part");
                name
            },
            |n| {
                let mut name = n.to_string_lossy().to_string();
                name.push_str(".part");
                name
            },
        );
        parent.join(file_name)
    };

    let mut guard = PartFileGuard::new(part_path.clone());

    let pb = if let Some(total) = content_length {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
                )
                .unwrap()
                .progress_chars("=> "),
        );
        pb.set_message("Downloading");
        pb
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg} {bytes}")
                .unwrap(),
        );
        pb.set_message("Downloading");
        pb
    };

    {
        let mut file = fs::File::create(&part_path).with_context(Ctx::write_error())?;

        loop {
            let chunk = tokio::time::timeout(Duration::from_secs(30), response.chunk())
                .await
                .with_context(Ctx::idle_timeout())?
                .with_context(Ctx::stream_error())?;

            match chunk {
                Some(bytes) => {
                    file.write_all(&bytes).with_context(Ctx::write_error())?;
                    pb.inc(bytes.len() as u64);
                }
                None => break,
            }
        }
    }

    pb.finish_and_clear();

    fs::rename(&part_path, &output_path).with_context(Ctx::write_error())?;
    guard.disarm();

    let file_size = fs::metadata(&output_path).map_or(0, |m| m.len());

    let size_str = if file_size >= 1_000_000_000 {
        format!("{:.1} GB", file_size as f64 / 1_000_000_000.0)
    } else if file_size >= 1_000_000 {
        format!("{:.1} MB", file_size as f64 / 1_000_000.0)
    } else if file_size >= 1_000 {
        format!("{:.1} KB", file_size as f64 / 1_000.0)
    } else {
        format!("{} B", file_size)
    };

    output::success(format!("Downloaded {} ({size_str})", output_path.display()));

    Ok(())
}
