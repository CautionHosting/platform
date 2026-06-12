// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crate::ApiClient;

#[derive(Args, Debug)]
pub(crate) struct DownloadEif {
    #[arg(help = "App ID (default: from .caution/deployment)")]
    pub(crate) id: Option<String>,

    #[arg(short, long, help = "Output file path")]
    pub(crate) output: Option<PathBuf>,

    #[arg(short, long, help = "Overwrite existing file")]
    pub(crate) force: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DownloadEifError {
    #[error("no deployment found; run 'init' first or provide an app ID")]
    NoDeployment,

    #[error("authentication failed")]
    Auth(#[source] anyhow::Error),

    #[error("HTTP request failed")]
    Http(#[source] reqwest::Error),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("resource not found")]
    NotFound,

    #[error("HTTP status {0}")]
    HttpStatus(u16),

    #[error("output file already exists: {0}; use --force to overwrite")]
    FileExists(PathBuf),

    #[error("failed to write to file")]
    WriteError(#[source] std::io::Error),

    #[error("stream error")]
    StreamError(#[source] reqwest::Error),

    #[error("download idle timeout (no data received for 30s)")]
    IdleTimeout,
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
    let resource_id = match &args.id {
        Some(id) => id.clone(),
        None => {
            client
                .load_deployment()
                .map_err(|_| DownloadEifError::NoDeployment)?
                .resource_id
        }
    };

    let config = client
        .ensure_authenticated()
        .await
        .map_err(DownloadEifError::Auth)?;

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
        .map_err(DownloadEifError::Http)?;

    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 => DownloadEifError::Unauthorized,
            403 => DownloadEifError::Forbidden,
            404 => DownloadEifError::NotFound,
            code => DownloadEifError::HttpStatus(code),
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
        return Err(DownloadEifError::FileExists(output_path));
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
        let mut file = fs::File::create(&part_path).map_err(DownloadEifError::WriteError)?;

        loop {
            let chunk = tokio::time::timeout(Duration::from_secs(30), response.chunk())
                .await
                .map_err(|_| DownloadEifError::IdleTimeout)?
                .map_err(DownloadEifError::StreamError)?;

            match chunk {
                Some(bytes) => {
                    file.write_all(&bytes)
                        .map_err(DownloadEifError::WriteError)?;
                    pb.inc(bytes.len() as u64);
                }
                None => break,
            }
        }
    }

    pb.finish_and_clear();

    fs::rename(&part_path, &output_path).map_err(DownloadEifError::WriteError)?;
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

    println!("Downloaded {} ({size_str})", output_path.display(),);

    Ok(())
}
