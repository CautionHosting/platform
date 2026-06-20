// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::Args;
use std::fs;
use std::path::PathBuf;

use crate::ApiClient;

#[derive(Args, Debug)]
pub(crate) struct MigrateProcfileArgs {
    #[arg(long, help = "Path to Procfile (default: ./Procfile)")]
    pub(crate) procfile: Option<PathBuf>,

    #[arg(long, help = "Output path (default: ./caution.hcl)")]
    pub(crate) output: Option<PathBuf>,

    #[arg(short, long, help = "Overwrite existing output file")]
    pub(crate) force: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MigrateProcfileError {
    #[error("failed to read {path}: {source}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse Procfile: {0}")]
    ParseError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("output file already exists: {0}; use --force to overwrite")]
    OutputExists(PathBuf),

    #[error("failed to serialize HCL configuration")]
    SerializeError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to write {path}: {source}")]
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub(crate) async fn migrate_procfile(
    _client: &ApiClient,
    args: &MigrateProcfileArgs,
) -> Result<(), MigrateProcfileError> {
    let procfile_path = args
        .procfile
        .clone()
        .unwrap_or_else(|| PathBuf::from("Procfile"));

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("caution.hcl"));

    let content = fs::read_to_string(&procfile_path).map_err(|source| {
        MigrateProcfileError::ReadError {
            path: procfile_path.clone(),
            source,
        }
    })?;

    let config = caution_config::ConfigurationFile::from_procfile(&content)
        .map_err(|e| MigrateProcfileError::ParseError(e.into()))?;

    if output_path.exists() && !args.force {
        return Err(MigrateProcfileError::OutputExists(output_path));
    }

    let hcl_output = hcl::to_string(&config)
        .map_err(|e| MigrateProcfileError::SerializeError(e.into()))?;

    fs::write(&output_path, &hcl_output).map_err(|source| {
        MigrateProcfileError::WriteError {
            path: output_path.clone(),
            source,
        }
    })?;

    println!(
        "✓ Migrated {} → {}",
        procfile_path.display(),
        output_path.display()
    );

    println!("  Note: The generated caution.hcl does not include a `caution {{}}` block.");
    println!("  Review and add machine_type, managed_credentials, etc. if needed.");

    Ok(())
}
