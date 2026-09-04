// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::{Path, PathBuf};

use dterror::{BoxError, CtxError, Location, ResultExt};

use crate::{ApiClient, output, prompt};

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CachePathError {
    #[error("Could not load cache directory [{location:?}]")]
    GetCacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Show the cache directory path.
pub fn path(client: &ApiClient) -> Result<(), CachePathError> {
    use CachePathErrorCtx as Ctx;

    let cache_dir = client.get_cache_dir().with_context(Ctx::get_cache_dir())?;
    output::status(format!("{}", cache_dir.display()));
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CacheSizeError {
    #[error("Could not load cache directory [{location:?}]")]
    GetCacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Could not get cache directory size ({path:?}) [{location:?}]")]
    GetDirSize {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Show total cache size.
pub fn size(client: &ApiClient) -> Result<(), CacheSizeError> {
    use CacheSizeErrorCtx as Ctx;

    let cache_dir = client.get_cache_dir().with_context(Ctx::get_cache_dir())?;

    if !cache_dir.exists() {
        output::status("Cache is empty (0 bytes)");
        return Ok(());
    }

    let total_size = dir_size(&cache_dir).with_context(Ctx::get_dir_size(&cache_dir))?;
    output::status(format_size(total_size));

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CacheListError {
    #[error("Could not load cache directory [{location:?}]")]
    GetCacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// List cached items.
pub fn list(client: &ApiClient) -> Result<(), CacheListError> {
    use CacheListErrorCtx as Ctx;

    let cache_dir = client.get_cache_dir().with_context(Ctx::get_cache_dir())?;

    if !cache_dir.exists() {
        output::status("Cache is empty");
        return Ok(());
    }

    let downloads_dir = cache_dir.join("downloads");
    if downloads_dir.exists() {
        output::data_header("Downloads:");
        if let Ok(entries) = fs::read_dir(&downloads_dir) {
            let mut items: Vec<_> = entries.filter_map(|e| e.ok()).collect();
            if items.is_empty() {
                output::status("  (empty)");
            } else {
                items.sort_by_key(|e| e.path());
                for entry in items {
                    let path = entry.path();
                    let size = dir_size(&path).unwrap_or(0);
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    output::status(format!("  {} ({})", name, format_size(size)));
                }
            }
        }
    } else {
        output::status("Cache is empty");
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum CacheDestroyError {
    #[error("Could not load cache directory [{location:?}]")]
    GetCacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Could not get cache directory size ({path:?}) [{location:?}]")]
    GetDirSize {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Could not confirm deletion [{location:?}]")]
    ConfirmDeletion {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Could not remove all files in directory ({path:?}) [{location:?}]")]
    RemoveFiles {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Clear the cache, optionally skipping the confirmation prompt.
pub fn destroy(client: &ApiClient, force: bool) -> Result<(), CacheDestroyError> {
    use CacheDestroyErrorCtx as Ctx;

    let cache_dir = client.get_cache_dir().with_context(Ctx::get_cache_dir())?;

    if !cache_dir.exists() {
        output::status("Cache is already empty");
        return Ok(());
    }

    let total_size = dir_size(&cache_dir).with_context(Ctx::get_dir_size(&cache_dir))?;

    if !force {
        output::status("About to delete cache:");
        output::status(format!("  Path: {}", cache_dir.display()));
        output::status(format!("  Size: {}", format_size(total_size)));
        output::status("");
        let confirmed = prompt::confirm("Are you sure you want to delete the cache? [y/N] ")
            .with_context(Ctx::confirm_deletion())?;
        if !confirmed {
            output::status("Aborted.");
            return Ok(());
        }
    }

    fs::remove_dir_all(&cache_dir).with_context(Ctx::remove_files(&cache_dir))?;

    output::success(format!("Cache cleared ({} freed)", format_size(total_size)));
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirSizeErrorKind {
    Metadata,
    ReadDir,
    ReadDirEntry,
    Recursive,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("Unable to calculate dir size for {path:?} ({kind:?}) [{location:?}]")]
pub struct DirSizeError {
    kind: DirSizeErrorKind,

    #[context(borrow = Path)]
    path: PathBuf,

    #[location]
    location: Location,

    #[source]
    source: BoxError,
}

/// Compute the total size of a file tree.
fn dir_size(path: &PathBuf) -> Result<u64, DirSizeError> {
    use DirSizeErrorCtx as Ctx;
    use DirSizeErrorKind as ErrorKind;

    let mut total = 0;
    if path.is_file() {
        return Ok(fs::metadata(path)
            .with_context(Ctx::new(ErrorKind::Metadata, path))?
            .len());
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).with_context(Ctx::new(ErrorKind::ReadDir, path))? {
            let entry = entry.with_context(Ctx::new(ErrorKind::ReadDirEntry, path))?;
            let path = entry.path();
            if path.is_file() {
                total += fs::metadata(&path)
                    .with_context(Ctx::new(ErrorKind::Metadata, &path))?
                    .len();
            } else if path.is_dir() {
                total += dir_size(&path).with_context(Ctx::new(ErrorKind::Recursive, &path))?;
            }
        }
    }
    Ok(total)
}

/// Format a byte count in human-readable units.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}
