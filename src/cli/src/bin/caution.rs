// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::error::Error;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        cli::output::error(format!("\nError: {e}"));

        let mut source = e.source();
        while let Some(err) = source {
            cli::output::error(format!("Caused by: {err}"));
            source = err.source();
        }

        std::process::exit(1);
    }
}
