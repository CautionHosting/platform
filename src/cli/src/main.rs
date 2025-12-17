// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        eprintln!("\nError: {e}");

        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("Caused by: {err}");
            source = err.source();
        }

        std::process::exit(1);
    }
}

