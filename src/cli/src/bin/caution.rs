// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::error::Error;

fn print_heuristics() {
    let build_heuristics_content = include_str!(concat!(env!("OUT_DIR"), "/heuristics.json"));
    let mut build_heuristics: Vec<caution_environment_heuristics::Heuristic> =
        serde_json::from_str(build_heuristics_content)
            .expect("should have valid constant build heuristics");
    let mut run_heuristics = caution_environment_heuristics::heuristics();

    caution_environment_heuristics::collapse_heuristics(&mut build_heuristics);
    caution_environment_heuristics::collapse_heuristics(&mut run_heuristics);

    if !build_heuristics.is_empty() || !run_heuristics.is_empty() {
        cli::output::warning("Potentially unsafe environment:");
    }

    for heuristic in build_heuristics {
        cli::output::warning(format!("[BUILD] {heuristic}"));
    }

    for heuristic in run_heuristics {
        cli::output::warning(format!("  [RUN] {heuristic}"));
    }
}

#[tokio::main]
async fn main() {
    print_heuristics();

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
