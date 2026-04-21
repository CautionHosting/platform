// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

fn print_heuristics() {
    let build_heuristics_content = include_str!(concat!(env!("OUT_DIR"), "/heuristics.json"));
    let build_heuristics: Vec<caution_environment_heuristics::Heuristic> =
        serde_json::from_str(build_heuristics_content)
            .expect("should have valid constant build heuristics");
    let run_heuristics = caution_environment_heuristics::heuristics();

    if !build_heuristics.is_empty() || !run_heuristics.is_empty() {
        eprintln!("Potentially unsafe environment:");
    }

    for heuristic in build_heuristics {
        eprintln!("[BUILD] {heuristic}");
    }

    for heuristic in run_heuristics {
        eprintln!("  [RUN] {heuristic}");
    }
}

#[tokio::main]
async fn main() {
    print_heuristics();

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
