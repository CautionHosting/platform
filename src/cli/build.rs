fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let heuristics = caution_environment_heuristics::heuristics();
    let heuristics_file = std::fs::File::create(out_dir.join("heuristics.json"))
        .expect("should be able to open heuristics file");

    serde_json::to_writer(heuristics_file, &heuristics)
        .expect("should be able to serialize heuristics to heuristics.json");
}
