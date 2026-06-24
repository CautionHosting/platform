mod error;
mod patcher;
mod xpath;

use clap::Parser;
use std::fs;
use std::process;

use crate::error::PatcherError;
use crate::patcher::patch_hcl_value;

#[derive(Parser)]
#[command(name = "hcl-patcher", about = "Patch values in HCL files using XPath-like selectors")]
struct Args {
    /// Path to the HCL file
    file: String,

    /// XPath-like selector (e.g. /caution/provider/type)
    selector: String,

    /// New value to set
    value: String,

    /// Value type: string, bool, or number
    #[arg(long = "type")]
    type_: String,

    /// Write output to a file instead of modifying in-place
    #[arg(long)]
    output: Option<String>,
}

fn run(args: Args) -> Result<(), PatcherError> {
    let hcl_input = fs::read_to_string(&args.file)?;
    let patched = patch_hcl_value(&hcl_input, &args.selector, &args.value, &args.type_)?;

    match &args.output {
        Some(path) => fs::write(path, &patched)?,
        None => fs::write(&args.file, &patched)?,
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("error: {e}");
        process::exit(e.exit_code());
    }
}
