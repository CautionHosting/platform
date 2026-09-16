mod error;
mod patcher;
mod xpath;

use clap::Parser;
use dterror::ResultExt;
use std::fs;
use std::process;

use crate::error::{PatcherError, PatcherErrorCtx};
use crate::patcher::patch_hcl_value;

#[derive(Parser)]
#[command(
    name = "hcl-patcher",
    about = "Patch values in HCL files using XPath-like selectors"
)]
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

#[tracing::instrument(skip_all, err)]
fn run(args: Args) -> Result<(), PatcherError> {
    use PatcherErrorCtx as Ctx;

    let hcl_input = fs::read_to_string(&args.file).with_context(Ctx::io())?;
    let patched = patch_hcl_value(&hcl_input, &args.selector, &args.value, &args.type_)?;

    match &args.output {
        Some(path) => fs::write(path, &patched).with_context(Ctx::io())?,
        None => fs::write(&args.file, &patched).with_context(Ctx::io())?,
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("error: {}", e.client_message());
        process::exit(e.exit_code());
    }
}
