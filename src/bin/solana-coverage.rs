use anyhow::{Result, bail};
use solana_coverage::util::{StripCurrentDir, find_files_with_extension};
use std::{
    env::{args, current_dir},
    path::PathBuf,
};

const SBF_TRACE_DIR: &str = "SBF_TRACE_DIR";

struct Options {
    #[allow(dead_code)]
    args: Vec<String>,
    debug: bool,
    help: bool,
}

fn main() -> Result<()> {
    let options = parse_args();

    if options.help {
        println!(
            "{} {}

A tool for computing test coverage of Solana programs.

Usage: SRC_PATHS=$PWD/src/[;$PWD/src_path2;...] \
SBF_PATHS=$PWD/target/deploy[;$PWD/fixtures;...] SBF_TRACE_DIR=sbf_trace_dir {0}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }

    let sbf_trace_dir = if let Ok(d) = std::env::var(SBF_TRACE_DIR) {
        PathBuf::from(d)
    } else {
        let current_dir = current_dir()?;
        current_dir.join("sbf_trace_dir")
    };

    let regs_paths = find_files_with_extension(std::slice::from_ref(&sbf_trace_dir), "regs");

    if regs_paths.is_empty() {
        bail!(
            "Found no regs files in: {}
Are you sure you run your tests with register tracing enabled",
            sbf_trace_dir.strip_current_dir().display(),
        );
    }

    solana_coverage::run(sbf_trace_dir, options.debug)?;

    Ok(())
}

fn parse_args() -> Options {
    let mut debug = false;
    let mut help = false;
    let args = args()
        .skip(1)
        .filter_map(|arg| {
            if arg == "--debug" {
                debug = true;
                None
            } else if arg == "--help" || arg == "-h" {
                help = true;
                None
            } else {
                Some(arg)
            }
        })
        .collect::<Vec<_>>();
    Options { args, debug, help }
}
