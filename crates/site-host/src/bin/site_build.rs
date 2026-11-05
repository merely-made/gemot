// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use gemot_site_host as site_host;
use site_host::{
    Site,
    generate::{self, BuildOptions, BuildRequest, OutputFormat},
};
use std::{fs, io::Read, path::Path};

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: site-build native|project SOURCE gemtext|scroll|markdown|html OUTPUT_DIR"
                .into(),
        );
    }
    let target = match args[2].as_str() {
        "gemtext" => OutputFormat::Gemtext,
        "scroll" => OutputFormat::Scroll,
        "markdown" => OutputFormat::Markdown,
        "html" => OutputFormat::Html,
        _ => return Err("Unknown output format".into()),
    };
    let artifact = match args[0].as_str() {
        "native" => Site::open(Path::new(&args[1]))?.generate(BuildOptions::new(target))?,
        "project" => {
            let mut bytes = Vec::new();
            fs::File::open(&args[1])
                .map_err(|e| e.to_string())?
                .take(site_host::MAX_ENCODED_SNAPSHOT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > site_host::MAX_ENCODED_SNAPSHOT_BYTES {
                return Err("Build project exceeds input budget".into());
            }
            let mut request: BuildRequest =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            request.options.target = target;
            request.build()?
        }
        _ => return Err("Source mode must be native or project".into()),
    };
    let receipt = generate::export(&artifact, Path::new(&args[3]))?;
    println!(
        "{} pages, {} assets; artifact {}",
        receipt.page_count,
        receipt.asset_count,
        receipt
            .artifact_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("site-build: {error}");
        std::process::exit(1);
    }
}
