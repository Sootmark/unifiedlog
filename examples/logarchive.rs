//! Reads a `.logarchive` directory and writes its entries as JSON lines,
//! with the fields (and message layout) of Mandiant's
//! `unifiedlog_iterator`, for comparisons.
//!
//! `cargo run --release --example logarchive -- system_logs.logarchive > out.jsonl`

use std::io::Write;
use std::path::PathBuf;

#[path = "../tests/support/archive.rs"]
mod archive;

fn main() -> std::io::Result<()> {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: logarchive <path to .logarchive>");
        std::process::exit(2);
    };
    let (entries, problems) = archive::read(&archive::Archive::new(&path, false));
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for read in &entries {
        writeln!(out, "{}", archive::to_json(read))?;
    }
    for problem in &problems {
        eprintln!("{problem}");
    }
    eprintln!("{} entries, {} problems", entries.len(), problems.len());
    Ok(())
}
