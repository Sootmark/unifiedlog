//! macOS Unified Logs (`/var/db/diagnostics`, `/var/db/uuidtext`, and the
//! `.logarchive` bundles `log collect` writes): every log entry, with its
//! time, process, thread, activity, subsystem and category, the format
//! string and the message it makes.
//!
//! Four kinds of files make up the logs. Tracev3 files (`Persist/`,
//! `Special/`, `Signpost/`, `HighVolume/`) hold the entries: a header
//! chunk, then catalogs (the processes, their images and subsystems) each
//! followed by chunksets, LZ4- or LZBITMAP-compressed runs of firehose
//! chunks (log entries, activities, signposts, traces, losses) and
//! oversize, statedump and simpledump chunks. An entry holds no text of
//! its own: its format string is in a uuidtext file named by its image's
//! UUID, or in a shared cache strings file (`uuidtext/dsc/`), and its
//! values ("items") are filled in as `printf` does. Times are Mach
//! continuous times, turned into wall-clock times by the timesync files
//! (`timesync/`).
//!
//! The library reads bytes and touches no files: give the [`Reader`] the
//! timesync files, a [`Source`] for the strings files (a closure will do),
//! then each tracev3 file.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::path::Path;
//!
//! let archive = Path::new("system_logs.logarchive");
//! let mut reader = unifiedlog::Reader::new(|file: unifiedlog::StringFile| {
//!     std::fs::read(archive.join(file.path())).ok()
//! });
//! for timesync in std::fs::read_dir(archive.join("timesync"))? {
//!     reader.add_timesync(&std::fs::read(timesync?.path())?);
//! }
//! let log = reader.read(&std::fs::read(archive.join("Persist/0000000000000001.tracev3"))?);
//! for entry in log.entries.iter().chain(&reader.finish()) {
//!     println!("{:?} {} {} {}", entry.time(), entry.pid, entry.process, entry.message);
//! }
//! # Ok(())
//! # }
//! ```

mod bplist;
mod catalog;
mod chunkset;
mod decoders;
mod dsc;
mod dumps;
mod entry;
mod firehose;
mod format;
mod header;
mod items;
mod lz4;
mod lzbitmap;
mod reader;
mod state;
mod strings;
mod text;
mod timesync;
mod uuid;
mod uuidtext;

pub use entry::{Entry, EventType, FormatSource, LogType, Loss, Signpost, State};
pub use format::{format, MISSING, PRIVATE};
pub use header::Header;
pub use items::{Frame, Item, Value};
pub use reader::{Log, Reader};
pub use strings::{Source, StringFile};
pub use timesync::{Boot, SyncRecord, Timesync};
pub use uuid::Uuid;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
