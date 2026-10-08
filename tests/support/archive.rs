//! Reading a `.logarchive` (a directory, or one whose files are gzipped),
//! and showing entries as Mandiant's `unifiedlog_iterator` does, for
//! comparisons.

use std::fmt::Write;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use common::json::Json;
use unifiedlog::{Entry, Reader, StringFile};

/// The directories that hold tracev3 files.
const TRACE_DIRS: [&str; 4] = ["HighVolume", "Persist", "Signpost", "Special"];

/// An entry and what it came from.
pub struct Read {
    /// The tracev3 file, relative to the archive.
    pub file: String,
    /// The file's time zone name.
    pub timezone: String,
    /// The entry.
    pub entry: Entry,
}

/// A log archive's files: a directory, its files plain or gzipped (`.gz`
/// added to every name).
#[derive(Clone)]
pub struct Archive {
    dir: PathBuf,
    gzipped: bool,
}

impl Archive {
    /// An archive in a directory.
    pub fn new(dir: &Path, gzipped: bool) -> Self {
        Self {
            dir: dir.to_path_buf(),
            gzipped,
        }
    }

    /// A file's bytes, by its path in the archive.
    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        if !self.gzipped {
            return std::fs::read(self.dir.join(path)).ok();
        }
        let raw = std::fs::File::open(self.dir.join(format!("{path}.gz"))).ok()?;
        let mut bytes = Vec::new();
        common::gzip::Decoder::new(raw)
            .read_to_end(&mut bytes)
            .ok()?;
        Some(bytes)
    }

    /// The paths of the files in a directory of the archive whose names end
    /// with `suffix`, sorted.
    fn files_in(&self, dir: &str, suffix: &str) -> Vec<String> {
        let suffix = if self.gzipped {
            format!("{suffix}.gz")
        } else {
            suffix.to_owned()
        };
        let mut files: Vec<String> = std::fs::read_dir(self.dir.join(dir))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(&suffix) && !n.starts_with("._"))
            .map(|n| format!("{dir}/{}", n.trim_end_matches(".gz")))
            .collect();
        files.sort();
        files
    }

    /// The tracev3 files, sorted by path.
    fn tracev3_files(&self) -> Vec<String> {
        let mut files: Vec<String> = TRACE_DIRS
            .iter()
            .flat_map(|dir| self.files_in(dir, ".tracev3"))
            .collect();
        if self.file("logdata.LiveData.tracev3").is_some() {
            files.push("logdata.LiveData.tracev3".to_owned());
        }
        files.sort();
        files
    }
}

/// Every entry of an archive, in the order Mandiant's reader gives them
/// (tracev3 files by path; entries held back for oversize chunks last),
/// and the problems met.
pub fn read(archive: &Archive) -> (Vec<Read>, Vec<String>) {
    let strings = archive.clone();
    let mut reader = Reader::new(move |file: StringFile| strings.file(&file.path()));
    let mut problems = Vec::new();
    for path in archive.files_in("timesync", ".timesync") {
        problems.extend(reader.add_timesync(&archive.file(&path).unwrap_or_default()));
    }
    let mut read = Vec::new();
    for file in archive.tracev3_files() {
        let log = reader.read(&archive.file(&file).unwrap_or_default());
        let timezone = log
            .header
            .as_ref()
            .map(|h| h.timezone_name().to_owned())
            .unwrap_or_default();
        problems.extend(log.problems.into_iter().map(|p| format!("{file}: {p}")));
        read.extend(log.entries.into_iter().map(|entry| Read {
            file: file.clone(),
            timezone: timezone.clone(),
            entry,
        }));
    }
    // Entries held back for oversize chunks: their file is not known here.
    let timezone = read.last().map(|r| r.timezone.clone()).unwrap_or_default();
    read.extend(reader.finish().into_iter().map(|entry| Read {
        file: String::new(),
        timezone: timezone.clone(),
        entry,
    }));
    (read, problems)
}

/// The message as Mandiant's reader shows it: signposts and backtraces
/// prefixed.
pub fn mandiant_message(entry: &Entry) -> String {
    let mut message = entry.message.clone();
    if let Some(signpost) = entry.signpost {
        message = format!(
            "Signpost ID: {:X} - Signpost Name: {:X}\n {message}",
            signpost.id, signpost.name
        );
    }
    if !entry.backtrace.is_empty() {
        let mut lines = String::from("Backtrace:\n");
        for frame in &entry.backtrace {
            let _ = writeln!(lines, "\"{}\" +0x{:x}", frame.image.hex(), frame.offset);
        }
        message = lines + &message;
    }
    message
}

fn uuid(uuid: Option<unifiedlog::Uuid>) -> Json {
    Json::String(uuid.map(|u| u.hex()).unwrap_or_default())
}

/// An entry as a JSON object with the fields Mandiant's reader writes, and
/// its continuous time.
pub fn to_json(read: &Read) -> Json {
    let e = &read.entry;
    Json::object([
        ("subsystem", Json::String(e.subsystem.clone())),
        ("thread_id", Json::UInt(e.thread_id)),
        ("pid", Json::UInt(e.pid)),
        ("euid", Json::UInt(u64::from(e.euid))),
        ("library", Json::String(e.library.clone())),
        ("library_uuid", uuid(e.library_uuid)),
        ("activity_id", Json::UInt(e.activity_id)),
        ("parent_activity_id", Json::UInt(e.parent_activity_id)),
        ("time", e.unix_nanos.map_or(Json::Null, Json::Int)),
        ("continuous_time", Json::UInt(e.continuous_time)),
        ("category", Json::String(e.category.clone())),
        ("event_type", Json::String(e.event_type.name().to_owned())),
        ("log_type", Json::String(e.log_type.name().to_owned())),
        ("process", Json::String(e.process.clone())),
        ("process_uuid", uuid(e.process_uuid)),
        ("message", Json::String(mandiant_message(e))),
        ("raw_message", Json::String(e.raw_message.clone())),
        ("boot_uuid", Json::String(e.boot_uuid.hex())),
        ("timezone_name", Json::String(read.timezone.clone())),
        ("evidence", Json::String(read.file.clone())),
    ])
}
