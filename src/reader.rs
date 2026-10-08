//! The reader: tracev3 files in, entries out.

use std::collections::HashMap;

use crate::catalog::{self, Catalog, Process};
use crate::chunkset::{self, Chunk};
use crate::dumps::{self, Oversize, Simpledump, Statedump};
use crate::entry::{Entry, EventType, FormatSource, LogType, Loss, Signpost, State};
use crate::firehose::{self, kind, Firehose, Tracepoint};
use crate::format::format;
use crate::header::{self, Header};
use crate::items::Items;
use crate::state;
use crate::strings::{Found, Lookup, Source, Strings};
use crate::timesync::Timesync;
use crate::uuid::Uuid;

/// Chunk tags.
mod tag {
    pub const HEADER: u32 = 0x1000;
    pub const CATALOG: u32 = 0x600b;
    pub const CHUNKSET: u32 = 0x600d;
    pub const FIREHOSE: u32 = 0x6001;
    pub const OVERSIZE: u32 = 0x6002;
    pub const STATEDUMP: u32 = 0x6003;
    pub const SIMPLEDUMP: u32 = 0x6004;
}

/// What identifies an oversize chunk: the process pair and the reference.
type OversizeKey = (u64, u32, u32);

/// Reads tracev3 files into entries, with the timesync files and the
/// strings files they need.
///
/// Give it the timesync files first, then each tracev3 file. A log entry
/// whose items are in an oversize chunk of a file not read yet is held
/// back until [`Reader::finish`].
pub struct Reader<S> {
    strings: Strings<S>,
    timesync: Timesync,
    oversize: HashMap<OversizeKey, Items>,
    pending: Vec<(Entry, OversizeKey)>,
}

/// A tracev3 file's entries.
#[derive(Debug, Clone, Default)]
pub struct Log {
    /// Its header, when it has one.
    pub header: Option<Header>,
    /// Its entries, in file order.
    pub entries: Vec<Entry>,
    /// Damage met, and strings files that could not be read; reading goes
    /// on at the next chunk.
    pub problems: Vec<String>,
}

impl<S: Source> Reader<S> {
    /// A reader that gets uuidtext and shared cache strings files from
    /// `source`.
    pub fn new(source: S) -> Self {
        Self {
            strings: Strings::new(source),
            timesync: Timesync::default(),
            oversize: HashMap::new(),
            pending: Vec::new(),
        }
    }

    /// Adds a timesync file; what could not be read is returned.
    pub fn add_timesync(&mut self, bytes: &[u8]) -> Vec<String> {
        self.timesync.add(bytes)
    }

    /// The boots and sync records added so far.
    #[must_use]
    pub fn timesync(&self) -> &Timesync {
        &self.timesync
    }

    /// Reads a tracev3 file.
    pub fn read(&mut self, tracev3: &[u8]) -> Log {
        let mut problems = Vec::new();
        let file = parse_file(tracev3, &mut problems);
        let file_oversize = oversize_of(&file.sections);
        let mut builder = Builder {
            strings: &mut self.strings,
            timesync: &self.timesync,
            boot: file
                .header
                .as_ref()
                .map(|h| h.boot_uuid)
                .unwrap_or_default(),
            oversize: [&file_oversize, &self.oversize],
        };
        let mut entries = Vec::new();
        for section in &file.sections {
            builder.section(section, &mut entries, &mut self.pending);
        }
        self.oversize.extend(file_oversize);
        problems.append(&mut self.strings.problems);
        Log {
            header: file.header,
            entries,
            problems,
        }
    }

    /// The entries held back for their oversize chunks, now with the items
    /// of every file read; those still not found show
    /// `<Missing message data>` for their conversions.
    pub fn finish(&mut self) -> Vec<Entry> {
        let pending = std::mem::take(&mut self.pending);
        pending
            .into_iter()
            .map(|(mut entry, key)| {
                match self.oversize.get(&key) {
                    Some(items) => entry.items.clone_from(&items.items),
                    None => entry.missing = Some(format!("no oversize chunk {}", key.2)),
                }
                with_message(entry)
            })
            .collect()
    }
}

/// A tracev3 file's chunks, decoded.
struct File {
    header: Option<Header>,
    sections: Vec<Section>,
}

/// A catalog and the chunks of the chunksets after it.
#[derive(Default)]
struct Section {
    catalog: Catalog,
    firehoses: Vec<Firehose>,
    oversizes: Vec<Oversize>,
    statedumps: Vec<Statedump>,
    simpledumps: Vec<Simpledump>,
}

fn parse_file(data: &[u8], problems: &mut Vec<String>) -> File {
    let mut file = File {
        header: None,
        sections: Vec::new(),
    };
    for chunk in chunkset::chunks(data, problems) {
        match chunk.tag {
            tag::HEADER => match header::parse(chunk.data) {
                Ok(header) => file.header = Some(header),
                Err(e) => problems.push(e),
            },
            tag::CATALOG => {
                let catalog = catalog::parse(chunk.data, problems).unwrap_or_else(|e| {
                    problems.push(e);
                    Catalog::default()
                });
                file.sections.push(Section {
                    catalog,
                    ..Section::default()
                });
            }
            tag::CHUNKSET => {
                if file.sections.is_empty() {
                    file.sections.push(Section::default());
                }
                if let Some(section) = file.sections.last_mut() {
                    read_chunkset(chunk.data, section, problems);
                }
            }
            other => problems.push(format!("chunk tag {other:#x} is unknown")),
        }
    }
    file
}

fn read_chunkset(data: &[u8], section: &mut Section, problems: &mut Vec<String>) {
    let decompressed = match chunkset::decompress(data) {
        Ok(decompressed) => decompressed,
        Err(e) => return problems.push(e),
    };
    for Chunk { tag, data } in chunkset::chunkset_chunks(&decompressed, problems) {
        let read = match tag {
            tag::FIREHOSE => firehose::parse(data, problems).map(|f| section.firehoses.push(f)),
            tag::OVERSIZE => dumps::oversize(data).map(|o| section.oversizes.push(o)),
            tag::STATEDUMP => dumps::statedump(data).map(|s| section.statedumps.push(s)),
            tag::SIMPLEDUMP => dumps::simpledump(data).map(|s| section.simpledumps.push(s)),
            other => Err(format!("chunkset chunk tag {other:#x} is unknown")),
        };
        if let Err(e) = read {
            problems.push(e);
        }
    }
}

/// The oversize chunks of a file, by key; the first of a key wins.
fn oversize_of(sections: &[Section]) -> HashMap<OversizeKey, Items> {
    let mut found = HashMap::new();
    for oversize in sections.iter().flat_map(|s| &s.oversizes) {
        let key = (oversize.proc_id.0, oversize.proc_id.1, oversize.data_ref);
        found.entry(key).or_insert_with(|| oversize.items.clone());
    }
    found
}

/// Builds the entries of one file.
struct Builder<'a, S> {
    strings: &'a mut Strings<S>,
    timesync: &'a Timesync,
    boot: Uuid,
    /// This file's oversize chunks, then those of the files before it.
    oversize: [&'a HashMap<OversizeKey, Items>; 2],
}

impl<S: Source> Builder<'_, S> {
    fn section(
        &mut self,
        section: &Section,
        entries: &mut Vec<Entry>,
        pending: &mut Vec<(Entry, OversizeKey)>,
    ) {
        for firehose in &section.firehoses {
            let process = section
                .catalog
                .process(firehose.proc_id.0, firehose.proc_id.1);
            for tracepoint in &firehose.tracepoints {
                let mut entry = self.tracepoint(firehose, process, tracepoint);
                match oversize_key(firehose, tracepoint) {
                    Some(key) => match self.oversize_items(key) {
                        Some(items) => {
                            entry.items.clone_from(&items.items);
                            entries.push(with_message(entry));
                        }
                        None => pending.push((entry, key)),
                    },
                    None => entries.push(with_message(entry)),
                }
            }
        }
        for dump in &section.simpledumps {
            entries.push(self.simpledump(&section.catalog, dump));
        }
        for dump in &section.statedumps {
            entries.push(self.statedump(&section.catalog, dump));
        }
    }

    fn oversize_items(&self, key: OversizeKey) -> Option<&Items> {
        self.oversize.iter().find_map(|map| map.get(&key))
    }

    /// The entry common to every kind: time, process, thread.
    fn base(&self, continuous_time: u64, from_boot: bool, process: Option<&Process>) -> Entry {
        Entry {
            continuous_time,
            unix_nanos: self
                .timesync
                .unix_nanos(self.boot, continuous_time, from_boot),
            boot_uuid: self.boot,
            pid: process.map_or(0, |p| u64::from(p.pid)),
            euid: process.map_or(0, |p| p.euid),
            ..Entry::default()
        }
    }

    /// A tracepoint's entry, all but its message (its items may be in an
    /// oversize chunk).
    fn tracepoint(
        &mut self,
        firehose: &Firehose,
        process: Option<&Process>,
        t: &Tracepoint,
    ) -> Entry {
        let event_type = event_type(t.kind);
        let mut entry = Entry {
            event_type,
            log_type: LogType::of(t.log_type, event_type),
            thread_id: t.thread_id,
            items: t.items.clone(),
            backtrace: t.backtrace.clone(),
            ..self.base(t.continuous_time, firehose.base_time == 0, process)
        };
        set_activity(&mut entry, t);
        if let Some(subsystem) = process
            .and_then(|p| p.subsystem(t.subsystem_id))
            .filter(|_| t.subsystem_id != 0)
        {
            entry.subsystem.clone_from(&subsystem.name);
            entry.category.clone_from(&subsystem.category);
        }
        entry.signpost = t.signpost.map(|(id, name)| Signpost { id, name });
        entry.loss = t.loss.map(|(start, end, count)| Loss { start, end, count });
        if entry.loss.is_some() {
            entry.log_type = LogType::Loss;
        }
        match self.find_format(process, t) {
            Some(found) => set_found(&mut entry, found),
            None => entry.format_source = FormatSource::None,
        }
        entry
    }

    /// The format string and paths, for entries that have them.
    fn find_format(&mut self, process: Option<&Process>, t: &Tracepoint) -> Option<Found> {
        match t.kind {
            kind::LOG | kind::ACTIVITY | kind::SIGNPOST => Some(self.strings.find(&Lookup {
                process,
                formatter: &t.formatter,
                offset: t.format_offset,
                pc_id: t.pc_id,
                large_offsets: t.kind != kind::LOG,
            })),
            kind::TRACE => Some(self.strings.find_trace(process, t.format_offset)),
            _ => None,
        }
    }

    fn simpledump(&mut self, catalog: &Catalog, dump: &Simpledump) -> Entry {
        let process = catalog.process(dump.first_proc_id, dump.second_proc_id);
        Entry {
            event_type: EventType::Simpledump,
            log_type: LogType::Simpledump,
            thread_id: dump.thread_id,
            subsystem: dump.subsystem.clone(),
            message: dump.message.clone(),
            process: self.strings.process_path(process).unwrap_or_default(),
            process_uuid: process.and_then(|p| p.main_uuid),
            library_uuid: Some(dump.sender_uuid),
            format_source: FormatSource::None,
            ..self.base(dump.continuous_time, false, process)
        }
    }

    fn statedump(&mut self, catalog: &Catalog, dump: &Statedump) -> Entry {
        let process = catalog.process(dump.proc_id.0, dump.proc_id.1);
        let state = State {
            title: dump.title.clone(),
            data_type: dump.data_type,
            decoder_library: dump.decoder_library.clone(),
            decoder_type: dump.decoder_type.clone(),
            data: dump.data.clone(),
        };
        Entry {
            event_type: EventType::Statedump,
            log_type: LogType::Statedump,
            activity_id: dump.activity_id,
            message: state::describe(&state),
            process: self.strings.process_path(process).unwrap_or_default(),
            process_uuid: process.and_then(|p| p.main_uuid),
            library_uuid: Some(dump.sender_uuid),
            format_source: FormatSource::None,
            state: Some(state),
            ..self.base(dump.continuous_time, false, process)
        }
    }
}

/// The key of the oversize chunk holding a log or signpost's items.
fn oversize_key(firehose: &Firehose, t: &Tracepoint) -> Option<OversizeKey> {
    let has_items = matches!(t.kind, kind::LOG | kind::SIGNPOST) && t.data_ref != 0;
    has_items.then_some((firehose.proc_id.0, firehose.proc_id.1, t.data_ref))
}

/// An entry with its message: its format string filled with its items.
fn with_message(mut entry: Entry) -> Entry {
    entry.message = format(&entry.raw_message, &entry.items);
    entry
}

fn event_type(kind: u8) -> EventType {
    match kind {
        kind::LOG => EventType::Log,
        kind::ACTIVITY => EventType::Activity,
        kind::TRACE => EventType::Trace,
        kind::SIGNPOST => EventType::Signpost,
        kind::LOSS => EventType::Loss,
        other => EventType::Unknown(other),
    }
}

/// The activity identifiers: an activity created inside another names it
/// as its parent.
fn set_activity(entry: &mut Entry, t: &Tracepoint) {
    if t.kind != kind::ACTIVITY {
        entry.activity_id = u64::from(t.current_activity_id);
    } else if t.other_activity_id != 0 {
        entry.activity_id = u64::from(t.other_activity_id);
        entry.parent_activity_id = u64::from(t.activity_id);
    } else {
        entry.activity_id = u64::from(t.activity_id);
    }
}

fn set_found(entry: &mut Entry, found: Found) {
    entry.raw_message = found.format.unwrap_or_default();
    entry.process = found.process.unwrap_or_default();
    entry.process_uuid = found.process_uuid;
    entry.library = found.library.unwrap_or_default();
    entry.library_uuid = found.library_uuid;
    entry.format_source = found.source;
    entry.missing = found.missing;
}
