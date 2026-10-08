//! Finding an entry's format string and the paths of its process and
//! library, in the uuidtext and shared cache strings files the caller's
//! [`Source`] provides. Files are read once and kept.
//!
//! Where the format string is depends on the entry's flags: the main
//! executable's uuidtext file; the shared cache (at the offset, extended by
//! the large-offset fields); the uuidtext file of the image loaded at an
//! address (`absolute`); or that of an image the entry names
//! (`uuid_relative`). A format offset with its high bit set is "dynamic":
//! the format string is `%s`.

use std::collections::HashMap;

use crate::catalog::Process;
use crate::dsc::{self, SharedCache};
use crate::entry::FormatSource;
use crate::firehose::{Formatter, FormatterKind};
use crate::uuid::Uuid;
use crate::uuidtext::{self, UuidText};

/// A strings file the reader needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringFile {
    /// An image's uuidtext file: `uuidtext/XX/YYYY…` (the UUID's first two
    /// hex digits name the directory, the other thirty the file).
    UuidText(Uuid),
    /// A shared cache strings file: `uuidtext/dsc/<UUID>`.
    SharedCache(Uuid),
}

impl StringFile {
    /// The file's path in a uuidtext directory (or a log archive), with `/`.
    #[must_use]
    pub fn path(&self) -> String {
        match self {
            Self::UuidText(uuid) => {
                let hex = uuid.hex();
                format!("{}/{}", &hex[..2], &hex[2..])
            }
            Self::SharedCache(uuid) => format!("dsc/{}", uuid.hex()),
        }
    }
}

/// Where the reader gets uuidtext and shared cache strings files: their
/// bytes, or `None` when there is no such file.
///
/// Any `FnMut(StringFile) -> Option<Vec<u8>>` closure is a source:
///
/// ```no_run
/// let dir = std::path::PathBuf::from("system_logs.logarchive");
/// let source = move |file: unifiedlog::StringFile| std::fs::read(dir.join(file.path())).ok();
/// let reader = unifiedlog::Reader::new(source);
/// ```
pub trait Source {
    /// A file's bytes, or `None` when there is no such file.
    fn read(&mut self, file: StringFile) -> Option<Vec<u8>>;
}

impl<F: FnMut(StringFile) -> Option<Vec<u8>>> Source for F {
    fn read(&mut self, file: StringFile) -> Option<Vec<u8>> {
        self(file)
    }
}

/// The format string's offset bit that says it is `%s`.
const DYNAMIC: u64 = 0x8000_0000;

/// What was found for an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The format string, when found.
    pub format: Option<String>,
    /// The process's main executable.
    pub process: Option<String>,
    /// Its UUID.
    pub process_uuid: Option<Uuid>,
    /// The library (or executable) the entry came from.
    pub library: Option<String>,
    /// Its UUID.
    pub library_uuid: Option<Uuid>,
    /// Which file the format string was looked for in.
    pub source: FormatSource,
    /// Why the format string was not found.
    pub missing: Option<String>,
}

/// The strings files read so far, and the source of others.
pub struct Strings<S> {
    source: S,
    uuidtexts: HashMap<Uuid, Option<UuidText>>,
    caches: HashMap<Uuid, Option<SharedCache>>,
    /// Files that could not be read.
    pub problems: Vec<String>,
}

/// What a lookup is for: the entry's kind decides some of the rules.
#[derive(Debug, Clone, Copy)]
pub struct Lookup<'a> {
    /// The process, from the catalog.
    pub process: Option<&'a Process>,
    /// Where the format string is.
    pub formatter: &'a Formatter,
    /// The format string's offset.
    pub offset: u32,
    /// The low bits of the caller's address.
    pub pc_id: u32,
    /// Activities and signposts read large-cache offsets differently.
    pub large_offsets: bool,
}

impl<S: Source> Strings<S> {
    /// Strings files from `source`.
    pub fn new(source: S) -> Self {
        Self {
            source,
            uuidtexts: HashMap::new(),
            caches: HashMap::new(),
            problems: Vec::new(),
        }
    }

    /// The format string and paths for an entry.
    pub fn find(&mut self, lookup: &Lookup) -> Found {
        let main = lookup.process.and_then(|p| p.main_uuid);
        let place = where_is(lookup);
        let mut found = match place {
            Place::SharedCache(offset) => self.in_shared_cache(
                lookup.process.and_then(|p| p.dsc_uuid),
                offset,
                lookup.offset,
            ),
            Place::Absolute(address) => {
                let image = lookup
                    .process
                    .and_then(|p| p.image_at(address))
                    .map(|i| i.uuid);
                let dynamic = u64::from(lookup.offset) == address;
                self.in_uuidtext(image, u64::from(lookup.offset), dynamic)
            }
            Place::Image(uuid) => self.in_uuidtext(Some(uuid), u64::from(lookup.offset), false),
            Place::MainExe => self.in_uuidtext(main, u64::from(lookup.offset), false),
        };
        found.source = match place {
            Place::MainExe => FormatSource::MainExe,
            Place::SharedCache(_) => FormatSource::SharedCache,
            Place::Absolute(_) => FormatSource::Absolute,
            Place::Image(_) => FormatSource::UuidRelative,
        };
        found.process_uuid = main;
        found.process = self.image_path(main);
        found
    }

    /// The format string for a trace entry: always in the main executable,
    /// and never dynamic.
    pub fn find_trace(&mut self, process: Option<&Process>, offset: u32) -> Found {
        let main = process.and_then(|p| p.main_uuid);
        let mut found = self.uuidtext_string(main, u64::from(offset));
        found.process_uuid = main;
        found.process = self.image_path(main);
        found
    }

    /// The process path for a simpledump or statedump: the main
    /// executable's.
    pub fn process_path(&mut self, process: Option<&Process>) -> Option<String> {
        self.image_path(process.and_then(|p| p.main_uuid))
    }

    fn in_shared_cache(&mut self, dsc: Option<Uuid>, offset: u64, written: u32) -> Found {
        let Some(cache) = dsc.and_then(|uuid| self.shared_cache(uuid)) else {
            return missing(format!("no shared cache strings file {}", hex_or_none(dsc)));
        };
        if u64::from(written) & DYNAMIC != 0 {
            if let Some(image) = cache.first_image() {
                return library_found("%s".to_owned(), image.uuid, image.path.clone());
            }
        }
        if let Some(dsc::Found { format, image }) = cache.format_string(offset) {
            return library_found(format, image.uuid, image.path.clone());
        }
        let mut found = missing(format!(
            "no format string at {offset:#x} in the shared cache"
        ));
        if let Some(image) = cache.first_image() {
            found.library = Some(image.path.clone());
            found.library_uuid = Some(image.uuid);
        }
        found
    }

    /// A format string in an image's uuidtext file; `dynamic` also when
    /// the offset's high bit says so.
    fn in_uuidtext(&mut self, image: Option<Uuid>, offset: u64, dynamic: bool) -> Found {
        if dynamic || offset & DYNAMIC != 0 {
            let path = self.image_path(image);
            if path.is_some() {
                return Found {
                    format: Some("%s".to_owned()),
                    library: path,
                    library_uuid: image,
                    ..Found::default()
                };
            }
        }
        self.uuidtext_string(image, offset)
    }

    fn uuidtext_string(&mut self, image: Option<Uuid>, offset: u64) -> Found {
        let Some(text) = image.and_then(|uuid| self.uuidtext(uuid)) else {
            let mut found = missing(format!("no uuidtext file {}", hex_or_none(image)));
            found.library_uuid = image;
            return found;
        };
        let format = text.format_string(offset);
        let library = text.image_path();
        let mut found = match format {
            Some(format) => Found {
                format: Some(format),
                ..Found::default()
            },
            None => missing(format!(
                "no format string at {offset:#x} in {}",
                hex_or_none(image)
            )),
        };
        found.library = library;
        found.library_uuid = image;
        found
    }

    fn image_path(&mut self, image: Option<Uuid>) -> Option<String> {
        let uuid = image.filter(|uuid| !uuid.is_nil())?;
        self.uuidtext(uuid)?.image_path()
    }

    fn uuidtext(&mut self, uuid: Uuid) -> Option<&UuidText> {
        if !self.uuidtexts.contains_key(&uuid) {
            let parsed = self.load(StringFile::UuidText(uuid), |bytes| uuidtext::parse(&bytes));
            self.uuidtexts.insert(uuid, parsed);
        }
        self.uuidtexts.get(&uuid)?.as_ref()
    }

    fn shared_cache(&mut self, uuid: Uuid) -> Option<&SharedCache> {
        if !self.caches.contains_key(&uuid) {
            let parsed = self.load(StringFile::SharedCache(uuid), dsc::parse);
            self.caches.insert(uuid, parsed);
        }
        self.caches.get(&uuid)?.as_ref()
    }

    /// Reads and parses a file once; a file that does not parse is
    /// reported.
    fn load<T>(
        &mut self,
        file: StringFile,
        parse: impl FnOnce(Vec<u8>) -> Result<T, String>,
    ) -> Option<T> {
        let bytes = self.source.read(file)?;
        match parse(bytes) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                self.problems.push(format!("{}: {e}", file.path()));
                None
            }
        }
    }
}

/// Where a format string is.
enum Place {
    MainExe,
    SharedCache(u64),
    Absolute(u64),
    Image(Uuid),
}

/// Where an entry's format string is, from its formatter fields.
fn where_is(lookup: &Lookup) -> Place {
    let f = lookup.formatter;
    let offset = u64::from(lookup.offset);
    let large_cache = f.kind == FormatterKind::LargeSharedCache
        && f.large_shared_cache != 0
        && (!lookup.large_offsets || f.large_offset != 0);
    if f.kind == FormatterKind::SharedCache || large_cache {
        return Place::SharedCache(shared_cache_offset(f, offset));
    }
    match (f.kind, f.uuid) {
        (FormatterKind::Absolute, _) => {
            Place::Absolute(u64::from(f.alt_index) << 32 | u64::from(lookup.pc_id))
        }
        (FormatterKind::UuidRelative, Some(uuid)) => Place::Image(uuid),
        _ => Place::MainExe,
    }
}

/// A shared cache offset, extended by the large-offset fields: a large
/// offset of 1 or 2 (above the large-cache field) adds that many 2 GiB;
/// else a large-cache field adds half its value in 4 GiB; else the large
/// offset adds its value in 4 GiB.
fn shared_cache_offset(f: &Formatter, offset: u64) -> u64 {
    if f.large_offset == 0 {
        return offset;
    }
    let high = u64::from(f.large_offset);
    let base = if matches!(f.large_offset, 1 | 2) && f.large_offset > f.large_shared_cache {
        0x8000_0000 * high
    } else if f.large_shared_cache != 0 {
        0x1_0000_0000 * u64::from(f.large_shared_cache / 2)
    } else {
        0x1_0000_0000 * high
    };
    base + offset
}

fn missing(why: String) -> Found {
    Found {
        missing: Some(why),
        ..Found::default()
    }
}

fn library_found(format: String, uuid: Uuid, path: String) -> Found {
    Found {
        format: Some(format),
        library: Some(path),
        library_uuid: Some(uuid),
        ..Found::default()
    }
}

fn hex_or_none(uuid: Option<Uuid>) -> String {
    uuid.map_or_else(|| "(none in the catalog)".to_owned(), |u| u.hex())
}
