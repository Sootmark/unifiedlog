//! The catalog chunk (0x600b): the processes whose entries the chunksets
//! after it hold. Entries name their process by a pair of identifiers;
//! the catalog gives its pid and effective user, the UUIDs of its main
//! executable and shared cache, the images it loaded, and its subsystems
//! and categories.
//!
//! After the preamble: five 16-bit values (offsets, from the end of this
//! header, of the subsystem strings, the process entries and the
//! sub-chunks, and how many process entries and sub-chunks there are),
//! persona offset and count, padding, the earliest time, then the UUIDs,
//! the subsystem strings and the process entries.

use std::collections::HashMap;

use common::bytes::{Reader, Result};

use crate::chunkset::padding;
use crate::text::{c_string_at, invalid};
use crate::uuid::Uuid;

/// The catalog fields before its UUIDs, after the preamble.
const HEADER_SIZE: usize = 24;
/// A process's subsystem entry: identifier and two string offsets.
const SUBSYSTEM_ENTRY_SIZE: usize = 6;

/// The processes a catalog describes, by their identifier pair.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    processes: HashMap<(u64, u32), Process>,
}

/// A process, as the catalog describes it.
#[derive(Debug, Clone, Default)]
pub struct Process {
    /// Its pid.
    pub pid: u32,
    /// Its effective user.
    pub euid: u32,
    /// Its main executable's UUID (names its uuidtext file).
    pub main_uuid: Option<Uuid>,
    /// Its shared cache's UUID (names its `dsc/` file).
    pub dsc_uuid: Option<Uuid>,
    /// The images it loaded, for entries whose format string is located by
    /// address (the `absolute` flag).
    pub images: Vec<Image>,
    /// Its subsystems and categories, by identifier.
    pub subsystems: Vec<Subsystem>,
}

/// An image loaded at an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image {
    /// Where it starts.
    pub load_address: u64,
    /// How big it is.
    pub size: u32,
    /// Its UUID.
    pub uuid: Uuid,
}

/// A subsystem and category pair, by the identifier entries use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subsystem {
    /// What entries call it.
    pub id: u16,
    /// The subsystem's name (`com.apple.network`).
    pub name: String,
    /// The category (`connection`).
    pub category: String,
}

impl Catalog {
    /// The process an entry names.
    pub fn process(&self, first_proc_id: u64, second_proc_id: u32) -> Option<&Process> {
        self.processes.get(&(first_proc_id, second_proc_id))
    }
}

impl Process {
    /// The subsystem and category for an identifier.
    pub fn subsystem(&self, id: u16) -> Option<&Subsystem> {
        self.subsystems.iter().find(|s| s.id == id)
    }

    /// The image whose range holds an address (its end included).
    pub fn image_at(&self, address: u64) -> Option<&Image> {
        self.images.iter().find(|image| {
            address >= image.load_address
                && address <= image.load_address.saturating_add(u64::from(image.size))
        })
    }
}

/// Reads a catalog chunk's data (after its 16-byte preamble). Damaged
/// process entries are skipped and reported.
pub fn parse(data: &[u8], problems: &mut Vec<String>) -> std::result::Result<Catalog, String> {
    read(data, problems).map_err(|e| format!("catalog: {e}"))
}

fn read(data: &[u8], problems: &mut Vec<String>) -> Result<Catalog> {
    let mut r = Reader::new(data);
    let strings_offset = usize::from(r.u16_le()?);
    let processes_offset = usize::from(r.u16_le()?);
    let process_count = r.u16_le()?;
    if processes_offset < strings_offset {
        return Err(invalid(2, "process entries after the subsystem strings"));
    }
    r.seek(HEADER_SIZE)?;
    let uuids = (0..strings_offset / 16)
        .map(|_| r.array().map(Uuid))
        .collect::<Result<Vec<_>>>()?;
    let strings = r.bytes(processes_offset - strings_offset)?;
    r.seek(HEADER_SIZE + processes_offset)?;
    let mut catalog = Catalog::default();
    for _ in 0..process_count {
        match read_process(&mut r, &uuids, strings) {
            Ok((key, process)) => {
                catalog.processes.insert(key, process);
            }
            Err(e) => {
                problems.push(format!("catalog process entry: {e}"));
                break;
            }
        }
    }
    Ok(catalog)
}

/// A process entry and its identifier pair.
fn read_process(r: &mut Reader, uuids: &[Uuid], strings: &[u8]) -> Result<((u64, u32), Process)> {
    r.skip(4)?; // index and an unknown value
    let main_index = usize::from(r.u16_le()?);
    let dsc_index = usize::from(r.u16_le()?);
    let key = (r.u64_le()?, r.u32_le()?);
    let mut process = Process {
        pid: r.u32_le()?,
        euid: r.u32_le()?,
        main_uuid: uuids.get(main_index).copied(),
        dsc_uuid: uuids.get(dsc_index).copied(),
        ..Process::default()
    };
    r.skip(4)?; // persona
    let image_count = r.u32_le()?;
    r.skip(4)?;
    for _ in 0..image_count {
        let size = r.u32_le()?;
        r.skip(4)?;
        let index = usize::from(r.u16_le()?);
        let low = u64::from(r.u32_le()?);
        let high = u64::from(r.u16_le()?);
        if let Some(&uuid) = uuids.get(index) {
            process.images.push(Image {
                load_address: high << 32 | low,
                size,
                uuid,
            });
        }
    }
    let subsystem_count = r.u32_le()? as usize;
    r.skip(4)?;
    for _ in 0..subsystem_count {
        let id = r.u16_le()?;
        let subsystem = usize::from(r.u16_le()?);
        let category = usize::from(r.u16_le()?);
        process.subsystems.push(Subsystem {
            id,
            name: c_string_at(strings, subsystem).unwrap_or_default(),
            category: c_string_at(strings, category).unwrap_or_default(),
        });
    }
    r.skip(padding(
        subsystem_count.saturating_mul(SUBSYSTEM_ENTRY_SIZE),
        8,
    ))?;
    Ok((key, process))
}
