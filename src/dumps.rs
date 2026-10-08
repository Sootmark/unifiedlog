//! The other chunks a chunkset holds: oversize (0x6002, the items of a
//! log entry too large for its firehose chunk), statedump (0x6003, a
//! snapshot of a process's state: a property list, a protocol buffer or
//! an object) and simpledump (0x6004, a single string, since macOS 12).

use common::bytes::{Reader, Result};

use crate::items::{self, Items};
use crate::text::c_string;
use crate::uuid::Uuid;

/// An oversize chunk: the items of the log entry that refers to it.
#[derive(Debug, Clone, Default)]
pub struct Oversize {
    /// The process's identifier pair.
    pub proc_id: (u64, u32),
    /// The reference the log entry holds.
    pub data_ref: u32,
    /// The items.
    pub items: Items,
}

/// Reads an oversize chunk's data (after its preamble).
pub fn oversize(data: &[u8]) -> std::result::Result<Oversize, String> {
    read_oversize(&mut Reader::new(data)).map_err(|e| format!("oversize chunk: {e}"))
}

fn read_oversize(r: &mut Reader) -> Result<Oversize> {
    let proc_id = (r.u64_le()?, r.u32_le()?);
    r.skip(4 + 8)?; // TTL, reserved, continuous time
    let data_ref = r.u32_le()?;
    let public_size = usize::from(r.u16_le()?);
    let private_size = usize::from(r.u16_le()?);
    let data = r.bytes((public_size + private_size).min(r.remaining()))?;
    let private = data.get(public_size..);
    Ok(Oversize {
        proc_id,
        data_ref,
        items: items::read(data, false, private)?,
    })
}

/// A statedump chunk.
#[derive(Debug, Clone, Default)]
pub struct Statedump {
    /// The process's identifier pair.
    pub proc_id: (u64, u32),
    /// The continuous time.
    pub continuous_time: u64,
    /// The activity it belongs to.
    pub activity_id: u64,
    /// The image that wrote it.
    pub sender_uuid: Uuid,
    /// What the data is: 1 a property list, 2 a protocol buffer, 3 an object.
    pub data_type: u32,
    /// For objects: the library that decodes them.
    pub decoder_library: String,
    /// For objects: their type.
    pub decoder_type: String,
    /// Its title.
    pub title: String,
    /// The data.
    pub data: Vec<u8>,
}

/// An object, which a library's decoder renders.
pub const STATEDUMP_OBJECT: u32 = 3;

/// Reads a statedump chunk's data (after its preamble).
pub fn statedump(data: &[u8]) -> std::result::Result<Statedump, String> {
    read_statedump(&mut Reader::new(data)).map_err(|e| format!("statedump chunk: {e}"))
}

fn read_statedump(r: &mut Reader) -> Result<Statedump> {
    let proc_id = (r.u64_le()?, r.u32_le()?);
    r.skip(4)?; // TTL and reserved
    let mut dump = Statedump {
        proc_id,
        continuous_time: r.u64_le()?,
        activity_id: r.u64_le()?,
        sender_uuid: Uuid(r.array()?),
        data_type: r.u32_le()?,
        ..Statedump::default()
    };
    let size = r.u32_le()? as usize;
    let library = c_string(r.bytes(64)?);
    let decoder_type = c_string(r.bytes(64)?);
    if dump.data_type == STATEDUMP_OBJECT {
        dump.decoder_library = library;
        dump.decoder_type = decoder_type;
    }
    dump.title = c_string(r.bytes(64)?);
    dump.data = r.bytes(size.min(r.remaining()))?.to_vec();
    Ok(dump)
}

/// A simpledump chunk.
#[derive(Debug, Clone, Default)]
pub struct Simpledump {
    /// The first of the process's identifier pair.
    pub first_proc_id: u64,
    /// The second of the pair.
    pub second_proc_id: u32,
    /// The continuous time.
    pub continuous_time: u64,
    /// The thread.
    pub thread_id: u64,
    /// The image that wrote it.
    pub sender_uuid: Uuid,
    /// The subsystem.
    pub subsystem: String,
    /// The message.
    pub message: String,
}

/// Reads a simpledump chunk's data (after its preamble).
pub fn simpledump(data: &[u8]) -> std::result::Result<Simpledump, String> {
    read_simpledump(&mut Reader::new(data)).map_err(|e| format!("simpledump chunk: {e}"))
}

fn read_simpledump(r: &mut Reader) -> Result<Simpledump> {
    let first_proc_id = r.u64_le()?;
    let second_proc_id = r.u32_le()?;
    r.skip(4)?; // TTL, log type, unknown
    let mut dump = Simpledump {
        first_proc_id,
        second_proc_id,
        continuous_time: r.u64_le()?,
        thread_id: r.u64_le()?,
        ..Simpledump::default()
    };
    r.skip(8)?; // the caller's address
    dump.sender_uuid = Uuid(r.array()?);
    r.skip(16 + 4)?; // the shared cache's UUID, unknown
    let subsystem_size = r.u32_le()? as usize;
    let message_size = r.u32_le()? as usize;
    dump.subsystem = c_string(r.bytes(subsystem_size)?);
    dump.message = c_string(r.bytes(message_size)?);
    Ok(dump)
}
