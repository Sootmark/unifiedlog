//! Firehose chunks (0x6001): the log entries ("tracepoints") of one
//! process, in a chunkset.
//!
//! After the preamble: the process's identifier pair, a TTL, whether the
//! chunk was collapsed, the size of its public data, the virtual offset of
//! its private data (0x1000 when it has none), and the base continuous
//! time. The public data is the tracepoints, each 8-byte aligned: a 24-byte
//! header (the kind of entry, the log type, flags, the format string's
//! location, the thread, the time since the base, the data size) and the
//! data. What the data holds depends on the kind (log, activity, trace,
//! signpost, loss) and on the flags; most end with data items.

use common::bytes::{Reader, Result};

use crate::chunkset::padding;
use crate::items::{self, Frame, Item, Items, Value};
use crate::text::invalid;
use crate::uuid::Uuid;

/// The private data's virtual offset when there is none.
const NO_PRIVATE_DATA: u16 = 0x1000;
/// A tracepoint's header.
const TRACEPOINT_HEADER: usize = 24;

/// Entry kinds (the tracepoint's first byte).
pub mod kind {
    /// An activity (`os_activity_create`, user actions).
    pub const ACTIVITY: u8 = 0x2;
    /// A trace entry (an older, compact form).
    pub const TRACE: u8 = 0x3;
    /// A log entry (`os_log`).
    pub const LOG: u8 = 0x4;
    /// A signpost (`os_signpost`).
    pub const SIGNPOST: u8 = 0x6;
    /// Entries the system dropped.
    pub const LOSS: u8 = 0x7;
}

/// Tracepoint flags.
mod flag {
    pub const CURRENT_ACTIVITY: u16 = 0x0001;
    pub const UNIQUE_PID: u16 = 0x0010;
    pub const LARGE_OFFSET: u16 = 0x0020;
    pub const PERSONA: u16 = 0x0040;
    pub const PRIVATE_DATA: u16 = 0x0100;
    /// The subsystem for logs and signposts, another activity for activities.
    pub const SUBSYSTEM_OR_OTHER_ACTIVITY: u16 = 0x0200;
    pub const RULES: u16 = 0x0400;
    pub const OVERSIZE: u16 = 0x0800;
    pub const BACKTRACE: u16 = 0x1000;
    pub const SIGNPOST_NAME: u16 = 0x8000;
    /// The bits that say where the format string is.
    pub const FORMATTER: u16 = 0x000e;
}

/// A user action activity: it has no activity identifier of its own.
const USER_ACTION: u8 = 0x3;

/// Where a tracepoint's format string is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Formatter {
    /// Which file holds it.
    pub kind: FormatterKind,
    /// The high bits of a large offset (with `LARGE_OFFSET`).
    pub large_offset: u16,
    /// The high bits of an offset in a large shared cache.
    pub large_shared_cache: u16,
    /// Absolute: the high bits of the address.
    pub alt_index: u16,
    /// UUID-relative: the image holding it.
    pub uuid: Option<Uuid>,
}

/// Which file holds a format string.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FormatterKind {
    /// The process's main executable's uuidtext file.
    #[default]
    MainExe,
    /// The shared cache strings file.
    SharedCache,
    /// The shared cache strings file, with a 16-bit extension of the offset.
    LargeSharedCache,
    /// The uuidtext file of the image loaded at an address.
    Absolute,
    /// The uuidtext file of the image the entry names.
    UuidRelative,
    /// A combination of flags not seen before.
    Unknown,
}

/// A tracepoint: one log entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tracepoint {
    /// The kind of entry (see [`kind`]).
    pub kind: u8,
    /// The log type (default, info, debug, error, fault; activity and
    /// signpost types).
    pub log_type: u8,
    /// The flags.
    pub flags: u16,
    /// The format string's location (an offset in its file).
    pub format_offset: u32,
    /// The thread.
    pub thread_id: u64,
    /// The continuous time (the chunk's base plus the entry's delta).
    pub continuous_time: u64,
    /// The new activity (activities that are not user actions).
    pub activity_id: u32,
    /// The current activity.
    pub current_activity_id: u32,
    /// Another activity (activities only).
    pub other_activity_id: u32,
    /// The unique pid (activities only).
    pub unique_pid: u64,
    /// The low bits of the caller's address.
    pub pc_id: u32,
    /// Where the format string is.
    pub formatter: Formatter,
    /// The subsystem's identifier in the catalog.
    pub subsystem_id: u16,
    /// The oversize chunk holding the items, when they did not fit.
    pub data_ref: u32,
    /// The signpost's identifier and name.
    pub signpost: Option<(u64, u32)>,
    /// Loss entries: first and last time lost, and how many entries.
    pub loss: Option<(u64, u64, u64)>,
    /// The values for the format string.
    pub items: Vec<Item>,
    /// The backtrace, when recorded.
    pub backtrace: Vec<Frame>,
}

/// A firehose chunk's process and tracepoints.
#[derive(Debug, Clone, Default)]
pub struct Firehose {
    /// The process's identifier pair (for the catalog).
    pub proc_id: (u64, u32),
    /// The continuous time the tracepoints' times count from.
    pub base_time: u64,
    /// The tracepoints, in order.
    pub tracepoints: Vec<Tracepoint>,
}

/// Reads a firehose chunk's data (after its preamble). Damage stops the
/// reading of the chunk's tracepoints and is reported.
pub fn parse(data: &[u8], problems: &mut Vec<String>) -> std::result::Result<Firehose, String> {
    let mut r = Reader::new(data);
    let header = read_header(&mut r).map_err(|e| format!("firehose chunk: {e}"))?;
    let public_end = (header.data_start + usize::from(header.public_size)).min(data.len());
    let public = data.get(r.position()..public_end).unwrap_or_default();
    let private = private_data(data, &header, public_end);
    let mut firehose = Firehose {
        proc_id: header.proc_id,
        base_time: header.base_time,
        tracepoints: Vec::new(),
    };
    let mut at = 0;
    while public.len() - at >= TRACEPOINT_HEADER {
        match read_tracepoint(&public[at..], &header, private) {
            Ok(Some(Read {
                tracepoint,
                size,
                damage,
            })) => {
                if let Some(e) = damage {
                    problems.push(format!("firehose tracepoint at {at}: {e}"));
                }
                let known = is_known(tracepoint.kind);
                firehose.tracepoints.push(tracepoint);
                if !known {
                    break;
                }
                at += size;
            }
            Ok(None) => break,
            Err(e) => {
                problems.push(format!("firehose tracepoint at {at}: {e}"));
                break;
            }
        }
    }
    Ok(firehose)
}

fn is_known(kind: u8) -> bool {
    [
        kind::ACTIVITY,
        kind::TRACE,
        kind::LOG,
        kind::SIGNPOST,
        kind::LOSS,
    ]
    .contains(&kind)
}

/// What the chunk's header says.
struct ChunkHeader {
    proc_id: (u64, u32),
    collapsed: bool,
    /// Where the public data size is: private offsets count from here.
    data_start: usize,
    public_size: u16,
    private_offset: u16,
    base_time: u64,
}

fn read_header(r: &mut Reader) -> Result<ChunkHeader> {
    let proc_id = (r.u64_le()?, r.u32_le()?);
    r.skip(1)?; // TTL
    let collapsed = r.u8()? == 1;
    r.skip(2)?;
    let data_start = r.position();
    let public_size = r.u16_le()?;
    let private_offset = r.u16_le()?;
    r.skip(4)?;
    Ok(ChunkHeader {
        proc_id,
        collapsed,
        data_start,
        public_size,
        private_offset,
        base_time: r.u64_le()?,
    })
}

/// The chunk's private data: at its virtual offset from the data start,
/// or, in a collapsed chunk, right after the public data.
fn private_data<'a>(
    data: &'a [u8],
    header: &ChunkHeader,
    public_end: usize,
) -> Option<Private<'a>> {
    if header.private_offset == NO_PRIVATE_DATA {
        return None;
    }
    let offset = usize::from(header.private_offset);
    let bytes = if header.collapsed || offset > data.len() - header.data_start {
        let size = usize::from(NO_PRIVATE_DATA.saturating_sub(header.private_offset));
        data.get(public_end..(public_end + size).min(data.len()))?
    } else {
        data.get(header.data_start + offset..)?
    };
    Some(Private {
        bytes,
        virtual_offset: header.private_offset,
    })
}

/// A chunk's private data and the virtual offset it starts at.
#[derive(Debug, Clone, Copy)]
struct Private<'a> {
    bytes: &'a [u8],
    virtual_offset: u16,
}

impl<'a> Private<'a> {
    /// The private data from a virtual offset on.
    fn from(&self, offset: u16) -> Option<&'a [u8]> {
        let start = usize::from(offset.checked_sub(self.virtual_offset)?);
        self.bytes.get(start..)
    }
}

/// A tracepoint as read.
struct Read {
    tracepoint: Tracepoint,
    /// The bytes it takes, with its padding.
    size: usize,
    /// What could not be read in its data: the fields before it are kept.
    damage: Option<String>,
}

/// A tracepoint; `None` at the zeros that follow the last one.
fn read_tracepoint(
    data: &[u8],
    header: &ChunkHeader,
    private: Option<Private>,
) -> Result<Option<Read>> {
    let mut r = Reader::new(data);
    let kind = r.u8()?;
    if kind == 0 {
        return Ok(None);
    }
    let mut tracepoint = Tracepoint {
        kind,
        log_type: r.u8()?,
        flags: r.u16_le()?,
        format_offset: r.u32_le()?,
        thread_id: r.u64_le()?,
        ..Tracepoint::default()
    };
    let delta = u64::from(r.u32_le()?) | u64::from(r.u16_le()?) << 32;
    tracepoint.continuous_time = header.base_time.wrapping_add(delta);
    let size = usize::from(r.u16_le()?);
    let mut body = r.sub(size)?;
    let damage = if is_known(kind) {
        read_body(&mut body, &mut tracepoint, private)
            .err()
            .map(|e| e.to_string())
    } else {
        None
    };
    Ok(Some(Read {
        tracepoint,
        size: TRACEPOINT_HEADER + size + padding(size, 8),
        damage,
    }))
}

/// The data after a tracepoint's header, by kind.
fn read_body(r: &mut Reader, t: &mut Tracepoint, private: Option<Private>) -> Result<()> {
    match t.kind {
        kind::LOSS => {
            t.loss = Some((r.u64_le()?, r.u64_le()?, r.u64_le()?));
            Ok(())
        }
        kind::TRACE => read_trace(r, t),
        kind::ACTIVITY => {
            read_activity_ids(r, t)?;
            t.pc_id = r.u32_le()?;
            t.formatter = read_formatter(r, t.flags)?;
            read_items(r, t, None)
        }
        _ => {
            let private_range = read_log_ids(r, t)?;
            t.pc_id = r.u32_le()?;
            t.formatter = read_formatter(r, t.flags)?;
            read_log_tail(r, t)?;
            let private = private_range
                .map(|offset| private.and_then(|p| p.from(offset)).unwrap_or_default());
            read_items(r, t, private)
        }
    }
}

/// An activity's identifiers.
fn read_activity_ids(r: &mut Reader, t: &mut Tracepoint) -> Result<()> {
    if t.log_type != USER_ACTION {
        t.activity_id = read_activity_id(r)?;
    }
    if t.flags & flag::UNIQUE_PID != 0 {
        t.unique_pid = r.u64_le()?;
    }
    if t.flags & flag::CURRENT_ACTIVITY != 0 {
        t.current_activity_id = read_activity_id(r)?;
    }
    if t.flags & flag::PERSONA != 0 {
        r.skip(4)?;
    }
    if t.flags & flag::SUBSYSTEM_OR_OTHER_ACTIVITY != 0 {
        t.other_activity_id = read_activity_id(r)?;
    }
    Ok(())
}

/// An activity identifier and the sentinel after it.
fn read_activity_id(r: &mut Reader) -> Result<u32> {
    let id = r.u32_le()?;
    r.skip(4)?;
    Ok(id)
}

/// A log or signpost's fields before its caller address, and the virtual
/// offset of its private values when it has some.
fn read_log_ids(r: &mut Reader, t: &mut Tracepoint) -> Result<Option<u16>> {
    if t.flags & flag::CURRENT_ACTIVITY != 0 {
        t.current_activity_id = read_activity_id(r)?;
    }
    if t.flags & flag::PERSONA != 0 {
        r.skip(4)?;
    }
    if t.flags & flag::PRIVATE_DATA == 0 {
        return Ok(None);
    }
    let offset = r.u16_le()?;
    r.skip(2)?; // size
    Ok(Some(offset))
}

/// A log or signpost's fields after its format string's location.
fn read_log_tail(r: &mut Reader, t: &mut Tracepoint) -> Result<()> {
    if t.flags & flag::SUBSYSTEM_OR_OTHER_ACTIVITY != 0 {
        t.subsystem_id = r.u16_le()?;
    }
    let signpost_id = if t.kind == kind::SIGNPOST {
        Some(r.u64_le()?)
    } else {
        None
    };
    if t.flags & flag::RULES != 0 {
        r.skip(1)?;
    }
    if t.flags & flag::OVERSIZE != 0 {
        t.data_ref = r.u32_le()?;
    }
    if let Some(id) = signpost_id {
        t.signpost = Some((id, read_signpost_name(r, t)?));
    }
    Ok(())
}

/// A signpost's name reference, with its high bit when the format string
/// is in a large shared cache.
fn read_signpost_name(r: &mut Reader, t: &Tracepoint) -> Result<u32> {
    if t.flags & flag::SIGNPOST_NAME == 0 {
        return Ok(0);
    }
    let mut name = r.u32_le()?;
    let f = &t.formatter;
    if (f.kind == FormatterKind::SharedCache && f.large_offset != 0) || f.large_shared_cache != 0 {
        r.skip(2)?;
        name = name.wrapping_add(0x8000_0000);
    }
    Ok(name)
}

/// Where the format string is, from the flags and the fields they add.
fn read_formatter(r: &mut Reader, flags: u16) -> Result<Formatter> {
    let mut formatter = Formatter::default();
    match flags & flag::FORMATTER {
        0x2 => formatter.kind = FormatterKind::MainExe,
        0x4 => {
            formatter.kind = FormatterKind::SharedCache;
            if flags & flag::LARGE_OFFSET != 0 {
                formatter.large_offset = r.u16_le()?;
            }
        }
        0x8 => {
            formatter.kind = FormatterKind::Absolute;
            formatter.alt_index = r.u16_le()?;
        }
        0xa => {
            formatter.kind = FormatterKind::UuidRelative;
            formatter.uuid = Some(Uuid(r.array()?));
        }
        0xc => {
            formatter.kind = FormatterKind::LargeSharedCache;
            if flags & flag::LARGE_OFFSET != 0 {
                formatter.large_offset = r.u16_le()?;
            }
            formatter.large_shared_cache = r.u16_le()?;
        }
        _ => formatter.kind = FormatterKind::Unknown,
    }
    Ok(formatter)
}

/// The data items after the fields, when there is room for them.
fn read_items(r: &mut Reader, t: &mut Tracepoint, private: Option<&[u8]>) -> Result<()> {
    if r.remaining() < 2 {
        return Ok(());
    }
    let data = r.bytes(r.remaining())?;
    let Items { items, backtrace } = items::read(data, t.flags & flag::BACKTRACE != 0, private)?;
    t.items = items;
    t.backtrace = backtrace;
    Ok(())
}

/// A trace entry: the caller address, then its values stored backwards
/// (the values, their sizes, how many there are, read from the end).
fn read_trace(r: &mut Reader, t: &mut Tracepoint) -> Result<()> {
    t.pc_id = r.u32_le()?;
    let data = r.bytes(r.remaining())?;
    let Some((&count, rest)) = data.split_last() else {
        return Ok(());
    };
    let count = usize::from(count);
    let sizes_start = rest
        .len()
        .checked_sub(count)
        .ok_or_else(|| invalid(r.offset(), "trace value sizes"))?;
    let (mut values, sizes) = rest.split_at(sizes_start);
    let mut items = Vec::with_capacity(count);
    for &size in sizes.iter().rev() {
        let start = values
            .len()
            .checked_sub(usize::from(size))
            .ok_or_else(|| invalid(r.offset(), "a trace value"))?;
        let bytes = &values[start..];
        values = &values[..start];
        let bits = bytes.iter().rev().fold(0u64, |n, &b| n << 8 | u64::from(b));
        items.push(Item {
            kind: 0,
            value: Value::Number {
                bits,
                size: size.min(8),
            },
        });
    }
    items.reverse();
    t.items = items;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A firehose chunk's data (after the preamble) holding the given
    /// tracepoints, with no private data.
    fn chunk(tracepoints: &[Vec<u8>]) -> Vec<u8> {
        let mut public = Vec::new();
        for t in tracepoints {
            public.extend_from_slice(t);
            public.resize(public.len() + padding(public.len(), 8), 0);
        }
        let mut data = Vec::new();
        data.extend_from_slice(&7u64.to_le_bytes()); // first proc id
        data.extend_from_slice(&9u32.to_le_bytes()); // second proc id
        data.extend_from_slice(&[0, 0, 0, 0]); // ttl, collapsed, unknown
        data.extend_from_slice(&(16 + public.len() as u16).to_le_bytes());
        data.extend_from_slice(&NO_PRIVATE_DATA.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&1000u64.to_le_bytes()); // base time
        data.extend_from_slice(&public);
        data
    }

    /// A tracepoint: its header, then `body`.
    fn tracepoint(kind: u8, log_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut t = vec![kind, log_type];
        t.extend_from_slice(&flags.to_le_bytes());
        t.extend_from_slice(&0x1234u32.to_le_bytes()); // format offset
        t.extend_from_slice(&42u64.to_le_bytes()); // thread
        t.extend_from_slice(&5u32.to_le_bytes()); // time delta
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&(body.len() as u16).to_le_bytes());
        t.extend_from_slice(body);
        t
    }

    fn parse_one(t: Vec<u8>) -> Tracepoint {
        let mut problems = Vec::new();
        let firehose = parse(&chunk(&[t]), &mut problems).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(firehose.proc_id, (7, 9));
        firehose.tracepoints.into_iter().next().unwrap()
    }

    #[test]
    fn a_log_entry_with_its_optional_fields() {
        // current activity, main_exe, subsystem, rules, oversize
        let flags = 0x0001 | 0x0002 | 0x0200 | 0x0400 | 0x0800;
        let mut body = Vec::new();
        body.extend_from_slice(&[0x11, 0, 0, 0, 0, 0, 0, 0x80]); // activity, sentinel
        body.extend_from_slice(&0xabcdu32.to_le_bytes()); // pc
        body.extend_from_slice(&3u16.to_le_bytes()); // subsystem
        body.push(1); // ttl
        body.extend_from_slice(&77u32.to_le_bytes()); // data ref
        body.extend_from_slice(&[0x02, 1, 0x00, 4, 9, 0, 0, 0]); // one number item
        let t = parse_one(tracepoint(kind::LOG, 0x10, flags, &body));
        assert_eq!(
            (t.current_activity_id, t.pc_id, t.subsystem_id, t.data_ref),
            (0x11, 0xabcd, 3, 77)
        );
        assert_eq!(t.formatter.kind, FormatterKind::MainExe);
        assert_eq!(
            (t.thread_id, t.continuous_time, t.format_offset),
            (42, 1005, 0x1234)
        );
        assert_eq!(t.items[0].value, Value::Number { bits: 9, size: 4 });
    }

    #[test]
    fn formatter_flags() {
        let read =
            |flags: u16, bytes: &[u8]| read_formatter(&mut Reader::new(bytes), flags).unwrap();
        let shared = read(0x0004 | 0x0020, &[2, 0]);
        assert_eq!(
            (shared.kind, shared.large_offset),
            (FormatterKind::SharedCache, 2)
        );
        let absolute = read(0x0008, &[5, 0]);
        assert_eq!(
            (absolute.kind, absolute.alt_index),
            (FormatterKind::Absolute, 5)
        );
        let relative = read(0x000a, &[0xaa; 16]);
        assert_eq!(relative.uuid, Some(Uuid([0xaa; 16])));
        let large = read(0x000c | 0x0020, &[1, 0, 4, 0]);
        assert_eq!(
            (large.kind, large.large_offset, large.large_shared_cache),
            (FormatterKind::LargeSharedCache, 1, 4)
        );
        assert_eq!(read(0x0006, &[]).kind, FormatterKind::Unknown);
    }

    #[test]
    fn activities_signposts_losses_and_traces() {
        // activity: new id, unique pid, other activity; shared cache
        let mut body = vec![0x21, 0, 0, 0, 0, 0, 0, 0x80];
        body.extend_from_slice(&99u64.to_le_bytes());
        body.extend_from_slice(&[0x20, 0, 0, 0, 0, 0, 0, 0x80]);
        body.extend_from_slice(&1u32.to_le_bytes());
        let t = parse_one(tracepoint(
            kind::ACTIVITY,
            1,
            0x0010 | 0x0200 | 0x0004,
            &body,
        ));
        assert_eq!(
            (t.activity_id, t.unique_pid, t.other_activity_id),
            (0x21, 99, 0x20)
        );

        // signpost with a name
        let mut body = 2u32.to_le_bytes().to_vec(); // pc
        body.extend_from_slice(&0xfeedu64.to_le_bytes()); // signpost id
        body.extend_from_slice(&0x55u32.to_le_bytes()); // name
        let t = parse_one(tracepoint(kind::SIGNPOST, 0x80, 0x0002 | 0x8000, &body));
        assert_eq!(t.signpost, Some((0xfeed, 0x55)));

        let mut body = 1u64.to_le_bytes().to_vec();
        body.extend_from_slice(&2u64.to_le_bytes());
        body.extend_from_slice(&3u64.to_le_bytes());
        assert_eq!(
            parse_one(tracepoint(kind::LOSS, 0, 0, &body)).loss,
            Some((1, 2, 3))
        );

        // trace: pc, then values 7 (1 byte) and 0x0102 (2 bytes) stored
        // backwards: the values (last first), their sizes (first last), count
        let body = [0, 0, 0, 0, 7, 0x02, 0x01, 1, 2, 2];
        let t = parse_one(tracepoint(kind::TRACE, 0, 0x0002, &body));
        let values: Vec<_> = t.items.iter().map(|i| i.value.clone()).collect();
        assert_eq!(
            values,
            vec![
                Value::Number { bits: 7, size: 1 },
                Value::Number {
                    bits: 0x0102,
                    size: 2
                }
            ]
        );
    }

    #[test]
    fn a_damaged_tracepoint_keeps_its_header() {
        let mut problems = Vec::new();
        let firehose = parse(
            &chunk(&[tracepoint(kind::LOG, 0, 0x0001, &[1, 2])]),
            &mut problems,
        )
        .unwrap();
        assert_eq!(firehose.tracepoints.len(), 1);
        assert_eq!(firehose.tracepoints[0].thread_id, 42);
        assert_eq!(problems.len(), 1);
    }
}
