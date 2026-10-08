//! Data items: the values a format string formats.
//!
//! An entry's data is a count of items, then each item: a type byte, a
//! size byte, and either the value inline (numbers, and the widths and
//! precisions `*` asks for) or a 16-bit offset and size into the string
//! area after the items (strings, objects, raw data) or into the chunk's
//! private data (private values). A backtrace may sit between the items
//! and the string area.
//!
//! The type byte's low nibble says how the value was marked: bit 0x1
//! private, 0x2 public, 0x4 sensitive. The high nibble says what it is:
//! 0x0 a number, 0x1 a width or precision, 0x2 a string, 0x3 raw data
//! (`%P`), 0x4 an object (`%@`), 0xf a hashed value; 0x8 marks newer
//! private kinds.

use common::bytes::{Reader, Result};

use crate::chunkset::padding;
use crate::text::c_string;
use crate::uuid::Uuid;

/// A value for a format string's conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its type byte, as written (see the module docs).
    pub kind: u8,
    /// Its value.
    pub value: Value,
}

/// What an item holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A number: its bits, zero-extended, and its size in bytes.
    Number {
        /// The bits, little-endian as written, zero-extended to 64.
        bits: u64,
        /// The size written (1, 2, 4 or 8 bytes).
        size: u8,
    },
    /// A width or precision for the next conversion (`%*d`, `%.*s`).
    Count(u64),
    /// A string or an object's description.
    Text(String),
    /// Raw bytes (`%P` and hashed values).
    Bytes(Vec<u8>),
    /// A NULL string or object, shown as `(null)`.
    Null,
    /// A value the system did not record, shown as `<private>`.
    Private,
}

/// A backtrace frame: an image and an offset in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// The image's UUID.
    pub image: Uuid,
    /// The offset of the return address in that image.
    pub offset: u32,
}

/// Item types whose inline value is a width or precision.
const COUNTS: [u8; 2] = [0x10, 0x12];
/// Private and sensitive numbers, kept in the private data.
const PRIVATE_NUMBERS: [u8; 2] = [0x01, 0x05];
/// Public strings and objects, in the string area.
const PUBLIC_TEXT: [u8; 4] = [0x20, 0x22, 0x40, 0x42];
/// Public raw data and hashed values, in the string area.
const PUBLIC_BYTES: [u8; 3] = [0x30, 0x32, 0xf2];
/// Private and sensitive strings and objects, in the private data.
const PRIVATE_TEXT: [u8; 7] = [0x21, 0x25, 0x41, 0x45, 0x81, 0x85, 0xf1];
/// Private raw data, in the private data.
const PRIVATE_BYTES: [u8; 2] = [0x31, 0x35];
/// A range size's bit that says the value was cut to fit; a private
/// number of that size alone was not recorded.
const CUT: u16 = 0x8000;
/// What marks a string the system cut to fit.
const TRUNCATED: &str = "<…>";
/// What a backtrace starts with when no flag announces it.
const BACKTRACE_SIGNATURE: [u8; 3] = [0x01, 0x00, 0x12];

/// An item as read, before its value is found.
#[derive(Debug, Clone, Copy)]
enum Raw<'a> {
    Inline(&'a [u8]),
    Range { offset: u16, size: u16 },
}

/// The items of an entry or oversize chunk, and its backtrace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Items {
    /// The values, in order.
    pub items: Vec<Item>,
    /// The backtrace, when recorded.
    pub backtrace: Vec<Frame>,
}

/// Reads the items in `data` (from the count on). `has_backtrace` is the
/// entry's flag for one; without it a backtrace is still recognized by
/// its signature. `private` is the entry's private data when the entry
/// says it recorded some (possibly none: its private values were all
/// NULL); without it, private values were not recorded.
pub fn read(data: &[u8], has_backtrace: bool, private: Option<&[u8]>) -> Result<Items> {
    let mut r = Reader::new(data);
    r.skip(1)?;
    let count = r.u8()?;
    let mut raw = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        raw.push(read_raw(&mut r)?);
    }
    // String offsets count from here, before the backtrace if there is one.
    let strings = r.peek(r.remaining())?;
    let backtrace = if has_backtrace || starts_backtrace(&r) {
        read_backtrace(&mut r)?
    } else {
        Vec::new()
    };
    let items = raw
        .into_iter()
        .map(|(kind, raw)| Item {
            kind,
            value: value(kind, raw, strings, private),
        })
        .collect();
    Ok(Items { items, backtrace })
}

/// An item's type and what follows it.
fn read_raw<'a>(r: &mut Reader<'a>) -> Result<(u8, Raw<'a>)> {
    let kind = r.u8()?;
    let size = r.u8()?;
    let raw = if is_inline(kind) {
        Raw::Inline(r.bytes(usize::from(size))?)
    } else {
        Raw::Range {
            offset: r.u16_le()?,
            size: r.u16_le()?,
        }
    };
    Ok((kind, raw))
}

/// Whether an item's value is inline (numbers, counts, and unknown
/// types); others are a range.
fn is_inline(kind: u8) -> bool {
    !(PRIVATE_NUMBERS.contains(&kind)
        || PUBLIC_TEXT.contains(&kind)
        || PUBLIC_BYTES.contains(&kind)
        || PRIVATE_TEXT.contains(&kind)
        || PRIVATE_BYTES.contains(&kind))
}

fn starts_backtrace(r: &Reader) -> bool {
    r.remaining() > BACKTRACE_SIGNATURE.len()
        && r.peek(BACKTRACE_SIGNATURE.len()).ok() == Some(&BACKTRACE_SIGNATURE[..])
}

/// A backtrace: a header, the images' UUIDs, the frames' offsets and their
/// image indexes, padded to 4 bytes.
fn read_backtrace(r: &mut Reader) -> Result<Vec<Frame>> {
    r.skip(3)?;
    let image_count = usize::from(r.u8()?);
    let frame_count = usize::from(r.u16_le()?);
    let images = (0..image_count)
        .map(|_| r.array().map(Uuid))
        .collect::<Result<Vec<_>>>()?;
    let offsets = (0..frame_count)
        .map(|_| r.u32_le())
        .collect::<Result<Vec<_>>>()?;
    let indexes = r.bytes(frame_count)?;
    r.skip(padding(frame_count, 4))?;
    Ok(offsets
        .into_iter()
        .zip(indexes)
        .map(|(offset, &index)| Frame {
            image: images.get(usize::from(index)).copied().unwrap_or_default(),
            offset,
        })
        .collect())
}

/// An item's value, from inline bytes, the string area or private data.
fn value(kind: u8, raw: Raw, strings: &[u8], private: Option<&[u8]>) -> Value {
    match raw {
        Raw::Inline(bytes) if COUNTS.contains(&kind) => Value::Count(number(bytes)),
        Raw::Inline(bytes) => Value::Number {
            bits: number(bytes),
            size: bytes.len() as u8,
        },
        Raw::Range { offset, size } => ranged(kind, offset, size, strings, private),
    }
}

/// The value of an item that names a range of the string area or of the
/// private data.
fn ranged(kind: u8, offset: u16, size: u16, strings: &[u8], private: Option<&[u8]>) -> Value {
    if PUBLIC_TEXT.contains(&kind) {
        return match size {
            0 => Value::Null,
            _ => text(slice(strings, offset, size & !CUT), size & CUT != 0),
        };
    }
    if PUBLIC_BYTES.contains(&kind) {
        return Value::Bytes(slice(strings, offset, size).to_vec());
    }
    let Some(private) = private else {
        return Value::Private;
    };
    if size == 0 {
        // With the private data recorded, an empty value is a NULL one.
        return Value::Null;
    }
    if private.is_empty() {
        return Value::Private;
    }
    if PRIVATE_NUMBERS.contains(&kind) {
        if size == CUT {
            return Value::Private;
        }
        let bytes = slice(private, offset, size);
        return Value::Number {
            bits: number(bytes),
            size: bytes.len() as u8,
        };
    }
    let bytes = slice(private, offset, size & !CUT);
    if PRIVATE_BYTES.contains(&kind) {
        Value::Bytes(bytes.to_vec())
    } else {
        text(bytes, size & CUT != 0)
    }
}

/// A recorded string; one the system cut to fit is marked `<…>`, as
/// Apple's tools mark it.
fn text(bytes: &[u8], cut: bool) -> Value {
    let text = c_string(bytes);
    Value::Text(if cut { text + TRUNCATED } else { text })
}

/// The bytes a range names, cut to what is there.
fn slice(data: &[u8], offset: u16, size: u16) -> &[u8] {
    let start = usize::from(offset).min(data.len());
    let end = (start + usize::from(size)).min(data.len());
    &data[start..end]
}

/// A little-endian number of up to 8 bytes.
fn number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(8)
        .rev()
        .fold(0, |n, &b| n << 8 | u64::from(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_strings_and_private_values() {
        let mut data = vec![0x02, 4];
        data.extend_from_slice(&[0x00, 4, 0xff, 0xff, 0xff, 0xff]);
        data.extend_from_slice(&[0x22, 4, 0, 0, 4, 0]);
        data.extend_from_slice(&[0x21, 4, 0, 0, 3, 0]);
        data.extend_from_slice(&[0x01, 4, 3, 0, 2, 0]);
        data.extend_from_slice(b"abc\0");
        let private = b"xy\0\x05\x00";
        let read = read(&data, false, Some(private)).unwrap();
        let values: Vec<_> = read.items.into_iter().map(|i| i.value).collect();
        assert_eq!(
            values,
            vec![
                Value::Number {
                    bits: 0xffff_ffff,
                    size: 4
                },
                Value::Text("abc".into()),
                Value::Text("xy".into()),
                Value::Number { bits: 5, size: 2 },
            ]
        );
    }

    #[test]
    fn without_private_data_private_values_are_private() {
        let data = [0x02, 2, 0x21, 4, 0, 0, 3, 0, 0x41, 4, 0, 0, 0, 0];
        let read = read(&data, false, None).unwrap();
        assert!(read.items.iter().all(|i| i.value == Value::Private));
    }

    #[test]
    fn empty_strings_are_null_and_counts_are_counts() {
        let data = [0x02, 2, 0x12, 4, 9, 0, 0, 0, 0x40, 4, 0, 0, 0, 0];
        let read = read(&data, false, None).unwrap();
        assert_eq!(read.items[0].value, Value::Count(9));
        assert_eq!(read.items[1].value, Value::Null);
    }

    #[test]
    fn a_backtrace_by_signature() {
        let mut data = vec![0x02, 0];
        data.extend_from_slice(&[0x01, 0x00, 0x12, 1, 2, 0]);
        data.extend_from_slice(&[0xaa; 16]);
        data.extend_from_slice(&0x10u32.to_le_bytes());
        data.extend_from_slice(&0x20u32.to_le_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        let read = read(&data, false, None).unwrap();
        assert_eq!(read.backtrace.len(), 2);
        assert_eq!(read.backtrace[1].offset, 0x20);
        assert_eq!(read.backtrace[1].image, Uuid([0xaa; 16]));
    }
}
