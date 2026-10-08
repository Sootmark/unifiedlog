//! Binary property lists (`bplist00`), as statedumps hold them, written
//! as JSON.
//!
//! A binary property list is objects, an offset table and a 32-byte
//! trailer (the offset and reference sizes, the object count, the top
//! object and where the offset table is). Each object starts with a marker
//! byte: its high nibble the type (0 null and booleans, 1 integer, 2 real,
//! 3 date, 4 data, 5 ASCII string, 6 UTF-16 string, 8 UID, 0xa array,
//! 0xc set, 0xd dictionary), its low nibble a size (0xf: an integer object
//! with the size follows). Containers hold references: indexes into the
//! offset table.
//!
//! The JSON keeps dictionaries' keys in their order; data is an array of
//! byte values and dates are ISO 8601 strings.

use std::cell::Cell;
use std::fmt::Write;

use common::time::civil_from_days;

use crate::decoders::json_string;

/// The header.
const MAGIC: &[u8] = b"bplist00";
/// The trailer's size.
const TRAILER: usize = 32;
/// How deep containers may nest.
const MAX_DEPTH: usize = 64;
/// How many objects one list may write (references can repeat objects).
const MAX_OBJECTS: u32 = 1_000_000;
/// Seconds from 1970 to 2001, where property list dates count from.
const COCOA_EPOCH: i64 = 978_307_200;

/// A binary property list as JSON, or why it could not be read.
pub fn to_json(data: &[u8]) -> Result<String, String> {
    let plist =
        Plist::new(data).ok_or_else(|| "binary property list trailer is not valid".to_owned())?;
    let mut out = String::new();
    plist
        .write(plist.top, 0, &mut out)
        .ok_or_else(|| "binary property list object is not valid".to_owned())?;
    Ok(out)
}

/// A binary property list's layout.
struct Plist<'a> {
    data: &'a [u8],
    offset_size: usize,
    ref_size: usize,
    count: u64,
    top: u64,
    table: usize,
    written: Cell<u32>,
}

impl<'a> Plist<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if !data.starts_with(MAGIC) || data.len() < MAGIC.len() + TRAILER {
            return None;
        }
        let trailer = &data[data.len() - TRAILER..];
        Some(Self {
            data,
            offset_size: usize::from(trailer[6]),
            ref_size: usize::from(trailer[7]),
            count: be(&trailer[8..16]),
            top: be(&trailer[16..24]),
            table: usize::try_from(be(&trailer[24..32])).ok()?,
            written: Cell::new(0),
        })
    }

    /// Where object `index` starts.
    fn offset(&self, index: u64) -> Option<usize> {
        if index >= self.count {
            return None;
        }
        let at = self
            .table
            .checked_add(usize::try_from(index).ok()?.checked_mul(self.offset_size)?)?;
        usize::try_from(be(self.bytes(at, self.offset_size)?)).ok()
    }

    /// `length` bytes at `at`, if they are there.
    fn bytes(&self, at: usize, length: usize) -> Option<&'a [u8]> {
        self.data.get(at..at.checked_add(length)?)
    }

    /// Writes object `index` as JSON.
    fn write(&self, index: u64, depth: usize, out: &mut String) -> Option<()> {
        self.written.set(self.written.get() + 1);
        if depth > MAX_DEPTH || self.written.get() > MAX_OBJECTS {
            return None;
        }
        let marker_at = self.offset(index)?;
        let marker = *self.data.get(marker_at)?;
        let at = marker_at + 1;
        let (kind, size) = (marker >> 4, marker & 0xf);
        match kind {
            0x0 => out.push_str(match size {
                0x8 => "false",
                0x9 => "true",
                _ => "null",
            }),
            0x1 => {
                let _ = write!(out, "{}", integer(self.bytes(at, 1 << size.min(4))?));
            }
            0x2 => {
                out.push_str(&real(real_value(self.bytes(at, 1 << size.min(3))?)?));
            }
            0x3 => out.push_str(&json_string(&date(real_value(self.bytes(at, 8)?)?))),
            0x8 => {
                let _ = write!(out, "{}", be(self.bytes(at, usize::from(size) + 1)?));
            }
            _ => self.write_sized(kind, size, at, depth, out)?,
        }
        Some(())
    }

    /// Objects with a length: data, strings and containers (`at` is after
    /// the marker).
    fn write_sized(
        &self,
        kind: u8,
        size: u8,
        at: usize,
        depth: usize,
        out: &mut String,
    ) -> Option<()> {
        let (length, start) = self.length(size, at)?;
        match kind {
            0x4 => {
                let bytes = self.bytes(start, length)?;
                let values: Vec<String> = bytes.iter().map(u8::to_string).collect();
                let _ = write!(out, "[{}]", values.join(","));
            }
            0x5 => {
                let bytes = self.bytes(start, length)?;
                out.push_str(&json_string(&String::from_utf8_lossy(bytes)));
            }
            0x6 => {
                let bytes = self.bytes(start, length.checked_mul(2)?)?;
                let units = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]));
                let text: String = char::decode_utf16(units)
                    .map(|c| c.unwrap_or('\u{fffd}'))
                    .collect();
                out.push_str(&json_string(&text));
            }
            0xa | 0xc => self.write_array(start, length, depth, out)?,
            0xd => self.write_dictionary(start, length, depth, out)?,
            _ => return None,
        }
        Some(())
    }

    /// An object's length and where its contents start: the size nibble,
    /// or the integer object after the marker (`at`).
    fn length(&self, size: u8, at: usize) -> Option<(usize, usize)> {
        if size != 0xf {
            return Some((usize::from(size), at));
        }
        let marker = *self.data.get(at)?;
        if marker >> 4 != 0x1 {
            return None;
        }
        let width = 1usize << (marker & 0xf).min(3);
        let length = usize::try_from(be(self.bytes(at + 1, width)?)).ok()?;
        Some((length, at + 1 + width))
    }

    fn reference(&self, at: usize) -> Option<u64> {
        Some(be(self.bytes(at, self.ref_size)?))
    }

    fn write_array(
        &self,
        start: usize,
        length: usize,
        depth: usize,
        out: &mut String,
    ) -> Option<()> {
        out.push('[');
        for i in 0..length {
            if i > 0 {
                out.push(',');
            }
            let reference = self.reference(start.checked_add(i.checked_mul(self.ref_size)?)?)?;
            self.write(reference, depth + 1, out)?;
        }
        out.push(']');
        Some(())
    }

    fn write_dictionary(
        &self,
        start: usize,
        length: usize,
        depth: usize,
        out: &mut String,
    ) -> Option<()> {
        let values = start.checked_add(length.checked_mul(self.ref_size)?)?;
        out.push('{');
        for i in 0..length {
            if i > 0 {
                out.push(',');
            }
            let step = i.checked_mul(self.ref_size)?;
            self.write(self.reference(start.checked_add(step)?)?, depth + 1, out)?;
            out.push(':');
            self.write(self.reference(values.checked_add(step)?)?, depth + 1, out)?;
        }
        out.push('}');
        Some(())
    }
}

/// A big-endian unsigned number of up to 8 bytes (more are cut).
fn be(bytes: &[u8]) -> u64 {
    bytes.iter().take(8).fold(0, |n, &b| n << 8 | u64::from(b))
}

/// An integer: 1, 2 and 4 bytes are unsigned, 8 signed, 16 the low 8.
fn integer(bytes: &[u8]) -> i128 {
    match bytes.len() {
        8 => i128::from(be(bytes) as i64),
        16 => i128::from(be(&bytes[8..]) as i64),
        _ => i128::from(be(bytes)),
    }
}

fn real_value(bytes: &[u8]) -> Option<f64> {
    match bytes.len() {
        4 => Some(f64::from(f32::from_bits(be(bytes) as u32))),
        8 => Some(f64::from_bits(be(bytes))),
        _ => None,
    }
}

/// A real as JSON: shortest form, a fraction always shown, `null` when not
/// a number.
fn real(value: f64) -> String {
    if value.is_finite() {
        format!("{value:?}")
    } else {
        "null".to_owned()
    }
}

/// A date (seconds since 2001) as ISO 8601 UTC.
fn date(seconds: f64) -> String {
    let unix = (seconds.floor() as i64).saturating_add(COCOA_EPOCH);
    let (year, month, day) = civil_from_days(unix.div_euclid(86_400));
    let in_day = unix.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / 3600,
        in_day / 60 % 60,
        in_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `{"a": true, "b": [1, "x"], "c": 1.5}` as written by hand.
    fn sample() -> Vec<u8> {
        let mut data = MAGIC.to_vec();
        let mut offsets = Vec::new();
        let mut object = |data: &mut Vec<u8>, bytes: &[u8]| {
            offsets.push(data.len() as u8);
            data.extend_from_slice(bytes);
        };
        object(&mut data, &[0xd3, 1, 2, 3, 4, 5, 6]); // 0: dict a, b, c -> 4, 5, 6
        object(&mut data, b"\x51a"); // 1
        object(&mut data, b"\x51b"); // 2
        object(&mut data, b"\x51c"); // 3
        object(&mut data, &[0x09]); // 4: true
        object(&mut data, &[0xa2, 7, 8]); // 5: array
        object(&mut data, &[0x23, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]); // 6: 1.5
        object(&mut data, &[0x10, 1]); // 7: 1
        object(&mut data, b"\x51x"); // 8
        let table = data.len() as u64;
        data.extend_from_slice(&offsets);
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&[1, 1]);
        data.extend_from_slice(&9u64.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&table.to_be_bytes());
        data
    }

    #[test]
    fn writes_json() {
        assert_eq!(
            to_json(&sample()).unwrap(),
            r#"{"a":true,"b":[1,"x"],"c":1.5}"#
        );
    }

    #[test]
    fn damage_is_an_error() {
        let mut data = sample();
        let len = data.len();
        data[len - 1] = 0xff;
        assert!(to_json(&data).is_err());
        assert!(to_json(b"bplist00").is_err());
        assert_eq!(date(0.0), "2001-01-01T00:00:00Z");
    }
}
