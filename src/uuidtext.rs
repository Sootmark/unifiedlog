//! Uuidtext files (`uuidtext/XX/YYYY…`, named by an image's UUID): an
//! image's format strings and its path.
//!
//! A signature (`0x66778899`), a version, how many ranges there are, then
//! each range's start (the format string offset it begins at) and size,
//! then the ranges' strings one after another, and the image's path last.

use common::bytes::{Reader, Result};

use crate::text::{c_string_at, invalid};

/// A uuidtext file's signature.
const SIGNATURE: u32 = 0x6677_8899;

/// An image's format strings and path.
#[derive(Debug, Clone, Default)]
pub struct UuidText {
    /// Each range: the format string offset it begins at, its size.
    ranges: Vec<(u32, u32)>,
    /// The ranges' strings, then the image's path.
    strings: Vec<u8>,
}

/// Reads a uuidtext file.
pub fn parse(bytes: &[u8]) -> std::result::Result<UuidText, String> {
    read(&mut Reader::new(bytes)).map_err(|e| format!("uuidtext: {e}"))
}

fn read(r: &mut Reader) -> Result<UuidText> {
    if r.u32_le()? != SIGNATURE {
        return Err(invalid(0, "the uuidtext signature"));
    }
    r.skip(8)?; // major and minor version
    let count = r.u32_le()?;
    let mut ranges = Vec::new();
    for _ in 0..count {
        ranges.push((r.u32_le()?, r.u32_le()?));
    }
    Ok(UuidText {
        ranges,
        strings: r.bytes(r.remaining())?.to_vec(),
    })
}

impl UuidText {
    /// The format string at an offset, if a range holds it.
    pub fn format_string(&self, offset: u64) -> Option<String> {
        let mut start = 0usize;
        for &(range_start, size) in &self.ranges {
            let size = size as usize;
            if let Some(within) = offset.checked_sub(u64::from(range_start)) {
                if within < size as u64 {
                    return c_string_at(&self.strings, start.saturating_add(within as usize));
                }
            }
            start = start.saturating_add(size);
        }
        None
    }

    /// The image's path: the string after the ranges' strings.
    pub fn image_path(&self) -> Option<String> {
        let start = self
            .ranges
            .iter()
            .fold(0usize, |sum, &(_, size)| sum.saturating_add(size as usize));
        c_string_at(&self.strings, start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> Vec<u8> {
        let mut bytes = SIGNATURE.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[2, 0, 0, 0, 1, 0, 0, 0]);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0x100u32.to_le_bytes());
        bytes.extend_from_slice(&6u32.to_le_bytes());
        bytes.extend_from_slice(&0x200u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(b"a %d\0\0hi\0/usr/bin/true\0");
        bytes
    }

    #[test]
    fn finds_format_strings_and_the_path() {
        let text = parse(&file()).unwrap();
        assert_eq!(text.format_string(0x100).unwrap(), "a %d");
        assert_eq!(text.format_string(0x102).unwrap(), "%d");
        assert_eq!(text.format_string(0x200).unwrap(), "hi");
        assert!(text.format_string(0x106).is_none());
        assert!(text.format_string(0x50).is_none());
        assert_eq!(text.image_path().unwrap(), "/usr/bin/true");
    }

    #[test]
    fn rejects_other_files() {
        assert!(parse(b"hcsd").is_err());
        assert!(parse(&[]).is_err());
    }
}
