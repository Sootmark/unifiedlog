//! Chunks and chunksets.
//!
//! A tracev3 file is a run of chunks, each a 16-byte preamble (a tag, a
//! sub-tag and the data's size) and its data, padded to 8 bytes. The
//! chunkset chunk (0x600d) holds more chunks, compressed: LZ4 blocks
//! (`bv41`, its decompressed and compressed sizes, the block), stored
//! blocks (`bv4-`, the size, the bytes) and an end mark (`bv4$`); or, on
//! newer macOS, an LZBITMAP stream (`ZBM`).

use crate::{lz4, lzbitmap};

/// A chunk's preamble: tag, sub-tag, data size.
pub const PREAMBLE_SIZE: usize = 16;
/// An LZ4-compressed block.
const LZ4_BLOCK: &[u8; 4] = b"bv41";
/// A block stored as is.
const STORED_BLOCK: &[u8; 4] = b"bv4-";
/// The end of the blocks.
const END_MARK: &[u8; 4] = b"bv4$";
/// An LZBITMAP stream.
const LZBITMAP: &[u8; 3] = b"ZBM";

/// A chunk: its tag and its data (after the preamble).
#[derive(Debug, Clone, Copy)]
pub struct Chunk<'a> {
    /// What it is (0x1000 header, 0x600b catalog, 0x600d chunkset, 0x6001
    /// firehose, 0x6002 oversize, 0x6003 statedump, 0x6004 simpledump).
    pub tag: u32,
    /// Its data, after the preamble.
    pub data: &'a [u8],
}

/// The chunks of a tracev3 file, in order, each 8-byte aligned. Reading
/// stops at the first chunk that does not fit; that is reported.
pub fn chunks<'a>(data: &'a [u8], problems: &mut Vec<String>) -> Vec<Chunk<'a>> {
    read_chunks(data, Gap::Aligned, problems)
}

/// The chunks of a decompressed chunkset, in order. Zero bytes between
/// them are skipped: a chunk's size need not cover all of its padding.
pub fn chunkset_chunks<'a>(data: &'a [u8], problems: &mut Vec<String>) -> Vec<Chunk<'a>> {
    read_chunks(data, Gap::Zeros, problems)
}

/// What separates chunks.
#[derive(Clone, Copy)]
enum Gap {
    /// Padding to 8 bytes.
    Aligned,
    /// Any run of zero bytes.
    Zeros,
}

fn read_chunks<'a>(data: &'a [u8], gap: Gap, problems: &mut Vec<String>) -> Vec<Chunk<'a>> {
    let mut found = Vec::new();
    let mut at = 0;
    while data.len().saturating_sub(at) >= PREAMBLE_SIZE {
        let tag = u32_at(data, at);
        let size = u64::from(u32_at(data, at + 8)) | u64::from(u32_at(data, at + 12)) << 32;
        let start = at + PREAMBLE_SIZE;
        let Some(end) = usize::try_from(size)
            .ok()
            .and_then(|size| start.checked_add(size))
            .filter(|&end| end <= data.len())
        else {
            problems.push(format!(
                "chunk {tag:#x} at offset {at} claims {size} bytes, past the end"
            ));
            break;
        };
        found.push(Chunk {
            tag,
            data: &data[start..end],
        });
        at = match gap {
            Gap::Aligned => end + padding(end, 8),
            Gap::Zeros => end + data[end..].iter().take_while(|&&b| b == 0).count(),
        };
    }
    found
}

/// The padding after `size` bytes to the next multiple of `alignment`.
pub fn padding(size: usize, alignment: usize) -> usize {
    (alignment - size % alignment) % alignment
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// Decompresses a chunkset chunk's data (after its preamble).
///
/// # Errors
/// What is wrong with the compressed data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.starts_with(LZBITMAP) {
        return lzbitmap::decompress(data).map(|(out, _)| out);
    }
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(signature) = data.get(at..at + 4) {
        let block = if signature == LZ4_BLOCK {
            lz4_block(data, at)?
        } else if signature == STORED_BLOCK {
            stored_block(data, at)?
        } else if signature == END_MARK {
            return Ok(out);
        } else {
            return Err(format!(
                "chunkset block signature {signature:02x?} is unknown"
            ));
        };
        out.extend_from_slice(&block.bytes);
        at = block.end;
    }
    if out.is_empty() {
        Err("chunkset has no blocks".to_owned())
    } else {
        Ok(out)
    }
}

/// A decompressed block, and where the next one starts.
struct Block {
    bytes: Vec<u8>,
    end: usize,
}

fn lz4_block(data: &[u8], at: usize) -> Result<Block, String> {
    let decompressed = size_at(data, at + 4)?;
    let compressed = size_at(data, at + 8)?;
    let start = at + 12;
    let block = slice(data, start, compressed)?;
    Ok(Block {
        bytes: lz4::decompress(block, decompressed)?,
        end: start + compressed,
    })
}

fn stored_block(data: &[u8], at: usize) -> Result<Block, String> {
    let size = size_at(data, at + 4)?;
    let start = at + 8;
    Ok(Block {
        bytes: slice(data, start, size)?.to_vec(),
        end: start + size,
    })
}

fn size_at(data: &[u8], at: usize) -> Result<usize, String> {
    let bytes = slice(data, at, 4)?;
    Ok(u32_at(bytes, 0) as usize)
}

fn slice(data: &[u8], start: usize, size: usize) -> Result<&[u8], String> {
    start
        .checked_add(size)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| "chunkset block runs past the chunk".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_are_padded_to_eight_bytes() {
        let mut data = vec![];
        data.extend_from_slice(&0x6001u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&3u64.to_le_bytes());
        data.extend_from_slice(b"abc\0\0\0\0\0");
        data.extend_from_slice(&0x6002u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(b"de");
        let mut problems = vec![];
        let found = chunks(&data, &mut problems);
        assert_eq!(found.len(), 2);
        assert_eq!((found[0].tag, found[0].data), (0x6001, &b"abc"[..]));
        assert_eq!((found[1].tag, found[1].data), (0x6002, &b"de"[..]));
        assert!(problems.is_empty());
    }

    #[test]
    fn a_chunk_past_the_end_is_reported() {
        let mut data = 0x6001u64.to_le_bytes().to_vec();
        data.extend_from_slice(&100u64.to_le_bytes());
        let mut problems = vec![];
        assert!(chunks(&data, &mut problems).is_empty());
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn blocks_of_both_kinds() {
        let mut data = b"bv41".to_vec();
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&6u32.to_le_bytes());
        data.extend_from_slice(b"\x50hello");
        data.extend_from_slice(b"bv4-");
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(b"abc");
        data.extend_from_slice(b"bv4$");
        assert_eq!(decompress(&data).unwrap(), b"helloabc");
        assert!(decompress(b"bv42").is_err());
        assert!(decompress(b"bv41\x05\0\0\0\x09\0\0\0\x50he").is_err());
    }
}
