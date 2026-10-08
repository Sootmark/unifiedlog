//! LZBITMAP decompression, Apple's compression for chunksets on newer
//! macOS (`ZBM` streams).
//!
//! A stream is `ZBM`, a flags byte, then chunks. Each chunk has a 3-byte
//! compressed size (its header included) and a 3-byte decompressed size;
//! a decompressed size of 0 ends the stream. A chunk whose compressed size
//! is its decompressed size plus the 6-byte header holds the bytes as they
//! are. Any other chunk has three 3-byte offsets (to its distances, its
//! bitmaps and its tokens), its literals from byte 15, and ends with a
//! 17-byte table of 10-bit entries (a bitmap and how many distance bytes
//! it reads).
//!
//! Tokens are 4-bit indexes into that table, read low nibble first.
//! Indexes 0 to 2 take their bitmap from the bitmap bytes and read 0, 1 or
//! 2 distance bytes. Each bitmap describes 8 output bytes, low bit first: a
//! set bit copies the next literal, a clear bit repeats the byte `distance`
//! back. Without the no-run-length flag, a token followed by 0xf repeats:
//! 4 times, plus each nibble after up to the first that is not 0xf.

/// The stream signature.
const MAGIC: &[u8; 3] = b"ZBM";
/// Flag: chunks hold up to 32 KiB (else 16 KiB).
const FLAG_LARGE: u8 = 0x1;
/// Flag: tokens are not run-length encoded.
const FLAG_NO_RUN_LENGTH: u8 = 0x4;
/// The flag values seen or expected.
const KNOWN_FLAGS: [u8; 4] = [0x8, 0x9, 0xc, 0xd];
/// A chunk's header: two 3-byte sizes.
const CHUNK_HEADER: usize = 6;
/// Where a compressed chunk's literals start.
const LITERALS_START: usize = 15;
/// The table of bitmaps at a compressed chunk's end.
const TABLE_SIZE: usize = 17;
/// The token that marks a run.
const RUN: u8 = 0xf;
/// The distance before any is read.
const FIRST_DISTANCE: usize = 8;

/// Decompresses an LZBITMAP stream, and gives how many bytes it took.
///
/// # Errors
/// What is wrong with the stream.
pub fn decompress(stream: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let flags = stream_flags(stream)?;
    let max_chunk = if flags & FLAG_LARGE == 0 {
        0x4000
    } else {
        0x8000
    };
    let run_length = flags & FLAG_NO_RUN_LENGTH == 0;
    let mut out = Vec::new();
    let mut at = MAGIC.len() + 1;
    loop {
        let compressed = u24(stream, at)?;
        let decompressed = u24(stream, at + 3)?;
        if decompressed == 0 {
            return Ok((out, at + CHUNK_HEADER));
        }
        if decompressed > max_chunk || compressed > decompressed + CHUNK_HEADER {
            return Err(format!(
                "LZBITMAP chunk sizes {compressed} and {decompressed} are not valid"
            ));
        }
        let chunk = stream
            .get(at..at + compressed)
            .ok_or_else(|| "LZBITMAP chunk runs past the data".to_owned())?;
        if compressed == decompressed + CHUNK_HEADER {
            out.extend_from_slice(&chunk[CHUNK_HEADER..]);
        } else {
            Chunk::new(chunk, run_length)?.decode(decompressed, &mut out)?;
        }
        at += compressed;
    }
}

/// The flags byte after the signature.
fn stream_flags(stream: &[u8]) -> Result<u8, String> {
    if !stream.starts_with(MAGIC) {
        return Err("LZBITMAP stream does not start with ZBM".to_owned());
    }
    let flags = *stream
        .get(MAGIC.len())
        .ok_or_else(|| "LZBITMAP stream ends after its signature".to_owned())?;
    if KNOWN_FLAGS.contains(&flags) {
        Ok(flags)
    } else {
        Err(format!("LZBITMAP flags {flags:#x} are not supported"))
    }
}

/// A 3-byte little-endian value.
fn u24(data: &[u8], at: usize) -> Result<usize, String> {
    match data.get(at..at + 3) {
        Some(b) => Ok(usize::from(b[0]) | usize::from(b[1]) << 8 | usize::from(b[2]) << 16),
        None => Err("LZBITMAP data ends inside a size or offset".to_owned()),
    }
}

/// A compressed chunk being decoded: where each of its streams is at.
struct Chunk<'a> {
    data: &'a [u8],
    literal: usize,
    distance_at: usize,
    bitmap_at: usize,
    tokens: Tokens<'a>,
    table: [(u8, u8); 16],
    run_length: bool,
}

impl<'a> Chunk<'a> {
    fn new(data: &'a [u8], run_length: bool) -> Result<Self, String> {
        let distance_at = u24(data, CHUNK_HEADER)?;
        let bitmap_at = u24(data, CHUNK_HEADER + 3)?;
        let token_at = u24(data, CHUNK_HEADER + 6)?;
        let table_at = data
            .len()
            .checked_sub(TABLE_SIZE)
            .ok_or_else(|| "LZBITMAP chunk is smaller than its table".to_owned())?;
        if distance_at < LITERALS_START
            || distance_at > bitmap_at
            || bitmap_at > token_at
            || token_at > table_at
        {
            return Err("LZBITMAP chunk offsets are out of order".to_owned());
        }
        Ok(Self {
            data,
            literal: LITERALS_START,
            distance_at,
            bitmap_at,
            tokens: Tokens::new(&data[token_at..table_at]),
            table: bitmap_table(&data[table_at..], run_length),
            run_length,
        })
    }

    /// Writes `remaining` bytes to `out`.
    fn decode(mut self, mut remaining: usize, out: &mut Vec<u8>) -> Result<(), String> {
        let mut distance = FIRST_DISTANCE;
        while remaining > 0 {
            let index = self.tokens.next().ok_or_else(too_few_tokens)?;
            let repeat = self.repeat(index, remaining)?;
            for _ in 0..repeat {
                let (bitmap, distance_bytes) = self.entry(index)?;
                if let Some(read) = self.distance(distance_bytes)? {
                    distance = read;
                }
                remaining = self.expand(bitmap, distance, remaining, out)?;
                if remaining == 0 {
                    break;
                }
            }
        }
        Ok(())
    }

    /// How many times a token applies.
    fn repeat(&mut self, index: u8, remaining: usize) -> Result<usize, String> {
        if !self.run_length {
            return Ok(1);
        }
        if index == RUN {
            return Err("LZBITMAP run marker where a token belongs".to_owned());
        }
        if remaining <= 8 || self.tokens.peek() != Some(RUN) {
            return Ok(1);
        }
        self.tokens.next();
        let mut total = 4;
        loop {
            let nibble = self.tokens.next().ok_or_else(too_few_tokens)?;
            total += usize::from(nibble);
            if nibble != RUN {
                return Ok(total);
            }
        }
    }

    /// A token's bitmap and distance byte count.
    fn entry(&mut self, index: u8) -> Result<(u8, u8), String> {
        let (bitmap, distance_bytes) = self.table[usize::from(index & 0xf)];
        if index >= 3 {
            return Ok((bitmap, distance_bytes));
        }
        let bitmap = self.byte(self.bitmap_at)?;
        self.bitmap_at += 1;
        Ok((bitmap, distance_bytes))
    }

    /// A new distance, when the entry reads one.
    fn distance(&mut self, bytes: u8) -> Result<Option<usize>, String> {
        let distance = match bytes {
            0 => return Ok(None),
            1 => usize::from(self.byte(self.distance_at)?),
            2 => usize::from(u16::from_le_bytes([
                self.byte(self.distance_at)?,
                self.byte(self.distance_at + 1)?,
            ])),
            _ => return Err("LZBITMAP distance size is not valid".to_owned()),
        };
        self.distance_at += usize::from(bytes);
        Ok(Some(distance))
    }

    /// Writes up to 8 bytes as a bitmap says, and gives what remains.
    fn expand(
        &mut self,
        mut bitmap: u8,
        distance: usize,
        mut remaining: usize,
        out: &mut Vec<u8>,
    ) -> Result<usize, String> {
        for _ in 0..8 {
            let byte = if bitmap & 1 == 0 {
                back_reference(out, distance)?
            } else {
                let literal = self.byte(self.literal)?;
                self.literal += 1;
                literal
            };
            out.push(byte);
            bitmap >>= 1;
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }
        Ok(remaining)
    }

    fn byte(&self, at: usize) -> Result<u8, String> {
        self.data
            .get(at)
            .copied()
            .ok_or_else(|| "LZBITMAP chunk ends early".to_owned())
    }
}

fn too_few_tokens() -> String {
    "LZBITMAP chunk runs out of tokens".to_owned()
}

/// The byte `distance` back in the output.
fn back_reference(out: &[u8], distance: usize) -> Result<u8, String> {
    out.len()
        .checked_sub(distance)
        .filter(|_| distance != 0)
        .map(|at| out[at])
        .ok_or_else(|| format!("LZBITMAP distance {distance} is outside the output"))
}

/// The token table: three entries that read their bitmap, then the
/// chunk's 10-bit entries (12 with run-length tokens, else 13).
fn bitmap_table(table: &[u8], run_length: bool) -> [(u8, u8); 16] {
    let mut entries = [(0, 0); 16];
    entries[1] = (0, 1);
    entries[2] = (0, 2);
    let count = if run_length { 12 } else { 13 };
    for i in 0..count {
        let bit = i * 10;
        let pair = u16::from_le_bytes([table[bit / 8], table[bit / 8 + 1]]) >> (bit % 8);
        entries[3 + i] = ((pair & 0xff) as u8, ((pair >> 8) & 3) as u8);
    }
    entries
}

/// The 4-bit tokens, low nibble first.
struct Tokens<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Tokens<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn peek(&self) -> Option<u8> {
        let byte = self.bytes.get(self.at / 2)?;
        Some(if self.at % 2 == 0 {
            byte & 0xf
        } else {
            byte >> 4
        })
    }
}

impl Iterator for Tokens<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let nibble = self.peek()?;
        self.at += 1;
        Some(nibble)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream with one chunk stored as is.
    #[test]
    fn stored_chunk() {
        let mut stream = b"ZBM\x09".to_vec();
        stream.extend_from_slice(&[11, 0, 0, 5, 0, 0]);
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(&[6, 0, 0, 0, 0, 0]);
        let (out, used) = decompress(&stream).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(used, stream.len());
    }

    /// A compressed chunk of eight tokens 1 (each reads a bitmap byte and a
    /// distance byte): the first bitmap takes the four literals and repeats
    /// them, the others repeat what is 4 back.
    #[test]
    fn compressed_chunk_with_back_references() {
        let mut chunk = vec![0u8; 6];
        chunk.extend_from_slice(&[19, 0, 0, 27, 0, 0, 35, 0, 0]);
        chunk.extend_from_slice(b"abcd");
        chunk.extend_from_slice(&[4; 8]);
        chunk.extend_from_slice(&[0x0f, 0, 0, 0, 0, 0, 0, 0]);
        chunk.extend_from_slice(&[0x11; 4]);
        chunk.extend_from_slice(&[0; TABLE_SIZE]);
        chunk[0] = chunk.len() as u8;
        chunk[3] = 64;
        let mut stream = b"ZBM\x0c".to_vec();
        stream.extend_from_slice(&chunk);
        stream.extend_from_slice(&[6, 0, 0, 0, 0, 0]);
        let (out, used) = decompress(&stream).unwrap();
        assert_eq!(out, b"abcd".repeat(16));
        assert_eq!(used, stream.len());
    }

    #[test]
    fn damage_is_an_error() {
        assert!(decompress(b"").is_err());
        assert!(decompress(b"ZBM\x01").is_err());
        assert!(decompress(b"ZBM\x09\x40\x00\x00\x10\x00\x00").is_err());
        assert!(decompress(b"ZBM\x09\x20\x00").is_err());
    }
}
