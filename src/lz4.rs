//! LZ4 block decompression, as chunksets store their contents (`bv41`).
//!
//! A block is a run of sequences. Each starts with a token byte: its high
//! nibble is how many literal bytes follow, its low nibble how long the
//! match after them is, less 4. A nibble of 15 continues in the bytes that
//! follow (each adds its value, until one is below 255). After the literals
//! come a two-byte little-endian offset back into the output and the match.
//! The last sequence has literals only.

/// The shortest match a sequence can copy.
const MIN_MATCH: usize = 4;

/// Decompresses an LZ4 block that should give `expected` bytes.
///
/// # Errors
/// What is wrong with the block: it ends early, a match points before the
/// start of the output, or it gives more or fewer bytes than expected.
pub fn decompress(block: &[u8], expected: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(expected.min(block.len().saturating_mul(255)));
    let mut input = Input { block, at: 0 };
    while !input.is_done() {
        let token = input.byte()?;
        let literals = input.length(usize::from(token >> 4))?;
        out.extend_from_slice(input.take(literals)?);
        guard_size(out.len(), expected)?;
        if input.is_done() {
            break;
        }
        let offset = usize::from(u16::from_le_bytes([input.byte()?, input.byte()?]));
        let length = input.length(usize::from(token & 0x0f))? + MIN_MATCH;
        copy_match(&mut out, offset, length)?;
        guard_size(out.len(), expected)?;
    }
    if out.len() == expected {
        Ok(out)
    } else {
        Err(format!(
            "LZ4 block gave {} bytes, {expected} expected",
            out.len()
        ))
    }
}

/// Fails once the output outgrows what the block should give.
fn guard_size(size: usize, expected: usize) -> Result<(), String> {
    if size > expected {
        return Err(format!("LZ4 block gives more than {expected} bytes"));
    }
    Ok(())
}

/// Copies `length` bytes from `offset` back in the output, byte by byte:
/// a match may overlap the bytes it is writing.
fn copy_match(out: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), String> {
    if offset == 0 || offset > out.len() {
        return Err(format!(
            "LZ4 match offset {offset} is outside the {} bytes written",
            out.len()
        ));
    }
    let start = out.len() - offset;
    for at in start..start + length {
        let byte = out[at];
        out.push(byte);
    }
    Ok(())
}

/// The compressed bytes and the reading position.
struct Input<'a> {
    block: &'a [u8],
    at: usize,
}

impl<'a> Input<'a> {
    fn is_done(&self) -> bool {
        self.at >= self.block.len()
    }

    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .block
            .get(self.at)
            .ok_or_else(|| "LZ4 block ends early".to_owned())?;
        self.at += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(count)
            .filter(|&end| end <= self.block.len())
            .ok_or_else(|| "LZ4 literals run past the block".to_owned())?;
        let bytes = &self.block[self.at..end];
        self.at = end;
        Ok(bytes)
    }

    /// A nibble's length, with its continuation bytes when it is 15.
    fn length(&mut self, nibble: usize) -> Result<usize, String> {
        let mut length = nibble;
        if nibble == 15 {
            loop {
                let more = self.byte()?;
                length = length
                    .checked_add(usize::from(more))
                    .ok_or_else(|| "LZ4 length overflows".to_owned())?;
                if more != 255 {
                    break;
                }
            }
        }
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_only() {
        assert_eq!(decompress(b"\x50hello", 5).unwrap(), b"hello");
    }

    #[test]
    fn overlapping_match_repeats_bytes() {
        // "ab", then copy 6 bytes from 2 back, then literal "!".
        let block = [0x22, b'a', b'b', 0x02, 0x00, 0x10, b'!'];
        assert_eq!(decompress(&block, 9).unwrap(), b"abababab!");
    }

    #[test]
    fn long_literal_length_continues() {
        let mut block = vec![0xf0, 0x05];
        block.extend(std::iter::repeat(b'x').take(20));
        assert_eq!(decompress(&block, 20).unwrap(), vec![b'x'; 20]);
    }

    #[test]
    fn damage_is_an_error() {
        assert!(decompress(&[0x10], 1).is_err());
        assert!(decompress(&[0x11, b'a', 0x05, 0x00], 10).is_err());
        assert!(decompress(b"\x50hello", 4).is_err());
        assert!(decompress(b"\x50hello", 6).is_err());
    }
}
