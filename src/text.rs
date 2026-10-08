//! Text helpers: C strings, Base64, and the reading errors' wording.

use common::bytes::{Error, ErrorKind};

/// The text up to the first NUL (or the end), with invalid UTF-8 replaced.
pub fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The C string at `offset` in `bytes`, if the offset is inside them.
pub fn c_string_at(bytes: &[u8], offset: usize) -> Option<String> {
    bytes.get(offset..).map(c_string)
}

/// The Base64 alphabet (RFC 4648, with padding).
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Bytes as Base64, the way data with no decoder is shown.
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b = [
            group[0],
            *group.get(1).unwrap_or(&0),
            *group.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= group.len() {
                out.push(char::from(BASE64[(n >> (18 - 6 * i) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A reading error for a value that is present but not valid.
pub fn invalid(offset: usize, expected: &'static str) -> Error {
    Error {
        offset,
        kind: ErrorKind::Invalid { expected },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_strings_stop_at_nul() {
        assert_eq!(c_string(b"abc\0def"), "abc");
        assert_eq!(c_string(b"abc"), "abc");
        assert_eq!(c_string_at(b"abc\0def\0", 4).unwrap(), "def");
        assert!(c_string_at(b"abc", 4).is_none());
    }

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
