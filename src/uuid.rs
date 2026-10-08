//! UUIDs: of boots, images (executables and libraries) and shared caches.

use std::fmt::{self, Write};

/// A UUID, in the byte order the log files store it (big-endian).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// The all-zero UUID, which the catalog uses for "no image".
    pub const NIL: Self = Self([0; 16]);

    /// Whether this is the all-zero UUID.
    #[must_use]
    pub fn is_nil(&self) -> bool {
        *self == Self::NIL
    }

    /// The 32 uppercase hex digits, without dashes: how `uuidtext/` names
    /// its files.
    #[must_use]
    pub fn hex(&self) -> String {
        self.0.iter().fold(String::with_capacity(32), |mut hex, b| {
            let _ = write!(hex, "{b:02X}");
            hex
        })
    }

    /// A UUID from 16 bytes.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

/// `8-4-4-4-12` uppercase hex digits, as Apple's tools show UUIDs.
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_with_and_without_dashes() {
        let uuid = Uuid([
            0x11, 0x5c, 0x75, 0xbd, 0xe7, 0x7e, 0x40, 0xc2, 0xba, 0xcf, 0x46, 0xcc, 0xb6, 0x32,
            0xda, 0x2c,
        ]);
        assert_eq!(uuid.to_string(), "115C75BD-E77E-40C2-BACF-46CCB632DA2C");
        assert_eq!(uuid.hex(), "115C75BDE77E40C2BACF46CCB632DA2C");
        assert!(!uuid.is_nil());
        assert!(Uuid::NIL.is_nil());
    }
}
