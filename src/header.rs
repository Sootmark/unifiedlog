//! The header chunk (0x1000) that starts a tracev3 file: the boot it
//! belongs to, the clock's timebase, the time zone, and the system.

use common::bytes::{Reader, Result};

use crate::text::c_string;
use crate::uuid::Uuid;

/// Sub-chunk: the system's build and hardware model.
const SYSTEM: u32 = 0x6101;
/// Sub-chunk: the boot and the logd process that wrote the file.
const GENERATION: u32 = 0x6102;
/// Sub-chunk: the time zone file.
const TIME_ZONE: u32 = 0x6103;

/// What a tracev3 file's header says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// Mach time to nanoseconds: multiply by the numerator, divide by the
    /// denominator (1/1 on Intel, 125/3 on Apple silicon).
    pub timebase: (u32, u32),
    /// The continuous time (Mach ticks since boot) when the file started.
    pub continuous_time: u64,
    /// The time zone's offset from UTC, in minutes west.
    pub bias_minutes: i32,
    /// Whether daylight saving time was in effect.
    pub daylight_savings: bool,
    /// The system's build (`20D91`).
    pub build_version: String,
    /// The hardware model (`MacBookPro16,1`).
    pub hardware_model: String,
    /// The boot the file's entries belong to.
    pub boot_uuid: Uuid,
    /// The logd process that wrote the file.
    pub logd_pid: u32,
    /// How that logd process ended.
    pub logd_exit_status: u32,
    /// The time zone file (`/var/db/timezone/zoneinfo/America/New_York`).
    pub timezone_path: String,
}

impl Header {
    /// The time zone's name: the last part of its path (`New_York`).
    #[must_use]
    pub fn timezone_name(&self) -> &str {
        self.timezone_path
            .rsplit('/')
            .next()
            .unwrap_or(&self.timezone_path)
    }
}

/// Reads a header chunk's data (after its 16-byte preamble).
pub fn parse(data: &[u8]) -> std::result::Result<Header, String> {
    read(&mut Reader::new(data)).map_err(|e| format!("header chunk: {e}"))
}

fn read(r: &mut Reader) -> Result<Header> {
    let mut header = Header {
        timebase: (r.u32_le()?, r.u32_le()?),
        continuous_time: r.u64_le()?,
        ..Header::default()
    };
    r.skip(12)?; // wall time and an unknown value
    header.bias_minutes = r.i32_le()?;
    header.daylight_savings = r.u32_le()? != 0;
    r.skip(4)?; // flags
    while r.remaining() >= 8 {
        let tag = r.u32_le()?;
        let size = r.u32_le()? as usize;
        let mut sub = r.sub(size.min(r.remaining()))?;
        read_sub_chunk(tag, &mut sub, &mut header)?;
    }
    Ok(header)
}

fn read_sub_chunk(tag: u32, r: &mut Reader, header: &mut Header) -> Result<()> {
    match tag {
        SYSTEM => {
            r.skip(8)?;
            header.build_version = c_string(r.bytes(16)?);
            header.hardware_model = c_string(r.bytes(32)?);
        }
        GENERATION => {
            header.boot_uuid = Uuid(r.array()?);
            header.logd_pid = r.u32_le()?;
            header.logd_exit_status = r.u32_le()?;
        }
        TIME_ZONE => header.timezone_path = c_string(r.bytes(r.remaining().min(48))?),
        // 0x6100 repeats the continuous time; others are unknown.
        _ => {}
    }
    Ok(())
}
