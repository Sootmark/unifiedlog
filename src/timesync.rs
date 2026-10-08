//! Timesync files (`timesync/*.timesync`): what turns an entry's
//! continuous time into a wall-clock time.
//!
//! Entries are timed in Mach continuous time: ticks since their boot. A
//! timesync file holds boot records (`0xbbb0`: the boot's UUID, the
//! timebase and the wall time at boot) and sync records (`Ts`: a
//! continuous time and the wall time it was, in nanoseconds since 1970),
//! each sync record belonging to the boot record before it. An entry's
//! time is the wall time of the last sync record at or before it, plus the
//! ticks since then converted with the timebase.

use std::collections::HashMap;

use common::bytes::{Reader, Result};

use crate::text::invalid;
use crate::uuid::Uuid;

/// A boot record's signature.
const BOOT_SIGNATURE: u16 = 0xbbb0;
/// A sync record's signature (`Ts`, a space and a NUL).
const SYNC_SIGNATURE: u32 = 0x0020_7354;

/// The boots the timesync files describe, by boot UUID.
#[derive(Debug, Clone, Default)]
pub struct Timesync {
    boots: HashMap<Uuid, Boot>,
}

/// A boot: its timebase, when it happened, and its sync records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Boot {
    /// Mach time to nanoseconds: multiply by the first, divide by the
    /// second.
    pub timebase: (u32, u32),
    /// The wall time at boot (nanoseconds since 1970, UTC).
    pub boot_time: i64,
    /// The time zone's offset at boot, in minutes west.
    pub bias_minutes: i32,
    /// Whether daylight saving time was in effect at boot.
    pub daylight_savings: bool,
    /// The sync records, by continuous time.
    pub records: Vec<SyncRecord>,
}

/// A continuous time and the wall time it was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncRecord {
    /// The continuous time (Mach ticks since boot).
    pub continuous_time: u64,
    /// The wall time (nanoseconds since 1970, UTC).
    pub wall_time: i64,
    /// The time zone's offset, in minutes west.
    pub bias_minutes: i32,
    /// Whether daylight saving time was in effect.
    pub daylight_savings: bool,
}

impl Timesync {
    /// Adds a timesync file's records. Records of a boot already known
    /// (a long-running system writes several files) are merged into it.
    /// What could not be read is returned.
    pub fn add(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut problems = Vec::new();
        if let Err(e) = self.read(&mut Reader::new(bytes)) {
            problems.push(format!("timesync: {e}"));
        }
        for boot in self.boots.values_mut() {
            boot.sort_records();
        }
        problems
    }

    fn read(&mut self, r: &mut Reader) -> Result<()> {
        let mut current = None;
        while r.remaining() > 0 {
            if next_is_sync(r) {
                let record = read_sync(r)?;
                let uuid = current.ok_or_else(|| invalid(r.offset(), "a boot record first"))?;
                self.boots.entry(uuid).or_default().records.push(record);
            } else {
                let (uuid, boot) = read_boot(r)?;
                self.boots.entry(uuid).or_insert(boot);
                current = Some(uuid);
            }
        }
        Ok(())
    }

    /// A boot, by UUID.
    #[must_use]
    pub fn boot(&self, uuid: Uuid) -> Option<&Boot> {
        self.boots.get(&uuid)
    }

    /// The wall time (nanoseconds since 1970, UTC) of a continuous time in
    /// a boot. `from_boot` says whether the boot's own time may serve as
    /// the starting point (it does for firehose entries whose chunk starts
    /// at continuous time 0).
    #[must_use]
    pub fn unix_nanos(&self, boot: Uuid, continuous_time: u64, from_boot: bool) -> Option<i64> {
        self.boots
            .get(&boot)?
            .unix_nanos(continuous_time, from_boot)
    }
}

impl Boot {
    /// The wall time of a continuous time: from the last sync record at or
    /// before it; else from the boot time when `from_boot`; else from the
    /// first sync record.
    #[must_use]
    pub fn unix_nanos(&self, continuous_time: u64, from_boot: bool) -> Option<i64> {
        let after = self
            .records
            .partition_point(|r| r.continuous_time <= continuous_time);
        let (base_ticks, base_wall) = match after.checked_sub(1) {
            Some(last) => (
                self.records[last].continuous_time,
                self.records[last].wall_time,
            ),
            None if from_boot => (0, self.boot_time),
            None => {
                let first = self.records.first()?;
                (first.continuous_time, first.wall_time)
            }
        };
        let ticks = i128::from(continuous_time) - i128::from(base_ticks);
        let (numerator, denominator) = self.timebase;
        let nanos = ticks * i128::from(numerator) / i128::from(denominator.max(1));
        i64::try_from(i128::from(base_wall) + nanos).ok()
    }

    /// Sorts the sync records by continuous time (a stable sort: records
    /// of equal time keep their file order).
    fn sort_records(&mut self) {
        self.records.sort_by_key(|r| r.continuous_time);
    }
}

fn next_is_sync(r: &Reader) -> bool {
    r.peek(4)
        .is_ok_and(|bytes| bytes == SYNC_SIGNATURE.to_le_bytes())
}

fn read_boot(r: &mut Reader) -> Result<(Uuid, Boot)> {
    let start = r.offset();
    if r.u16_le()? != BOOT_SIGNATURE {
        return Err(invalid(start, "a timesync boot or sync record"));
    }
    let size = usize::from(r.u16_le()?);
    r.skip(4)?;
    let uuid = Uuid(r.array()?);
    let boot = Boot {
        timebase: (r.u32_le()?, r.u32_le()?),
        boot_time: r.i64_le()?,
        bias_minutes: r.i32_le()?,
        daylight_savings: r.u32_le()? != 0,
        records: Vec::new(),
    };
    let read = r.offset() - start;
    r.skip(size.saturating_sub(read))?;
    Ok((uuid, boot))
}

fn read_sync(r: &mut Reader) -> Result<SyncRecord> {
    r.skip(8)?; // signature and flags
    Ok(SyncRecord {
        continuous_time: r.u64_le()?,
        wall_time: r.i64_le()?,
        bias_minutes: r.i32_le()?,
        daylight_savings: r.u32_le()? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: Uuid = Uuid([0x11; 16]);

    fn boot_record(numerator: u32, denominator: u32, boot_time: i64) -> Vec<u8> {
        let mut bytes = BOOT_SIGNATURE.to_le_bytes().to_vec();
        bytes.extend_from_slice(&48u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&BOOT.0);
        bytes.extend_from_slice(&numerator.to_le_bytes());
        bytes.extend_from_slice(&denominator.to_le_bytes());
        bytes.extend_from_slice(&boot_time.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }

    fn sync_record(continuous_time: u64, wall_time: i64) -> Vec<u8> {
        let mut bytes = SYNC_SIGNATURE.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&continuous_time.to_le_bytes());
        bytes.extend_from_slice(&wall_time.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }

    fn timesync(numerator: u32, denominator: u32) -> Timesync {
        let mut file = boot_record(numerator, denominator, 1_000_000_000);
        file.extend(sync_record(3_000, 5_000_000_000));
        file.extend(sync_record(1_000, 2_000_000_000));
        let mut timesync = Timesync::default();
        assert!(timesync.add(&file).is_empty());
        timesync
    }

    #[test]
    fn times_count_from_the_last_record_before() {
        let t = timesync(1, 1);
        assert_eq!(t.unix_nanos(BOOT, 1_500, false), Some(2_000_000_500));
        assert_eq!(t.unix_nanos(BOOT, 3_000, false), Some(5_000_000_000));
        assert_eq!(t.unix_nanos(BOOT, 10_000, false), Some(5_000_007_000));
    }

    #[test]
    fn before_every_record_the_boot_time_or_the_first_record() {
        let t = timesync(1, 1);
        assert_eq!(t.unix_nanos(BOOT, 400, true), Some(1_000_000_400));
        assert_eq!(t.unix_nanos(BOOT, 400, false), Some(1_999_999_400));
        assert_eq!(t.unix_nanos(Uuid::NIL, 400, true), None);
    }

    #[test]
    fn apple_silicon_ticks_are_scaled() {
        let t = timesync(125, 3);
        assert_eq!(t.unix_nanos(BOOT, 1_000 + 3, false), Some(2_000_000_125));
        assert_eq!(t.boot(BOOT).unwrap().timebase, (125, 3));
    }

    #[test]
    fn damage_is_reported() {
        let mut t = Timesync::default();
        assert_eq!(t.add(&sync_record(1, 2)).len(), 1);
        assert_eq!(t.add(&[0xb0, 0xbb, 0]).len(), 1);
        assert_eq!(t.add(b"garbage!").len(), 1);
    }
}
