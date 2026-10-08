//! Shared cache strings files (`uuidtext/dsc/<UUID>`): the format strings
//! of every library in a dyld shared cache, and which library each comes
//! from.
//!
//! A signature (`hcsd`), a version (1 up to Big Sur, 2 since Monterey),
//! how many ranges and images there are, the ranges (where in the cache's
//! string space each starts, where its strings are in the file, their
//! size, and the image they belong to), then the images (UUID and the
//! offset of its path). Version 2 widens offsets to 64 bits and moves a
//! range's image index to its end.

use common::bytes::{Reader, Result};

use crate::text::{c_string_at, invalid};
use crate::uuid::Uuid;

/// A shared cache strings file's signature (`hcsd`).
const SIGNATURE: u32 = 0x6473_6368;

/// The format strings of a shared cache and the images they belong to.
#[derive(Debug, Clone, Default)]
pub struct SharedCache {
    bytes: Vec<u8>,
    /// Ranges, in file order.
    ranges: Vec<Range>,
    /// Whether the ranges are in ascending order (they always are in files
    /// seen so far), which allows a binary search.
    sorted: bool,
    images: Vec<CacheImage>,
}

/// A range of format strings.
#[derive(Debug, Clone, Copy)]
struct Range {
    /// Where it starts in the cache's string space.
    start: u64,
    /// Where its strings are in the file.
    data_offset: usize,
    size: u32,
    image: usize,
}

/// A library in the shared cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheImage {
    /// Its UUID.
    pub uuid: Uuid,
    /// Its path.
    pub path: String,
}

/// Reads a shared cache strings file, keeping its bytes.
pub fn parse(bytes: Vec<u8>) -> std::result::Result<SharedCache, String> {
    let (ranges, images) = read(&bytes).map_err(|e| format!("dsc: {e}"))?;
    let sorted = ranges.windows(2).all(|w| w[0].start <= w[1].start);
    Ok(SharedCache {
        bytes,
        ranges,
        sorted,
        images,
    })
}

fn read(bytes: &[u8]) -> Result<(Vec<Range>, Vec<CacheImage>)> {
    let r = &mut Reader::new(bytes);
    if r.u32_le()? != SIGNATURE {
        return Err(invalid(0, "the shared cache strings signature"));
    }
    let wide = r.u16_le()? >= 2;
    r.skip(2)?; // minor version
    let range_count = r.u32_le()?;
    let image_count = r.u32_le()?;
    let mut ranges = Vec::new();
    for _ in 0..range_count {
        ranges.push(read_range(r, wide)?);
    }
    let mut path_offsets = Vec::new();
    for _ in 0..image_count {
        path_offsets.push(read_image(r, wide)?);
    }
    let images = path_offsets
        .into_iter()
        .map(|(uuid, path_offset)| CacheImage {
            uuid,
            path: c_string_at(bytes, path_offset).unwrap_or_default(),
        })
        .collect();
    Ok((ranges, images))
}

fn read_range(r: &mut Reader, wide: bool) -> Result<Range> {
    let (image, start) = if wide {
        (None, r.u64_le()?)
    } else {
        (Some(r.u32_le()? as usize), u64::from(r.u32_le()?))
    };
    let data_offset = r.u32_le()? as usize;
    let size = r.u32_le()?;
    let image = match image {
        Some(index) => index,
        None => usize::try_from(r.u64_le()?).unwrap_or(usize::MAX),
    };
    Ok(Range {
        start,
        data_offset,
        size,
        image,
    })
}

fn read_image(r: &mut Reader, wide: bool) -> Result<(Uuid, usize)> {
    if wide {
        r.skip(8)?; // text offset
    } else {
        r.skip(4)?;
    }
    r.skip(4)?; // text size
    let uuid = Uuid(r.array()?);
    Ok((uuid, r.u32_le()? as usize))
}

/// A format string found in a shared cache, and its library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<'a> {
    /// The format string.
    pub format: String,
    /// The library it belongs to.
    pub image: &'a CacheImage,
}

impl SharedCache {
    /// The format string at an offset in the cache's string space, and its
    /// library.
    pub fn format_string(&self, offset: u64) -> Option<Found<'_>> {
        let range = self.range_at(offset)?;
        let within = usize::try_from(offset - range.start).ok()?;
        let at = range.data_offset.checked_add(within)?;
        let end = range.data_offset.checked_add(range.size as usize)?;
        let strings = self.bytes.get(..end.min(self.bytes.len()))?;
        Some(Found {
            format: c_string_at(strings, at)?,
            image: self.images.get(range.image)?,
        })
    }

    /// The library of the first range: what entries whose format string
    /// is not in the cache are attributed to.
    pub fn first_image(&self) -> Option<&CacheImage> {
        self.images.get(self.ranges.first()?.image)
    }

    fn range_at(&self, offset: u64) -> Option<&Range> {
        let holds = |r: &&Range| offset >= r.start && offset - r.start < u64::from(r.size);
        if self.sorted {
            let candidates = &self.ranges[..self.ranges.partition_point(|r| r.start <= offset)];
            let last = candidates.last()?.start;
            candidates
                .iter()
                .rev()
                .take_while(|r| r.start == last)
                .find(holds)
        } else {
            self.ranges.iter().find(holds)
        }
    }
}
