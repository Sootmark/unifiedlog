//! Arbitrary and damaged input: never a panic, damage reported instead.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use proptest::prelude::*;
use unifiedlog::{format, Item, Reader, StringFile, Timesync, Value};

/// A file of the Big Sur fixture, when there is one (gunzipped once).
fn fixture_file(path: &str) -> Option<Vec<u8>> {
    static FILES: OnceLock<Mutex<HashMap<String, Option<Vec<u8>>>>> = OnceLock::new();
    let files = FILES.get_or_init(Mutex::default);
    let mut files = files.lock().unwrap();
    files
        .entry(path.to_owned())
        .or_insert_with(|| gunzip(path))
        .clone()
}

fn gunzip(path: &str) -> Option<Vec<u8>> {
    let raw = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mandiant/big_sur")
            .join(format!("{path}.gz")),
    )
    .ok()?;
    let mut bytes = Vec::new();
    common::gzip::Decoder::new(raw.as_slice())
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

fn fixture(path: &str) -> Vec<u8> {
    fixture_file(path).unwrap()
}

/// Bytes with some of them changed and maybe cut short.
fn damage(mut bytes: Vec<u8>, changes: &[(usize, u8)], cut: Option<usize>) -> Vec<u8> {
    for &(at, value) in changes {
        if !bytes.is_empty() {
            let at = at % bytes.len();
            bytes[at] = value;
        }
    }
    if let Some(cut) = cut {
        bytes.truncate(cut % (bytes.len() + 1));
    }
    bytes
}

fn item() -> impl Strategy<Value = Item> {
    let value = prop_oneof![
        (any::<u64>(), 0u8..9).prop_map(|(bits, size)| Value::Number { bits, size }),
        any::<u64>().prop_map(Value::Count),
        ".{0,20}".prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        Just(Value::Null),
        Just(Value::Private),
    ];
    (any::<u8>(), value).prop_map(|(kind, value)| Item { kind, value })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_tracev3_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut reader = Reader::new(|_: StringFile| None);
        let _ = reader.read(&bytes);
        let _ = reader.finish();
    }

    #[test]
    fn arbitrary_strings_files(
        tracev3_changes in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..4),
        strings in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let tracev3 = damage(fixture("Signpost/0000000000000001.tracev3"), &tracev3_changes, None);
        let mut reader = Reader::new(move |_: StringFile| Some(strings.clone()));
        let _ = reader.read(&tracev3);
    }

    #[test]
    fn damaged_tracev3(
        changes in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..16),
        cut in proptest::option::of(any::<usize>()),
    ) {
        let tracev3 = damage(fixture("Special/0000000000000001.tracev3"), &changes, cut);
        let mut reader = Reader::new(|file: StringFile| fixture_file(&file.path()));
        let _ = reader.read(&tracev3);
    }

    #[test]
    fn damaged_lzbitmap(
        changes in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..16),
        cut in proptest::option::of(any::<usize>()),
    ) {
        let tracev3 = damage(fixture("lzbitmap/0000000000000001.tracev3"), &changes, cut);
        let mut reader = Reader::new(|_: StringFile| None);
        let _ = reader.read(&tracev3);
    }

    #[test]
    fn damaged_strings_files(
        changes in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..32),
        cut in proptest::option::of(any::<usize>()),
    ) {
        let tracev3 = fixture("Special/0000000000000001.tracev3");
        let mut reader = Reader::new(move |file: StringFile| {
            fixture_file(&file.path()).map(|b| damage(b, &changes, cut))
        });
        let _ = reader.read(&tracev3);
    }

    #[test]
    fn damaged_timesync(
        changes in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..16),
        cut in proptest::option::of(any::<usize>()),
        time in any::<u64>(),
    ) {
        let bytes = damage(fixture("timesync/0000000000000002.timesync"), &changes, cut);
        let mut timesync = Timesync::default();
        let _ = timesync.add(&bytes);
        let boot = unifiedlog::Uuid([0x9a; 16]);
        let _ = timesync.unix_nanos(boot, time, true);
    }

    #[test]
    fn arbitrary_formats(text in ".{0,60}", items in proptest::collection::vec(item(), 0..8)) {
        let _ = format(&text, &items);
    }

    #[test]
    fn printf_like_formats(
        spec in "%[-+ #0]{0,3}[0-9*]{0,3}(\\.[0-9*]{0,3})?(hh|h|l|ll|q|z|j|t)?[diouxXeEfFgGaAcCsSpP@m%]",
        annotation in proptest::option::of("\\{(public|private|bool|BOOL|errno|darwin.mode|time_t|uuid_t|network:sockaddr|mask.hash|mdns:dnshdr|odtypes:mbr_details|location:SqliteResult)\\}"),
        items in proptest::collection::vec(item(), 0..4),
    ) {
        let text = match annotation {
            Some(a) => format!("%{a}{}", &spec[1..]),
            None => spec,
        };
        let _ = format(&text, &items);
    }
}

#[test]
fn damage_is_reported() {
    let mut tracev3 = fixture("Special/0000000000000001.tracev3");
    tracev3.truncate(tracev3.len() / 2);
    let mut reader = Reader::new(|_: StringFile| None);
    let log = reader.read(&tracev3);
    assert!(!log.problems.is_empty());
    assert!(!log.entries.is_empty());
}
