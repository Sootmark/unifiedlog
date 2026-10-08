//! Comparisons with Mandiant's reader (`unifiedlog_iterator` v0.7.0) and
//! Apple's `log show`.
//!
//! The fixtures (`tests/fixtures/mandiant/`, Apache-2.0) are small log
//! archives made from Mandiant's test data by `tests/oracle/make_fixtures.py`,
//! which also wrote what Mandiant's reader gives for them
//! (`tests/oracle/mandiant.tsv.gz`); `tests/oracle/apple.py` wrote what
//! `log show` gives (`tests/oracle/apple.tsv.gz`).
//!
//! `archive_matches_mandiant` compares a whole archive and is ignored by
//! default: set `UNIFIEDLOG_ARCHIVE` to a `.logarchive` directory and
//! `UNIFIEDLOG_MANDIANT` to `unifiedlog_iterator`'s JSON lines for it
//! (`.gz` allowed), and optionally `UNIFIEDLOG_APPLE` to `log show --style
//! ndjson --info --debug --signpost` output, then run
//! `cargo test --release --test oracle -- --ignored --nocapture`.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use common::json::{self, Json};

#[path = "support/apple.rs"]
mod apple;
#[path = "support/archive.rs"]
mod archive;
#[path = "support/compare.rs"]
mod compare;

use apple::{Apple, Index, Tally};
use archive::Archive;
use compare::Row;

/// The fixtures, by name.
const FIXTURES: [&str; 5] = [
    "big_sur",
    "big_sur_private",
    "high_sierra",
    "monterey",
    "tahoe",
];

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// A text file, gunzipped when its name ends in `.gz`.
fn text(path: &Path) -> String {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    if path.extension().is_some_and(|e| e == "gz") {
        let mut text = String::new();
        common::gzip::Decoder::new(raw.as_slice())
            .read_to_string(&mut text)
            .unwrap();
        text
    } else {
        String::from_utf8(raw).unwrap()
    }
}

/// A fixture's entries, as rows and as entries.
fn fixture(name: &str) -> (Vec<Row>, Vec<archive::Read>) {
    let (read, problems) = archive::read(&Archive::new(
        &repo("tests/fixtures/mandiant").join(name),
        true,
    ));
    assert!(problems.is_empty(), "{name}: {problems:?}");
    let rows = read
        .iter()
        .map(|r| Row::from_json(name, &archive::to_json(r)).unwrap())
        .collect();
    (rows, read)
}

/// Mandiant's rows for every fixture.
fn mandiant_rows() -> Vec<Row> {
    let text = text(&repo("tests/oracle/mandiant.tsv.gz"));
    let mut lines = text.lines();
    let names: Vec<&str> = lines.next().unwrap().split('\t').collect();
    lines
        .map(|line| Row::from_tsv(&names, line).unwrap())
        .collect()
}

#[test]
fn fixtures_match_mandiant() {
    let theirs = mandiant_rows();
    let mine: Vec<Row> = FIXTURES.iter().flat_map(|name| fixture(name).0).collect();
    let pairing = compare::pair(&mine, &theirs);
    let report = compare::report(&mine, &theirs, &pairing);
    println!("{report}");
    assert!(pairing.only_mine.is_empty() && pairing.only_theirs.is_empty());
    assert!(report.structure_percent() >= 99.9, "{report}");
}

#[test]
fn fixtures_messages_match_apple() {
    let mut index = Index::default();
    let text = text(&repo("tests/oracle/apple.tsv.gz"));
    for line in text.lines().skip(1) {
        let (fixture, apple) = Apple::from_tsv(line).unwrap();
        index.add(&fixture, apple);
    }
    let mut tally = Tally::default();
    for name in FIXTURES {
        for read in fixture(name).1 {
            tally.add(&read.entry, index.find(name, &read.entry));
        }
    }
    println!("{tally:#?}");
    assert!(tally.compared > 9_000);
    assert!(tally.percent() >= 99.5, "{tally:#?}");
}

#[test]
fn lzbitmap_chunksets_read_as_lz4_ones() {
    let archive = Archive::new(&repo("tests/fixtures/mandiant/big_sur"), true);
    let read = |path: &str| {
        let strings = archive.clone();
        let mut reader =
            unifiedlog::Reader::new(move |f: unifiedlog::StringFile| strings.file(&f.path()));
        reader.read(&archive.file(path).unwrap())
    };
    let lz4 = read("Special/0000000000000001.tracev3");
    let lzbitmap = read("lzbitmap/0000000000000001.tracev3");
    assert!(lzbitmap.problems.is_empty(), "{:?}", lzbitmap.problems);
    assert_eq!(lz4.entries.len(), 1826);
    assert_eq!(lz4.entries, lzbitmap.entries);
}

/// JSON lines, gunzipped when the name ends in `.gz`.
fn json_lines(path: &Path) -> Vec<Json> {
    text(path)
        .lines()
        .filter_map(|line| json::parse(line).ok())
        .collect()
}

#[test]
#[ignore = "needs UNIFIEDLOG_ARCHIVE and UNIFIEDLOG_MANDIANT"]
fn archive_matches_mandiant() {
    let archive =
        PathBuf::from(std::env::var_os("UNIFIEDLOG_ARCHIVE").expect("UNIFIEDLOG_ARCHIVE"));
    let oracle =
        PathBuf::from(std::env::var_os("UNIFIEDLOG_MANDIANT").expect("UNIFIEDLOG_MANDIANT"));
    let (read, problems) = archive::read(&Archive::new(&archive, false));
    println!("{} entries, {} problems", read.len(), problems.len());
    let mine: Vec<Row> = read
        .iter()
        .map(|r| Row::from_json("", &archive::to_json(r)).unwrap())
        .collect();
    let theirs: Vec<Row> = json_lines(&oracle)
        .iter()
        .filter_map(|j| Row::from_json("", j))
        .collect();
    let pairing = compare::pair(&mine, &theirs);
    let report = compare::report(&mine, &theirs, &pairing);
    println!("{report}");
    if let Some(path) = std::env::var_os("UNIFIEDLOG_APPLE") {
        let mut index = Index::default();
        for apple in json_lines(Path::new(&path))
            .iter()
            .filter_map(Apple::from_json)
        {
            index.add("", apple);
        }
        let mut tally = Tally::default();
        for r in &read {
            tally.add(&r.entry, index.find("", &r.entry));
        }
        println!("messages as Apple's: {} of {} ({:.3}%), {} not shown by Apple, {} statedumps or named signposts left out", tally.agreed, tally.compared, tally.percent(), tally.unseen, tally.skipped);
    }
    assert!(report.structure_percent() >= 99.9, "{report}");
}
