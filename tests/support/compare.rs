//! Pairing this crate's entries with another reader's, and counting where
//! they agree.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use common::json::Json;

/// The fields compared, as Mandiant's reader names them.
pub const FIELDS: [&str; 15] = [
    "pid",
    "euid",
    "thread_id",
    "event_type",
    "log_type",
    "subsystem",
    "category",
    "process",
    "library",
    "raw_message",
    "message",
    "activity_id",
    "parent_activity_id",
    "process_uuid",
    "library_uuid",
];

/// The fields that must all agree for an entry to count as matching on
/// structure (with the time, which pairs entries).
pub const STRUCTURE: [&str; 9] = [
    "pid",
    "thread_id",
    "event_type",
    "log_type",
    "subsystem",
    "category",
    "process",
    "library",
    "raw_message",
];

/// Times agree within this many nanoseconds: Mandiant's reader computes
/// them in floating point.
const TIME_TOLERANCE: i64 = 1_000;

/// An entry as text fields.
#[derive(Debug, Clone, Default)]
pub struct Row {
    /// What it is compared within (a fixture's name, or "").
    pub group: String,
    /// The thread.
    pub thread: u64,
    /// The time, in nanoseconds since 1970.
    pub time: i64,
    /// The fields, by name.
    pub fields: BTreeMap<String, String>,
}

impl Row {
    /// A row from a JSON object with Mandiant's field names; times may be
    /// floating point, as Mandiant writes them.
    pub fn from_json(group: &str, json: &Json) -> Option<Self> {
        let Json::Object(members) = json else {
            return None;
        };
        let mut fields = BTreeMap::new();
        for (name, value) in members {
            let text = match value {
                Json::String(s) => s.clone(),
                Json::Float(f) => format!("{f}"),
                other => other.to_string(),
            };
            fields.insert(name.clone(), text);
        }
        let time = match json.get("time")? {
            Json::Float(f) => f.round() as i64,
            other => other.as_i64()?,
        };
        Some(Self {
            group: group.to_owned(),
            thread: json.get("thread_id")?.as_u64()?,
            time,
            fields,
        })
    }

    /// A row from a TSV line with the given column names, its group the
    /// first part of the `file` column.
    pub fn from_tsv(names: &[&str], line: &str) -> Option<Self> {
        let fields: BTreeMap<String, String> = names
            .iter()
            .zip(line.split('\t'))
            .map(|(name, value)| ((*name).to_owned(), unescape(value)))
            .collect();
        Some(Self {
            group: fields.get("file")?.split('/').next()?.to_owned(),
            thread: fields.get("thread_id")?.parse().ok()?,
            time: fields.get("time")?.parse().ok()?,
            fields,
        })
    }

    /// A field, or "" when absent.
    pub fn get(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }
}

/// How two lists of rows pair up.
#[derive(Debug, Default)]
pub struct Pairing {
    /// Pairs of indexes: mine, theirs.
    pub pairs: Vec<(usize, usize)>,
    /// My rows with no partner.
    pub only_mine: Vec<usize>,
    /// Their rows with no partner.
    pub only_theirs: Vec<usize>,
}

/// A TSV field's text, its escapes (`\t`, `\n`, `\r`, `\\`) undone.
pub fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Pairs rows of the same group and thread whose times agree, in time order; among
/// rows at the same time, one with the same format string first.
pub fn pair(mine: &[Row], theirs: &[Row]) -> Pairing {
    let mine_by_thread = by_thread(mine);
    let mut theirs_by_thread = by_thread(theirs);
    let mut pairing = Pairing::default();
    for (thread, a) in &mine_by_thread {
        let mut b = theirs_by_thread.remove(thread).unwrap_or_default();
        let (mut i, mut j) = (0, 0);
        while i < a.len() && j < b.len() {
            let (tm, tt) = (mine[a[i]].time, theirs[b[j]].time);
            if (tm - tt).abs() <= TIME_TOLERANCE {
                prefer_same_format(&mine[a[i]], theirs, &mut b, j);
                pairing.pairs.push((a[i], b[j]));
                i += 1;
                j += 1;
            } else if tm < tt {
                pairing.only_mine.push(a[i]);
                i += 1;
            } else {
                pairing.only_theirs.push(b[j]);
                j += 1;
            }
        }
        pairing.only_mine.extend(&a[i..]);
        pairing.only_theirs.extend(&b[j..]);
    }
    for rest in theirs_by_thread.into_values() {
        pairing.only_theirs.extend(rest);
    }
    pairing
}

/// Moves to `at` the first of their rows at the same time with my row's
/// format string, if one is there.
fn prefer_same_format(row: &Row, theirs: &[Row], order: &mut [usize], at: usize) {
    let same_time = order[at..]
        .iter()
        .take_while(|&&k| (theirs[k].time - row.time).abs() <= TIME_TOLERANCE)
        .count();
    if let Some(offset) = order[at..at + same_time]
        .iter()
        .position(|&k| theirs[k].get("raw_message") == row.get("raw_message"))
    {
        order.swap(at, at + offset);
    }
}

/// Row indexes by group and thread, each list sorted by time (then input
/// order).
fn by_thread(rows: &[Row]) -> HashMap<(&str, u64), Vec<usize>> {
    let mut groups: HashMap<(&str, u64), Vec<usize>> = HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        groups.entry((&row.group, row.thread)).or_default().push(i);
    }
    for group in groups.values_mut() {
        group.sort_by_key(|&i| (rows[i].time, i));
    }
    groups
}

/// Where paired rows agree.
#[derive(Debug, Default)]
pub struct Report {
    /// My rows.
    pub mine: usize,
    /// Their rows.
    pub theirs: usize,
    /// Rows paired.
    pub paired: usize,
    /// Paired rows that agree on every structure field.
    pub structure: usize,
    /// Of those, the rows whose messages agree too.
    pub all: usize,
    /// Disagreements, by field.
    pub mismatches: BTreeMap<&'static str, usize>,
}

/// Counts agreements between paired rows.
pub fn report(mine: &[Row], theirs: &[Row], pairing: &Pairing) -> Report {
    let mut report = Report {
        mine: mine.len(),
        theirs: theirs.len(),
        paired: pairing.pairs.len(),
        ..Report::default()
    };
    for &(a, b) in &pairing.pairs {
        let (m, t) = (&mine[a], &theirs[b]);
        for field in FIELDS {
            if m.get(field) != t.get(field) {
                *report.mismatches.entry(field).or_default() += 1;
            }
        }
        if STRUCTURE.iter().all(|f| m.get(f) == t.get(f)) {
            report.structure += 1;
            if m.get("message") == t.get("message") {
                report.all += 1;
            }
        }
    }
    report
}

impl Report {
    /// The share of their rows that match on structure, in percent.
    pub fn structure_percent(&self) -> f64 {
        percent(self.structure, self.theirs)
    }
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        100.0
    } else {
        100.0 * part as f64 / whole as f64
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "mine {}, theirs {}, paired {}",
            self.mine, self.theirs, self.paired
        )?;
        writeln!(
            f,
            "structure and raw_message agree: {} ({:.3}%); messages too: {} ({:.3}%)",
            self.structure,
            self.structure_percent(),
            self.all,
            percent(self.all, self.theirs)
        )?;
        for (field, count) in &self.mismatches {
            writeln!(f, "  {field}: {count} differ")?;
        }
        Ok(())
    }
}
