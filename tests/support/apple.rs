//! What Apple's `log show` gives, for comparing messages: entries are
//! found by thread and continuous time, which both readers give exactly.

use std::collections::HashMap;

use common::json::Json;
use unifiedlog::{Entry, EventType, MISSING};

use super::compare::unescape;

/// An entry as `log show --style ndjson` writes it.
#[derive(Debug, Clone, Default)]
pub struct Apple {
    /// The thread.
    pub thread: u64,
    /// The continuous time (`machTimestamp`).
    pub continuous_time: u64,
    /// The format string.
    pub format: String,
    /// The message.
    pub message: String,
    /// The signpost's name, for signposts.
    pub signpost_name: String,
}

impl Apple {
    /// An entry from a `log show` JSON line; `None` for timesync events.
    pub fn from_json(json: &Json) -> Option<Self> {
        if json.get("eventType")?.as_str()? == "timesyncEvent" {
            return None;
        }
        let text = |name: &str| {
            json.get(name)
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned()
        };
        Some(Self {
            thread: json.get("threadID")?.as_u64()?,
            continuous_time: json.get("machTimestamp")?.as_u64()?,
            format: text("formatString"),
            message: text("eventMessage"),
            signpost_name: text("signpostName"),
        })
    }

    /// An entry from a line of `tests/oracle/apple.tsv.gz`, and its fixture.
    pub fn from_tsv(line: &str) -> Option<(String, Self)> {
        let fields: Vec<String> = line.split('\t').map(unescape).collect();
        let [fixture, thread, time, _, format, message, signpost_name] = fields.as_slice() else {
            return None;
        };
        Some((
            fixture.clone(),
            Self {
                thread: thread.parse().ok()?,
                continuous_time: time.parse().ok()?,
                format: format.clone(),
                message: message.clone(),
                signpost_name: signpost_name.clone(),
            },
        ))
    }
}

/// Apple's entries, by group, thread and continuous time.
#[derive(Default)]
pub struct Index(HashMap<(String, u64, u64), Vec<Apple>>);

impl Index {
    /// Adds an entry.
    pub fn add(&mut self, group: &str, apple: Apple) {
        self.0
            .entry((group.to_owned(), apple.thread, apple.continuous_time))
            .or_default()
            .push(apple);
    }

    /// Apple's entry for one of mine: same thread and time, the same
    /// format string first.
    pub fn find(&self, group: &str, entry: &Entry) -> Option<&Apple> {
        let candidates = self
            .0
            .get(&(group.to_owned(), entry.thread_id, entry.continuous_time))?;
        candidates
            .iter()
            .find(|a| a.format == entry.raw_message)
            .or_else(|| candidates.first())
    }
}

/// How many messages agree with Apple's, of those compared.
#[derive(Debug, Default)]
pub struct Tally {
    /// Entries compared.
    pub compared: usize,
    /// Entries whose messages agree.
    pub agreed: usize,
    /// Entries Apple's tool does not show.
    pub unseen: usize,
    /// Entries left out (statedumps, which Apple shows otherwise).
    pub skipped: usize,
    /// Some of the disagreements: mine, Apple's.
    pub examples: Vec<(String, String)>,
}

impl Tally {
    /// Compares one of my entries with Apple's.
    pub fn add(&mut self, entry: &Entry, apple: Option<&Apple>) {
        let Some(apple) = apple else {
            self.unseen += 1;
            return;
        };
        if entry.event_type == EventType::Statedump || named_in_format(entry, apple) {
            self.skipped += 1;
            return;
        }
        self.compared += 1;
        let theirs = normalize(&apple.message);
        if entry.message.trim_end() == theirs {
            self.agreed += 1;
        } else if self.examples.len() < 20 {
            self.examples.push((entry.message.clone(), theirs));
        }
    }

    /// The share that agrees, in percent.
    pub fn percent(&self) -> f64 {
        if self.compared == 0 {
            100.0
        } else {
            100.0 * self.agreed as f64 / self.compared as f64
        }
    }
}

/// A signpost whose stored format string starts with its name (macOS
/// 10.13): Apple's tool splits the name off, Mandiant's and this crate keep
/// the string as stored.
fn named_in_format(entry: &Entry, apple: &Apple) -> bool {
    entry.event_type == EventType::Signpost
        && !apple.signpost_name.is_empty()
        && entry
            .raw_message
            .starts_with(&format!("{} ", apple.signpost_name))
}

/// Apple's message as this crate writes it: signpost annotations' markers
/// (`__##__signpost.telemetry#____#number1#_##_#VALUE##__##`) reduced to
/// the value, missing data shown as Mandiant does, trailing whitespace cut.
pub fn normalize(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find("__##__") {
        out.push_str(&rest[..start]);
        let marker = &rest[start..];
        match (marker.find("#_##_#"), marker.find("##__##")) {
            (Some(value), Some(end)) if value < end => {
                out.push_str(&marker[value + 6..end]);
                rest = &marker[end + 6..];
            }
            _ => {
                out.push_str("__##__");
                rest = &marker[6..];
            }
        }
    }
    out.push_str(rest);
    out.replace("<decode: missing data>", MISSING)
        .trim_end()
        .to_owned()
}
