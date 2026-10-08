//! Log entries, as the reader gives them.

use common::time::Ts;

use crate::items::{Frame, Item};
use crate::uuid::Uuid;

/// A log entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// What kind of entry it is.
    pub event_type: EventType,
    /// Its level or sub-kind.
    pub log_type: LogType,
    /// When, in Mach continuous time (ticks since boot).
    pub continuous_time: u64,
    /// When, in nanoseconds since 1970 (UTC); `None` when no timesync
    /// record covers its boot.
    pub unix_nanos: Option<i64>,
    /// The boot it belongs to.
    pub boot_uuid: Uuid,
    /// The process.
    pub pid: u64,
    /// The process's effective user.
    pub euid: u32,
    /// The thread.
    pub thread_id: u64,
    /// The activity it belongs to (or creates).
    pub activity_id: u64,
    /// The activity's parent, for activities created inside another.
    pub parent_activity_id: u64,
    /// The subsystem (`com.apple.network`).
    pub subsystem: String,
    /// The category.
    pub category: String,
    /// The process's executable.
    pub process: String,
    /// Its UUID.
    pub process_uuid: Option<Uuid>,
    /// The library or executable that wrote the entry.
    pub library: String,
    /// Its UUID.
    pub library_uuid: Option<Uuid>,
    /// Which file the format string came from.
    pub format_source: FormatSource,
    /// The format string (empty when not found; see `missing`).
    pub raw_message: String,
    /// The message: the format string filled with the items.
    pub message: String,
    /// The values the format string was filled with.
    pub items: Vec<Item>,
    /// Signposts: their identifier and name.
    pub signpost: Option<Signpost>,
    /// The backtrace, when one was recorded.
    pub backtrace: Vec<Frame>,
    /// Loss entries: what was lost.
    pub loss: Option<Loss>,
    /// Statedumps: the dumped state.
    pub state: Option<State>,
    /// Why the format string or the items could not be found, when so.
    pub missing: Option<String>,
}

impl Entry {
    /// When, as a timestamp (to 100 ns).
    #[must_use]
    pub fn time(&self) -> Option<Ts> {
        self.unix_nanos.map(Ts::from_unix_nanos)
    }
}

/// What kind of entry it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum EventType {
    /// A log message (`os_log`).
    #[default]
    Log,
    /// An activity (`os_activity_create`, user actions).
    Activity,
    /// A trace message.
    Trace,
    /// A signpost (`os_signpost`).
    Signpost,
    /// Messages the system dropped.
    Loss,
    /// A simpledump: one string, from a dump of state.
    Simpledump,
    /// A statedump: a property list, protocol buffer or object.
    Statedump,
    /// A kind of entry not known (the tracepoint's first byte).
    Unknown(u8),
}

impl EventType {
    /// Its name (`Log`, `Activity`, …).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Log => "Log",
            Self::Activity => "Activity",
            Self::Trace => "Trace",
            Self::Signpost => "Signpost",
            Self::Loss => "Loss",
            Self::Simpledump => "Simpledump",
            Self::Statedump => "Statedump",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// An entry's level, or for activities and signposts its sub-kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum LogType {
    /// Default level.
    #[default]
    Default,
    /// Info level.
    Info,
    /// Debug level.
    Debug,
    /// Error level.
    Error,
    /// Fault level.
    Fault,
    /// An activity's creation.
    Create,
    /// A user action activity.
    Useraction,
    /// A process signpost event.
    ProcessSignpostEvent,
    /// A process signpost interval's start.
    ProcessSignpostStart,
    /// A process signpost interval's end.
    ProcessSignpostEnd,
    /// A system signpost event.
    SystemSignpostEvent,
    /// A system signpost interval's start.
    SystemSignpostStart,
    /// A system signpost interval's end.
    SystemSignpostEnd,
    /// A thread signpost event.
    ThreadSignpostEvent,
    /// A thread signpost interval's start.
    ThreadSignpostStart,
    /// A thread signpost interval's end.
    ThreadSignpostEnd,
    /// A simpledump.
    Simpledump,
    /// A statedump.
    Statedump,
    /// A loss entry.
    Loss,
}

impl LogType {
    /// The log type of a tracepoint's type byte, for its kind of entry.
    #[must_use]
    pub fn of(value: u8, event: EventType) -> Self {
        match value {
            0x01 if event == EventType::Activity => Self::Create,
            0x01 => Self::Info,
            0x02 => Self::Debug,
            0x03 => Self::Useraction,
            0x10 => Self::Error,
            0x11 => Self::Fault,
            0x40 => Self::ThreadSignpostEvent,
            0x41 => Self::ThreadSignpostStart,
            0x42 => Self::ThreadSignpostEnd,
            0x80 => Self::ProcessSignpostEvent,
            0x81 => Self::ProcessSignpostStart,
            0x82 => Self::ProcessSignpostEnd,
            0xc0 => Self::SystemSignpostEvent,
            0xc1 => Self::SystemSignpostStart,
            0xc2 => Self::SystemSignpostEnd,
            _ => Self::Default,
        }
    }

    /// Its name (`Default`, `Info`, `ProcessSignpostStart`, …).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Info => "Info",
            Self::Debug => "Debug",
            Self::Error => "Error",
            Self::Fault => "Fault",
            Self::Create => "Create",
            Self::Useraction => "Useraction",
            Self::ProcessSignpostEvent => "ProcessSignpostEvent",
            Self::ProcessSignpostStart => "ProcessSignpostStart",
            Self::ProcessSignpostEnd => "ProcessSignpostEnd",
            Self::SystemSignpostEvent => "SystemSignpostEvent",
            Self::SystemSignpostStart => "SystemSignpostStart",
            Self::SystemSignpostEnd => "SystemSignpostEnd",
            Self::ThreadSignpostEvent => "ThreadSignpostEvent",
            Self::ThreadSignpostStart => "ThreadSignpostStart",
            Self::ThreadSignpostEnd => "ThreadSignpostEnd",
            Self::Simpledump => "Simpledump",
            Self::Statedump => "Statedump",
            Self::Loss => "Loss",
        }
    }
}

/// Which file an entry's format string came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FormatSource {
    /// The process's main executable's uuidtext file.
    #[default]
    MainExe,
    /// The shared cache strings file.
    SharedCache,
    /// The uuidtext file of the image loaded at the caller's address.
    Absolute,
    /// The uuidtext file of an image the entry names.
    UuidRelative,
    /// None: the entry has no format string (loss, dumps) or flags not
    /// seen before.
    None,
}

/// A signpost's identifier and name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signpost {
    /// Its identifier: entries of one interval share it.
    pub id: u64,
    /// Its name's reference (an offset in the strings files).
    pub name: u32,
}

/// What a loss entry says was lost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Loss {
    /// The continuous time the loss started.
    pub start: u64,
    /// The continuous time it ended.
    pub end: u64,
    /// How many entries were lost.
    pub count: u64,
}

/// A statedump's state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// Its title.
    pub title: String,
    /// What the data is: 1 a property list, 2 a protocol buffer, 3 an
    /// object.
    pub data_type: u32,
    /// For objects: the library that decodes them.
    pub decoder_library: String,
    /// For objects: their type.
    pub decoder_type: String,
    /// The data, as written.
    pub data: Vec<u8>,
}
