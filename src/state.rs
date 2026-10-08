//! Statedumps: how their state is shown in a message.

use crate::bplist;
use crate::dumps::STATEDUMP_OBJECT;
use crate::entry::State;
use crate::text::{base64, c_string};

/// A property list.
const PLIST: u32 = 1;
/// A protocol buffer.
const PROTOBUF: u32 = 2;

/// A statedump's message: its title, its decoder's library and type, and
/// its data.
pub fn describe(state: &State) -> String {
    format!(
        "title: {}\nObject Type: {}\nObject Type: {}\n{}",
        state.title,
        state.decoder_library,
        state.decoder_type,
        data(state)
    )
}

/// The data as text: property lists as JSON, text as itself, others as
/// Base64.
fn data(state: &State) -> String {
    match state.data_type {
        PLIST if state.data.starts_with(b"bplist") => {
            bplist::to_json(&state.data).unwrap_or_else(|e| format!("{e}: {}", base64(&state.data)))
        }
        PROTOBUF => format!("Protocol buffer: {}", base64(&state.data)),
        STATEDUMP_OBJECT => format!(
            "Unsupported Statedump object: {}-{}",
            state.title,
            base64(&state.data)
        ),
        _ => c_string(&state.data),
    }
}
