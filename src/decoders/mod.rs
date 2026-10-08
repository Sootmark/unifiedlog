//! Value decoders: what an annotation such as `%{bool}d`, `%{errno}d`,
//! `%{time_t}d`, `%{uuid_t}.16P` or `%{network:sockaddr}.*P` turns a value
//! into. The texts are those Apple's `log` shows, where known.

mod darwin;
mod location;
mod mdns;
mod network;
mod opendirectory;

pub use darwin::strerror;

use std::fmt::Write;

use crate::items::{Item, Value};
use crate::text::base64;
use crate::uuid::Uuid;

/// The item type of a hashed value.
const HASHED: u8 = 0xf2;

/// A value decoded as its annotation asks, or `None` when no decoder
/// applies (the value is then formatted as usual).
pub fn decode(annotation: &str, item: &Item) -> Option<String> {
    annotation
        .split(',')
        .map(str::trim)
        .find_map(|name| decode_as(name, item))
}

fn decode_as(name: &str, item: &Item) -> Option<String> {
    let value = &item.value;
    match name {
        "bool" => Some(if number(value)? == 0 { "false" } else { "true" }.to_owned()),
        "BOOL" => Some(if number(value)? == 0 { "NO" } else { "YES" }.to_owned()),
        "uuid_t" => Some(Uuid::from_slice(bytes(value)?)?.to_string()),
        // Only a hashed value is shown as a hash: with private data
        // recorded, the value itself is there.
        "mask.hash" if item.kind == HASHED => Some(mask_hash(value)?),
        "location:escape_only" => Some(escape_only(value)?),
        _ => darwin_or_network(name, value)
            .or_else(|| directory_or_location(name, value))
            .or_else(|| dns(name, value)),
    }
}

fn darwin_or_network(name: &str, value: &Value) -> Option<String> {
    match name {
        "errno" | "darwin.errno" => Some(darwin::errno(number(value)?)),
        "mach.errno" => Some(darwin::mach_error(number(value)?)),
        "darwin.signal" => Some(darwin::signal(number(value)?)),
        "darwin.mode" => Some(darwin::mode(number(value)?)),
        "time_t" => Some(darwin::time(number(value)?)),
        "bytes" => Some(darwin::byte_count(number(value)?)),
        "network:in_addr" => network::in_addr(value),
        "network:in6_addr" => network::in6_addr(bytes(value)?),
        "network:sockaddr" => network::sockaddr(bytes(value)?),
        "network:tcp_flags" => Some(network::tcp_flags(number(value)?)),
        "network:tcp_state" => Some(network::tcp_state(number(value)?)),
        _ => None,
    }
}

fn directory_or_location(name: &str, value: &Value) -> Option<String> {
    match name {
        "odtypes:ODError" => Some(opendirectory::od_error(number(value)?)),
        "odtypes:mbridtype" => Some(opendirectory::member_id_type(number(value)?)),
        "odtypes:mbr_details" => opendirectory::member_details(bytes(value)?),
        "odtypes:nt_sid_t" => opendirectory::sid(bytes(value)?),
        "location:CLClientAuthorizationStatus" => {
            Some(location::authorization_status(number(value)?))
        }
        "location:CLDaemonStatus_Type::Reachability" => {
            Some(location::reachability(number(value)?))
        }
        "location:CLSubHarvesterIdentifier" => Some(location::subharvester(number(value)?)),
        "location:IOMessage" => Some(location::io_message(number(value)?)),
        "location:SqliteResult" => location::sqlite_result(bytes(value)?),
        "location:_CLClientManagerStateTrackerState" => {
            location::client_manager_state(bytes(value)?)
        }
        _ => None,
    }
}

fn dns(name: &str, value: &Value) -> Option<String> {
    match name {
        "mdns:dnshdr" => mdns::header(bytes(value)?),
        "mdns:dns.idflags" => Some(mdns::id_flags(number(value)?)),
        "mdns:dns.counts" => Some(mdns::counts(number(value)?)),
        "mdns:rrtype" => Some(mdns::record_type(number(value)?)),
        "mdns:protocol" => Some(mdns::protocol(number(value)?)),
        "mdns:nreason" => Some(mdns::reason(number(value)?)),
        "mdns:addrmv" => Some(mdns::add_remove(number(value)?)),
        "mdns:yesno" => Some(mdns::yes_no(number(value)?)),
        "mdns:acceptable" => Some(mdns::acceptable(number(value)?)),
        "mdns:gaiopts" => Some(mdns::getaddrinfo_options(number(value)?)),
        "mdns:time_duration" => Some(mdns::duration(number(value)?)),
        "mdns:termination_reason" => Some(mdns::termination_reason(number(value)?)),
        "mdnsresponder:dns_scope_type" => Some(mdns::scope_type(number(value)?)),
        "mdnsresponder:kev_dl_event" => Some(mdns::data_link_event(number(value)?)),
        "mdnsresponder:domain_name" => mdns::domain_name(bytes(value)?),
        "mdnsresponder:domain_label" => mdns::domain_label(bytes(value)?),
        "mdnsresponder:ip_addr" => mdns::ip_addr(bytes(value)?),
        "mdnsresponder:mac_addr" => Some(mdns::mac_addr(bytes(value)?)),
        _ => None,
    }
}

/// A hashed value: `<mask.hash: 'Base64'>`, or `(null)` when empty.
fn mask_hash(value: &Value) -> Option<String> {
    match value {
        Value::Bytes(bytes) if bytes.is_empty() => Some("<mask.hash: (null)>".to_owned()),
        Value::Bytes(bytes) => Some(format!("<mask.hash: '{}'>", base64(bytes))),
        Value::Null => Some("<mask.hash: (null)>".to_owned()),
        _ => None,
    }
}

/// A string as a quoted JSON string; a NULL one as `""`.
fn escape_only(value: &Value) -> Option<String> {
    match value {
        Value::Text(text) => Some(json_string(text)),
        Value::Null => Some(json_string("")),
        _ => None,
    }
}

/// A number item's value, signed by its size.
fn number(value: &Value) -> Option<i64> {
    match *value {
        Value::Number { bits, size } => Some(match size {
            1 => i64::from(bits as i8),
            2 => i64::from(bits as i16),
            4 => i64::from(bits as i32),
            _ => bits as i64,
        }),
        _ => None,
    }
}

fn bytes(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

/// A string in double quotes, escaped as JSON (slashes too, as Apple's
/// encoder does).
pub fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(n: i64, size: u8) -> Item {
        Item {
            kind: 0x02,
            value: Value::Number {
                bits: n as u64,
                size,
            },
        }
    }

    fn data(bytes: &[u8]) -> Item {
        Item {
            kind: 0x32,
            value: Value::Bytes(bytes.to_vec()),
        }
    }

    #[test]
    fn numbers() {
        assert_eq!(decode("public, bool", &number(0, 4)).unwrap(), "false");
        assert_eq!(decode("BOOL", &number(1, 4)).unwrap(), "YES");
        assert_eq!(
            decode("errno", &number(2, 4)).unwrap(),
            "[2: No such file or directory]"
        );
        assert_eq!(
            decode("darwin.errno", &number(999, 4)).unwrap(),
            "[999: Unknown error: 999]"
        );
        assert_eq!(
            decode("darwin.mode", &number(0o100_644, 4)).unwrap(),
            "-rw-r--r--"
        );
        assert_eq!(
            decode("darwin.mode", &number(0o41_777, 4)).unwrap(),
            "drwxrwxrwt"
        );
        assert_eq!(
            decode("time_t", &number(1_642_303_846, 8)).unwrap(),
            "2022-01-16T03:30:46.000Z"
        );
        assert_eq!(
            decode("odtypes:ODError", &number(2, 4)).unwrap(),
            "Not Found"
        );
        assert_eq!(
            decode("network:in_addr", &number(0x0100_007f, 4)).unwrap(),
            "127.0.0.1"
        );
        assert!(decode("public", &number(1, 4)).is_none());
    }

    #[test]
    fn bytes_and_text() {
        let uuid = data(&[0x44; 16]);
        assert_eq!(
            decode("uuid_t", &uuid).unwrap(),
            "44444444-4444-4444-4444-444444444444"
        );
        let sockaddr = data(&[16, 2, 0x01, 0xbb, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            decode("network:sockaddr", &sockaddr).unwrap(),
            "10.0.0.1:443"
        );
        let member = data(b"\x23\xfe\xff\xff\xff/Local/Default\0");
        assert_eq!(
            decode("odtypes:mbr_details", &member).unwrap(),
            "user: -2@/Local/Default"
        );
        let text = Item {
            kind: 0x22,
            value: Value::Text("a\"b".into()),
        };
        assert_eq!(decode("location:escape_only", &text).unwrap(), "\"a\\\"b\"");
        let mut sid = vec![1, 2, 0, 0, 0, 0, 0, 5];
        sid.extend_from_slice(&21u32.to_le_bytes());
        sid.extend_from_slice(&1482u32.to_le_bytes());
        assert_eq!(
            decode("odtypes:nt_sid_t", &data(&sid)).unwrap(),
            "S-1-5-21-1482"
        );
    }
}
