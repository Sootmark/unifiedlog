//! Core Location values: what its JSON-like messages show for statuses,
//! results and states. Strings are quoted, as Apple's decoders write them.

use super::json_string;

/// A client's authorization status.
pub fn authorization_status(value: i64) -> String {
    let name = match value {
        0 => Some("NotDetermined"),
        1 => Some("Restricted"),
        2 => Some("Denied"),
        3 => Some("AuthorizedAlways"),
        4 => Some("AuthorizedWhenInUse"),
        _ => None,
    };
    quoted(value, name, "CLClientAuthorizationStatus")
}

/// The daemon's network reachability.
pub fn reachability(value: i64) -> String {
    let name = match value {
        0 => Some("kReachabilityUnavailable"),
        1 => Some("kReachabilitySmall"),
        2 => Some("kReachabilityLarge"),
        1000 => Some("kReachabilityUnachievable"),
        _ => None,
    };
    quoted(value, name, "CLDaemonStatus_Type::Reachability")
}

/// A harvester's name.
pub fn subharvester(value: i64) -> String {
    const NAMES: [&str; 16] = [
        "CellLegacy",
        "Cell",
        "Wifi",
        "Tracks",
        "Realtime",
        "App",
        "Pass",
        "Indoor",
        "Pressure",
        "Poi",
        "Trace",
        "Avenger",
        "Altimeter",
        "Ionosphere",
        "ADLAvenger",
        "Unknown",
    ];
    let name = usize::try_from(value)
        .ok()
        .and_then(|i| NAMES.get(i).copied());
    quoted(value, name, "CLSubHarvesterIdentifier")
}

/// An IOKit power message's name.
pub fn io_message(value: i64) -> String {
    let name = match value as u32 {
        0xe000_0270 => Some("CanSystemSleep"),
        0xe000_0280 => Some("SystemWillSleep"),
        0xe000_0290 => Some("SystemWillNotSleep"),
        0xe000_0300 => Some("SystemHasPoweredOn"),
        0xe000_0310 => Some("SystemWillRestart"),
        0xe000_0320 => Some("SystemWillPowerOn"),
        0xe000_0330 => Some("CopyClientID"),
        0xe000_0340 => Some("SystemCapabilityChange"),
        0xe000_0350 => Some("DeviceSignaledWakeup"),
        0xe000_0010 => Some("ServiceIsTerminated"),
        0xe000_0020 => Some("ServiceIsSuspended"),
        0xe000_0030 => Some("ServiceIsResumed"),
        0xe000_0100 => Some("ServiceIsRequestingClose"),
        0xe000_0101 => Some("ServiceIsAttemptingOpen"),
        0xe000_0110 => Some("ServiceWasClosed"),
        0xe000_0120 => Some("ServiceBusyStateChange"),
        0xe000_0128 => Some("ConsoleSecurityChange"),
        0xe000_0130 => Some("ServicePropertyChange"),
        0xe000_0200 => Some("CanDevicePowerOff"),
        0xe000_0210 => Some("DeviceWillPowerOff"),
        0xe000_0220 => Some("DeviceWillNotPowerOff"),
        0xe000_0230 => Some("DeviceHasPoweredOn"),
        0xe000_0250 => Some("SystemWillPowerOff"),
        0xe000_0255 => Some("SystemPagingOff"),
        _ => None,
    };
    quoted(value, name, "IOMessage")
}

/// An SQLite result code (four bytes) by its name (`SQLITE_OK`).
pub fn sqlite_result(bytes: &[u8]) -> Option<String> {
    const NAMES: [&str; 29] = [
        "SQLITE_OK",
        "SQLITE_ERROR",
        "SQLITE_INTERNAL",
        "SQLITE_PERM",
        "SQLITE_ABORT",
        "SQLITE_BUSY",
        "SQLITE_LOCKED",
        "SQLITE_NOMEM",
        "SQLITE_READONLY",
        "SQLITE_INTERRUPT",
        "SQLITE_IOERR",
        "SQLITE_CORRUPT",
        "SQLITE_NOTFOUND",
        "SQLITE_FULL",
        "SQLITE_CANTOPEN",
        "SQLITE_PROTOCOL",
        "SQLITE_EMPTY",
        "SQLITE_SCHEMA",
        "SQLITE_TOOBIG",
        "SQLITE_CONSTRAINT",
        "SQLITE_MISMATCH",
        "SQLITE_MISUSE",
        "SQLITE_NOLFS",
        "SQLITE_AUTH",
        "SQLITE_FORMAT",
        "SQLITE_RANGE",
        "SQLITE_NOTADB",
        "SQLITE_NOTICE",
        "SQLITE_WARNING",
    ];
    let code = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    let name = match code {
        100 => Some("SQLITE_ROW"),
        101 => Some("SQLITE_DONE"),
        _ => NAMES.get(code as usize).copied(),
    };
    Some(quoted(i64::from(code), name, "SqliteResult"))
}

/// The client manager's state: whether location is restricted, and the
/// location services status.
pub fn client_manager_state(bytes: &[u8]) -> Option<String> {
    let enabled = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    let restricted = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
    Some(format!(
        "{{\"locationRestricted\":{},\"locationServicesEnabledStatus\":{enabled}}}",
        restricted != 0
    ))
}

/// A name in quotes, or, for a value with none, the failure Apple's
/// decoder reports: `{"type":"decode failure","raw value":5,"expected
/// type":"CLClientAuthorizationStatus"}`.
fn quoted(value: i64, name: Option<&str>, expected: &str) -> String {
    name.map_or_else(
        || {
            format!(
                r#"{{"type":"decode failure","raw value":{value},"expected type":"{expected}"}}"#
            )
        },
        json_string,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_quoted() {
        assert_eq!(authorization_status(2), "\"Denied\"");
        assert_eq!(reachability(2), "\"kReachabilityLarge\"");
        assert_eq!(subharvester(10), "\"Trace\"");
        assert_eq!(io_message(0xe000_0270), "\"CanSystemSleep\"");
        assert_eq!(sqlite_result(&[0, 0, 0, 0]).unwrap(), "\"SQLITE_OK\"");
        assert_eq!(
            reachability(7),
            r#"{"type":"decode failure","raw value":7,"expected type":"CLDaemonStatus_Type::Reachability"}"#
        );
        assert_eq!(
            client_manager_state(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            "{\"locationRestricted\":false,\"locationServicesEnabledStatus\":1}"
        );
    }
}
