//! mDNSResponder values: DNS headers, record types, protocols and the
//! small enumerations its messages use.

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A DNS header (12 bytes): `id: 0x8760 (34656), flags: 0x0100 (Q/Query,
/// RD, NoError), counts: 1/0/0/0`.
pub fn header(bytes: &[u8]) -> Option<String> {
    let word = |at: usize| Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?));
    let id = word(0)?;
    let flags = word(2)?;
    let counts = [word(4)?, word(6)?, word(8)?, word(10)?];
    Some(format!(
        "{}, counts: {}/{}/{}/{}",
        id_and_flags(id, flags),
        counts[0],
        counts[1],
        counts[2],
        counts[3]
    ))
}

/// An identifier and flags packed in 32 bits (`mdns:dns.idflags`).
pub fn id_flags(value: i64) -> String {
    let value = value as u32;
    id_and_flags((value >> 16) as u16, value as u16)
}

/// Four 16-bit counts packed in 64 bits (`mdns:dns.counts`): `1/0/0/0`.
pub fn counts(value: i64) -> String {
    let value = value as u64;
    format!(
        "{}/{}/{}/{}",
        value >> 48 & 0xffff,
        value >> 32 & 0xffff,
        value >> 16 & 0xffff,
        value & 0xffff
    )
}

fn id_and_flags(id: u16, flags: u16) -> String {
    format!(
        "id: {id:#06X} ({id}), flags: {flags:#06X} ({})",
        describe_flags(flags)
    )
    .replace("0X", "0x")
}

/// `Q/Query, RD, NoError`: query or response, the opcode, the flags set,
/// the response code.
fn describe_flags(flags: u16) -> String {
    let kind = if flags & 0x8000 == 0 { "Q" } else { "R" };
    let opcode = match flags >> 11 & 0xf {
        0 => "Query".to_owned(),
        1 => "IQuery".to_owned(),
        2 => "Status".to_owned(),
        4 => "Notify".to_owned(),
        5 => "Update".to_owned(),
        other => format!("Opcode{other}"),
    };
    let mut parts = vec![format!("{kind}/{opcode}")];
    for (bit, name) in [
        (0x400, "AA"),
        (0x200, "TC"),
        (0x100, "RD"),
        (0x80, "RA"),
        (0x40, "Z"),
        (0x20, "AD"),
        (0x10, "CD"),
    ] {
        if flags & bit != 0 {
            parts.push(name.to_owned());
        }
    }
    parts.push(response_code(flags & 0xf));
    parts.join(", ")
}

fn response_code(code: u16) -> String {
    let name = match code {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        6 => "YXDomain",
        7 => "YXRRSet",
        8 => "NXRRSet",
        9 => "NotAuth",
        10 => "NotZone",
        _ => return format!("RCode{code}"),
    };
    name.to_owned()
}

/// A DNS name in wire format (length-prefixed labels) as dotted text with
/// its final dot: `api.apple.com.`.
pub fn domain_name(bytes: &[u8]) -> Option<String> {
    let mut name = String::new();
    let mut at = 0;
    while let Some(&length) = bytes.get(at) {
        if length == 0 {
            break;
        }
        let label = bytes.get(at + 1..at + 1 + usize::from(length))?;
        push_label(&mut name, label);
        name.push('.');
        at += 1 + usize::from(length);
    }
    Some(if name.is_empty() {
        ".".to_owned()
    } else {
        name
    })
}

/// One DNS label (length-prefixed).
pub fn domain_label(bytes: &[u8]) -> Option<String> {
    let (&length, rest) = bytes.split_first()?;
    let mut label = String::new();
    push_label(&mut label, rest.get(..usize::from(length))?);
    Some(label)
}

/// A label in DNS presentation form: dots, spaces and backslashes escaped
/// with a backslash, other unprintable bytes as `\DDD`.
fn push_label(out: &mut String, label: &[u8]) {
    for &byte in label {
        match byte {
            b'.' | b' ' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x21..=0x7e => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\{byte:03}");
            }
        }
    }
}

/// An address with its family first (4 bytes, little-endian: 4 or 6).
pub fn ip_addr(bytes: &[u8]) -> Option<String> {
    let family = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    match family {
        4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?).to_string()),
        6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(4..20)?).ok()?).to_string()),
        _ => None,
    }
}

/// A hardware address: hex bytes joined by colons.
pub fn mac_addr(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A resource record type's name (`A`, `AAAA`, `HTTPS`).
pub fn record_type(value: i64) -> String {
    let name = match value {
        0 => "Reserved",
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        10 => "NULL",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        108 => "EUI48",
        109 => "EUI64",
        249 => "TKEY",
        250 => "TSIG",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        32768 => "TA",
        32769 => "DLV",
        _ => return format!("TYPE{value}"),
    };
    name.to_owned()
}

/// A transport's name.
pub fn protocol(value: i64) -> String {
    let name = match value {
        0 => "NULL-PROTO",
        1 => "UDP",
        2 => "TCP",
        3 => "TLS",
        4 => "HTTPS",
        _ => return value.to_string(),
    };
    name.to_owned()
}

/// Why a query got no answer.
pub fn reason(value: i64) -> String {
    let name = match value {
        0 => "none",
        1 => "no-data",
        2 => "nxdomain",
        3 => "query-suppressed",
        4 => "no-dns-service",
        5 => "server error",
        _ => return value.to_string(),
    };
    name.to_owned()
}

/// `getaddrinfo` options: `0x9 {auth-tags, use-failover}`.
pub fn getaddrinfo_options(value: i64) -> String {
    const NAMES: [(i64, &str); 6] = [
        (0x1, "auth-tags"),
        (0x2, "need-encryption"),
        (0x4, "in-app-browser"),
        (0x8, "use-failover"),
        (0x10, "prohibit-encrypted-dns"),
        (0x20, "use-cache-only"),
    ];
    let names: Vec<&str> = NAMES
        .iter()
        .filter(|&&(bit, _)| value & bit != 0)
        .map(|&(_, name)| name)
        .collect();
    format!("{:#X} {{{}}}", value as u32, names.join(", ")).replacen("0X", "0x", 1)
}

/// A duration in seconds: `1d 1h 1m 1s`, leaving out zero parts (`0s`).
pub fn duration(seconds: i64) -> String {
    let seconds = seconds.unsigned_abs();
    let parts = [
        (seconds / 86_400, 'd'),
        (seconds / 3600 % 24, 'h'),
        (seconds / 60 % 60, 'm'),
        (seconds % 60, 's'),
    ];
    let text: Vec<String> = parts
        .iter()
        .filter(|&&(n, _)| n != 0)
        .map(|&(n, unit)| format!("{n}{unit}"))
        .collect();
    if text.is_empty() {
        "0s".to_owned()
    } else {
        text.join(" ")
    }
}

/// A DNS service's scope.
pub fn scope_type(value: i64) -> String {
    let name = match value {
        0 => "Unscoped",
        1 => "Interface scoped",
        2 => "Service scoped",
        _ => return value.to_string(),
    };
    name.to_owned()
}

/// Why a session ended.
pub fn termination_reason(value: i64) -> String {
    let name = match value {
        0 => "none",
        1 => "idle",
        2 => "back-pressure",
        3 => "keepalive-timeout",
        4 => "client-error",
        5 => "server-error",
        _ => return value.to_string(),
    };
    name.to_owned()
}

/// A data-link kernel event's name (`KEV_DL_LINK_ON`); empty when there is
/// none, as Apple's decoder writes it.
pub fn data_link_event(value: i64) -> String {
    const NAMES: [&str; 30] = [
        "KEV_DL_SIFFLAGS",
        "KEV_DL_SIFMETRICS",
        "KEV_DL_SIFMTU",
        "KEV_DL_SIFPHYS",
        "KEV_DL_SIFMEDIA",
        "KEV_DL_SIFGENERIC",
        "KEV_DL_ADDMULTI",
        "KEV_DL_DELMULTI",
        "KEV_DL_IF_ATTACHED",
        "KEV_DL_IF_DETACHING",
        "KEV_DL_IF_DETACHED",
        "KEV_DL_LINK_OFF",
        "KEV_DL_LINK_ON",
        "KEV_DL_PROTO_ATTACHED",
        "KEV_DL_PROTO_DETACHED",
        "KEV_DL_LINK_ADDRESS_CHANGED",
        "KEV_DL_WAKEFLAGS_CHANGED",
        "KEV_DL_IF_IDLE_ROUTE_REFCNT",
        "KEV_DL_IFCAP_CHANGED",
        "KEV_DL_LINK_QUALITY_METRIC_CHANGED",
        "KEV_DL_NODE_PRESENCE",
        "KEV_DL_NODE_ABSENCE",
        "KEV_DL_PRIMARY_ELECTED",
        "KEV_DL_ISSUES",
        "KEV_DL_IFDELEGATE_CHANGED",
        "<Unknown Data-Link event>",
        "KEV_DL_AWDL_UNRESTRICTED",
        "KEV_DL_RRC_STATE_CHANGED",
        "KEV_DL_QOS_MODE_CHANGED",
        "KEV_DL_LOW_POWER_MODE_CHANGED",
    ];
    usize::try_from(value)
        .ok()
        .and_then(|v| v.checked_sub(1))
        .and_then(|i| NAMES.get(i))
        .map_or_else(String::new, |&name| name.to_owned())
}

/// An address added or removed.
pub fn add_remove(value: i64) -> String {
    if value == 0 { "rmv" } else { "add" }.to_owned()
}

/// A yes or no.
pub fn yes_no(value: i64) -> String {
    if value == 0 { "no" } else { "yes" }.to_owned()
}

/// Whether a response was acceptable.
pub fn acceptable(value: i64) -> String {
    if value == 0 {
        "unacceptable"
    } else {
        "acceptable"
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_flags() {
        let query = [0x87, 0x60, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            header(&query).unwrap(),
            "id: 0x8760 (34656), flags: 0x0100 (Q/Query, RD, NoError), counts: 1/0/0/0"
        );
        assert_eq!(
            id_flags(0x6ab8_8180),
            "id: 0x6AB8 (27320), flags: 0x8180 (R/Query, RD, RA, NoError)"
        );
        assert_eq!(
            id_flags(0x0000_8403),
            "id: 0x0000 (0), flags: 0x8403 (R/Query, AA, NXDomain)"
        );
        assert_eq!(counts(0x0001_0002_0001_0000), "1/2/1/0");
        assert_eq!(getaddrinfo_options(9), "0x9 {auth-tags, use-failover}");
        assert_eq!(getaddrinfo_options(0x40), "0x40 {}");
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(3600), "1h");
        assert_eq!(duration(90_061), "1d 1h 1m 1s");
        assert_eq!(duration(1_000_000), "11d 13h 46m 40s");
        assert_eq!(data_link_event(19), "KEV_DL_IFCAP_CHANGED");
        assert_eq!(data_link_event(0), "");
        assert_eq!(
            domain_name(b"\x03api\x05apple\x03com\x00").unwrap(),
            "api.apple.com."
        );
        let mut v6 = vec![6, 0, 0, 0, 0xff, 2];
        v6.extend_from_slice(&[0; 13]);
        v6.push(0xfb);
        assert_eq!(ip_addr(&v6).unwrap(), "ff02::fb");
    }
}
