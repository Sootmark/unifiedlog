//! Network values: addresses and socket addresses.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::items::Value;

/// An IPv4 address: four bytes, or a 32-bit number in network order.
pub fn in_addr(value: &Value) -> Option<String> {
    let octets: [u8; 4] = match value {
        Value::Number { bits, .. } => (*bits as u32).to_le_bytes(),
        Value::Bytes(bytes) => bytes.get(..4)?.try_into().ok()?,
        _ => return None,
    };
    Some(Ipv4Addr::from(octets).to_string())
}

/// A socket address: IPv4 (`a.b.c.d:port`) or IPv6 (`[addr]:port`), the
/// port left out when it is 0.
pub fn sockaddr(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some("<NULL>".to_owned());
    }
    let family = *bytes.get(1)?;
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    match family {
        2 => {
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?);
            Some(if port == 0 {
                ip.to_string()
            } else {
                format!("{ip}:{port}")
            })
        }
        30 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(8..24)?).ok()?);
            Some(if port == 0 {
                ip.to_string()
            } else {
                format!("[{ip}]:{port}")
            })
        }
        _ => Some(format!("Unknown sockaddr family: {family}")),
    }
}

/// An IPv6 address: sixteen bytes.
pub fn in6_addr(bytes: &[u8]) -> Option<String> {
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).to_string())
}

/// TCP flags as tcpdump letters (`[S.E]`): FIN, SYN, RST, PSH, ACK as a
/// dot, URG, ECE, CWR.
pub fn tcp_flags(flags: i64) -> String {
    let letters: String = [
        (0x01, 'F'),
        (0x02, 'S'),
        (0x04, 'R'),
        (0x08, 'P'),
        (0x10, '.'),
        (0x20, 'U'),
        (0x40, 'E'),
        (0x80, 'C'),
    ]
    .iter()
    .filter(|&&(bit, _)| flags & bit != 0)
    .map(|&(_, letter)| letter)
    .collect();
    format!("[{letters}]")
}

/// A TCP state's name (`SYN_SENT`).
pub fn tcp_state(state: i64) -> String {
    const NAMES: [&str; 11] = [
        "CLOSED",
        "LISTEN",
        "SYN_SENT",
        "SYN_RCVD",
        "ESTABLISHED",
        "CLOSE_WAIT",
        "FIN_WAIT_1",
        "CLOSING",
        "LAST_ACK",
        "FIN_WAIT_2",
        "TIME_WAIT",
    ];
    usize::try_from(state)
        .ok()
        .and_then(|i| NAMES.get(i))
        .map_or_else(|| state.to_string(), |&name| name.to_owned())
}
