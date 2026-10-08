//! Open Directory values: errors, membership types and details, and
//! Windows security identifiers.

use std::fmt::Write;

/// An Open Directory error's name.
pub fn od_error(code: i64) -> String {
    OD_ERRORS
        .iter()
        .find(|&&(c, _)| i64::from(c) == code)
        .map_or_else(|| code.to_string(), |&(_, name)| name.to_owned())
}

/// A membership identifier type's name (`membership.h`).
pub fn member_id_type(code: i64) -> String {
    let name = match code {
        0 => "UID",
        1 => "GID",
        3 => "SID",
        4 => "Username",
        5 => "Groupname",
        6 => "UUID",
        7 => "Group NFSv4",
        8 => "User NFSv4",
        10 => "GSS Exported Name",
        11 => "X509 DN",
        12 => "Kerberos ID",
        _ => return format!("Unknown type {code}"),
    };
    name.to_owned()
}

/// A membership lookup's details: `user: 501@/Local/Default`.
pub fn member_details(bytes: &[u8]) -> Option<String> {
    let (&kind, rest) = bytes.split_first()?;
    let (who, rest) = match kind {
        35 | 163 => (
            format!(
                "user: {}",
                i32::from_le_bytes(rest.get(..4)?.try_into().ok()?)
            ),
            &rest[4..],
        ),
        195 => (
            format!(
                "group: {}",
                i32::from_le_bytes(rest.get(..4)?.try_into().ok()?)
            ),
            &rest[4..],
        ),
        36 | 160 | 164 | 68 => {
            let end = rest.iter().position(|&b| b == 0)?;
            let label = if kind == 68 { "group" } else { "user" };
            let name = String::from_utf8_lossy(&rest[..end]);
            (format!("{label}: {name}"), &rest[end + 1..])
        }
        _ => (format!("Unknown Member type {kind}: @"), rest),
    };
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(if end == 0 {
        format!("{who} <not found>")
    } else {
        format!("{who}@{}", String::from_utf8_lossy(&rest[..end]))
    })
}

/// A Windows security identifier: `S-1-5-21-…`.
pub fn sid(bytes: &[u8]) -> Option<String> {
    let revision = *bytes.first()?;
    let count = usize::from(*bytes.get(1)?);
    let authority = bytes
        .get(2..8)?
        .iter()
        .fold(0u64, |n, &b| n << 8 | u64::from(b));
    let mut out = format!("S-{revision}-{authority}");
    for at in 0..count {
        let start = 8 + at * 4;
        let sub = u32::from_le_bytes(bytes.get(start..start + 4)?.try_into().ok()?);
        let _ = write!(out, "-{sub}");
    }
    Some(out)
}

/// Open Directory error codes and names (`ODFrameworkErrors`).
const OD_ERRORS: [(u16, &str); 64] = [
    (0, "ODNoError"),
    (2, "Not Found"),
    (1000, "ODErrorSessionLocalOnlyDaemonInUse"),
    (1001, "ODErrorSessionNormalDaemonInUse"),
    (1002, "ODErrorSessionDaemonNotRunning"),
    (1003, "ODErrorSessionDaemonRefused"),
    (1100, "ODErrorSessionProxyCommunicationError"),
    (1101, "ODErrorSessionProxyVersionMismatch"),
    (1102, "ODErrorSessionProxyIPUnreachable"),
    (1103, "ODErrorSessionProxyUnknownHost"),
    (2000, "ODErrorNodeUnknownName"),
    (2001, "ODErrorNodeUnknownType"),
    (2002, "ODErrorNodeDisabled"),
    (2100, "ODErrorNodeConnectionFailed"),
    (2200, "ODErrorNodeUnknownHost"),
    (3000, "ODErrorQuerySynchronize"),
    (3100, "ODErrorQueryInvalidMatchType"),
    (3101, "ODErrorQueryUnsupportedMatchType"),
    (3102, "ODErrorQueryTimeout"),
    (4000, "ODErrorRecordReadOnlyNode"),
    (4001, "ODErrorRecordPermissionError"),
    (4100, "ODErrorRecordParameterError"),
    (4101, "ODErrorRecordInvalidType"),
    (4102, "ODErrorRecordAlreadyExists"),
    (4103, "ODErrorRecordTypeDisabled"),
    (4104, "ODErrorRecordNoLongerExists"),
    (4200, "ODErrorRecordAttributeUnknownType"),
    (4201, "ODErrorRecordAttributeNotFound"),
    (4202, "ODErrorRecordAttributeValueSchemaError"),
    (4203, "ODErrorRecordAttributeValueNotFound"),
    (5000, "ODErrorCredentialsInvalid"),
    (5001, "ODErrorCredentialsInvalidComputer"),
    (5100, "ODErrorCredentialsMethodNotSupported"),
    (5101, "ODErrorCredentialsNotAuthorized"),
    (5102, "ODErrorCredentialsParameterError"),
    (5103, "ODErrorCredentialsOperationFailed"),
    (5200, "ODErrorCredentialsServerUnreachable"),
    (5201, "ODErrorCredentialsServerNotFound"),
    (5202, "ODErrorCredentialsServerError"),
    (5203, "ODErrorCredentialsServerTimeout"),
    (5204, "ODErrorCredentialsContactPrimary"),
    (5205, "ODErrorCredentialsServerCommunicationError"),
    (5300, "ODErrorCredentialsAccountNotFound"),
    (5301, "ODErrorCredentialsAccountDisabled"),
    (5302, "ODErrorCredentialsAccountExpired"),
    (5303, "ODErrorCredentialsAccountInactive"),
    (5304, "ODErrorCredentialsAccountTemporarilyLocked"),
    (5305, "ODErrorCredentialsAccountLocked"),
    (5400, "ODErrorCredentialsPasswordExpired"),
    (5401, "ODErrorCredentialsPasswordChangeRequired"),
    (5402, "ODErrorCredentialsPasswordQualityFailed"),
    (5403, "ODErrorCredentialsPasswordTooShort"),
    (5404, "ODErrorCredentialsPasswordTooLong"),
    (5405, "ODErrorCredentialsPasswordNeedsLetter"),
    (5406, "ODErrorCredentialsPasswordNeedsDigit"),
    (5407, "ODErrorCredentialsPasswordChangeTooSoon"),
    (5408, "ODErrorCredentialsPasswordUnrecoverable"),
    (5500, "ODErrorCredentialsInvalidLogonHours"),
    (6000, "ODErrorPolicyUnsupported"),
    (6001, "ODErrorPolicyOutOfRange"),
    (10000, "ODErrorPluginOperationNotSupported"),
    (10001, "ODErrorPluginError"),
    (10002, "ODErrorDaemonError"),
    (10003, "ODErrorPluginOperationTimeout"),
];
