//! Darwin values: error numbers, signals, file modes and times.

use common::time::civil_from_days;

/// `[2: No such file or directory]`; 0 is `Success`.
pub fn errno(code: i64) -> String {
    let message = if code == 0 {
        "Success".to_owned()
    } else {
        strerror(code)
    };
    format!("[{code}: {message}]")
}

/// An error number's text, as `strerror` gives it (`%m`).
pub fn strerror(code: i64) -> String {
    usize::try_from(code)
        .ok()
        .and_then(|i| ERRNO.get(i))
        .map_or_else(|| format!("Unknown error: {code}"), |&m| m.to_owned())
}

/// `[sigsegv: Segmentation fault]`-style text: the signal's name and its
/// description.
pub fn signal(code: i64) -> String {
    match usize::try_from(code).ok().and_then(|i| SIGNALS.get(i)) {
        Some(_) if code == 0 => "[sigSignal 0: Signal 0]".to_owned(),
        Some((name, description)) => format!("[{name}: {description}]"),
        None => format!("[{code}: Unknown signal]"),
    }
}

/// `[0x10000003: (ipc/send) invalid destination port]`: a Mach error and
/// its text, for the message errors (`mach/message.h`).
pub fn mach_error(code: i64) -> String {
    let code = code as u32;
    let text = MACH_ERRORS
        .iter()
        .find(|&&(c, _)| c == code)
        .map_or("unknown error", |&(_, text)| text);
    format!("[{code:#x}: {text}]")
}

/// A byte count in SI units with three significant digits: `1 B`,
/// `1.02 kB`, `2.15 GB`.
pub fn byte_count(bytes: i64) -> String {
    const UNITS: [&str; 6] = ["kB", "MB", "GB", "TB", "PB", "EB"];
    if bytes.unsigned_abs() < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    for unit in UNITS {
        value /= 1000.0;
        if value.abs() < 999.5 {
            return format!("{} {unit}", three_digits(value));
        }
    }
    format!("{bytes} B")
}

/// A number with three significant digits, no trailing zeros (`%.3g`).
fn three_digits(value: f64) -> String {
    let decimals = match value.abs() {
        v if v < 9.995 => 2,
        v if v < 99.95 => 1,
        _ => 0,
    };
    let text = format!("{value:.decimals$}");
    if text.contains('.') {
        text.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        text
    }
}

/// `-rwxr-xr-x`: the file type and permission bits, as `ls -l` shows them.
pub fn mode(mode: i64) -> String {
    let mode = mode as u32;
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '-',
    };
    let mut out = String::from(kind);
    for (shift, special, set, unset) in [
        (6, 0o4000, 's', 'S'),
        (3, 0o2000, 's', 'S'),
        (0, 0o1000, 't', 'T'),
    ] {
        let bits = mode >> shift & 7;
        out.push(if bits & 4 != 0 { 'r' } else { '-' });
        out.push(if bits & 2 != 0 { 'w' } else { '-' });
        out.push(match (bits & 1 != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    out
}

/// Seconds since 1970 as an ISO 8601 UTC time, to the millisecond.
pub fn time(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let in_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        in_day / 3600,
        in_day / 60 % 60,
        in_day % 60
    )
}

/// `strerror` texts, by error number (macOS).
const ERRNO: [&str; 107] = [
    "Undefined error: 0",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted system call",
    "Input/output error",
    "Device not configured",
    "Argument list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource deadlock avoided",
    "Cannot allocate memory",
    "Permission denied",
    "Bad address",
    "Block device required",
    "Resource busy",
    "File exists",
    "Cross-device link",
    "Operation not supported by device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate ioctl for device",
    "Text file busy",
    "File too large",
    "No space left on device",
    "Illegal seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Numerical argument out of domain",
    "Result too large",
    "Resource temporarily unavailable",
    "Operation now in progress",
    "Operation already in progress",
    "Socket operation on non-socket",
    "Destination address required",
    "Message too long",
    "Protocol wrong type for socket",
    "Protocol not available",
    "Protocol not supported",
    "Socket type not supported",
    "Operation not supported",
    "Protocol family not supported",
    "Address family not supported by protocol family",
    "Address already in use",
    "Can't assign requested address",
    "Network is down",
    "Network is unreachable",
    "Network dropped connection on reset",
    "Software caused connection abort",
    "Connection reset by peer",
    "No buffer space available",
    "Socket is already connected",
    "Socket is not connected",
    "Can't send after socket shutdown",
    "Too many references: can't splice",
    "Operation timed out",
    "Connection refused",
    "Too many levels of symbolic links",
    "File name too long",
    "Host is down",
    "No route to host",
    "Directory not empty",
    "Too many processes",
    "Too many users",
    "Disc quota exceeded",
    "Stale NFS file handle",
    "Too many levels of remote in path",
    "RPC struct is bad",
    "RPC version wrong",
    "RPC prog. not avail",
    "Program version wrong",
    "Bad procedure for program",
    "No locks available",
    "Function not implemented",
    "Inappropriate file type or format",
    "Authentication error",
    "Need authenticator",
    "Device power is off",
    "Device error",
    "Value too large to be stored in data type",
    "Bad executable (or shared library)",
    "Bad CPU type in executable",
    "Shared library version mismatch",
    "Malformed Mach-o file",
    "Operation canceled",
    "Identifier removed",
    "No message of desired type",
    "Illegal byte sequence",
    "Attribute not found",
    "Bad message",
    "EMULTIHOP (Reserved)",
    "No message available on STREAM",
    "ENOLINK (Reserved)",
    "No STREAM resources",
    "Not a STREAM",
    "Protocol error",
    "STREAM ioctl timeout",
    "Operation not supported on socket",
    "Policy not found",
    "State not recoverable",
    "Previous owner died",
    "Interface output queue is full",
];

/// Signal names and descriptions, by number (macOS).
const SIGNALS: [(&str, &str); 32] = [
    ("", ""),
    ("sighup", "Hangup"),
    ("sigint", "Interrupt"),
    ("sigquit", "Quit"),
    ("sigill", "Illegal instruction"),
    ("sigtrap", "Trace/BPT trap"),
    ("sigabrt", "Abort trap"),
    ("sigemt", "EMT trap"),
    ("sigfpe", "Floating point exception"),
    ("sigkill", "Killed"),
    ("sigbus", "Bus error"),
    ("sigsegv", "Segmentation fault"),
    ("sigsys", "Bad system call"),
    ("sigpipe", "Broken pipe"),
    ("sigalrm", "Alarm clock"),
    ("sigterm", "Terminated"),
    ("sigurg", "Urgent I/O condition"),
    ("sigstop", "Suspended (signal)"),
    ("sigtstp", "Suspended"),
    ("sigcont", "Continued"),
    ("sigchld", "Child exited"),
    ("sigttin", "Stopped (tty input)"),
    ("sigttou", "Stopped (tty output)"),
    ("sigio", "I/O possible"),
    ("sigxcpu", "Cputime limit exceeded"),
    ("sigxfsz", "Filesize limit exceeded"),
    ("sigvtalrm", "Virtual timer expired"),
    ("sigprof", "Profiling timer expired"),
    ("sigwinch", "Window size changes"),
    ("siginfo", "Information request"),
    ("sigusr1", "User defined signal 1"),
    ("sigusr2", "User defined signal 2"),
];

/// Mach message errors and their texts.
const MACH_ERRORS: [(u32, &str); 29] = [
    (0x0, "(os/kern) successful"),
    (0x1000_0001, "(ipc/send) send in progress"),
    (0x1000_0002, "(ipc/send) invalid data"),
    (0x1000_0003, "(ipc/send) invalid destination port"),
    (0x1000_0004, "(ipc/send) timed out"),
    (0x1000_0005, "(ipc/send) invalid voucher"),
    (0x1000_0007, "(ipc/send) interrupted"),
    (0x1000_0008, "(ipc/send) message too small"),
    (0x1000_0009, "(ipc/send) invalid reply port"),
    (0x1000_000a, "(ipc/send) invalid port right"),
    (0x1000_000b, "(ipc/send) invalid notify port"),
    (0x1000_000c, "(ipc/send) invalid memory"),
    (0x1000_000d, "(ipc/send) no buffer for message"),
    (0x1000_000e, "(ipc/send) message too large"),
    (0x1000_000f, "(ipc/send) invalid msg-type"),
    (0x1000_0010, "(ipc/send) invalid header"),
    (0x1000_0011, "(ipc/send) invalid trailer"),
    (0x1000_4001, "(ipc/rcv) receive in progress"),
    (0x1000_4002, "(ipc/rcv) invalid name"),
    (0x1000_4003, "(ipc/rcv) timed out"),
    (0x1000_4004, "(ipc/rcv) msg too large"),
    (0x1000_4005, "(ipc/rcv) interrupted"),
    (0x1000_4006, "(ipc/rcv) port moved into set"),
    (0x1000_4007, "(ipc/rcv) invalid notify port"),
    (0x1000_4008, "(ipc/rcv) invalid msg-buffer"),
    (0x1000_4009, "(ipc/rcv) port has been destroyed"),
    (0x1000_400a, "(ipc/rcv) port in set"),
    (0x1000_400b, "(ipc/rcv) header error"),
    (0x1000_400c, "(ipc/rcv) body error"),
];
