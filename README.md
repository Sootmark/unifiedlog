# unifiedlog

macOS Unified Logs (`/var/db/diagnostics` and `/var/db/uuidtext`, or a `.logarchive` from `log collect`): every log entry with its time, process, thread, activity, subsystem and category, its format string and the message it makes. One dependency, its sibling `sootmark-common` (times); no Apple tools, and no file access: the caller hands over bytes, so it builds for `wasm32` too.

```toml
[dependencies]
sootmark-unifiedlog = "0.1"
```

```rust
let archive = std::path::Path::new("system_logs.logarchive");
let mut reader = unifiedlog::Reader::new(|file: unifiedlog::StringFile| {
    std::fs::read(archive.join(file.path())).ok()
});
for timesync in std::fs::read_dir(archive.join("timesync"))? {
    reader.add_timesync(&std::fs::read(timesync?.path())?);
}
let log = reader.read(&std::fs::read(archive.join("Persist/0000000000000001.tracev3"))?);
for entry in log.entries.iter().chain(&reader.finish()) {
    println!("{:?} {} {} {} {}", entry.time(), entry.pid, entry.process, entry.subsystem, entry.message);
}
```

## What you get

- `Reader`: give it the timesync files, a `Source` for the uuidtext and shared cache strings files (any `FnMut(StringFile) -> Option<Vec<u8>>`; `StringFile::path()` is the file's path in a uuidtext directory or archive), then each tracev3 file. `read` gives a `Log`: the file's `Header` (boot, timebase, time zone, build, hardware model) and its entries; `finish` gives the entries whose items were in an oversize chunk of a file not read yet.
- `Entry`: event type (log, activity, trace, signpost, loss, simpledump, statedump) and log type (default, info, debug, error, fault, activity create, user action, process/thread/system signpost event, start and end), continuous time and UTC time (nanoseconds, from the timesync files; `time()` as a `common::time::Ts`), boot UUID, pid, effective user, thread, activity and parent activity, subsystem and category, process and library paths and UUIDs, where the format string came from (main executable, shared cache, absolute, UUID-relative), the format string (`raw_message`), the message, the items it was made from (numbers with their size, strings, raw data, `<private>`, NULL, widths and precisions), signpost identifier and name reference, backtrace frames, what a loss entry lost, a statedump's title, decoder and data, and `missing`: why a format string or the items could not be found.
- Tracev3 structure: header, catalog (processes, images and load addresses, subsystems and categories), chunksets compressed with LZ4 (`bv41`), stored (`bv4-`) or LZBITMAP (`ZBM`, written and read here without a library), firehose tracepoints and every flag-dependent field (current and other activity, unique pid, persona, private data range, formatter: main executable, shared cache, large offset, large shared cache, absolute with alternate index, UUID-relative; subsystem, TTL, oversize reference, signpost identifier and name, backtraces), private data (also collapsed chunks), oversize, statedump and simpledump chunks; uuidtext files and shared cache strings files (versions 1 and 2).
- Messages, the way Apple's `log` shows them (decoder texts checked against `log show` on macOS 26): `printf` conversions with flags, width, precision and `*` (`%d %i %u %x %X %o %p %c %C %s %S %@ %P %f %e %g %m`, lengths `hh h l ll q z j t`), `%{public}`/`%{private}`/`%{sensitive}`, values cut to fit marked `<…>`, `<private>`, `(null)` and `<Missing message data>`; decoders `bool`, `BOOL`, `errno` and `darwin.errno` (`[2: No such file or directory]`), `darwin.signal`, `darwin.mode` (`-rwxr-xr-x`), `mach.errno`, `time_t` (UTC, ISO 8601), `bytes` (`2.15 GB`), `uuid_t`, `mask.hash` (`<mask.hash: '…'>`), `network:in_addr`, `in6_addr`, `sockaddr`, `tcp_flags`, `tcp_state`, `odtypes:ODError`, `mbridtype`, `mbr_details`, `nt_sid_t`, mDNSResponder's (`mdns:dnshdr`, `dns.idflags`, `dns.counts`, `rrtype`, `protocol`, `nreason`, `addrmv`, `yesno`, `acceptable`, `gaiopts`, `time_duration`, `termination_reason`, `mdnsresponder:domain_name`, `domain_label`, `ip_addr`, `mac_addr`, `dns_scope_type`, `kev_dl_event`), Core Location's (`location:escape_only`, `CLClientAuthorizationStatus`, `CLDaemonStatus_Type::Reachability`, `CLSubHarvesterIdentifier`, `IOMessage`, `SqliteResult`, `_CLClientManagerStateTrackerState`); statedump property lists as JSON.
- Damage is reported, never a panic: a chunk, chunkset, catalog entry or tracepoint that does not read is listed in `problems` and reading goes on (a tracepoint's size is known, so the next one is still read); damaged uuidtext and shared cache files are reported too.

## Tested against

- Mandiant's [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs) reader (`unifiedlog_iterator` v0.7.0) on the six log archives of its v1.0.0 test data (Apache-2.0), and Apple's `log show` (macOS 26) on the same archives. Every entry is paired by thread and time; "structure" is the time, pid, thread, event type, log type, subsystem, category, process, library and format string all equal.

| Archive | Entries (Mandiant) | Structure as Mandiant's | Message as Mandiant's | Message as Apple's |
|---|---|---|---|---|
| High Sierra (10.13) | 569,796 | 569,763 (99.994%) | 522,887 (91.77%) | 442,314 of 442,319 (99.999%) |
| Big Sur (11) | 747,616 | 747,562 (99.993%) | 583,476 (78.05%) | 746,851 of 747,088 (99.968%) |
| Big Sur, private data on | 887,890 | 887,830 (99.993%) | 677,325 (76.29%) | 887,106 of 887,381 (99.969%) |
| Big Sur, private data mixed | 1,287,628 | 1,287,606 (99.998%) | 975,908 (75.79%) | 1,283,333 of 1,285,288 (99.848%) |
| Monterey (12) | 2,397,109 | 2,396,209 (99.962%) | 1,479,675 (61.73%) | 2,395,520 of 2,396,288 (99.968%) |
| Tahoe (26) | 4,288,584 | 4,287,666 (99.979%) | 3,491,594 (81.42%) | 4,282,226 of 4,284,489 (99.947%) |

  Apple's column leaves out statedumps (Apple's tool shows them in its own layout), High Sierra's signposts whose format string starts with their name (Apple's tool splits the name off; Mandiant's and this crate keep the string as stored), and the entries Apple's tool does not show (losses, statedumps it times differently, and entries both the live and persisted files hold: 0.03% to 0.17%).

  Every entry Mandiant's reader gives is found here, and no other (one exception: Tahoe, where Mandiant's reader also gives one "Unknown" entry it reads from misaligned bytes after a tracepoint whose padding is not zero). Where the structure differs, Mandiant writes an error text as the format string (`Error: Invalid offset …`, `Failed to get string message from …`) and this crate leaves it empty and says why in `missing`; and High Sierra's 30 trace entries have their format string here, which Mandiant leaves empty. Monterey's 531 other differences are the process path, which Mandiant leaves empty when the format string is not found and this crate still fills in. Outside the structure, the effective user of simpledumps (7% of Monterey's entries) is the catalog's here, as Apple's tool shows it; Mandiant writes 0.
  Messages differ from Mandiant's where Mandiant departs from what Apple's `log` shows (of the messages that differ from Mandiant's, 99.6% to 99.8% are Apple's; 94.5% on High Sierra, for the signpost names above): it prints `%x` and `%p` in uppercase without `0x`, floats in their shortest form rather than with C's six digits, negative numbers for `%u`, UUIDs without dashes, hashed values without `<mask.hash: '…'>`, signpost annotations with their name appended (`61 (signpost.telemetry:number2)`), `errno` values without their number, and backtrace offsets in decimal after `0x`; this crate follows Apple. Where this crate differs from Apple's `log`: Apple's tool writes times in the local time zone (`time_t` here is UTC), splits the signpost name off High Sierra signposts' format strings (kept as stored here, as Mandiant does), shows statedumps in its own layout (here, as Mandiant does: title, decoder, data as JSON), writes `<decode: missing data>` (here Mandiant's `<Missing message data>`), shows some unrecorded private values as `(null)` in an archive where private data was on for some processes only (here `<private>`: nothing in the entry tells them apart), and decodes values this crate does not yet (below).
- The fixtures in `tests/fixtures/mandiant/` (five small archives made from that test data, and an LZBITMAP copy of one tracev3 file made with macOS's own compressor): all 10,081 entries agree with Mandiant's reader on structure, and 9,681 of the 9,682 messages compared with Apple's `log show` agree (statedumps left out). `tests/oracle/` holds both readers' output and the scripts that wrote it.
- Unit tests for LZ4, LZBITMAP, timesync, tracepoint flags and formatting; arbitrary and damaged bytes (tracev3, chunksets, timesync, uuidtext and shared cache files, format strings) never panic.

## Not decoded yet

- Statedump protocol buffers (shown as Base64) and objects (Core Location's state trackers, `DNS Configuration`, `Network information`: shown as `Unsupported Statedump object: title-Base64`, as Mandiant does when it has no decoder).
- Decoders: `location:_CLLocationManagerStateTrackerState` and newer Core Location enumerations (`CLClientInUseLevel`, authorization request types), `mdns:rd.svcb`, `bluetooth:*`, `audio:4CC`, `network:tcp_packets`. Their values are shown as plain numbers, strings or data.
- Signpost names: the name's reference is given, not its text.

## License

MIT or Apache-2.0, at your option. The format knowledge comes from Mandiant's macos-UnifiedLogs and plaso's `unified_logging` format definitions (both Apache-2.0); the code is this crate's own. The test fixtures are Mandiant's test data (Apache-2.0, see `tests/fixtures/mandiant/NOTICE`).
