"""Builds tests/fixtures/mandiant/ and tests/oracle/mandiant.tsv.gz from
Mandiant's test data (macos-UnifiedLogs v1.0.0, test_data.zip, Apache-2.0)
and Mandiant's reader (unifiedlog_iterator v0.7.0).

Each fixture is a small log archive: a few tracev3 files (one cut at a
catalog boundary), the timesync files, and the uuidtext and shared cache
strings files its entries use, with every format string its entries do not
use overwritten with zeros (so the files compress to little). The script
checks that Mandiant's reader gives the same output for the stripped
archive as for the full one.

usage: python3 -I make_fixtures.py TEST_DATA ITERATOR WORK REPO
  TEST_DATA  the unzipped test_data directory
  ITERATOR   unifiedlog_iterator
  WORK       an empty scratch directory
  REPO       this repository
"""

import gzip
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

# name, archive, tracev3 files, where to cut the first file (None: whole).
FIXTURES = [
    ("big_sur", "system_logs_big_sur.logarchive",
     ["Special/0000000000000001.tracev3", "Signpost/0000000000000001.tracev3"], None),
    ("high_sierra", "system_logs_high_sierra.logarchive",
     ["Special/0000000000000002.tracev3"], None),
    ("monterey", "system_logs_monterey.logarchive",
     ["Persist/000000000000000f.tracev3"], 75032),
    ("big_sur_private", "system_logs_big_sur_private_enabled.logarchive",
     ["Signpost/0000000000000006.tracev3"], None),
    ("tahoe", "system_logs_tahoe.logarchive",
     ["Special/0000000000000010.tracev3"], None),
]

TSV_FIELDS = ["file", "time", "thread_id", "pid", "euid", "event_type", "log_type",
              "activity_id", "parent_activity_id", "subsystem", "category", "process",
              "process_uuid", "library", "library_uuid", "raw_message", "message"]


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def run_iterator(iterator, archive, out):
    if os.path.exists(out):
        os.remove(out)
    subprocess.run([iterator, "-m", "log-archive", "-i", archive, "-o", out, "-f", "jsonl"],
                   check=True, stderr=subprocess.DEVNULL)
    with open(out) as f:
        return [json.loads(line) for line in f]


def copy_base(source, dest, files, cut, notice):
    """The tracev3 files (the first one cut), the timesync files, Info.plist."""
    for i, rel in enumerate(files):
        os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(source, rel), "rb") as f:
            data = f.read()
        notice.append((rel, sha256(os.path.join(source, rel)),
                       f"cut to its first {cut} bytes" if i == 0 and cut else ""))
        if i == 0 and cut:
            data = data[:cut]
        with open(os.path.join(dest, rel), "wb") as f:
            f.write(data)
    shutil.copytree(os.path.join(source, "timesync"), os.path.join(dest, "timesync"))
    for name in sorted(os.listdir(os.path.join(source, "timesync"))):
        notice.append((f"timesync/{name}", sha256(os.path.join(source, "timesync", name)), ""))
    shutil.copy(os.path.join(source, "Info.plist"), os.path.join(dest, "Info.plist"))
    notice.append(("Info.plist", sha256(os.path.join(source, "Info.plist")), ""))


def link_strings(source, dest):
    """Every uuidtext directory and the dsc directory, by symlink."""
    for name in os.listdir(source):
        if len(name) == 2 or name == "dsc":
            os.symlink(os.path.join(source, name), os.path.join(dest, name))


def strings_in(data, start, size):
    """The NUL-terminated strings in data[start:start+size], with where each
    starts and ends."""
    end = start + size
    at = start
    while at < end:
        nul = data.find(b"\0", at, end)
        stop = end if nul < 0 else nul
        yield at, stop, bytes(data[at:stop]).decode("utf-8", "replace")
        at = stop + 1


def wanted(data, spans, needed):
    """The needed strings this file holds: each kept where it is whole, or,
    when nowhere whole, where another string ends with it (linkers merge
    string tails)."""
    present = {text for start, size in spans for _, _, text in strings_in(data, start, size)}
    whole = needed & present
    tails = {n for n in needed - present if n}
    return whole, tails


def strip_strings(data, spans, needed):
    """Zeros every string in the spans that is not wanted."""
    whole, tails = wanted(data, spans, needed)
    for start, size in spans:
        for at, stop, text in list(strings_in(data, start, size)):
            if text not in whole and not any(text.endswith(t) for t in tails):
                data[at:stop] = b"\0" * (stop - at)


def strip_uuidtext(data, needed):
    data = bytearray(data)
    count = struct.unpack_from("<I", data, 12)[0]
    spans = []
    at = 16 + 8 * count
    for i in range(count):
        size = struct.unpack_from("<I", data, 16 + 8 * i + 4)[0]
        spans.append((at, size))
        at += size
    strip_strings(data, spans, needed)
    return bytes(data)


def image_uuids(data, start, count, size):
    """The shared cache's image UUIDs (each 16 bytes before an entry's last
    four, the path offset)."""
    uuids = []
    for i in range(count):
        end = start + (i + 1) * size - 4
        uuids.append(bytes(data[end - 16:end]).hex().upper())
    return uuids


def strip_dsc(data, needed, images):
    """Zeros unused format strings, and drops the ranges left with none
    (but the first, and those of the entries' images): the image table
    moves up behind the shorter range table, so every file offset stays
    valid."""
    data = bytearray(data)
    major = struct.unpack_from("<H", data, 4)[0]
    ranges, image_count = struct.unpack_from("<II", data, 8)
    range_size, image_size = (24, 32) if major >= 2 else (16, 28)
    table = []
    for i in range(ranges):
        at = 16 + i * range_size
        if major >= 2:
            _, offset, size, image = struct.unpack_from("<QIIQ", data, at)
        else:
            image, _, offset, size = struct.unpack_from("<IIII", data, at)
        table.append((at, offset, size, image))
    strip_strings(data, [(offset, size) for _, offset, size, _ in table], needed)
    image_start = 16 + ranges * range_size
    uuids = image_uuids(data, image_start, image_count, image_size)

    def keep(i, offset, size, image):
        used = image < len(uuids) and uuids[image] in images
        return i == 0 or any(data[offset:offset + size]) or used

    kept = [bytes(data[at:at + range_size]) for i, (at, offset, size, image) in enumerate(table)
            if keep(i, offset, size, image)]
    tables_end = image_start + image_count * image_size
    tables = b"".join(kept) + bytes(data[image_start:tables_end])
    data[8:12] = struct.pack("<I", len(kept))
    data[16:tables_end] = tables + b"\0" * (tables_end - 16 - len(tables))
    return bytes(data)


def stripped_strings(source, dest, entries, dsc_names, notice):
    """The uuidtext files of the entries' images and the shared cache
    strings files they use, with unused format strings zeroed."""
    needed = {e["raw_message"] for e in entries}
    uuids = {e[k] for e in entries for k in ("library_uuid", "process_uuid") if e[k]}
    for uuid in sorted(uuids):
        rel = f"{uuid[:2]}/{uuid[2:]}"
        path = os.path.join(source, rel)
        if not os.path.isfile(path):
            continue
        os.makedirs(os.path.join(dest, uuid[:2]), exist_ok=True)
        with open(path, "rb") as f:
            data = strip_uuidtext(f.read(), needed)
        with open(os.path.join(dest, rel), "wb") as f:
            f.write(data)
        notice.append((rel, sha256(path), "unused format strings zeroed"))
    os.makedirs(os.path.join(dest, "dsc"))
    for name in dsc_names:
        path = os.path.join(source, "dsc", name)
        with open(path, "rb") as f:
            data = strip_dsc(f.read(), needed, uuids)
        with open(os.path.join(dest, "dsc", name), "wb") as f:
            f.write(data)
        notice.append((f"dsc/{name}", sha256(path), "unused format strings and their ranges removed"))


def used_shared_caches(iterator, source, full, entries, work):
    """The shared cache strings files the entries need: those without which
    Mandiant's output changes."""
    names = sorted(os.listdir(os.path.join(source, "dsc")))
    os.remove(os.path.join(full, "dsc"))
    os.makedirs(os.path.join(full, "dsc"))
    used = []
    for name in names:
        for other in names:
            link = os.path.join(full, "dsc", other)
            if os.path.lexists(link):
                os.remove(link)
            if other != name:
                os.symlink(os.path.join(source, "dsc", other), link)
        without = run_iterator(iterator, full, os.path.join(work, "without.jsonl"))
        if without_evidence(without) != without_evidence(entries):
            used.append(name)
    return used


def without_evidence(entries):
    """Entries to compare: without the file path, and without the data of
    protocol buffer statedumps (Mandiant writes their fields in hash map
    order, which changes from run to run)."""
    out = []
    for e in entries:
        e = {k: v for k, v in e.items() if k != "evidence"}
        if e["event_type"] == "Statedump" and '"wire_type"' in e["message"]:
            e["message"] = e["message"].split("\n{", 1)[0]
        out.append(e)
    return out


def tsv_value(value):
    text = str(value)
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def tsv_rows(name, archive_dir, entries):
    rows = []
    for e in entries:
        rel = os.path.relpath(e["evidence"], archive_dir)
        row = dict(e, file=f"{name}/{rel}", time=round(e["time"]))
        rows.append("\t".join(tsv_value(row[k]) for k in TSV_FIELDS))
    return rows


def gzip_tree(src, dest):
    for root, _, files in os.walk(src):
        for name in files:
            path = os.path.join(root, name)
            out = os.path.join(dest, os.path.relpath(path, src)) + ".gz"
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(path, "rb") as f, open(out, "wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as g:
                    g.write(f.read())


def main():
    test_data, iterator, work, repo = sys.argv[1:5]
    fixtures = os.path.join(repo, "tests", "fixtures", "mandiant")
    rows = []
    notice = []
    for name, archive, files, cut in FIXTURES:
        source = os.path.join(test_data, archive)
        full = os.path.join(work, name + ".full")
        mini = os.path.join(work, name)
        os.makedirs(full)
        os.makedirs(mini)
        fixture_notice = []
        copy_base(source, full, files, cut, fixture_notice)
        copy_base(source, mini, files, cut, [])
        link_strings(source, full)
        entries = run_iterator(iterator, full, os.path.join(work, name + ".full.jsonl"))
        dsc_names = used_shared_caches(iterator, source, full, entries, work)
        stripped_strings(source, mini, entries, dsc_names, fixture_notice)
        check = run_iterator(iterator, mini, os.path.join(work, name + ".jsonl"))
        assert without_evidence(check) == without_evidence(entries), name
        rows += tsv_rows(name, mini, check)
        gzip_tree(mini, os.path.join(fixtures, name))
        notice += [(f"{name}/{rel}", digest, note) for rel, digest, note in fixture_notice]
    with gzip.GzipFile(os.path.join(repo, "tests", "oracle", "mandiant.tsv.gz"), "wb", 9, mtime=0) as f:
        f.write(("\t".join(TSV_FIELDS) + "\n" + "\n".join(rows) + "\n").encode())
    with open(os.path.join(work, "notice.txt"), "w") as f:
        for rel, digest, note in notice:
            f.write(f"  {rel}  {digest}{'  (' + note + ')' if note else ''}\n")


if __name__ == "__main__":
    main()
