"""Writes tests/oracle/apple.tsv.gz: what Apple's `log show` (macOS 26)
reads from the fixtures in tests/fixtures/mandiant/, for the messages.

One line per entry: fixture, thread, continuous time (machTimestamp),
event type, format string, message, signpost name. Timesync events are left
out.

usage (macOS only): python3 -I apple.py REPO WORK
  REPO  this repository
  WORK  an empty scratch directory
"""

import gzip
import json
import os
import shutil
import subprocess
import sys

FIELDS = ["fixture", "thread_id", "continuous_time", "event_type", "format_string", "message",
          "signpost_name"]


def tsv_value(value):
    text = str(value)
    return text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def unpack(src, dest):
    for root, _, files in os.walk(src):
        for name in files:
            path = os.path.join(root, name)
            out = os.path.join(dest, os.path.relpath(path, src))
            if out.endswith(".gz"):
                out = out[:-3]
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with gzip.open(path, "rb") as f, open(out, "wb") as o:
                shutil.copyfileobj(f, o)


def main():
    repo, work = sys.argv[1:3]
    fixtures = os.path.join(repo, "tests", "fixtures", "mandiant")
    rows = []
    for name in sorted(os.listdir(fixtures)):
        if not os.path.isdir(os.path.join(fixtures, name)):
            continue
        archive = os.path.join(work, name + ".logarchive")
        unpack(os.path.join(fixtures, name), archive)
        shown = subprocess.run(["/usr/bin/log", "show", "--archive", archive, "--style", "ndjson",
                                "--info", "--debug", "--signpost"],
                               check=True, capture_output=True, text=True).stdout
        for line in shown.splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("eventType") == "timesyncEvent":
                continue
            row = [name, e.get("threadID", 0), e.get("machTimestamp", 0), e.get("eventType", ""),
                   e.get("formatString", ""), e.get("eventMessage", ""), e.get("signpostName", "")]
            rows.append("\t".join(tsv_value(v) for v in row))
    with gzip.GzipFile(os.path.join(repo, "tests", "oracle", "apple.tsv.gz"), "wb", 9, mtime=0) as f:
        f.write(("\t".join(FIELDS) + "\n" + "\n".join(rows) + "\n").encode())


if __name__ == "__main__":
    main()
