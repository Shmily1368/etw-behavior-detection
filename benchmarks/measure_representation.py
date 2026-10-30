#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Measure file representations, not network bandwidth or detection accuracy."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("files", nargs="+", type=Path)
    args = p.parse_args()
    for path in args.files:
        data = path.read_bytes()
        lines = sum(bool(x.strip()) for x in data.splitlines())
        print(json.dumps({
            "file": path.name, "sha256": hashlib.sha256(data).hexdigest(),
            "file_bytes": len(data), "gzip_bytes": len(gzip.compress(data, mtime=0)),
            "nonempty_records": lines, "bytes_per_record": len(data)/lines if lines else None,
            "scope": "file contents only; excludes Kafka and network framing",
        }, separators=(",", ":")))


if __name__ == "__main__":
    main()
