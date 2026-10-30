#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Convert feature_replay TSV to explicit features-v1 NDJSON; do not infer provenance."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--dictionary", type=Path, required=True)
    parser.add_argument("--provenance-kind", choices=["synthetic-test", "collected", "imported"], required=True)
    parser.add_argument("--provenance-description", required=True)
    args = parser.parse_args()
    raw = args.dictionary.read_bytes()
    dictionary = raw.decode("utf-8").splitlines()
    if len(dictionary) != 2863 or len(set(dictionary)) != 2863:
        parser.error("dictionary must contain 2863 distinct ordered API lines")
    for number, line in enumerate(args.input.read_text().splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            parser.error(f"line {number}: expected process key, feature version and sparse values")
        key, version, sparse = fields
        if not sparse:
            parser.error(f"line {number}: no committed features; legacy pending groups are not automatically flushed")
        values = []
        for entry in sparse.split(","):
            index, weight = entry.split("_")
            values.append([int(index), float(weight)])
        print(json.dumps({
            "schema_version": "features-v1", "id": key, "feature_version": version,
            "dimensions": 2863, "api_dictionary_sha256": hashlib.sha256(raw).hexdigest(),
            "values": values,
            "provenance": {"kind": args.provenance_kind, "description": args.provenance_description},
        }, separators=(",", ":")))


if __name__ == "__main__":
    main()
