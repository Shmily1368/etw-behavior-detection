#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded multi-client load generation inspired by the original ReadData scheduler."""
import argparse
import json
import sys
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--clients", type=int, default=1)
    p.add_argument("--rate", type=float, default=10, help="total scheduled records/second")
    p.add_argument("--records", type=int, required=True)
    args = p.parse_args()
    if not 1 <= args.clients <= 10000 or not 0 < args.rate <= 100000 or not 1 <= args.records <= 1000000:
        p.error("clients/rate/records outside bounded ranges")
    rows = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    if not rows:
        p.error("no input records")
    start = time.monotonic()
    try:
        for i in range(args.records):
            target = start + i / args.rate
            remaining = target - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            print(json.dumps({
                "simulation": True, "sequence": i, "client": f"simulated-{i % args.clients}",
                "scheduled_offset_seconds": i / args.rate,
                "actual_offset_seconds": time.monotonic() - start,
                "record": rows[i % len(rows)],
            }, separators=(",", ":")), flush=True)
    except BrokenPipeError:
        return
    elapsed = time.monotonic() - start
    print(json.dumps({"generated": args.records, "elapsed_seconds": elapsed,
                      "scope": "simulated client schedule to stdout; not distributed network measurement"}), file=sys.stderr)


if __name__ == "__main__":
    main()
