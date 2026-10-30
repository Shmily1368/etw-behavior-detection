#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check replay determinism and fixture provenance, without inventing accuracy."""
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    outputs = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
    inputs = [json.loads(line) for line in (ROOT / "examples/features.ndjson").read_text().splitlines()]
    assert len(outputs) == len(inputs) == 2
    for result, record in zip(outputs, inputs):
        assert result["id"] == record["id"]
        assert result["status"] == "classified"
        assert result["api_dictionary_sha256"] == record["api_dictionary_sha256"]
        assert result["input_provenance"]["kind"] == "synthetic-test"
        assert result["class_code"] and math.isfinite(result["model_score"])
        assert 0 <= result["model_score"] <= 1
    expected_path = ROOT / "examples/expected-predictions.json"
    if expected_path.exists():
        expected = json.loads(expected_path.read_text())
        for result, known in zip(outputs, expected):
            assert result["id"] == known["id"]
            assert result["class_code"] == known["class_code"]
            assert abs(result["model_score"] - known["model_score"]) < 1e-12
        print("Replay matches observed fixture predictions; no accuracy inference.")
    else:
        print("Initial replay output validated; expected classes await this first observed run.")


if __name__ == "__main__":
    main()
