#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify model/dictionary bytes and document the PMML feature subset."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / "models/manifest.json").read_text())
    model = ROOT / "models/random_forest.pmml"
    dictionary = ROOT / "models/API.csv"
    for p, key in [(model, "model_sha256"), (dictionary, "api_dictionary_sha256")]:
        if hashlib.sha256(p.read_bytes()).hexdigest() != manifest[key]:
            raise SystemExit(f"{p.name}: asset hash mismatch")
    lines = dictionary.read_text().splitlines()
    assert len(lines) == len(set(lines)) == 2863
    tree = ET.parse(model)
    ns = {"p": "http://www.dmg.org/PMML-4_4"}
    fields = tree.findall(".//p:DataField", ns)
    x_fields = [x.attrib["name"] for x in fields if x.attrib["name"].startswith("x")]
    assert len(fields) == 951 and len(x_fields) == 950
    assert all(1 <= int(x[1:]) <= 2863 for x in x_fields)
    assert len(tree.findall(".//p:TreeModel", ns)) == 100
    print("Assets verified: 2863 ordered APIs; 950 PMML feature fields; 100 trees.")


if __name__ == "__main__":
    main()
