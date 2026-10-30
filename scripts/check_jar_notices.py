#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify downloadable detector artifacts retain project and dependency notices."""
import sys
import zipfile
from pathlib import Path


def main():
    with zipfile.ZipFile(Path(sys.argv[1])) as jar:
        assert b"GNU AFFERO GENERAL PUBLIC LICENSE" in jar.read("META-INF/LICENSE-project")
        assert b"Shmily1368" in jar.read("META-INF/NOTICE-project")
        notices = [name for name in jar.namelist() if name.startswith("META-INF/dependency-notices/") and not name.endswith("/")]
        assert notices, "dependency notices were not packaged"
        print(f"Project AGPL/NOTICE and {len(notices)} dependency notice resources preserved.")


if __name__ == "__main__":
    main()
