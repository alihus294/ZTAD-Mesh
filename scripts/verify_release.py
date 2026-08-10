#!/usr/bin/env python3
"""Dependency-free verifier for a ZTAD release directory."""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify files listed by a ZTAD CHECKSUMS.sha256 file")
    parser.add_argument("checksums", nargs="?", default="CHECKSUMS.sha256")
    args = parser.parse_args(argv)
    checksum_file = Path(args.checksums).resolve()
    if not checksum_file.is_file() or checksum_file.is_symlink():
        print(f"ERROR: checksum file is not a regular file: {checksum_file}", file=sys.stderr)
        return 2

    seen: set[str] = set()
    failures = 0
    entries = 0
    for line_number, line in enumerate(checksum_file.read_text(encoding="utf-8").splitlines(), 1):
        match = LINE.fullmatch(line)
        if not match:
            print(f"ERROR: malformed checksum line {line_number}", file=sys.stderr)
            failures += 1
            continue
        expected, name = match.groups()
        if name in seen:
            print(f"ERROR: duplicate checksum entry: {name}", file=sys.stderr)
            failures += 1
            continue
        seen.add(name)
        entries += 1
        target = checksum_file.parent / name
        if not target.is_file() or target.is_symlink():
            print(f"MISSING: {name}")
            failures += 1
            continue
        actual = sha256(target)
        if actual == expected:
            print(f"OK: {name}")
        else:
            print(f"FAILED: {name}")
            failures += 1

    if entries == 0:
        print("ERROR: checksum file has no entries", file=sys.stderr)
        return 2
    if failures:
        print(f"Verification failed: {failures} issue(s).", file=sys.stderr)
        return 1
    print(f"Verification passed: {entries} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
