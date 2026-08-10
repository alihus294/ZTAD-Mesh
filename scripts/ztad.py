#!/usr/bin/env python3
"""Portable entry point for the bundled or repository-installed ZTAD toolkit."""
from pathlib import Path
import sys

here = Path(__file__).resolve()
toolkit = here.parents[1] / "toolkit"
if not toolkit.is_dir():
    raise SystemExit(f"ZTAD toolkit not found at {toolkit}")
sys.path.insert(0, str(toolkit))
from ztad.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
