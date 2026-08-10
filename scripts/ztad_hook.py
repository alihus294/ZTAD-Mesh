#!/usr/bin/env python3
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
TOOLKIT = ROOT / "toolkit"
if str(TOOLKIT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT))
from ztad.hooks import main
if __name__ == "__main__":
    raise SystemExit(main())
