from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_bug_lifecycle_cli_bootstraps_bundled_toolkit_under_python_isolated_mode(tmp_path: Path):
    proc = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts/ztad_bug_lifecycle.py"), "--help"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "exact fail-closed bug-to-production lifecycle" in proc.stdout
