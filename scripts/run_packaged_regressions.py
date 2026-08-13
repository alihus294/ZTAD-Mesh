#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "toolkit"))

from ztad.distribution import (  # noqa: E402
    MARKETPLACE_NAME,
    PLUGIN_NAME,
    safe_extract_archive,
    validate_distribution_archive,
)

INSTALL_CRITICAL_TESTS = (
    "tests/test_v4_cli_and_bundle.py",
    "tests/test_checks_runtime.py",
    "tests/test_cli_dispatch_regression.py",
    "tests/test_v43_guarded_fast_path.py",
    "tests/test_v43_runtime_controls.py",
)


def _run(archive: Path, kind: str, scope: str) -> int:
    validation = validate_distribution_archive(archive, kind)
    if not validation["valid"]:
        print(json.dumps({"valid": False, "stage": "archive-validation", "details": validation}, indent=2, sort_keys=True))
        return 1

    expected_top = PLUGIN_NAME if kind == "plugin" else MARKETPLACE_NAME
    with tempfile.TemporaryDirectory(prefix="ztad-packaged-regression-") as temporary:
        extracted = safe_extract_archive(
            archive.resolve(),
            Path(temporary) / "extract",
            expected_top_level=expected_top,
        )
        plugin_root = extracted if kind == "plugin" else extracted / "plugins" / PLUGIN_NAME
        if not plugin_root.is_dir() or plugin_root.is_symlink():
            print(json.dumps({"valid": False, "stage": "plugin-root", "path": str(plugin_root)}, indent=2, sort_keys=True))
            return 1

        env = os.environ.copy()
        env["PYTHONPATH"] = str(plugin_root / "toolkit")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        argv = [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        if scope == "full":
            argv.append("tests")
        else:
            argv.extend(INSTALL_CRITICAL_TESTS)

        completed = subprocess.run(argv, cwd=plugin_root, env=env, check=False)
        result = {
            "valid": completed.returncode == 0,
            "kind": kind,
            "scope": scope,
            "archive": str(archive.resolve()),
            "plugin_root": str(plugin_root),
            "pytest_exit_code": completed.returncode,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run regressions from the exact packaged ZTAD archive")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--kind", choices=("plugin", "marketplace"), required=True)
    parser.add_argument("--scope", choices=("install-critical", "full"), default="install-critical")
    args = parser.parse_args(argv)
    return _run(args.archive, args.kind, args.scope)


if __name__ == "__main__":
    raise SystemExit(main())
