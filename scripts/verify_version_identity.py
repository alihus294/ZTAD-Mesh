#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.+][0-9A-Za-z.-]+)?$")


def _read_runtime_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: list[str] = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "__version__" for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            values.append(value.value)
    if len(values) != 1:
        raise ValueError(f"expected exactly one literal __version__ assignment in {path}, found {len(values)}")
    return values[0]


def verify(root: Path = ROOT) -> dict[str, object]:
    errors: list[str] = []
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        errors.append(f"invalid VERSION: {version!r}")

    plugin_version = json.loads((root / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))["version"]
    pyproject_version = tomllib.loads((root / "toolkit/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    try:
        runtime_version = _read_runtime_version(root / "toolkit/ztad/__init__.py")
    except (SyntaxError, ValueError) as exc:
        runtime_version = "<invalid>"
        errors.append(str(exc))

    identities = {
        "VERSION": version,
        "plugin": plugin_version,
        "pyproject": pyproject_version,
        "runtime": runtime_version,
    }
    if len(set(identities.values())) != 1:
        errors.append("version mismatch: " + ", ".join(f"{name}={value}" for name, value in identities.items()))

    required_markers = {
        "README.md": [
            f"# Zero-Trust Agentic Delivery Mesh {version}",
            f"## What {version} implements",
        ],
        "QUICKSTART.md": [
            f"# ZTAD Mesh {version} Quick Start",
            f"`v{version}` GitHub Release",
        ],
        "docs/PLUGIN_INSTALLATION.md": [
            f"# Codex Plugin Installation — {version}",
            f"zero-trust-agentic-delivery-marketplace-{version}.zip",
            f"zero-trust-agentic-delivery-plugin-{version}.zip",
            f"plugin version `{version}`",
        ],
        "traceability/TRACEABILITY_MATRIX.md": [f"# ZTAD Mesh {version} Traceability Matrix"],
        ".github/ISSUE_TEMPLATE/bug_report.yml": [f"placeholder: {version}"],
        "CHANGELOG.md": [f"## {version} — "],
    }
    for relative, markers in required_markers.items():
        text = (root / relative).read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                errors.append(f"{relative}: missing release identity marker {marker!r}")

    generator = (root / "scripts/generate_traceability.py").read_text(encoding="utf-8")
    if 'VERSION_FILE = ROOT / "VERSION"' not in generator:
        errors.append("scripts/generate_traceability.py must derive release identity from VERSION")
    if re.search(r"ZTAD Mesh [0-9]+\.[0-9]+\.[0-9]+ Traceability Matrix", generator):
        errors.append("scripts/generate_traceability.py contains a hard-coded release identity")

    for relative in (
        "toolkit/ztad/__init__.py",
        "scripts/generate_traceability.py",
        "docs/THREAT_MODEL.md",
        "docs/SECURITY_CONTROLS.md",
        "docs/SOURCE_MAPPING.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        if "4.2.0" in text:
            errors.append(f"{relative}: stale 4.2.0 live identity remains")

    return {
        "valid": not errors,
        "version": version,
        "identities": identities,
        "errors": errors,
    }


def main() -> int:
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
