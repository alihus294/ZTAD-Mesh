#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def _read_required(root: Path, relative: str, errors: list[str]) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        errors.append(f"{relative}: missing regular release-identity surface")
        return ""
    return path.read_text(encoding="utf-8")


def verify(root: Path = ROOT, *, profile: str = "source") -> dict[str, object]:
    if profile not in {"source", "distribution"}:
        raise ValueError("profile must be 'source' or 'distribution'")

    root = root.resolve()
    errors: list[str] = []
    version_text = _read_required(root, "VERSION", errors)
    version = version_text.strip()
    if not SEMVER.fullmatch(version):
        errors.append(f"invalid VERSION: {version!r}")

    plugin_text = _read_required(root, ".codex-plugin/plugin.json", errors)
    pyproject_text = _read_required(root, "toolkit/pyproject.toml", errors)
    runtime_path = root / "toolkit/ztad/__init__.py"

    try:
        plugin_version = json.loads(plugin_text)["version"] if plugin_text else "<missing>"
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        plugin_version = "<invalid>"
        errors.append(f".codex-plugin/plugin.json: invalid version metadata: {exc}")
    try:
        pyproject_version = tomllib.loads(pyproject_text)["project"]["version"] if pyproject_text else "<missing>"
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        pyproject_version = "<invalid>"
        errors.append(f"toolkit/pyproject.toml: invalid version metadata: {exc}")
    try:
        if not runtime_path.is_file() or runtime_path.is_symlink():
            raise ValueError(f"missing regular runtime version surface: {runtime_path}")
        runtime_version = _read_runtime_version(runtime_path)
    except (OSError, SyntaxError, ValueError) as exc:
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

    packaged_markers = {
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
        "CHANGELOG.md": [f"## {version} — "],
    }
    source_only_markers = {
        ".github/ISSUE_TEMPLATE/bug_report.yml": [f"placeholder: {version}"],
    }

    required_markers = dict(packaged_markers)
    if profile == "source":
        required_markers.update(source_only_markers)
    for relative, markers in required_markers.items():
        text = _read_required(root, relative, errors)
        for marker in markers:
            if marker not in text:
                errors.append(f"{relative}: missing release identity marker {marker!r}")

    generator = _read_required(root, "scripts/generate_traceability.py", errors)
    if 'VERSION_FILE = ROOT / "VERSION"' not in generator:
        errors.append("scripts/generate_traceability.py must derive release identity from VERSION")
    if re.search(r"ZTAD Mesh [0-9]+\.[0-9]+\.[0-9]+ Traceability Matrix", generator):
        errors.append("scripts/generate_traceability.py contains a hard-coded release identity")

    packaged_stale_surfaces = (
        "toolkit/ztad/__init__.py",
        "scripts/generate_traceability.py",
        "docs/THREAT_MODEL.md",
        "docs/SECURITY_CONTROLS.md",
        "docs/SOURCE_MAPPING.md",
    )
    source_stale_surfaces = (".github/ISSUE_TEMPLATE/bug_report.yml",)
    stale_surfaces = packaged_stale_surfaces + (source_stale_surfaces if profile == "source" else ())
    for relative in stale_surfaces:
        text = _read_required(root, relative, errors)
        if "4.2.0" in text:
            errors.append(f"{relative}: stale 4.2.0 live identity remains")

    return {
        "valid": not errors,
        "profile": profile,
        "version": version,
        "identities": identities,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ZTAD release identity surfaces")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--profile", choices=("source", "distribution"), default="source")
    args = parser.parse_args(argv)
    result = verify(args.root, profile=args.profile)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
