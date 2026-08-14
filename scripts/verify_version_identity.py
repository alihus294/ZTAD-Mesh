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

# These are release-facing files that are copied into both the Plugin and
# Marketplace distributions.  Repository-only metadata is kept separate below
# so a clean extracted package does not depend on .github files.
PACKAGED_MARKERS: dict[str, tuple[str, ...]] = {
    "README.md": (
        "# Zero-Trust Agentic Delivery Mesh {version}",
        "## What {version} implements",
    ),
    "QUICKSTART.md": (
        "# ZTAD Mesh {version} Quick Start",
        "`v{version}` GitHub Release",
    ),
    "docs/PLUGIN_INSTALLATION.md": (
        "# Codex Plugin Installation — {version}",
        "zero-trust-agentic-delivery-marketplace-{version}.zip",
        "zero-trust-agentic-delivery-plugin-{version}.zip",
        "plugin version `{version}`",
    ),
    "traceability/TRACEABILITY_MATRIX.md": ("# ZTAD Mesh {version} Traceability Matrix",),
    "CHANGELOG.md": ("## {version} — ",),
}

# Current operational and normative documents must identify the release in
# their first heading.  Historical review snapshots and validation records are
# deliberately excluded from this map.
CURRENT_HEADING_PREFIXES: dict[str, str] = {
    "docs/ARCHITECTURE.md": "# Architecture",
    "docs/EVALS.md": "# Evaluation Strategy",
    "docs/LIMITATIONS.md": "# Known Limitations",
    "docs/CONTROL_COVERAGE.md": "# Control Coverage",
    "docs/HOST_ACCEPTANCE.md": "# Target Host Acceptance",
    "docs/CAPABILITY_MATRIX.md": "# Capability Matrix",
    "docs/FINAL_OPERATING_POLICY.md": "# Final Operating Policy",
    "docs/MODEL_SELECTION.md": "# Model Selection and Work Distribution",
    "docs/OPERATING_GUIDE.md": "# Operating Guide",
    "docs/VALIDATION_REPORT.md": "# Validation Report",
    "references/MASTER_PLAN.md": "# ZTAD Mesh",
    "docs/SECURITY_CONTROLS.md": "# Security Controls",
    "docs/THREAT_MODEL.md": "# Threat Model",
    "docs/BUG_TO_PRODUCTION_PROTOCOL.md": "# Autonomous Fail-Closed Bug-to-Production Protocol",
}

SOURCE_ONLY_MARKERS: dict[str, tuple[str, ...]] = {
    ".github/ISSUE_TEMPLATE/bug_report.yml": ("placeholder: {version}",),
}


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
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"{relative}: cannot read release-identity surface: {exc}")
        return ""


def _identity_values_match(identities: dict[str, object], errors: list[str]) -> None:
    values = list(identities.values())
    if not values or not all(isinstance(value, str) for value in values):
        errors.append("release identity values must all be strings")
        errors.append("version mismatch: " + ", ".join(f"{name}={value!r}" for name, value in identities.items()))
        return
    if any(value != values[0] for value in values[1:]):
        errors.append("version mismatch: " + ", ".join(f"{name}={value}" for name, value in identities.items()))


def _render_markers(markers: tuple[str, ...], version: str) -> tuple[str, ...]:
    return tuple(marker.format(version=version) for marker in markers)


def _check_current_heading(relative: str, text: str, prefix: str, version: str, errors: list[str]) -> None:
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if not first_line.startswith(prefix):
        errors.append(f"{relative}: first heading must start with {prefix!r}")
        return
    if not re.search(rf"(?<![0-9]){re.escape(version)}(?![0-9])", first_line):
        errors.append(f"{relative}: first heading does not identify current version {version}")


def verify(root: Path = ROOT, *, profile: str = "source") -> dict[str, object]:
    if profile not in {"source", "distribution"}:
        raise ValueError("profile must be 'source' or 'distribution'")

    root = root.resolve()
    errors: list[str] = []
    version_text = _read_required(root, "VERSION", errors)
    version = version_text.strip()
    if not SEMVER.fullmatch(version):
        errors.append(f"invalid VERSION: {version!r}")
    marker_version = version if SEMVER.fullmatch(version) else "<invalid-version>"

    plugin_text = _read_required(root, ".codex-plugin/plugin.json", errors)
    pyproject_text = _read_required(root, "toolkit/pyproject.toml", errors)
    runtime_path = root / "toolkit/ztad/__init__.py"

    plugin_version: object = "<missing>"
    pyproject_version: object = "<missing>"
    runtime_version: object = "<missing>"
    try:
        plugin = json.loads(plugin_text) if plugin_text else {}
        if not isinstance(plugin, dict) or not isinstance(plugin.get("version"), str):
            raise ValueError("version must be a string")
        plugin_version = plugin["version"]
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        plugin_version = "<invalid>"
        errors.append(f".codex-plugin/plugin.json: invalid version metadata: {exc}")
    try:
        project = tomllib.loads(pyproject_text).get("project", {}) if pyproject_text else {}
        if not isinstance(project, dict) or not isinstance(project.get("version"), str):
            raise ValueError("project.version must be a string")
        pyproject_version = project["version"]
    except (tomllib.TOMLDecodeError, ValueError, TypeError) as exc:
        pyproject_version = "<invalid>"
        errors.append(f"toolkit/pyproject.toml: invalid version metadata: {exc}")
    try:
        if not runtime_path.is_file() or runtime_path.is_symlink():
            raise ValueError(f"missing regular runtime version surface: {runtime_path}")
        runtime_version = _read_runtime_version(runtime_path)
    except (OSError, SyntaxError, ValueError) as exc:
        runtime_version = "<invalid>"
        errors.append(str(exc))

    identities: dict[str, object] = {
        "VERSION": version,
        "plugin": plugin_version,
        "pyproject": pyproject_version,
        "runtime": runtime_version,
    }
    _identity_values_match(identities, errors)

    for relative, markers in PACKAGED_MARKERS.items():
        text = _read_required(root, relative, errors)
        for marker in _render_markers(markers, marker_version):
            if marker not in text:
                errors.append(f"{relative}: missing release identity marker {marker!r}")

    for relative, prefix in CURRENT_HEADING_PREFIXES.items():
        text = _read_required(root, relative, errors)
        _check_current_heading(relative, text, prefix, marker_version, errors)

    if profile == "source":
        for relative, markers in SOURCE_ONLY_MARKERS.items():
            text = _read_required(root, relative, errors)
            for marker in _render_markers(markers, marker_version):
                if marker not in text:
                    errors.append(f"{relative}: missing source-only release identity marker {marker!r}")

    generator = _read_required(root, "scripts/generate_traceability.py", errors)
    if 'VERSION_FILE = ROOT / "VERSION"' not in generator:
        errors.append("scripts/generate_traceability.py must derive release identity from VERSION")
    if re.search(r"ZTAD Mesh [0-9]+\.[0-9]+\.[0-9]+ Traceability Matrix", generator):
        errors.append("scripts/generate_traceability.py contains a hard-coded release identity")

    # These files are shipped or used as current runtime metadata.  A stale
    # historical review or validation artifact is intentionally not scanned.
    packaged_stale_surfaces = (
        "toolkit/ztad/__init__.py",
        "scripts/generate_traceability.py",
        "docs/THREAT_MODEL.md",
        "docs/SECURITY_CONTROLS.md",
        "docs/SOURCE_MAPPING.md",
    )
    stale_surfaces = packaged_stale_surfaces + (tuple(SOURCE_ONLY_MARKERS) if profile == "source" else ())
    for relative in stale_surfaces:
        text = _read_required(root, relative, errors)
        if "4.2.0" in text:
            errors.append(f"{relative}: stale 4.2.0 live identity remains")

    return {
        "valid": not errors,
        "profile": profile,
        "version": version,
        "identities": identities,
        "checked_packaged_surfaces": sorted(set(PACKAGED_MARKERS) | set(CURRENT_HEADING_PREFIXES)),
        "checked_source_only_surfaces": sorted(SOURCE_ONLY_MARKERS) if profile == "source" else [],
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
