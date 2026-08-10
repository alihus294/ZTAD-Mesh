from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from .bundle import validate_bundle
from .util import load_data

MARKETPLACE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
PLUGIN_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
INSTALLATION_VALUES = {"NOT_AVAILABLE", "AVAILABLE", "INSTALLED_BY_DEFAULT"}
AUTHENTICATION_VALUES = {"ON_INSTALL", "ON_USE"}


def _safe_local_plugin_path(root: Path, raw: Any) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw.startswith("./"):
        return None, "Local plugin source.path must be a ./-prefixed string"
    relative = raw[2:]
    candidate = PurePosixPath(relative)
    if not relative or relative in {".", "./"} or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None, "Local plugin source.path must name a non-root directory inside the marketplace"
    resolved = (root / Path(*candidate.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None, "Local plugin source.path escapes the marketplace root"
    return resolved, None


def validate_marketplace(root: Path) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    manifest_path = root / ".agents/plugins/marketplace.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return {
            "valid": False,
            "errors": ["Missing regular .agents/plugins/marketplace.json"],
            "marketplace_root": str(root),
            "plugin_count": 0,
            "plugins": [],
        }
    try:
        data = load_data(manifest_path)
    except Exception as exc:
        return {
            "valid": False,
            "errors": [f"Invalid marketplace JSON: {exc}"],
            "marketplace_root": str(root),
            "plugin_count": 0,
            "plugins": [],
        }
    if not isinstance(data, dict):
        errors.append("Marketplace root must be a JSON object")
        data = {}
    allowed_top = {"name", "interface", "plugins"}
    extra_top = set(data) - allowed_top
    if extra_top:
        errors.append("Unsupported marketplace fields: " + ", ".join(sorted(extra_top)))
    name = data.get("name")
    if not isinstance(name, str) or not MARKETPLACE_NAME.fullmatch(name):
        errors.append("Marketplace name must contain only ASCII letters, digits, '_' or '-'")
    interface = data.get("interface")
    if not isinstance(interface, dict) or not isinstance(interface.get("displayName"), str) or not interface["displayName"].strip():
        errors.append("Marketplace interface.displayName is required")
    elif set(interface) - {"displayName"}:
        errors.append("Unsupported marketplace interface fields: " + ", ".join(sorted(set(interface) - {"displayName"})))

    entries = data.get("plugins")
    if not isinstance(entries, list) or not entries:
        errors.append("Marketplace plugins must be a non-empty array")
        entries = []
    seen_names: set[str] = set()
    plugin_results: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        prefix = f"plugins[{index}]"
        entry_errors: list[str] = []
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        allowed_entry = {"name", "source", "policy", "category"}
        if set(entry) - allowed_entry:
            entry_errors.append("unsupported fields: " + ", ".join(sorted(set(entry) - allowed_entry)))
        plugin_name = entry.get("name")
        if not isinstance(plugin_name, str) or not PLUGIN_NAME.fullmatch(plugin_name):
            entry_errors.append("name must be stable kebab-case")
        elif plugin_name in seen_names:
            entry_errors.append("duplicate plugin name")
        else:
            seen_names.add(plugin_name)
        source = entry.get("source")
        plugin_path: Path | None = None
        if not isinstance(source, dict) or source.get("source") != "local" or set(source) - {"source", "path"}:
            entry_errors.append("source must be exactly a local source object with path")
        else:
            plugin_path, path_error = _safe_local_plugin_path(root, source.get("path"))
            if path_error:
                entry_errors.append(path_error)
        policy = entry.get("policy")
        if not isinstance(policy, dict) or set(policy) - {"installation", "authentication"}:
            entry_errors.append("policy must contain only installation and authentication")
        else:
            if policy.get("installation") not in INSTALLATION_VALUES:
                entry_errors.append("policy.installation is invalid")
            if policy.get("authentication") not in AUTHENTICATION_VALUES:
                entry_errors.append("policy.authentication is invalid")
        if not isinstance(entry.get("category"), str) or not entry["category"].strip():
            entry_errors.append("category is required")

        bundle_result: dict[str, Any] | None = None
        if plugin_path is not None:
            if not plugin_path.is_dir() or plugin_path.is_symlink():
                entry_errors.append("local plugin directory is missing or not regular")
            else:
                bundle_result = validate_bundle(plugin_path)
                if not bundle_result["valid"]:
                    entry_errors.append("plugin bundle validation failed")
                plugin_manifest = plugin_path / ".codex-plugin/plugin.json"
                if plugin_manifest.is_file():
                    try:
                        declared_manifest = load_data(plugin_manifest)
                        declared_name = declared_manifest.get("name") if isinstance(declared_manifest, dict) else None
                    except Exception:
                        declared_name = None
                    if plugin_name and declared_name != plugin_name:
                        entry_errors.append("marketplace plugin name does not match plugin.json")
        errors.extend(f"{prefix}: {message}" for message in entry_errors)
        plugin_results.append({
            "name": plugin_name,
            "path": str(plugin_path) if plugin_path else None,
            "valid": not entry_errors,
            "errors": entry_errors,
            "bundle": bundle_result,
        })

    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "marketplace_root": str(root),
        "plugin_count": len(plugin_results),
        "plugins": plugin_results,
        "claim_boundary": "This validates package structure only; it does not prove installation or hosted runtime behavior.",
    }
