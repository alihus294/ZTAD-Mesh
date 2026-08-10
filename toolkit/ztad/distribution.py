from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from datetime import datetime, timezone
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .bundle import validate_bundle
from .errors import ConfigurationError
from .marketplace import validate_marketplace
from .util import atomic_write, safe_relative_path, sha256_file, utc_now, walk_regular_files

PLUGIN_NAME = "zero-trust-agentic-delivery"
MARKETPLACE_NAME = "zero-trust-agentic-delivery-marketplace"
MANIFEST_NAME = "MANIFEST.sha256"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000

_EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
}
_EXCLUDED_TOP_LEVEL_NAMES = {"dist", "build-output", ".github"}
_EXCLUDED_FILE_NAMES = {".coverage", ".DS_Store", ".gitignore", MANIFEST_NAME, "CHECKSUMS.sha256"}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
_MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_WINDOWS_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
_PORTABLE_FORBIDDEN = set('<>:"|?*\\')


def _portable_relative_path(raw: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ConfigurationError(f"Control characters are prohibited in distribution paths: {raw!r}")
    if any(character in _PORTABLE_FORBIDDEN for character in raw):
        raise ConfigurationError(f"Non-portable character in distribution path: {raw!r}")
    try:
        normalized = safe_relative_path(raw)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    for part in PurePosixPath(normalized).parts:
        if part.endswith((" ", ".")) or _WINDOWS_RESERVED.fullmatch(part):
            raise ConfigurationError(f"Non-portable distribution path segment: {part!r}")
    return normalized


def _portable_collision_key(raw: str) -> str:
    return unicodedata.normalize("NFC", raw).casefold()


def _excluded(relative: Path) -> bool:
    if not relative.parts:
        return False
    if relative.parts[0] in _EXCLUDED_TOP_LEVEL_NAMES:
        return True
    if any(part in _EXCLUDED_DIRECTORY_NAMES for part in relative.parts):
        return True
    if (
        relative.name in _EXCLUDED_FILE_NAMES
        or relative.name.startswith(".coverage.")
        or (relative.parts and relative.parts[0] == "validation" and relative.name.startswith(("ci-", "github-preupload-")))
        or relative.suffix in _EXCLUDED_SUFFIXES
    ):
        return True
    return False


def _assert_regular_source_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ConfigurationError(f"Distribution root must be a regular directory: {root}")
    portable_paths: dict[str, str] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if _excluded(relative):
            continue
        normalized = _portable_relative_path(relative.as_posix())
        collision_key = _portable_collision_key(normalized)
        previous = portable_paths.get(collision_key)
        if previous is not None and previous != normalized:
            raise ConfigurationError(f"Cross-platform path collision: {previous!r} and {normalized!r}")
        portable_paths[collision_key] = normalized
        if path.is_symlink():
            raise ConfigurationError(f"Symlinks are prohibited in distributions: {relative.as_posix()}")
        if not path.is_dir() and not path.is_file():
            raise ConfigurationError(f"Special files are prohibited in distributions: {relative.as_posix()}")


def _copy_clean_tree(source: Path, destination: Path) -> int:
    _assert_regular_source_tree(source)
    count = 0
    destination.mkdir(parents=True, exist_ok=False)
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        relative = path.relative_to(source)
        if _excluded(relative):
            continue
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        source_mode = stat.S_IMODE(path.stat().st_mode)
        os.chmod(target, 0o755 if source_mode & stat.S_IXUSR else 0o644)
        count += 1
    return count


def _manifest_entries(root: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for path in walk_regular_files(root):
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST_NAME:
            continue
        _portable_relative_path(relative)
        entries.append((sha256_file(path).removeprefix("sha256:"), relative))
    return entries


def write_internal_manifest(root: Path) -> dict[str, Any]:
    entries = _manifest_entries(root)
    text = "".join(f"{digest}  {relative}\n" for digest, relative in entries)
    manifest_path = root / MANIFEST_NAME
    atomic_write(manifest_path, text.encode("utf-8"), mode=0o644)
    return {
        "path": MANIFEST_NAME,
        "entry_count": len(entries),
        "sha256": sha256_file(manifest_path),
    }


def verify_internal_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / MANIFEST_NAME
    errors: list[str] = []
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return {"valid": False, "errors": [f"Missing regular {MANIFEST_NAME}"], "entry_count": 0}
    expected: dict[str, str] = {}
    expected_portable: dict[str, str] = {}
    for line_number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        match = _MANIFEST_LINE.fullmatch(line)
        if not match:
            errors.append(f"Malformed manifest line {line_number}")
            continue
        digest, relative = match.groups()
        try:
            normalized = _portable_relative_path(relative)
        except ConfigurationError as exc:
            errors.append(f"Unsafe manifest path on line {line_number}: {exc}")
            continue
        if normalized == MANIFEST_NAME:
            errors.append(f"{MANIFEST_NAME} must not list itself")
            continue
        portable_key = _portable_collision_key(normalized)
        if normalized in expected or portable_key in expected_portable:
            errors.append(f"Duplicate or cross-platform-colliding manifest path: {normalized}")
            continue
        expected[normalized] = digest
        expected_portable[portable_key] = normalized

    actual_files: dict[str, Path] = {}
    actual_portable: dict[str, str] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        try:
            normalized = _portable_relative_path(relative)
        except ConfigurationError as exc:
            errors.append(f"Non-portable packaged path: {relative}: {exc}")
            continue
        portable_key = _portable_collision_key(normalized)
        if portable_key in actual_portable and actual_portable[portable_key] != normalized:
            errors.append(f"Cross-platform packaged path collision: {actual_portable[portable_key]} and {normalized}")
        actual_portable[portable_key] = normalized
        if path.is_symlink():
            errors.append(f"Symlink found during manifest verification: {relative}")
        elif path.is_file() and relative != MANIFEST_NAME:
            actual_files[relative] = path
        elif not path.is_dir() and not path.is_file():
            errors.append(f"Special file found during manifest verification: {relative}")

    missing = sorted(set(expected) - set(actual_files))
    unlisted = sorted(set(actual_files) - set(expected))
    if missing:
        errors.append("Manifest lists missing files: " + ", ".join(missing[:20]))
    if unlisted:
        errors.append("Manifest omits files: " + ", ".join(unlisted[:20]))
    for relative in sorted(set(expected) & set(actual_files)):
        actual = sha256_file(actual_files[relative]).removeprefix("sha256:")
        if actual != expected[relative]:
            errors.append(f"Digest mismatch: {relative}")
    return {
        "valid": not errors,
        "errors": errors,
        "entry_count": len(expected),
        "manifest_sha256": sha256_file(manifest_path),
    }


def _zip_mode(path: Path) -> int:
    mode = stat.S_IMODE(path.stat().st_mode)
    return 0o755 if mode & stat.S_IXUSR else 0o644


def _write_reproducible_zip(root: Path, archive: Path, top_level: str) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_name(f".{archive.name}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as handle:
            for path in walk_regular_files(root):
                relative = path.relative_to(root).as_posix()
                archive_name = f"{top_level}/{relative}"
                info = zipfile.ZipInfo(archive_name, ZIP_TIMESTAMP)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (_zip_mode(path) & 0xFFFF) << 16
                info.flag_bits |= 0x800  # UTF-8 filenames.
                handle.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_member_path(name: str) -> PurePosixPath:
    if not name or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        raise ConfigurationError(f"Unsafe ZIP member path: {name!r}")
    try:
        _portable_relative_path(name.rstrip("/"))
    except ConfigurationError as exc:
        raise ConfigurationError(f"Unsafe ZIP member path: {name!r}: {exc}") from exc
    candidate = PurePosixPath(name)
    meaningful = [part for part in candidate.parts if part not in {""}]
    if not meaningful or any(part in {".", ".."} for part in meaningful):
        raise ConfigurationError(f"Unsafe ZIP member path: {name!r}")
    return PurePosixPath(*meaningful)


def safe_extract_archive(archive: Path, destination: Path, *, expected_top_level: str) -> Path:
    if not archive.is_file() or archive.is_symlink():
        raise ConfigurationError(f"Archive must be a regular file: {archive}")
    destination.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    seen_portable: set[str] = set()
    total_size = 0
    with zipfile.ZipFile(archive) as handle:
        infos = handle.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_FILES:
            raise ConfigurationError("Archive has an invalid file count")
        for info in infos:
            if info.flag_bits & 0x1:
                raise ConfigurationError(f"Encrypted ZIP members are prohibited: {info.filename}")
            candidate = _safe_member_path(info.filename)
            if candidate.parts[0] != expected_top_level:
                raise ConfigurationError(f"Archive member is outside expected top-level directory: {info.filename}")
            normalized = candidate.as_posix()
            portable_key = _portable_collision_key(normalized)
            if normalized in seen or portable_key in seen_portable:
                raise ConfigurationError(f"Duplicate or cross-platform-colliding ZIP member: {normalized}")
            seen.add(normalized)
            seen_portable.add(portable_key)
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise ConfigurationError(f"Unsupported ZIP compression method: {normalized}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ConfigurationError(f"ZIP symlinks are prohibited: {normalized}")
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ConfigurationError(f"ZIP special-file member is prohibited: {normalized}")
            total_size += info.file_size
            if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ConfigurationError("Archive exceeds the uncompressed size limit")
            if info.file_size and not info.compress_size:
                raise ConfigurationError(f"Archive member has an invalid zero compressed size: {normalized}")
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise ConfigurationError(f"Archive member exceeds compression-ratio limit: {normalized}")
            target = destination.joinpath(*candidate.parts)
            resolved_parent = target.parent.resolve()
            try:
                resolved_parent.relative_to(destination.resolve())
            except ValueError as exc:
                raise ConfigurationError(f"Archive member escapes extraction directory: {normalized}") from exc
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with handle.open(info, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            os.chmod(target, 0o755 if mode & stat.S_IXUSR else 0o644)
    extracted_root = destination / expected_top_level
    if not extracted_root.is_dir() or extracted_root.is_symlink():
        raise ConfigurationError("Expected extracted top-level directory is missing")
    return extracted_root


def validate_distribution_archive(archive: Path, kind: str) -> dict[str, Any]:
    if kind not in {"plugin", "marketplace"}:
        raise ConfigurationError("Distribution kind must be 'plugin' or 'marketplace'")
    expected = PLUGIN_NAME if kind == "plugin" else MARKETPLACE_NAME
    with tempfile.TemporaryDirectory(prefix="ztad-archive-validation-") as temporary:
        extracted = safe_extract_archive(archive.resolve(), Path(temporary) / "extract", expected_top_level=expected)
        manifest = verify_internal_manifest(extracted)
        package = validate_bundle(extracted) if kind == "plugin" else validate_marketplace(extracted)
        if kind == "marketplace":
            package["marketplace_root"] = expected
            for plugin in package.get("plugins", []):
                if isinstance(plugin, dict) and plugin.get("name"):
                    plugin["path"] = f"plugins/{plugin['name']}"
        nested_manifest: dict[str, Any] | None = None
        if kind == "marketplace":
            nested = extracted / "plugins" / PLUGIN_NAME
            nested_manifest = verify_internal_manifest(nested)
        valid = manifest["valid"] and package["valid"] and (nested_manifest is None or nested_manifest["valid"])
        return {
            "valid": valid,
            "kind": kind,
            "archive": str(archive.resolve()),
            "archive_sha256": sha256_file(archive.resolve()),
            "archive_size": archive.stat().st_size,
            "top_level": expected,
            "manifest": manifest,
            "package": package,
            "nested_plugin_manifest": nested_manifest,
        }


def _marketplace_manifest(version: str) -> dict[str, Any]:
    return {
        "name": "ztad-local",
        "interface": {"displayName": "ZTAD Local Marketplace"},
        "plugins": [
            {
                "name": PLUGIN_NAME,
                "source": {"source": "local", "path": f"./plugins/{PLUGIN_NAME}"},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Developer Tools",
            }
        ],
        "release": {"version": version},
    }


def _write_marketplace_manifest(root: Path, version: str) -> None:
    # The local marketplace format does not define a release field, so keep version
    # provenance in a sibling file rather than adding an unsupported catalog key.
    data = _marketplace_manifest(version)
    release = data.pop("release")
    target = root / ".agents/plugins/marketplace.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(target, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"), mode=0o644)
    atomic_write(root / "MARKETPLACE_VERSION.json", (json.dumps(release, indent=2, sort_keys=True) + "\n").encode("utf-8"), mode=0o644)


def _release_generated_at() -> str:
    """Return a reproducible release timestamp when SOURCE_DATE_EPOCH is set."""
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return utc_now()
    try:
        epoch = int(raw, 10)
    except ValueError as exc:
        raise ConfigurationError("SOURCE_DATE_EPOCH must be a non-negative integer") from exc
    if epoch < 0:
        raise ConfigurationError("SOURCE_DATE_EPOCH must be a non-negative integer")
    try:
        value = datetime.fromtimestamp(epoch, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ConfigurationError("SOURCE_DATE_EPOCH is outside the supported timestamp range") from exc
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _reproducible_build_timestamp() -> str:
    """Return a reproducible UTC timestamp when SOURCE_DATE_EPOCH is supplied."""
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return utc_now()
    try:
        epoch = int(raw, 10)
    except ValueError as exc:
        raise ConfigurationError("SOURCE_DATE_EPOCH must be a non-negative integer") from exc
    if epoch < 0:
        raise ConfigurationError("SOURCE_DATE_EPOCH must be a non-negative integer")
    try:
        value = datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ConfigurationError("SOURCE_DATE_EPOCH is outside the supported timestamp range") from exc
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _artifact_record(path: Path, kind: str) -> dict[str, Any]:
    return {
        "name": path.name,
        "kind": kind,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _write_checksums(paths: Iterable[Path], target: Path) -> None:
    lines = [f"{sha256_file(path).removeprefix('sha256:')}  {path.name}\n" for path in sorted(paths, key=lambda item: item.name)]
    atomic_write(target, "".join(lines).encode("utf-8"), mode=0o644)


def verify_checksum_file(checksum_file: Path) -> dict[str, Any]:
    checksum_file = checksum_file.resolve()
    errors: list[str] = []
    verified: list[dict[str, Any]] = []
    if not checksum_file.is_file() or checksum_file.is_symlink():
        return {"valid": False, "errors": [f"Checksum file must be a regular file: {checksum_file}"], "verified": []}
    seen: set[str] = set()
    for line_number, line in enumerate(checksum_file.read_text(encoding="utf-8").splitlines(), 1):
        match = _MANIFEST_LINE.fullmatch(line)
        if not match:
            errors.append(f"Malformed checksum line {line_number}")
            continue
        expected, raw_name = match.groups()
        try:
            relative = _portable_relative_path(raw_name)
        except ConfigurationError as exc:
            errors.append(f"Unsafe checksum path on line {line_number}: {exc}")
            continue
        if "/" in relative or relative in seen:
            errors.append(f"Checksum entries must be unique files in the checksum directory: {relative}")
            continue
        seen.add(relative)
        target = checksum_file.parent / relative
        if not target.is_file() or target.is_symlink():
            errors.append(f"Missing regular checksum target: {relative}")
            continue
        actual = sha256_file(target).removeprefix("sha256:")
        matched = actual == expected
        verified.append({"name": relative, "expected": expected, "actual": actual, "matched": matched})
        if not matched:
            errors.append(f"Checksum mismatch: {relative}")
    if not seen:
        errors.append("Checksum file is empty")
    return {"valid": not errors, "errors": errors, "verified": verified, "entry_count": len(seen)}


def build_distributions(root: Path, output_dir: Path, *, create_stable_aliases: bool = True) -> dict[str, Any]:
    root = root.resolve()
    output_dir = output_dir.resolve()
    source_validation = validate_bundle(root)
    if not source_validation["valid"]:
        raise ConfigurationError("Source bundle validation failed: " + "; ".join(source_validation["errors"]))
    version_path = root / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip()
    if not _SEMVER.fullmatch(version):
        raise ConfigurationError(f"VERSION is not semantic versioning: {version!r}")
    try:
        output_dir.relative_to(root)
    except ValueError:
        pass
    else:
        if output_dir.name not in _EXCLUDED_TOP_LEVEL_NAMES:
            raise ConfigurationError("Output directory inside the source must be named dist or build-output")
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ztad-distribution-") as temporary:
        staging = Path(temporary)
        plugin_root = staging / PLUGIN_NAME
        copied_files = _copy_clean_tree(root, plugin_root)
        plugin_manifest = write_internal_manifest(plugin_root)
        plugin_validation = validate_bundle(plugin_root)
        plugin_manifest_validation = verify_internal_manifest(plugin_root)
        if not plugin_validation["valid"] or not plugin_manifest_validation["valid"]:
            raise ConfigurationError("Staged plugin validation failed")

        marketplace_root = staging / MARKETPLACE_NAME
        nested_plugin = marketplace_root / "plugins" / PLUGIN_NAME
        nested_plugin.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(plugin_root, nested_plugin, symlinks=False)
        _write_marketplace_manifest(marketplace_root, version)
        marketplace_manifest = write_internal_manifest(marketplace_root)
        marketplace_validation = validate_marketplace(marketplace_root)
        marketplace_manifest_validation = verify_internal_manifest(marketplace_root)
        if not marketplace_validation["valid"] or not marketplace_manifest_validation["valid"]:
            raise ConfigurationError("Staged marketplace validation failed")

        plugin_archive = output_dir / f"{PLUGIN_NAME}-plugin-{version}.zip"
        marketplace_archive = output_dir / f"{PLUGIN_NAME}-marketplace-{version}.zip"
        _write_reproducible_zip(plugin_root, plugin_archive, PLUGIN_NAME)
        _write_reproducible_zip(marketplace_root, marketplace_archive, MARKETPLACE_NAME)

    plugin_archive_validation = validate_distribution_archive(plugin_archive, "plugin")
    marketplace_archive_validation = validate_distribution_archive(marketplace_archive, "marketplace")
    if not plugin_archive_validation["valid"] or not marketplace_archive_validation["valid"]:
        raise ConfigurationError("Built archive validation failed")

    verifier_source = root / "scripts/verify_release.py"
    if not verifier_source.is_file() or verifier_source.is_symlink():
        raise ConfigurationError("Missing regular scripts/verify_release.py")
    verifier_path = output_dir / "verify_release.py"
    shutil.copyfile(verifier_source, verifier_path)
    os.chmod(verifier_path, 0o755)

    artifacts = [plugin_archive, marketplace_archive]
    alias_records: list[dict[str, Any]] = []
    if create_stable_aliases:
        aliases = [
            (plugin_archive, output_dir / f"{PLUGIN_NAME}-plugin.zip", "plugin-alias"),
            (marketplace_archive, output_dir / f"{PLUGIN_NAME}-marketplace.zip", "marketplace-alias"),
        ]
        for source, alias, kind in aliases:
            shutil.copyfile(source, alias)
            artifacts.append(alias)
            alias_records.append(_artifact_record(alias, kind))

    def portable_validation(record: dict[str, Any]) -> dict[str, Any]:
        cleaned = json.loads(json.dumps(record))
        cleaned["archive"] = Path(str(cleaned["archive"])).name
        return cleaned

    release_manifest_path = output_dir / "RELEASE_MANIFEST.json"
    checksum_targets = [*artifacts, verifier_path, release_manifest_path]
    release_manifest = {
        "schema_version": 1,
        "product": PLUGIN_NAME,
        "version": version,
        "generated_at": _release_generated_at(),
        "source_file_count": copied_files,
        # Persist validation of the clean packaged tree rather than transient
        # source-root caches, so excluded files cannot perturb release metadata.
        "source_validation": plugin_validation,
        "internal_manifests": {
            "plugin": plugin_manifest,
            "marketplace": marketplace_manifest,
        },
        "artifacts": [_artifact_record(plugin_archive, "plugin"), _artifact_record(marketplace_archive, "marketplace"), *alias_records],
        "support_files": [_artifact_record(verifier_path, "release-verifier")],
        "checksum_file": "CHECKSUMS.sha256",
        "checksum_scope": sorted(path.name for path in checksum_targets),
        "archive_validation": {
            "plugin": portable_validation(plugin_archive_validation),
            "marketplace": portable_validation(marketplace_archive_validation),
        },
        "claim_boundary": "Archive validation proves offline structure, manifests, and deterministic controls; SHA-256 checksums detect modification but do not authenticate the publisher; target-host ingestion and remote platform enforcement remain unproven.",
    }
    atomic_write(release_manifest_path, (json.dumps(release_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"), mode=0o644)
    checksums_path = output_dir / "CHECKSUMS.sha256"
    _write_checksums(checksum_targets, checksums_path)
    checksum_validation = verify_checksum_file(checksums_path)
    if not checksum_validation["valid"]:
        raise ConfigurationError("Generated release checksum verification failed")
    return {
        "built": True,
        "version": version,
        "output_dir": str(output_dir),
        "checksums": str(checksums_path),
        "release_manifest": str(release_manifest_path),
        "artifacts": release_manifest["artifacts"],
        "archive_validation": release_manifest["archive_validation"],
    }
