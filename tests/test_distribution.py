import hashlib
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ztad.distribution import (
    MARKETPLACE_NAME,
    PLUGIN_NAME,
    build_distributions,
    safe_extract_archive,
    validate_distribution_archive,
)
from ztad.errors import ConfigurationError

ROOT = Path(__file__).resolve().parents[1]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_distribution_build_is_reproducible_and_self_verifying(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "315532800")
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    transient_coverage = ROOT / ".coverage.distribution-test"
    transient_coverage.write_bytes(b"must not be packaged")
    try:
        first = build_distributions(ROOT, first_dir)
        second = build_distributions(ROOT, second_dir)
    finally:
        transient_coverage.unlink(missing_ok=True)

    plugin_name = f"{PLUGIN_NAME}-plugin-{first['version']}.zip"
    marketplace_name = f"{PLUGIN_NAME}-marketplace-{first['version']}.zip"
    assert _digest(first_dir / plugin_name) == _digest(second_dir / plugin_name)
    assert _digest(first_dir / marketplace_name) == _digest(second_dir / marketplace_name)
    assert _digest(first_dir / "RELEASE_MANIFEST.json") == _digest(second_dir / "RELEASE_MANIFEST.json")
    assert _digest(first_dir / "CHECKSUMS.sha256") == _digest(second_dir / "CHECKSUMS.sha256")
    assert (first_dir / f"{PLUGIN_NAME}-plugin.zip").read_bytes() == (first_dir / plugin_name).read_bytes()
    assert (first_dir / f"{PLUGIN_NAME}-marketplace.zip").read_bytes() == (first_dir / marketplace_name).read_bytes()

    assert validate_distribution_archive(first_dir / plugin_name, "plugin")["valid"]
    assert validate_distribution_archive(first_dir / marketplace_name, "marketplace")["valid"]
    assert first["archive_validation"]["plugin"]["valid"]
    assert second["archive_validation"]["marketplace"]["valid"]

    with zipfile.ZipFile(first_dir / plugin_name) as handle:
        names = handle.namelist()
    assert names
    assert all(name.startswith(f"{PLUGIN_NAME}/") for name in names)
    assert not any("__pycache__" in name or name.endswith(".pyc") or "/.pytest_cache/" in name for name in names)
    assert not any(Path(name).name.startswith(".coverage") for name in names)
    assert not any(name.startswith(f"{PLUGIN_NAME}/.github/") for name in names)
    assert f"{PLUGIN_NAME}/.gitignore" not in names
    assert f"{PLUGIN_NAME}/MANIFEST.sha256" in names


def test_safe_extract_rejects_zip_slip(tmp_path: Path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(f"{PLUGIN_NAME}/../escape.txt", "unsafe")
    with pytest.raises(ConfigurationError, match="Unsafe ZIP member path"):
        safe_extract_archive(archive, tmp_path / "extract", expected_top_level=PLUGIN_NAME)


def test_safe_extract_rejects_symlink_members(tmp_path: Path):
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo(f"{MARKETPLACE_NAME}/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(info, "target")
    with pytest.raises(ConfigurationError, match="ZIP symlinks are prohibited"):
        safe_extract_archive(archive, tmp_path / "extract", expected_top_level=MARKETPLACE_NAME)


def test_release_checksum_file_is_cross_platform_verifiable(tmp_path: Path):
    from ztad.distribution import verify_checksum_file

    output = tmp_path / "release"
    build_distributions(ROOT, output)
    result = verify_checksum_file(output / "CHECKSUMS.sha256")
    assert result["valid"], result["errors"]
    assert result["entry_count"] == 6
    checksum_text = (output / "CHECKSUMS.sha256").read_text(encoding="utf-8")
    assert "  RELEASE_MANIFEST.json\n" in checksum_text
    release_manifest = (output / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")
    assert str(output.resolve()) not in release_manifest
    external = subprocess.run(
        [sys.executable, str(output / "verify_release.py"), str(output / "CHECKSUMS.sha256")],
        cwd=output,
        text=True,
        capture_output=True,
        check=False,
    )
    assert external.returncode == 0, external.stderr
    assert "Verification passed" in external.stdout

    plugin_alias = output / f"{PLUGIN_NAME}-plugin.zip"
    plugin_alias.write_bytes(plugin_alias.read_bytes() + b"tampered")
    tampered = verify_checksum_file(output / "CHECKSUMS.sha256")
    assert not tampered["valid"]
    assert any("Checksum mismatch" in error for error in tampered["errors"])


def test_safe_extract_rejects_cross_platform_path_collisions(tmp_path: Path):
    archive = tmp_path / "collision.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(f"{PLUGIN_NAME}/Readme.txt", "one")
        handle.writestr(f"{PLUGIN_NAME}/README.TXT", "two")
    with pytest.raises(ConfigurationError, match="cross-platform-colliding"):
        safe_extract_archive(archive, tmp_path / "extract", expected_top_level=PLUGIN_NAME)


def test_safe_extract_rejects_unsupported_compression(tmp_path: Path):
    archive = tmp_path / "bzip2.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_BZIP2) as handle:
        handle.writestr(f"{PLUGIN_NAME}/file.txt", "content")
    with pytest.raises(ConfigurationError, match="Unsupported ZIP compression"):
        safe_extract_archive(archive, tmp_path / "extract", expected_top_level=PLUGIN_NAME)


def test_safe_extract_rejects_oversized_compressed_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "oversized.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(f"{PLUGIN_NAME}/file.txt", "content")
    monkeypatch.setattr("ztad.distribution.MAX_ARCHIVE_COMPRESSED_BYTES", 1)
    with pytest.raises(ConfigurationError, match="compressed size limit"):
        safe_extract_archive(archive, tmp_path / "extract", expected_top_level=PLUGIN_NAME)


def test_release_metadata_is_reproducible_with_source_date_epoch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    first_dir = tmp_path / "first-release"
    second_dir = tmp_path / "second-release"
    build_distributions(ROOT, first_dir)
    build_distributions(ROOT, second_dir)

    first = {path.name: _digest(path) for path in first_dir.iterdir() if path.is_file()}
    second = {path.name: _digest(path) for path in second_dir.iterdir() if path.is_file()}
    assert first == second
    manifest = (first_dir / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")
    assert '"generated_at": "1970-01-01T00:00:00Z"' in manifest


def test_release_rejects_invalid_source_date_epoch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-an-integer")
    with pytest.raises(ConfigurationError, match="SOURCE_DATE_EPOCH"):
        build_distributions(ROOT, tmp_path / "release")
