#!/usr/bin/env python3
"""Fail-closed verifier for published ZTAD release evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40,64}$")


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load(path: Path, errors: list[str]) -> dict[str, Any] | None:
    if not path.is_file() or path.is_symlink():
        errors.append(f"Missing regular evidence file: {path.name}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"Invalid JSON in {path.name}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"Evidence file must contain an object: {path.name}")
        return None
    return value


def verify(release_dir: Path, *, repository: str, source_sha: str, version: str, require_protected: bool = False) -> list[str]:
    errors: list[str] = []
    release_dir = release_dir.resolve()
    if not release_dir.is_dir() or release_dir.is_symlink():
        return [f"Release directory must be a regular directory: {release_dir}"]
    if not SHA1.fullmatch(source_sha):
        errors.append("source_sha must be a hexadecimal commit identifier")

    evidence = _load(release_dir / "RELEASE_EVIDENCE.json", errors)
    sbom = _load(release_dir / "SBOM.spdx.json", errors)
    provenance = _load(release_dir / "PROVENANCE.json", errors)
    if evidence is None or sbom is None or provenance is None:
        return errors

    for field, expected in (("repository", repository), ("source_sha", source_sha), ("version", version)):
        if evidence.get(field) != expected:
            errors.append(f"Release evidence {field} does not match the requested identity")
    if evidence.get("schema_version") != 1:
        errors.append("Unsupported release evidence schema version")

    records = evidence.get("artifact_digests")
    if not isinstance(records, list) or not records:
        errors.append("Release evidence must list at least one artifact subject")
        records = []
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            errors.append("Artifact subject record must be an object")
            continue
        name = record.get("name")
        digest = record.get("digest")
        size = record.get("size")
        if not isinstance(name, str) or not name or Path(name).name != name or name in names:
            errors.append(f"Invalid or duplicate artifact subject name: {name!r}")
            continue
        names.add(name)
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            errors.append(f"Invalid artifact digest for {name}")
            continue
        if not isinstance(size, int) or size < 0:
            errors.append(f"Invalid artifact size for {name}")
            continue
        target = release_dir / name
        if not target.is_file() or target.is_symlink():
            errors.append(f"Missing regular artifact subject: {name}")
            continue
        actual = _digest(target)
        if actual != digest or target.stat().st_size != size:
            errors.append(f"Artifact subject digest or size mismatch: {name}")
        normalized.append({"name": name, "digest": digest, "size": size})

    expected_identity = repository + "@" + source_sha + ":" + ",".join(item["name"] + "@" + item["digest"] for item in normalized)
    if evidence.get("artifact_identity") != expected_identity:
        errors.append("Immutable artifact identity does not match the subject list")

    sbom_digest = "sha256:" + hashlib.sha256(_canonical(sbom)).hexdigest()
    provenance_digest = "sha256:" + hashlib.sha256(_canonical(provenance)).hexdigest()
    if evidence.get("sbom_digest") != sbom_digest:
        errors.append("SBOM digest does not match SBOM content")
    if evidence.get("provenance_digest") != provenance_digest:
        errors.append("Provenance digest does not match provenance content")

    packages = sbom.get("packages")
    sbom_subjects: list[dict[str, Any]] = []
    if not isinstance(packages, list):
        errors.append("SBOM packages must be an array")
    else:
        for package in packages:
            if not isinstance(package, dict):
                errors.append("SBOM package must be an object")
                continue
            checksums = package.get("checksums")
            if not isinstance(checksums, list) or len(checksums) != 1 or not isinstance(checksums[0], dict):
                errors.append(f"SBOM package has no single SHA256 checksum: {package.get('name')!r}")
                continue
            checksum = checksums[0]
            sbom_subjects.append({"name": package.get("name"), "digest": "sha256:" + str(checksum.get("checksumValue", ""))})
    expected_sbom_subjects = [{"name": item["name"], "digest": item["digest"]} for item in normalized]
    if sorted(sbom_subjects, key=lambda item: (str(item.get("name")), str(item.get("digest")))) != sorted(expected_sbom_subjects, key=lambda item: (item["name"], item["digest"])):
        errors.append("SBOM subjects do not exactly match release artifacts")

    if provenance.get("repository") != repository or provenance.get("source_sha") != source_sha or provenance.get("version") != version:
        errors.append("Provenance identity does not match the release")
    provenance_subjects = provenance.get("subjects")
    if provenance_subjects != normalized:
        errors.append("Provenance subjects do not exactly match release artifacts")
    if provenance.get("sbom_digest") != sbom_digest:
        errors.append("Provenance does not bind the release SBOM digest")

    attestation_path = release_dir / "PROVENANCE_ATTESTATION.json"
    sbom_attestation_path = release_dir / "SBOM_ATTESTATION.json"
    attestation_digest = _digest(attestation_path) if attestation_path.is_file() and not attestation_path.is_symlink() else None
    sbom_attestation_digest = _digest(sbom_attestation_path) if sbom_attestation_path.is_file() and not sbom_attestation_path.is_symlink() else None
    if evidence.get("attestation_digest") != attestation_digest:
        errors.append("Provenance attestation digest does not match the published bundle")
    if evidence.get("sbom_attestation_digest") != sbom_attestation_digest:
        errors.append("SBOM attestation digest does not match the published bundle")
    protected = evidence.get("protected_attestation") is True and attestation_digest is not None and sbom_attestation_digest is not None
    if require_protected and not protected:
        errors.append("Protected provenance and SBOM attestations are required")

    fingerprint_subject = {
        "source_sha": source_sha,
        "version": version,
        "subjects": normalized,
        "sbom_digest": sbom_digest,
        "provenance_digest": provenance_digest,
        "attestation_digest": attestation_digest,
        "sbom_attestation_digest": sbom_attestation_digest,
    }
    expected_fingerprint = "sha256:" + hashlib.sha256(_canonical(fingerprint_subject)).hexdigest()
    if evidence.get("release_fingerprint") != expected_fingerprint:
        errors.append("Release fingerprint does not bind the complete evidence chain")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ZTAD release SBOM, provenance, attestations, and fingerprint")
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--require-protected", action="store_true")
    args = parser.parse_args(argv)
    errors = verify(args.release_dir, repository=args.repository, source_sha=args.source_sha, version=args.version, require_protected=args.require_protected)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Release evidence verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
