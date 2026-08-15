#!/usr/bin/env python3
"""Create deterministic release SBOM, provenance, and subject evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40,64}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _timestamp() -> str:
    raw = os.getenv("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(release_dir: Path, *, repository: str, source_sha: str, version: str, attestation_path: Path | None = None) -> dict[str, Any]:
    release_dir = release_dir.resolve()
    if not release_dir.is_dir() or release_dir.is_symlink():
        raise ValueError(f"Release directory must be a regular directory: {release_dir}")
    if not SHA1.fullmatch(source_sha):
        raise ValueError("source_sha must be a hexadecimal commit identifier")
    if not SEMVER.fullmatch(version):
        raise ValueError("version must be semantic versioning")
    excluded = {
        "SBOM.spdx.json",
        "PROVENANCE.json",
        "RELEASE_EVIDENCE.json",
        "PROVENANCE_ATTESTATION.json",
        "SBOM_ATTESTATION.json",
        "SUBJECT_CHECKSUMS.sha256",
        "CHECKSUMS.sha256",
    }
    artifacts = [
        {"name": path.name, "digest": _digest(path), "size": path.stat().st_size}
        for path in sorted(release_dir.iterdir())
        if path.is_file() and not path.is_symlink() and path.name not in excluded
    ]
    if not artifacts:
        raise ValueError("Release directory has no publishable artifact subjects")
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"ZTAD Mesh {version} release",
        "documentNamespace": f"https://github.com/{repository}/releases/{version}/{source_sha}",
        "creationInfo": {"created": _timestamp(), "creators": ["Tool: ZTAD release evidence generator"]},
        "packages": [
            {
                "SPDXID": f"SPDXRef-{item['name'].replace('.', '-').replace('_', '-')}"[:80],
                "name": item["name"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": item["digest"].removeprefix("sha256:")}],
            }
            for item in artifacts
        ],
    }
    sbom_digest = "sha256:" + hashlib.sha256(_canonical(sbom)).hexdigest()
    provenance = {
        "type": "https://slsa.dev/provenance/v1",
        "repository": repository,
        "source_sha": source_sha,
        "version": version,
        "builder": "github-actions",
        "created_at": _timestamp(),
        "subjects": artifacts,
        "sbom_digest": sbom_digest,
    }
    provenance_digest = "sha256:" + hashlib.sha256(_canonical(provenance)).hexdigest()
    attestation_digest = _digest(attestation_path) if attestation_path and attestation_path.is_file() and not attestation_path.is_symlink() else None
    sbom_attestation_path = release_dir / "SBOM_ATTESTATION.json"
    sbom_attestation_digest = _digest(sbom_attestation_path) if sbom_attestation_path.is_file() and not sbom_attestation_path.is_symlink() else None
    artifact_identity = repository + "@" + source_sha + ":" + ",".join(item["name"] + "@" + item["digest"] for item in artifacts)
    release_evidence = {
        "schema_version": 1,
        "repository": repository,
        "source_sha": source_sha,
        "version": version,
        "release_fingerprint": "sha256:" + hashlib.sha256(_canonical({"source_sha": source_sha, "version": version, "subjects": artifacts, "sbom_digest": sbom_digest, "provenance_digest": provenance_digest, "attestation_digest": attestation_digest, "sbom_attestation_digest": sbom_attestation_digest})).hexdigest(),
        "artifact_identity": artifact_identity,
        "artifact_digests": artifacts,
        "sbom_digest": sbom_digest,
        "provenance_digest": provenance_digest,
        "attestation_digest": attestation_digest,
        "sbom_attestation_digest": sbom_attestation_digest,
        "protected_attestation": attestation_digest is not None and sbom_attestation_digest is not None,
        "claim_boundary": "Protected platform attestation is authoritative only after the configured workflow uploads and verifies the exact subject.",
    }
    _write(release_dir / "SBOM.spdx.json", sbom)
    _write(release_dir / "PROVENANCE.json", provenance)
    _write(release_dir / "RELEASE_EVIDENCE.json", release_evidence)
    return release_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--attestation-path", type=Path)
    args = parser.parse_args()
    result = build(args.release_dir, repository=args.repository, source_sha=args.source_sha, version=args.version, attestation_path=args.attestation_path)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
