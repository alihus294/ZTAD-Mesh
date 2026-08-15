from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from ztad.schema_validation import validate_instance


ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_evidence_binds_artifacts_sbom_and_protected_attestations(tmp_path: Path) -> None:
    generator = _load_script("generate_release_evidence", "generate_release_evidence.py")
    verifier = _load_script("verify_release_evidence", "verify_release_evidence.py")
    (tmp_path / "plugin.zip").write_bytes(b"plugin")
    (tmp_path / "marketplace.zip").write_bytes(b"marketplace")

    generated = generator.build(
        tmp_path,
        repository="owner/repo",
        source_sha="a" * 40,
        version="4.3.9",
    )
    assert generated["protected_attestation"] is False
    assert verifier.verify(tmp_path, repository="owner/repo", source_sha="a" * 40, version="4.3.9") == []
    assert verifier.verify(tmp_path, repository="owner/repo", source_sha="a" * 40, version="4.3.9", require_protected=True)

    (tmp_path / "PROVENANCE_ATTESTATION.json").write_text('{\"kind\":\"provenance\"}\\n', encoding="utf-8")
    (tmp_path / "SBOM_ATTESTATION.json").write_text('{\"kind\":\"sbom\"}\\n', encoding="utf-8")
    generator.build(
        tmp_path,
        repository="owner/repo",
        source_sha="a" * 40,
        version="4.3.9",
        attestation_path=tmp_path / "PROVENANCE_ATTESTATION.json",
    )
    evidence = json.loads((tmp_path / "RELEASE_EVIDENCE.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas/release-evidence.schema.json").read_text(encoding="utf-8"))
    assert validate_instance(evidence, schema) == []
    assert evidence["protected_attestation"] is True
    assert verifier.verify(tmp_path, repository="owner/repo", source_sha="a" * 40, version="4.3.9", require_protected=True) == []

    (tmp_path / "plugin.zip").write_bytes(b"tampered")
    assert verifier.verify(tmp_path, repository="owner/repo", source_sha="a" * 40, version="4.3.9", require_protected=True)
