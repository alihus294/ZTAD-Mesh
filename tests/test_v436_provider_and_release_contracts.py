import json
from pathlib import Path

from ztad.providers import CodexExecProvider, ProviderRunRequest
from ztad.release_fingerprint import compute_release_fingerprint
from ztad.schema_validation import validate_strict_model_schema
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def test_agent_result_schema_is_strict_model_compatible():
    schema = load_data(ROOT / "schemas/agent-result.schema.json")
    assert validate_strict_model_schema(schema) == []


def test_invalid_strict_schema_never_invokes_provider_and_is_not_misreported_missing_output(tmp_path):
    marker = tmp_path / "provider-invoked"
    executable = tmp_path / "fake-codex"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n", encoding="utf-8")
    executable.chmod(0o755)
    schema = tmp_path / "invalid-strict-schema.json"
    schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"]
    }), encoding="utf-8")
    artifacts = tmp_path / "provider-artifacts"
    request = ProviderRunRequest(
        task_id="task-1",
        role="independent_reviewer",
        registry_id="codex-sol",
        model="gpt-5.6-sol",
        reasoning_effort="high",
        sandbox="read-only",
        prompt="Review only.",
        output_schema=schema,
        cwd=tmp_path,
        run_id="strict-schema-preflight",
        artifact_dir=artifacts,
    )
    result = CodexExecProvider(executable=str(executable), output_dir=artifacts).run(request)
    assert result.exit_code == 78
    assert not result.success
    assert any(item.startswith("invalid_json_schema:") for item in result.errors)
    assert "provider_output_missing" not in result.errors
    assert result.argv == ()
    assert not marker.exists()
    assert result.request_fingerprint
    assert result.receipt_hash
    receipt = json.loads((artifacts / "strict-schema-preflight.receipt.json").read_text(encoding="utf-8"))
    assert receipt["authority"] == "LOCAL_NON_AUTHORITATIVE"
    assert receipt["can_grant_merge_release_or_production"] is False
    assert receipt["request_fingerprint"] == result.request_fingerprint
    assert (artifacts / "strict-schema-preflight.stderr.txt").is_file()
    assert (artifacts / "strict-schema-preflight.events.jsonl").is_file()


def test_release_fingerprint_is_deterministic_and_non_authoritative():
    schema = load_data(ROOT / "schemas/release-manifest.schema.json")
    manifest = {
        "schema_version": 1,
        "repository": "owner/repo",
        "change_contract_hash": "sha256:" + "a" * 64,
        "merged_sha": "1" * 40,
        "artifact_digest": "sha256:" + "b" * 64,
        "build_workflow_sha": "2" * 40,
        "policy_bundle_hash": "sha256:" + "c" * 64,
        "toolchain_hash": "sha256:" + "d" * 64,
        "sbom_digest": "sha256:" + "e" * 64,
        "provenance_attestation": "attestation-ref",
        "test_evidence_refs": ["ev-1"],
        "risk": "R3",
        "rollback_artifact_digest": "sha256:" + "f" * 64,
        "feature_flags": [],
        "created_at": "2026-08-14T00:00:00Z",
    }
    first = compute_release_fingerprint(manifest, schema)
    second = compute_release_fingerprint(dict(reversed(list(manifest.items()))), schema)
    assert first["release_fingerprint"] == second["release_fingerprint"]
    assert first["authority"] == "LOCAL_NON_AUTHORITATIVE"
    assert first["can_grant_release_or_production"] is False


def test_release_policy_contains_prior_task_blocker_gates():
    policy = load_data(ROOT / "policies/release-policy.yaml")
    assert policy["version"] >= 3
    staging = set(policy["gates"]["STAGING"]["required_evidence"])
    release = set(policy["gates"]["RELEASE"]["required_evidence"])
    production = set(policy["gates"]["PRODUCTION"]["required_evidence"])
    assert {"RELEASE_FINGERPRINT_VERIFIED", "SIGNED_RELEASE_MANIFEST", "ARTIFACT_ATTESTATION_VERIFIED", "SBOM_VERIFIED"} <= staging
    assert {"ROLLBACK_REHEARSAL_VERIFIED", "OBSERVABILITY_READY"} <= release
    assert "PROTECTED_RELEASE_AUTHORIZATION" in production
