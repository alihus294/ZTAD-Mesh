from __future__ import annotations

import json
from pathlib import Path

from ztad.bug_lifecycle import evaluate_bug_transition, initialize_bug_lifecycle
from ztad.bug_protocol import (
    HOSTED_RUNTIME_SERVICE,
    PACKAGE_OR_PLUGIN,
    validate_package_release_metadata,
    validate_published_asset_metadata,
    validate_consumer_validation_metadata,
)
from ztad.delivery_model import HYBRID, derive_delivery_model, validate_delivery_model
from ztad.evidence_bundle import validate_evidence_bundle
from ztad.schema_validation import validate_instance
from ztad.util import load_data


ROOT = Path(__file__).resolve().parents[1]
POLICY = load_data(ROOT / "policies/bug-to-production-policy.yaml")
LIFECYCLE_SCHEMA = json.loads((ROOT / "schemas/bug-lifecycle.schema.json").read_text(encoding="utf-8"))
EVIDENCE_SCHEMA = json.loads((ROOT / "schemas/evidence.schema.json").read_text(encoding="utf-8"))
BUNDLE_SCHEMA = json.loads((ROOT / "schemas/evidence-bundle.schema.json").read_text(encoding="utf-8"))


def _package_root(root: Path) -> None:
    for relative in (".codex-plugin/plugin.json", "toolkit/pyproject.toml", "scripts/ztad.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("marker\n", encoding="utf-8")


def _case(repository: Path) -> dict:
    return {
        "case_id": "CASE-DELIVERY-MODEL-001",
        "repository": str(repository),
        "report": "The package lifecycle must not require a fictional runtime.",
        "classification": "CONFIRMED_BUG",
        "authoritative_sources": [
            {
                "source": "README.md",
                "authority": "repository",
                "authority_reason": "Repository source of truth",
                "evidence_ref": None,
            }
        ],
        "source_conflicts": [],
        "unresolved_ambiguities": [],
        "reproduction": {"command": "pytest"},
        "root_cause": {"summary": "Lifecycle model did not match delivery shape."},
        "blast_radius": {"scope": "package"},
        "change_plan": {"expected_files": ["toolkit/ztad/bug_lifecycle.py"]},
        "domains": ["GENERAL"],
        "risk": "R2",
        "base_sha": "a" * 40,
    }


def test_delivery_model_is_derived_from_source_markers(tmp_path: Path):
    package_root = tmp_path / "package"
    package_root.mkdir()
    _package_root(package_root)
    package = derive_delivery_model(package_root)
    assert package.model == PACKAGE_OR_PLUGIN
    assert package.proof_digest.startswith("sha256:")

    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    (runtime_root / "DEPLOYMENT.md").write_text("runtime\n", encoding="utf-8")
    runtime = derive_delivery_model(runtime_root)
    assert runtime.model == HOSTED_RUNTIME_SERVICE

    _package_root(runtime_root)
    assert derive_delivery_model(runtime_root).model == HYBRID


def test_runtime_source_cannot_be_downgraded_to_package_delivery(tmp_path: Path):
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    (runtime_root / "DEPLOYMENT.md").write_text("runtime\n", encoding="utf-8")
    package_root = tmp_path / "package"
    package_root.mkdir()
    _package_root(package_root)
    package = derive_delivery_model(package_root)

    errors = validate_delivery_model(
        runtime_root,
        model=PACKAGE_OR_PLUGIN,
        proof=package.proof,
        proof_digest=package.proof_digest,
    )
    assert any("does not match repository source of truth" in error for error in errors)


def test_package_only_lifecycle_rejects_fictional_staging(tmp_path: Path):
    repository = tmp_path / "package"
    repository.mkdir()
    _package_root(repository)
    case = _case(repository)
    lifecycle = initialize_bug_lifecycle(
        problem_case=case,
        policy=POLICY,
        repository_root=repository,
    )
    assert lifecycle["delivery_model"] == PACKAGE_OR_PLUGIN
    result = evaluate_bug_transition(
        lifecycle,
        "STAGING_PASS",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_schema=EVIDENCE_SCHEMA,
        repository_root=repository,
    )
    assert not result["allowed"]
    assert any("Package-only delivery" in reason for reason in result["reasons"])


def test_package_release_metadata_rejects_runtime_identity(tmp_path: Path):
    errors = validate_package_release_metadata(
        {
            "delivery_model": PACKAGE_OR_PLUGIN,
            "release_tag": "v4.3.11",
            "source_sha": "b" * 40,
            "artifact_identity": "package.zip",
            "artifact_digest": "sha256:" + "1" * 64,
            "release_fingerprint": "sha256:" + "2" * 64,
            "sbom_digest": "sha256:" + "3" * 64,
            "provenance_digest": "sha256:" + "4" * 64,
            "attestation_digest": "sha256:" + "5" * 64,
            "runtime_deployment": True,
            "deployed_revision": "c" * 40,
        },
        head_sha="b" * 40,
        artifact_digest="sha256:" + "1" * 64,
        merged_main_sha=None,
    )
    assert any("runtime deployment" in error for error in errors)
    assert any("production identity" in error for error in errors)


def _package_release_metadata(**overrides: object) -> dict:
    metadata = {
        "delivery_model": PACKAGE_OR_PLUGIN,
        "release_tag": "v4.3.11",
        "source_sha": "b" * 40,
        "artifact_identity": "marketplace-v4.3.11.zip",
        "artifact_digest": "sha256:" + "1" * 64,
        "release_fingerprint": "sha256:" + "2" * 64,
        "sbom_digest": "sha256:" + "3" * 64,
        "provenance_digest": "sha256:" + "4" * 64,
        "attestation_digest": "sha256:" + "5" * 64,
    }
    metadata.update(overrides)
    return metadata


def _consumer_metadata(**overrides: object) -> dict:
    metadata = {
        "artifact_digest": "sha256:" + "1" * 64,
        "archive_kind": ["plugin", "marketplace"],
        "clean_environment": True,
        "source_checkout_leakage_absent": True,
        "version_verified": True,
        "install_success": True,
        "packaged_regressions_passed": True,
        "security_modules_present": True,
        "schemas_policies_included": True,
        "consumer_artifact_digests": {"marketplace-v4.3.11.zip": "sha256:" + "1" * 64},
    }
    metadata.update(overrides)
    return metadata


def test_hybrid_requires_both_relevant_paths(tmp_path: Path):
    repository = tmp_path / "hybrid"
    repository.mkdir()
    _package_root(repository)
    (repository / "DEPLOYMENT.md").write_text("runtime\n", encoding="utf-8")
    case = _case(repository)
    lifecycle = initialize_bug_lifecycle(problem_case=case, policy=POLICY, repository_root=repository)
    assert lifecycle["delivery_model"] == HYBRID
    lifecycle.update({"state": "CONSUMER_VALIDATION_PASS", "last_completed_state": "CONSUMER_VALIDATION_PASS"})
    result = evaluate_bug_transition(
        lifecycle,
        "CLOSED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        repository_root=repository,
    )
    assert not result["allowed"]
    assert any("hybrid" in reason.lower() and "post-deploy" in reason.lower() for reason in result["reasons"])


def test_published_asset_digest_must_match_lifecycle_artifact():
    artifact_digest = "sha256:" + "1" * 64
    errors = validate_published_asset_metadata(
        _package_release_metadata(
            published_asset_digests={"marketplace-v4.3.11.zip": "sha256:" + "9" * 64},
            published_from_protected_build=True,
        ),
        head_sha="b" * 40,
        artifact_digest=artifact_digest,
        merged_main_sha=None,
    )
    assert any("include the exact lifecycle artifact digest" in error for error in errors)


def test_published_asset_rebuild_substitution_is_rejected():
    artifact_digest = "sha256:" + "1" * 64
    errors = validate_published_asset_metadata(
        _package_release_metadata(
            published_asset_digests={"marketplace-v4.3.11.zip": artifact_digest},
            published_from_protected_build=True,
            rebuild_after_validation=True,
        ),
        head_sha="b" * 40,
        artifact_digest=artifact_digest,
        merged_main_sha=None,
    )
    assert any("rebuild after validation" in error for error in errors)


def test_consumer_validation_must_use_the_packaged_artifact():
    errors = validate_consumer_validation_metadata(
        _consumer_metadata(artifact_digest="sha256:" + "9" * 64),
        artifact_digest="sha256:" + "1" * 64,
    )
    assert any("exact released artifact digest" in error for error in errors)


def test_consumer_validation_rejects_source_checkout_leakage():
    errors = validate_consumer_validation_metadata(
        _consumer_metadata(source_checkout_leakage_absent=False),
        artifact_digest="sha256:" + "1" * 64,
    )
    assert any("source_checkout_leakage_absent" in error for error in errors)


def test_package_release_does_not_claim_runtime_rollback(tmp_path: Path):
    repository = tmp_path / "package"
    repository.mkdir()
    _package_root(repository)
    case = _case(repository)
    lifecycle = initialize_bug_lifecycle(problem_case=case, policy=POLICY, repository_root=repository)
    result = evaluate_bug_transition(
        lifecycle,
        "ROLLBACK_REQUIRED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        repository_root=repository,
    )
    assert not result["allowed"]
    assert any("runtime rollback" in reason.lower() for reason in result["reasons"])


def test_runtime_delivery_still_requires_postdeploy_evidence(tmp_path: Path):
    repository = tmp_path / "runtime"
    repository.mkdir()
    (repository / "DEPLOYMENT.md").write_text("runtime\n", encoding="utf-8")
    case = _case(repository)
    lifecycle = initialize_bug_lifecycle(problem_case=case, policy=POLICY, repository_root=repository)
    lifecycle.update({"state": "PRODUCTION_RELEASED", "last_completed_state": "PRODUCTION_RELEASED"})
    result = evaluate_bug_transition(
        lifecycle,
        "CLOSED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        repository_root=repository,
    )
    assert not result["allowed"]
    assert any("post_deploy_verified" in reason.lower() for reason in result["reasons"])


def test_package_terminal_bundle_rejects_manually_added_runtime_claim():
    bundle = {
        "schema_version": 2,
        "issue_id": "CASE-FRAUD-PACKAGE-001",
        "original_report": "package claim",
        "classification": "CONFIRMED_BUG",
        "repository": "owner/repository",
        "final_state": "CLOSED",
        "closure_class": "PACKAGE_RELEASE",
        "delivery_model": PACKAGE_OR_PLUGIN,
        "delivery_model_proof": {"derivation": "source-of-truth-marker-set-v1"},
        "delivery_model_proof_digest": "sha256:" + "a" * 64,
        "package_release": {"release": "v4.3.11"},
        "artifact_verification": {"verified": True},
        "consumer_validation": {"validated": True},
        "production_release": {"production_release_id": "forged"},
        "subject_fingerprint": "sha256:" + "b" * 64,
        "evidence_records": [],
    }
    errors = validate_evidence_bundle(
        bundle,
        bundle_schema=BUNDLE_SCHEMA,
        evidence_schema=EVIDENCE_SCHEMA,
        trust_roots=None,
        policy=POLICY,
    )
    assert any("cannot contain runtime field production_release" in error for error in errors)
    assert validate_instance(bundle, BUNDLE_SCHEMA)
