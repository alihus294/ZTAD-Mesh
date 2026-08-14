from __future__ import annotations

from typing import Any

from .schema_validation import validate_instance
from .util import canonical_json, sha256_bytes

LOCAL_AUTHORITY = "LOCAL_NON_AUTHORITATIVE"

FINGERPRINT_FIELDS = (
    "repository",
    "change_contract_hash",
    "merged_sha",
    "artifact_digest",
    "build_workflow_sha",
    "policy_bundle_hash",
    "toolchain_hash",
    "sbom_digest",
    "provenance_attestation",
    "test_evidence_refs",
    "risk",
    "rollback_artifact_digest",
)


def compute_release_fingerprint(manifest: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    errors = validate_instance(manifest, schema)
    if errors:
        raise ValueError("Invalid release manifest: " + "; ".join(errors))
    subject = {field: manifest.get(field) for field in FINGERPRINT_FIELDS}
    fingerprint = sha256_bytes(canonical_json(subject))
    return {
        "schema_version": 1,
        "release_fingerprint": fingerprint,
        "subject": subject,
        "authority": LOCAL_AUTHORITY,
        "can_grant_release_or_production": False,
        "claim_boundary": "This deterministic local fingerprint identifies candidate material only. Protected E4+ evidence must verify/sign the exact subject before release authority exists.",
    }
