from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .crypto import verify_evidence_signature
from .errors import ConfigurationError
from .schema_validation import validate_instance
from .util import atomic_write, load_data
from .subject import SUBJECT_FIELDS, subject_fingerprint, subject_from_record
from .trust import trust_root_payload


TRUST_ORDER = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5, "E6": 6}
AUTHORITATIVE_MINIMUM = "E3"
AFFIRMATIVE_STATUSES = {"PASSED", "SUCCESS", "VERIFIED", "APPROVED", "COMPLETED", "READY", "ACTIVE"}

SUBJECT_REQUIRED_FIELDS = (
    "repository",
    "protected_base_sha",
    "pr_head_sha",
    "reviewed_diff_hash",
    "change_contract_hash",
    "policy_bundle_hash",
    "toolchain_hash",
)
SUBJECT_OPTIONAL_FIELDS = (
    "delivery_model",
    "delivery_model_proof_digest",
    "artifact_digest",
    "release_fingerprint",
    "sbom_digest",
    "provenance_digest",
    "attestation_digest",
    "production_release_id",
    "deployed_revision",
    "artifact_identity",
    "merged_main_sha",
    "merge_method",
    "merge_provenance",
    "post_merge_ci_run_id",
    "subject_epoch",
    "subject_version",
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_evidence_subject(subject: dict[str, Any] | None) -> list[str]:
    errors: list[str] = []
    if not isinstance(subject, dict):
        return ["Evidence subject must be an object"]
    subject = subject_from_record(subject)
    missing = [field for field in SUBJECT_REQUIRED_FIELDS if not subject.get(field)]
    if missing:
        errors.append("Evidence subject lacks required fields: " + ", ".join(missing))
    if subject.get("repository") is not None and not isinstance(subject.get("repository"), str):
        errors.append("Evidence subject repository must be a string")
    for field in ("protected_base_sha", "pr_head_sha", "merged_main_sha", "deployed_revision"):
        value = subject.get(field)
        if value is not None and (not isinstance(value, str) or not SHA_PATTERN.fullmatch(value)):
            errors.append(f"Evidence subject {field} must be an exact lowercase hexadecimal revision")
    for field in (
        "reviewed_diff_hash",
        "change_contract_hash",
        "policy_bundle_hash",
        "toolchain_hash",
        "artifact_digest",
        "release_fingerprint",
        "sbom_digest",
        "provenance_digest",
        "attestation_digest",
    ):
        value = subject.get(field)
        if value is not None and (not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value)):
            errors.append(f"Evidence subject {field} must be a sha256 digest")
    if subject.get("artifact_identity") is not None and (
        not isinstance(subject.get("artifact_identity"), str) or not subject.get("artifact_identity").strip()
    ):
        errors.append("Evidence subject artifact_identity must be a non-empty string")
    if subject.get("merge_method") is not None and subject.get("merge_method") not in {"MERGE", "SQUASH", "REBASE", "FAST_FORWARD"}:
        errors.append("Evidence subject merge_method is unsupported")
    if subject.get("merged_main_sha"):
        provenance = subject.get("merge_provenance")
        if not isinstance(provenance, dict):
            errors.append("Merged-main evidence requires merge_provenance")
        if not subject.get("post_merge_ci_run_id"):
            errors.append("Merged-main evidence requires post_merge_ci_run_id")
    active = subject.get("merged_main_sha") or subject.get("pr_head_sha")
    if subject.get("deployed_revision") and active and subject.get("deployed_revision") != active:
        errors.append("Evidence subject deployed_revision must equal the active merged-main or candidate revision")
    if subject.get("subject_epoch") is not None and (not isinstance(subject.get("subject_epoch"), int) or subject.get("subject_epoch") < 0):
        errors.append("Evidence subject subject_epoch must be a non-negative integer")
    allowed = set(SUBJECT_REQUIRED_FIELDS) | set(SUBJECT_OPTIONAL_FIELDS)
    extra = sorted(set(subject) - allowed)
    if extra:
        errors.append("Evidence subject has unsupported fields: " + ", ".join(extra))
    return sorted(set(errors))


MACHINE_EXECUTOR_EVIDENCE_TYPES = {
    "REGRESSION_RED_GREEN_PROVEN",
    "TARGETED_VALIDATION_PASSED",
    "FULL_REGRESSION_VALIDATION_PASSED",
    "DIFF_FORENSICS_PASSED",
    "SECURITY_VALIDATION_PASSED",
    "SECRETS_SCAN_PASSED",
    "FAIL_CLOSED_BOUNDARY_PASSED",
    "MIGRATION_NECESSITY_PROVEN",
    "MIGRATION_LEDGER_HISTORY_GUARD_PASSED",
    "FRESH_DB_REBUILD_PASSED",
    "DATABASE_RECOVERY_PLAN_VERIFIED",
    "OLD_APP_NEW_SCHEMA_COMPATIBILITY",
    "NEW_APP_OLD_SCHEMA_COMPATIBILITY",
    "RLS_TENANT_DATA_SAFETY_PASSED",
    "BOUNDED_MIGRATION_BACKFILL_PASSED",
    "AUTHZ_TENANT_MATRIX_PASSED",
    "SERVER_SIDE_AUTHORIZATION_PASSED",
    "TENANT_CROSSING_DENIED",
    "ID_TAMPERING_DENIED",
    "PROTECTED_DATA_LEAKAGE_CHECK_PASSED",
    "FINANCIAL_INVARIANTS_PASSED",
    "IDEMPOTENCY_PASSED",
    "CONCURRENCY_INVARIANTS_PASSED",
    "LEDGER_CONSISTENCY_PASSED",
    "NO_DUPLICATE_FINANCIAL_SIDE_EFFECT",
    "ROUNDING_TAX_VAT_ZERO_VALUE_PASSED",
    "FINAL_STATE_REFUND_SEMANTICS_PASSED",
    "ZATCA_INVARIANTS_PASSED",
    "ZATCA_LEGAL_STATE_MACHINE_PASSED",
    "ZATCA_DUPLICATE_PREVENTION_PASSED",
    "ZATCA_IMMUTABILITY_PASSED",
    "ZATCA_SANDBOX_ONLY_TEST_PASSED",
    "ZATCA_CLEARANCE_REPORTING_RETRY_CERTIFICATE_PASSED",
    "ZATCA_SIGNED_DOCUMENT_CUTOVER_PASSED",
    "PROVIDER_SEMANTICS_PASSED",
    "PROVIDER_STATE_RECONCILIATION_PASSED",
    "PROVIDER_IDEMPOTENCY_PASSED",
    "PROVIDER_SAFE_OUTAGE_PASSED",
    "PROVIDER_CONTRACT_FAILURE_RECONCILIATION_PASSED",
    "PARALLEL_REPRODUCTION_PASSED",
    "NO_DUPLICATE_DURABLE_SIDE_EFFECT",
    "CONSUMER_INSTALLATION_VALIDATED",
    "PACKAGED_REGRESSIONS_PASSED",
    "PACKAGE_CONTENT_SECURITY_VERIFIED",
}
REGISTERED_EXECUTOR_PRODUCERS = frozenset({
    "controller:test-executor",
    "controller:validation",
    "platform:protected-ci",
    "platform:protected-validation",
})


def validate_machine_evidence_provenance(record: dict[str, Any], *, subject: dict[str, Any] | None = None) -> list[str]:
    """Reject model-authored JSON that merely claims deterministic execution."""

    evidence_type = str(record.get("type") or "")
    if evidence_type not in MACHINE_EXECUTOR_EVIDENCE_TYPES:
        return []
    errors: list[str] = []
    producer = str(record.get("producer") or "")
    if producer not in REGISTERED_EXECUTOR_PRODUCERS:
        errors.append("Machine evidence must come from a registered deterministic executor/controller")
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    required = (
        "executor_id",
        "command_id",
        "argv_fingerprint",
        "working_directory",
        "start_at",
        "end_at",
        "exit_code",
        "stdout_hash",
        "stderr_hash",
        "check_configuration_hash",
        "toolchain_hash",
        "receipt_id",
        "producer_identity",
        "result_artifact_hash",
        "subject_fingerprint",
        "subject_epoch",
    )
    for field in required:
        if metadata.get(field) in (None, ""):
            errors.append(f"Machine evidence requires immutable provenance field {field}")
    if metadata.get("exit_code") != record.get("exit_code"):
        errors.append("Machine evidence exit_code does not match the receipt")
    if not isinstance(metadata.get("exit_code"), int) or isinstance(metadata.get("exit_code"), bool):
        errors.append("Machine evidence exit_code must be an integer")
    if record.get("command_id") is not None and metadata.get("command_id") != record.get("command_id"):
        errors.append("Machine evidence command_id does not match the receipt")
    if metadata.get("producer_identity") != producer:
        errors.append("Machine evidence producer_identity does not match the producer")
    if record.get("toolchain_hash") is not None and metadata.get("toolchain_hash") != record.get("toolchain_hash"):
        errors.append("Machine evidence toolchain_hash does not match the subject record")
    for field in ("argv_fingerprint", "stdout_hash", "stderr_hash", "check_configuration_hash", "result_artifact_hash", "toolchain_hash"):
        if metadata.get(field) is not None and not DIGEST_PATTERN.fullmatch(str(metadata.get(field))):
            errors.append(f"Machine evidence {field} must be a sha256 digest")
    start = _parse_time(metadata.get("start_at"))
    end = _parse_time(metadata.get("end_at"))
    if start is None:
        errors.append("Machine evidence start_at is invalid")
    if end is None:
        errors.append("Machine evidence end_at is invalid")
    if start is not None and end is not None and end < start:
        errors.append("Machine evidence end_at must not precede start_at")
    if subject is not None:
        expected_fp = subject_fingerprint(subject)
        if metadata.get("subject_fingerprint") != expected_fp:
            errors.append("Machine evidence subject_fingerprint mismatch")
        if metadata.get("subject_epoch") != int(subject.get("subject_epoch") or 0):
            errors.append("Machine evidence subject_epoch mismatch")
    if record.get("subject_fingerprint") is not None and metadata.get("subject_fingerprint") != record.get("subject_fingerprint"):
        errors.append("Machine evidence record and metadata subject_fingerprint mismatch")
    if metadata.get("manual") is True or metadata.get("model_authored") is True:
        errors.append("Model-authored or manually authored machine evidence is not authoritative")
    return sorted(set(errors))


def evidence_affirms(record: dict[str, Any]) -> bool:
    """Return whether an evidence record positively supports its claim.

    Approval-controller evidence requires APPROVED exactly. Other gate evidence
    must carry a positive terminal status; a valid signature over
    FAILED/REJECTED evidence never satisfies a gate.
    """
    status = str(record.get("status", "")).upper()
    evidence_type = str(record.get("type", ""))
    if evidence_type.endswith("_APPROVAL"):
        return status == "APPROVED"
    return status in AFFIRMATIVE_STATUSES


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Subject-bound evidence timestamps must be unambiguous. Naive local times
    # are rejected rather than interpreted using the verifier's timezone.
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def validate_evidence_record(
    evidence: dict[str, Any],
    *,
    schema: dict[str, Any] | None = None,
    subject: dict[str, str] | None = None,
    minimum_trust: str = "E3",
    trust_roots: Any = None,
    require_authoritative_signature: bool = True,
    require_affirmative_status: bool = False,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if minimum_trust not in TRUST_ORDER:
        return [f"Unknown minimum evidence trust level: {minimum_trust}"]
    if schema is not None:
        errors.extend(validate_instance(evidence, schema))
    if evidence.get("invalidated_by"):
        errors.append("Evidence is invalidated")
    trust = str(evidence.get("trust_level", "E0"))
    if trust not in TRUST_ORDER or TRUST_ORDER[trust] < TRUST_ORDER.get(minimum_trust, 3):
        errors.append(f"Evidence trust level {trust} is below required {minimum_trust}")
    if subject:
        expected_subject = subject_from_record(subject)
        actual_subject = subject_from_record(evidence)
        for key in SUBJECT_FIELDS:
            expected = expected_subject.get(key)
            if expected is None:
                continue
            raw_actual = evidence.get(key)
            if key in {"delivery_model", "delivery_model_proof_digest"} and raw_actual is None:
                # Historical fixtures created before delivery-model binding did
                # not carry this optional subject extension.  Keep that
                # compatibility only for the conservative hosted fallback;
                # package and hybrid evidence must bind the model explicitly.
                if expected_subject.get("delivery_model") == "HOSTED_RUNTIME_SERVICE":
                    continue
            if key in {"subject_epoch", "subject_version"} and raw_actual is None:
                if TRUST_ORDER.get(trust, 0) < TRUST_ORDER["E3"]:
                    continue
                errors.append(f"Evidence subject mismatch for {key}: the protected record must carry the field explicitly")
                continue
            actual = actual_subject.get(key)
            if actual != expected:
                errors.append(f"Evidence subject mismatch for {key}: expected {expected}, got {actual}")
        expected_fingerprint = subject_fingerprint(expected_subject)
        actual_fingerprint = evidence.get("subject_fingerprint")
        if TRUST_ORDER.get(trust, -1) >= TRUST_ORDER["E3"] and actual_fingerprint != expected_fingerprint:
            errors.append("Evidence subject_fingerprint must match the exact protected subject")
        elif actual_fingerprint is not None and actual_fingerprint != subject_fingerprint(actual_subject):
            errors.append("Evidence subject_fingerprint does not match the evidence subject")
    elif evidence.get("subject_fingerprint") is not None and evidence.get("subject_fingerprint") != subject_fingerprint(subject_from_record(evidence)):
        errors.append("Evidence subject_fingerprint does not match the evidence subject")
    producer = str(evidence.get("producer", ""))
    if producer.startswith("agent:") and TRUST_ORDER.get(trust, 0) >= TRUST_ORDER[AUTHORITATIVE_MINIMUM]:
        errors.append("Agent-produced evidence cannot have authoritative trust")
    if evidence.get("exit_code") not in (None, 0) and str(evidence.get("status", "")).upper() in AFFIRMATIVE_STATUSES:
        errors.append("Affirmative evidence cannot have a non-zero exit code")
    if require_affirmative_status and not evidence_affirms(evidence):
        errors.append("Evidence status is not affirmative for the asserted gate claim")
    errors.extend(validate_machine_evidence_provenance(evidence, subject=subject))

    current = now or datetime.now(timezone.utc)
    created = _parse_time(evidence.get("created_at"))
    if created is None:
        errors.append("Evidence created_at is invalid")
    elif created > current.replace(microsecond=0) + timedelta(minutes=5):
        errors.append("Evidence created_at is implausibly in the future")
    expires = _parse_time(evidence.get("expires_at"))
    if evidence.get("expires_at") and expires is None:
        errors.append("Evidence expires_at is invalid")
    elif expires is not None and expires <= current:
        errors.append("Evidence is expired")
    if created is not None and expires is not None and expires <= created:
        errors.append("Evidence expires_at must be later than created_at")

    if TRUST_ORDER.get(trust, 0) >= TRUST_ORDER[AUTHORITATIVE_MINIMUM]:
        if trust_roots is None:
            errors.append("Authoritative evidence cannot be accepted without configured trust roots")
        else:
            payload = trust_root_payload(trust_roots)
            if payload is None:
                errors.append("Configured trust roots are not a usable root set")
            else:
                errors.extend(verify_evidence_signature(evidence, payload))
    return sorted(set(errors))


def load_evidence_records(path: Path, *, max_records: int = 2000) -> list[dict[str, Any]]:
    """Load bounded JSON evidence without following symlinks or silently dropping malformed entries."""
    if path.is_symlink():
        raise ConfigurationError(f"Evidence input must not be a symlink: {path}")
    if path.is_dir():
        items = sorted(path.glob("*.json"))
        if len(items) > max_records:
            raise ConfigurationError(f"Evidence directory exceeds {max_records} JSON records: {path}")
        records: list[dict[str, Any]] = []
        for item in items:
            if item.is_symlink() or not item.is_file():
                raise ConfigurationError(f"Evidence record must be a regular non-symlink file: {item}")
            data = load_data(item)
            if not isinstance(data, dict) or "evidence_id" not in data:
                raise ConfigurationError(f"Evidence file must contain one evidence object: {item}")
            records.append(data)
        return records
    if not path.exists() or not path.is_file() or path.suffix.lower() != ".json":
        raise ConfigurationError(f"Evidence input must be a JSON file or directory: {path}")
    data = load_data(path)
    if isinstance(data, list):
        if len(data) > max_records:
            raise ConfigurationError(f"Evidence file exceeds {max_records} records: {path}")
        if any(not isinstance(item, dict) or "evidence_id" not in item for item in data):
            raise ConfigurationError(f"Evidence list contains a non-record entry: {path}")
        return list(data)
    if isinstance(data, dict) and "evidence_id" in data:
        return [data]
    raise ConfigurationError(f"Evidence input must contain one record or a list of records: {path}")


def create_local_untrusted_evidence(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    """Create a missing local evidence file without fabricating authority.

    The function is intentionally create-only. It refuses replacement, forces a
    local producer and E2-or-below trust, and marks the result as non-authoritative
    in metadata so a missing sidecar can be repaired without being promoted.
    """

    if path.exists() or path.is_symlink():
        raise ConfigurationError(f"Refusing to overwrite existing evidence file: {path}")
    if not isinstance(record, dict):
        raise ConfigurationError("Local evidence record must be an object")
    created = dict(record)
    created["trust_level"] = "E2"
    created["producer"] = str(created.get("producer") or "local:ztad")
    if not created["producer"].startswith("local:"):
        created["producer"] = "local:" + created["producer"]
    created["signature_or_attestation"] = None
    created["invalidated_by"] = list(created.get("invalidated_by") or [])
    metadata = dict(created.get("metadata") or {})
    metadata.update({
        "authority": "LOCAL_NON_AUTHORITATIVE",
        "can_grant_merge_release_or_production": False,
    })
    created["metadata"] = metadata
    atomic_write(path, (json.dumps(created, indent=2, sort_keys=True) + "\n").encode("utf-8"), mode=0o600)
    return created


def evidence_index(records: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(record.get("evidence_id")): record for record in records if record.get("evidence_id")}


def evaluate_required_evidence(
    records: Iterable[dict[str, Any]],
    required_types: Iterable[str],
    *,
    subject: dict[str, str],
    schema: dict[str, Any] | None = None,
    minimum_trust: str = "E3",
    trust_roots: Any = None,
    require_authoritative_signature: bool = True,
) -> dict[str, Any]:
    records_list = list(records)
    valid_by_type: dict[str, list[str]] = {}
    invalid: dict[str, list[str]] = {}
    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    seen_receipts: set[tuple[str, str]] = set()
    duplicate_receipts: list[str] = []
    for record in records_list:
        evidence_id = str(record.get("evidence_id", "<missing>"))
        if evidence_id in seen_ids:
            duplicate_ids.append(evidence_id)
        seen_ids.add(evidence_id)
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        receipt_id = metadata.get("receipt_id")
        if receipt_id not in (None, ""):
            receipt_key = (str(receipt_id), str(record.get("type") or ""))
            if receipt_key in seen_receipts:
                duplicate_receipts.append(receipt_key[0])
            seen_receipts.add(receipt_key)
        errors = validate_evidence_record(
            record,
            schema=schema,
            subject=subject,
            minimum_trust=minimum_trust,
            trust_roots=trust_roots,
            require_authoritative_signature=require_authoritative_signature,
            require_affirmative_status=True,
        )
        if errors:
            invalid[evidence_id] = errors
        else:
            valid_by_type.setdefault(str(record.get("type")), []).append(evidence_id)
    missing = [item for item in required_types if not valid_by_type.get(item)]
    if duplicate_ids:
        invalid["<duplicates>"] = ["Duplicate evidence IDs: " + ", ".join(sorted(set(duplicate_ids)))]
    if duplicate_receipts:
        invalid["<duplicate_receipts>"] = ["Duplicate machine receipt IDs: " + ", ".join(sorted(set(duplicate_receipts)))]
    return {
        "passed": not missing and not duplicate_ids and not duplicate_receipts,
        "missing_types": missing,
        "valid_evidence": valid_by_type,
        "invalid_evidence": invalid,
        "duplicate_evidence_ids": sorted(set(duplicate_ids)),
        "duplicate_receipt_ids": sorted(set(duplicate_receipts)),
    }
