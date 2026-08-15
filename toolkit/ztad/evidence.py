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


TRUST_ORDER = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5, "E6": 6}
AUTHORITATIVE_MINIMUM = "E3"
AFFIRMATIVE_STATUSES = {"PASSED", "SUCCESS", "VERIFIED", "APPROVED", "COMPLETED", "READY", "ACTIVE"}

SUBJECT_REQUIRED_FIELDS = ("repository", "change_contract_hash", "base_sha", "head_sha", "policy_bundle_hash", "toolchain_hash")
SUBJECT_OPTIONAL_FIELDS = (
    "artifact_digest",
    "release_fingerprint",
    "sbom_digest",
    "provenance_digest",
    "attestation_digest",
    "production_release_id",
    "deployed_revision",
    "artifact_identity",
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_evidence_subject(subject: dict[str, Any] | None) -> list[str]:
    errors: list[str] = []
    if not isinstance(subject, dict):
        return ["Evidence subject must be an object"]
    missing = [field for field in SUBJECT_REQUIRED_FIELDS if not subject.get(field)]
    if missing:
        errors.append("Evidence subject lacks required fields: " + ", ".join(missing))
    if subject.get("repository") is not None and not isinstance(subject.get("repository"), str):
        errors.append("Evidence subject repository must be a string")
    for field in ("base_sha", "head_sha"):
        value = subject.get(field)
        if value is not None and (not isinstance(value, str) or not SHA_PATTERN.fullmatch(value)):
            errors.append(f"Evidence subject {field} must be an exact lowercase hexadecimal revision")
    for field in (
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
    allowed = set(SUBJECT_REQUIRED_FIELDS) | set(SUBJECT_OPTIONAL_FIELDS)
    extra = sorted(set(subject) - allowed)
    if extra:
        errors.append("Evidence subject has unsupported fields: " + ", ".join(extra))
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
    trust_roots: dict[str, Any] | None = None,
    require_authoritative_signature: bool = True,
    require_affirmative_status: bool = False,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if schema is not None:
        errors.extend(validate_instance(evidence, schema))
    if evidence.get("invalidated_by"):
        errors.append("Evidence is invalidated")
    trust = str(evidence.get("trust_level", "E0"))
    if trust not in TRUST_ORDER or TRUST_ORDER[trust] < TRUST_ORDER.get(minimum_trust, 3):
        errors.append(f"Evidence trust level {trust} is below required {minimum_trust}")
    if subject:
        for key in (
            "repository",
            "change_contract_hash",
            "base_sha",
            "head_sha",
            "policy_bundle_hash",
            "toolchain_hash",
            *SUBJECT_OPTIONAL_FIELDS,
        ):
            expected = subject.get(key)
            if expected is not None and evidence.get(key) != expected:
                errors.append(f"Evidence subject mismatch for {key}: expected {expected}, got {evidence.get(key)}")
    producer = str(evidence.get("producer", ""))
    if producer.startswith("agent:") and TRUST_ORDER.get(trust, 0) >= TRUST_ORDER[AUTHORITATIVE_MINIMUM]:
        errors.append("Agent-produced evidence cannot have authoritative trust")
    if evidence.get("exit_code") not in (None, 0) and str(evidence.get("status", "")).upper() in AFFIRMATIVE_STATUSES:
        errors.append("Affirmative evidence cannot have a non-zero exit code")
    if require_affirmative_status and not evidence_affirms(evidence):
        errors.append("Evidence status is not affirmative for the asserted gate claim")

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

    if TRUST_ORDER.get(trust, 0) >= TRUST_ORDER[AUTHORITATIVE_MINIMUM] and require_authoritative_signature:
        if trust_roots is None:
            errors.append("Authoritative evidence cannot be accepted without configured trust roots")
        else:
            errors.extend(verify_evidence_signature(evidence, trust_roots))
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
    trust_roots: dict[str, Any] | None = None,
    require_authoritative_signature: bool = True,
) -> dict[str, Any]:
    records_list = list(records)
    valid_by_type: dict[str, list[str]] = {}
    invalid: dict[str, list[str]] = {}
    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    for record in records_list:
        evidence_id = str(record.get("evidence_id", "<missing>"))
        if evidence_id in seen_ids:
            duplicate_ids.append(evidence_id)
        seen_ids.add(evidence_id)
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
    return {
        "passed": not missing and not duplicate_ids,
        "missing_types": missing,
        "valid_evidence": valid_by_type,
        "invalid_evidence": invalid,
        "duplicate_evidence_ids": sorted(set(duplicate_ids)),
    }
