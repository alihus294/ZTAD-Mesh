from __future__ import annotations

from typing import Any, Iterable

from .schema_validation import validate_instance


def validate_finding(
    finding: dict[str, Any],
    *,
    schema: dict[str, Any],
    expected_head_sha: str,
    known_evidence_ids: Iterable[str] = (),
) -> list[str]:
    errors = validate_instance(finding, schema)
    if finding.get("head_sha") != expected_head_sha:
        errors.append("Finding head_sha does not match the reviewed revision")
    evidence_ids = set(known_evidence_ids)
    refs = finding.get("evidence_refs", []) or []
    for ref in refs:
        if evidence_ids and ref not in evidence_ids:
            errors.append(f"Finding references unknown evidence: {ref}")
    if finding.get("severity") in {"P0", "P1"}:
        if not refs:
            errors.append("Blocking finding requires evidence")
        if finding.get("verification_status") == "PROPOSED":
            # A proposal may block review progress but cannot be treated as a confirmed defect.
            pass
    if finding.get("verification_status") == "CONFIRMED":
        if not finding.get("reproduction") and not refs:
            errors.append("Confirmed finding requires a reproduction or proof evidence")
        if not finding.get("falsification_attempt"):
            errors.append("Confirmed finding requires a documented falsification attempt")
    if finding.get("verification_status") == "FALSIFIED" and not finding.get("uncertainty"):
        errors.append("Falsified finding requires a reason in uncertainty")
    line_start = finding.get("line_start")
    line_end = finding.get("line_end")
    if isinstance(line_start, int) and isinstance(line_end, int) and line_end < line_start:
        errors.append("line_end cannot be before line_start")
    return sorted(set(errors))
