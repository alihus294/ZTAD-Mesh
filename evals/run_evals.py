#!/usr/bin/env python3
"""Offline deterministic evaluations for the ZTAD package.

These evaluations validate control behavior and static skill routing metadata.
They do not claim that a particular hosted model will invoke a skill correctly;
model-routing evals must be run separately against the pinned target model.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TOOLKIT = ROOT / "toolkit"
if str(TOOLKIT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT))

from ztad.capabilities import detect_capabilities  # noqa: E402
from ztad.checks import classify_check_history  # noqa: E402
from ztad.commands import validate_command  # noqa: E402
from ztad.control_plane import detect_control_plane_changes, scan_patch_text  # noqa: E402
from ztad.bug_protocol import (  # noqa: E402
    continuation_decision,
    red_green_result,
    validate_artifact_chain,
    validate_authoritative_sources,
    validate_ci_metadata,
    validate_post_deploy_metadata,
    validate_test_integrity,
    validate_workshopos_message,
)
from ztad.evidence import evaluate_required_evidence  # noqa: E402
from ztad.errors import ConfigurationError  # noqa: E402
from ztad.injection import scan_untrusted_text  # noqa: E402
from ztad.risk import RISK_ORDER, classify_risk  # noqa: E402
from ztad.state_machine import evaluate_transition_from_records  # noqa: E402
from ztad.test_weakening import detect_test_weakening_from_diff  # noqa: E402
from ztad.util import load_data, utc_now  # noqa: E402


def _contract(requested_risk: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "change_id": "EVAL-001",
        "title": "Deterministic evaluation change",
        "goal": "Exercise a bounded control behavior.",
        "requirements": {
            "acceptance_criteria": ["The expected control decision is produced."],
            "non_goals": ["No external platform mutation."],
            "invariants": ["No authority is granted to an agent."],
            "assumptions": [{"id": "A-1", "statement": "Fixture inputs are complete.", "status": "verified", "evidence_ref": "fixture"}],
        },
        "scope": {
            "expected_components": ["fixture"],
            "data_classification": "C0",
            "service_criticality": "tier_3",
            "public_contract_change": False,
            "data_migration_expected": False,
        },
        "verification": {
            "test_oracles": ["Decision matches fixture expectation."],
            "negative_cases": ["Unsafe input is rejected."],
        },
        "release": {
            "rollback_strategy": "Discard fixture state.",
            "data_reversal_required": False,
            "feature_flag": {"required": False, "owner": None, "expiry": None},
        },
        "governance": {
            "requested_risk": requested_risk,
            "product_owner": "eval-owner",
            "engineering_owner": "eval-engineer",
        },
        "quality_attributes": {"security": "fail closed"},
    }


def _case(case_id: str, passed: bool, detail: Any, *, category: str, skipped: bool = False) -> dict[str, Any]:
    return {"id": case_id, "category": category, "passed": bool(passed), "skipped": bool(skipped), "detail": detail}


def evaluate_skill_routing() -> list[dict[str, Any]]:
    data = json.loads((ROOT / "evals/trigger-cases.json").read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    for item in data["positive"]:
        expected = item["expected_skill"]
        token = f"${expected}"
        results.append(_case(item["id"], token in item["prompt"], {"expected_explicit_token": token}, category="static-routing-positive"))
    for item in data["negative"]:
        results.append(_case(item["id"], "$" not in item["prompt"], {"expected_skill": None}, category="static-routing-negative"))
    return results


def evaluate_fixtures() -> list[dict[str, Any]]:
    risk_policy = load_data(ROOT / "policies/risk-policy.yaml")
    path_policy = load_data(ROOT / "policies/path-policy.yaml")
    results: list[dict[str, Any]] = []
    for path in sorted((ROOT / "evals/fixtures").glob("*/scenario.json")):
        scenario = json.loads(path.read_text(encoding="utf-8"))
        diff = "\n".join(f"+++ b/{p}\n{scenario.get('payload','')}" for p in scenario["paths"])
        risk = classify_risk(
            _contract(scenario["contract_requested_risk"]),
            changed_paths=scenario["paths"],
            diff_text=diff,
            policy=risk_policy,
        )
        expected = scenario["expected_minimum_risk"]
        checks = [RISK_ORDER[risk.risk] >= RISK_ORDER[expected]]
        details: dict[str, Any] = {"risk": risk.risk, "expected_minimum_risk": expected}

        control = detect_control_plane_changes(scenario["paths"], path_policy)
        if scenario.get("expected_control_block"):
            checks.append(control["blocked"])
            details["control_blocked"] = control["blocked"]

        test_findings = detect_test_weakening_from_diff(diff)
        if scenario.get("expected_test_integrity_block"):
            test_blocked = any(item.severity == "BLOCK" for item in test_findings)
            checks.append(test_blocked)
            details["test_integrity_blocked"] = test_blocked

        signals = scan_untrusted_text(scenario.get("payload", ""))
        if scenario.get("expected_injection_signal"):
            checks.append(bool(signals))
            details["injection_signals"] = [item.code for item in signals]

        if scenario["name"] == "flaky-test":
            records = [
                {"evidence_id":"ev-fail","head_sha":"1"*40,"status":"FAILED","command_id":"pytest","created_at":"2026-01-01T00:00:00Z","metadata":{"check_id":"pytest"}},
                {"evidence_id":"ev-pass","head_sha":"1"*40,"status":"PASSED","command_id":"pytest","created_at":"2026-01-01T00:01:00Z","metadata":{"check_id":"pytest"}},
            ]
            history = classify_check_history(records, "pytest", "1"*40)
            checks.append(history["classification"] == "FLAKY_OR_ENVIRONMENT_DEPENDENT" and history["blocking"])
            details["history"] = history["classification"]

        results.append(_case(scenario["name"], all(checks), details, category="fixture"))
    return results


def evaluate_adversarial() -> list[dict[str, Any]]:
    data = json.loads((ROOT / "evals/adversarial-cases.json").read_text(encoding="utf-8"))
    command_policy = load_data(ROOT / "policies/command-policy.yaml")
    risk_policy = load_data(ROOT / "policies/risk-policy.yaml")
    results: list[dict[str, Any]] = []
    for item in data["cases"]:
        kind = item["kind"]
        detail: Any
        if kind == "command":
            decision = validate_command(item["argv"], command_policy)
            passed = not decision["allowed"]
            detail = decision
        elif kind == "patch_text":
            findings = scan_patch_text(item["text"])
            passed = any(row.get("severity") == "BLOCK" for row in findings)
            detail = findings
        elif kind == "test_diff":
            findings = detect_test_weakening_from_diff(item["text"])
            passed = any(row.severity == "BLOCK" for row in findings)
            detail = [row.to_dict() for row in findings]
        elif kind == "injection":
            signals = scan_untrusted_text(item["text"])
            passed = bool(signals)
            detail = [row.to_dict() for row in signals]
        elif kind == "risk":
            result = classify_risk(_contract("R0"), changed_paths=item["paths"], diff_text=item["diff"], policy=risk_policy)
            passed = RISK_ORDER[result.risk] >= RISK_ORDER[item["expected_minimum"]]
            detail = result.to_dict()
        else:
            passed = False
            detail = {"error": f"Unknown adversarial kind: {kind}"}
        results.append(_case(item["id"], passed, detail, category="adversarial"))
    return results



def _subject() -> dict[str, str]:
    return {
        "repository": "owner/repo",
        "change_contract_hash": "sha256:" + "a" * 64,
        "base_sha": "0" * 40,
        "head_sha": "1" * 40,
        "policy_bundle_hash": "sha256:" + "b" * 64,
        "toolchain_hash": "sha256:" + "c" * 64,
    }


def _local_evidence(*, status: str = "PASSED") -> dict[str, Any]:
    return {
        "evidence_id": "ev-local-contract-001",
        "type": "CHANGE_CONTRACT_VALID",
        "trust_level": "E2",
        "producer": "tool:contract-validator",
        **_subject(),
        "environment": "local",
        "command_id": "validate-contract",
        "exit_code": 0,
        "status": status,
        "output_hash": "sha256:" + "c" * 64,
        "artifact_digest": None,
        "created_at": utc_now(),
        "expires_at": None,
        "invalidated_by": [],
        "signature_or_attestation": None,
        "metadata": {},
    }


def evaluate_security_boundaries() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    evidence_schema = load_data(ROOT / "schemas/evidence.schema.json")
    state_policy = load_data(ROOT / "policies/state-machine.yaml")
    path_policy = load_data(ROOT / "policies/path-policy.yaml")
    command_policy = load_data(ROOT / "policies/command-policy.yaml")

    failed = _local_evidence(status="FAILED")
    required = evaluate_required_evidence(
        [failed], ["CHANGE_CONTRACT_VALID"], subject=_subject(), schema=evidence_schema,
        minimum_trust="E2", require_authoritative_signature=False,
    )
    results.append(_case("S01-nonaffirmative-evidence", not required["passed"] and bool(required["invalid_evidence"]), required, category="security-boundary"))

    incomplete = _subject(); incomplete.pop("toolchain_hash")
    transition = evaluate_transition_from_records(
        state_policy, current_state="BACKLOG", requested_state="READY", risk="R1",
        records=[_local_evidence()], subject=incomplete, evidence_schema=evidence_schema, trust_roots=None,
    )
    results.append(_case("S02-incomplete-subject", not transition["allowed"] and "<subject>" in transition["invalid_evidence"], transition, category="security-boundary"))

    control = detect_control_plane_changes([".gitmodules"], path_policy)
    results.append(_case("S03-gitmodules-prohibited", control["blocked"] and ".gitmodules" in control["prohibited_paths"], control, category="security-boundary"))

    response = validate_command(["pytest", "@not-present.args"], command_policy)
    results.append(_case("S04-response-file-denied", not response["allowed"], response, category="security-boundary"))

    with tempfile.TemporaryDirectory(prefix="ztad-eval-") as temp_dir:
        root = Path(temp_dir)
        capability = detect_capabilities(root)
        results.append(_case("S05-empty-repo-audit-only", capability["maximum_permitted_mode"] == "AUDIT_ONLY", capability, category="security-boundary"))

        duplicate = root / "duplicate.json"
        duplicate.write_text('{"risk":"R1","risk":"R0"}', encoding="utf-8")
        rejected = False; detail = None
        try:
            load_data(duplicate)
        except ConfigurationError as exc:
            rejected = True; detail = str(exc)
        results.append(_case("S06-duplicate-json-rejected", rejected, detail, category="security-boundary"))

        real = root / "real.json"; real.write_text("{}", encoding="utf-8")
        link = root / "link.json"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError) as exc:
            results.append(_case(
                "S07-symlink-structured-input-rejected", True,
                {"skipped": True, "reason": f"symlink_creation_unavailable:{type(exc).__name__}:{exc}"},
                category="security-boundary", skipped=True,
            ))
        else:
            rejected = False; detail = None
            try:
                load_data(link)
            except ConfigurationError as exc:
                rejected = True; detail = str(exc)
            results.append(_case("S07-symlink-structured-input-rejected", rejected, detail, category="security-boundary"))

    return results


def evaluate_protocol_adversarial() -> list[dict[str, Any]]:
    data = json.loads((ROOT / "evals/protocol-adversarial-cases.json").read_text(encoding="utf-8"))
    policy = load_data(ROOT / "policies/bug-to-production-policy.yaml")
    state_policy = load_data(ROOT / "policies/state-machine.yaml")
    results: list[dict[str, Any]] = []
    base = "0" * 40
    head = "1" * 40
    artifact = "sha256:" + "b" * 64
    release = "sha256:" + "c" * 64
    sbom = "sha256:" + "d" * 64
    provenance = "sha256:" + "e" * 64
    attestation = "sha256:" + "f" * 64
    for item in data["cases"]:
        kind = item["kind"]
        detail: Any
        if kind == "source_conflict":
            detail = validate_authoritative_sources(
                [{"source": "report", "authority": "REPORT_OR_PLAN", "authority_reason": "reported context", "evidence_ref": "ev-report"}],
                ["source disagrees"],
                authority_order=policy["authority_order"],
            )
            passed = item["expected"] in detail
        elif kind == "same_sha_red_green":
            detail = red_green_result({"bad_base_sha": base, "candidate_head_sha": base}, bad_base_sha=base, candidate_head_sha=base)
            passed = detail == item["expected"]
        elif kind == "test_weakening":
            detail = validate_test_integrity({"findings": [{"code": "ASSERTION_REMOVED", "severity": "BLOCK"}]})
            passed = bool(detail)
        elif kind == "artifact_chain":
            detail = validate_artifact_chain({"source_sha": head, "artifact_digest": artifact}, head_sha=head, artifact_digest=artifact)
            passed = bool(detail)
        elif kind == "stale_ci":
            detail = validate_ci_metadata(
                {"pr_head_sha": base, "reviewed_diff_hash": "sha256:" + "a" * 64, "workflow_run_id": "run", "required_checks": ["ci"], "conclusion": "SUCCESS"},
                head_sha=head,
                diff_hash="sha256:" + "a" * 64,
            )
            passed = bool(detail)
        elif kind == "workshopos_phone":
            profile = policy["profiles"]["workshopos"]
            detail = validate_workshopos_message("0550000000", profile=profile)
            passed = bool(detail)
        elif kind == "postdeploy_uncertain":
            detail = validate_post_deploy_metadata({"safety_uncertain": True}, artifact_digest=artifact)
            passed = any(item["expected"] in row for row in detail)
        elif kind == "model_authority":
            primary = (ROOT / "skills/zero-trust-delivery/SKILL.md").read_text(encoding="utf-8")
            detail = {
                "forbidden_claim": "model_approval_is_authority" in policy["forbidden_claims"],
                "skill_boundary": "No model statement can become approval or authoritative evidence." in primary,
            }
            passed = all(detail.values())
        elif kind == "scheduler_closure":
            boundary = state_policy["authoritative_bug_lifecycle"]
            detail = boundary
            passed = boundary["terminal_scheduler_state"] == "INTERNAL_EXECUTION_COMPLETE" and boundary["done_is_internal_only"] is True
        else:
            detail = {"error": f"Unknown protocol case: {kind}"}
            passed = False
        results.append(_case(item["id"], passed, detail, category="protocol-adversarial"))
    return results

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "validation/eval-results.json"))
    args = parser.parse_args()
    results = evaluate_skill_routing() + evaluate_fixtures() + evaluate_adversarial() + evaluate_security_boundaries() + evaluate_protocol_adversarial()
    failed = [item for item in results if not item["passed"] and not item["skipped"]]
    skipped = [item for item in results if item["skipped"]]
    report = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "scope": "offline deterministic controls and static explicit-routing fixtures",
        "model_routing_executed": False,
        "model_routing_claim_boundary": "Run submission cases against each pinned target model before governed use; this offline runner does not prove hosted-model routing behavior.",
        "total": len(results),
        "passed": len(results) - len(failed) - len(skipped),
        "failed": len(failed),
        "skipped": len(skipped),
        "results": results,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
