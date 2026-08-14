from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _skill(name: str) -> str:
    return (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")


def test_problem_investigation_has_no_red_green_exception() -> None:
    text = _skill("problem-investigation")
    assert "same oracle must later prove `PASS` on the exact candidate" in text
    assert "do not substitute model judgment" in text
    assert "controller-reviewable exception with equivalent evidence" not in text


def test_finding_repair_cannot_skip_exact_red_green_proof() -> None:
    text = _skill("finding-verification-repair")
    assert "proves `FAIL` on the exact confirmed-bad revision" in text
    assert "`PASS` on the exact repaired candidate" in text
    assert "the lifecycle remains `BLOCKED`" in text
    assert "Add a failing regression test first when feasible" not in text


def test_supervisor_recommendation_is_not_protected_authority() -> None:
    text = _skill("supervisor-governance")
    assert "`APPROVE` is only a structured recommendation" in text
    assert "cannot itself satisfy `PROTECTED_SUPERVISOR_APPROVAL`" in text
    assert "cannot be mechanically translated into E6" in text
    assert "Production release authorization remains an external protected-authority action" in text


def test_independent_review_emits_lifecycle_pass_or_block() -> None:
    text = _skill("independent-review")
    assert "explicit lifecycle verdict (`PASS`, `BLOCK`, or `INSUFFICIENT_EVIDENCE`)" in text
    assert "only when metadata verdict is exactly `PASS`" in text
    assert "it is never E6 approval" in text


def test_release_readiness_never_equates_runtime_verification_with_closure() -> None:
    text = _skill("release-readiness")
    assert "must never create E6 by merely signing, wrapping, or translating a model recommendation" in text
    assert "`PRODUCTION_VERIFIED` means the exact production runtime evidence is sufficient for the `POST_DEPLOY_VERIFIED` claim only" in text
    assert "Never equate any readiness result with bug-lifecycle `CLOSED`" in text


def test_primary_skill_keeps_authoritative_lifecycle_boundary() -> None:
    text = _skill("zero-trust-delivery")
    assert "For every reported defect, `policies/bug-to-production-policy.yaml`" in text
    assert "`DONE` is not a valid bug-lifecycle state" in text
    assert "A code-fix case is closed only after `POST_DEPLOY_VERIFIED → CLOSED`" in text
