from pathlib import Path

from ztad.problem import (
    LOCAL_EVIDENCE_NOTICE,
    advance_problem_case,
    can_transition,
    initialize_problem_case,
    problem_case_fingerprint,
    problem_case_to_change_contract,
    validate_problem_case,
)
from ztad.schema_validation import validate_instance
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = load_data(ROOT / "schemas/problem-case.schema.json")
CONTRACT_SCHEMA = load_data(ROOT / "schemas/change-contract.schema.json")


def _git(repo: Path, *args: str) -> None:
    import subprocess
    subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "ZTAD Test")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "base")
    return repo


def _proven_case(tmp_path: Path) -> dict:
    repo = _repo(tmp_path)
    case = initialize_problem_case(repo, report="When X happens, Y is wrong.", expected_behavior="X must produce Z.")
    base = case["base_sha"]
    case.update({
        "state": "REGRESSION_BASELINE_PROVEN",
        "authoritative_sources": [{"source": "app.py", "authority": "EXECUTABLE_SOURCE", "evidence_ref": "ev-source"}],
        "classification": "CONFIRMED_BUG",
        "classification_evidence": ["ev-classification"],
        "reproduction": {
            "preconditions": ["base fixture"], "action": "run regression", "input": None,
            "expected": "Z", "actual": "Y", "environment": "local", "deterministic": True,
            "observed_frequency": "1/1", "evidence_refs": ["ev-red"],
        },
        "root_cause": {
            "trigger": "X", "incorrect_state_or_assumption": "wrong branch", "propagation": ["app.py"],
            "observable_failure": "Y", "affected_source": ["app.py"], "evidence_refs": ["ev-root"],
        },
        "rejected_hypotheses": [{"hypothesis": "cache", "disposition": "REJECTED", "evidence_refs": ["ev-cache"]}],
        "blast_radius": {"direct": ["app.py"], "adjacent": ["tests"], "security_boundaries": [], "data_boundaries": []},
        "invariants": ["Unrelated behavior remains unchanged."],
        "risk": "R1",
        "regression_baseline": {
            "base_sha": base, "test_or_oracle": "pytest tests/test_bug.py", "bad_result": "FAIL",
            "patched_result": None, "same_oracle": True, "exception_reason": None, "evidence_refs": ["ev-red"],
        },
        "change_plan": {
            "root_cause_summary": "wrong branch", "intended_fix": "correct the branch condition",
            "expected_files": ["app.py", "tests/test_bug.py"], "tests": ["pytest tests/test_bug.py"],
            "forbidden_scope": ["infra/production"], "database_impact": "none",
            "external_side_effects": "none", "rollback_or_containment": "restore the prior verified artifact",
        },
    })
    return case


def test_initialize_problem_case_is_read_only_and_marks_local_evidence(tmp_path):
    repo = _repo(tmp_path)
    before = (repo / "app.py").read_bytes()
    case = initialize_problem_case(repo, report="Observed problem")
    assert case["state"] == "UNVERIFIED_REPORT"
    assert case["local_evidence_notice"] == LOCAL_EVIDENCE_NOTICE
    assert case["base_sha"]
    assert (repo / "app.py").read_bytes() == before
    assert not validate_problem_case(case, SCHEMA)


def test_schema_rejects_unexpected_properties(tmp_path):
    case = initialize_problem_case(_repo(tmp_path), report="Observed problem")
    case["invented_authority"] = True
    errors = validate_problem_case(case, SCHEMA)
    assert any("Additional properties" in item or "unexpected" in item.lower() for item in errors)


def test_dirty_worktree_cannot_reach_change_plan_without_clean_isolation(tmp_path):
    case = _proven_case(tmp_path)
    case["state"] = "BLAST_RADIUS_MAPPED"
    case["worktree_status"]["dirty"] = True
    case["worktree_status"]["user_worktree_preserved"] = False
    case["worktree_status"]["isolated_clean_worktree"] = False
    decision = can_transition(case, "CHANGE_PLANNED", SCHEMA)
    assert not decision["allowed"]
    assert any("preserved" in reason or "isolated clean" in reason for reason in decision["reasons"])


def test_same_sha_fail_then_pass_is_not_accepted_as_red_green(tmp_path):
    case = _proven_case(tmp_path)
    case["regression_baseline"]["same_oracle"] = False
    errors = validate_problem_case(case, SCHEMA)
    assert any("same oracle" in error for error in errors)


def test_proven_case_advances_to_handoff_and_generates_valid_change_contract(tmp_path):
    case = _proven_case(tmp_path)
    assert not validate_problem_case(case, SCHEMA)
    handed = advance_problem_case(case, "HANDOFF_READY", SCHEMA)
    assert handed["state"] == "HANDOFF_READY"
    contract = problem_case_to_change_contract(handed, SCHEMA)
    assert not validate_instance(contract, CONTRACT_SCHEMA)
    assert contract["governance"]["requested_risk"] == "R1"
    assert contract["governance"]["human_decisions"][0]["value"] == problem_case_fingerprint(handed)


def test_unresolved_external_dependency_blocks_handoff(tmp_path):
    case = _proven_case(tmp_path)
    case["external_dependencies"] = ["protected production approval"]
    decision = can_transition(case, "HANDOFF_READY", SCHEMA)
    assert not decision["allowed"]
    assert any("external" in item.lower() for item in decision["reasons"])
