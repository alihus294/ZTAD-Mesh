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
from ztad.problem_isolation import isolate_problem_case
from ztad.schema_validation import validate_instance
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = load_data(ROOT / "schemas/problem-case.schema.json")
CONTRACT_SCHEMA = load_data(ROOT / "schemas/change-contract.schema.json")


def _git(repo: Path, *args: str) -> None:
    import subprocess
    subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True)


def _git_output(repo: Path, *args: str) -> str:
    import subprocess
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, capture_output=True
    ).stdout.strip()


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


def _blast_coverage() -> dict:
    return {
        "direct_components": ["app.py"],
        "adjacent_components": ["tests"],
        "callers_callees": ["test oracle"],
        "api_contracts": ["local behavior"],
        "database_data_boundaries": ["none"],
        "tenant_auth_boundaries": ["none"],
        "financial_zatca_boundaries": ["none"],
        "provider_boundaries": ["none"],
        "concurrency_idempotency_boundaries": ["none"],
        "deployment_infra_boundaries": ["none"],
        "tests": ["pytest tests/test_bug.py"],
        "observability": ["test output"],
        "migration_rollback_impact": ["restore prior artifact"],
        "invariants": ["unrelated behavior remains unchanged"],
        "validation_depth": ["base and candidate oracle"],
    }


def _proven_case(tmp_path: Path) -> dict:
    repo = _repo(tmp_path)
    case = initialize_problem_case(repo, report="When X happens, Y is wrong.", expected_behavior="X must produce Z.")
    base = case["base_sha"]
    case.update({
        "state": "REGRESSION_BASELINE_PROVEN",
        "authoritative_sources": [{"source": "app.py", "authority": "EXECUTABLE_SOURCE", "authority_reason": "Executable behavior is the highest available implementation authority for this local case.", "evidence_ref": "ev-source"}],
        "classification": "CONFIRMED_BUG",
        "classification_evidence": ["ev-classification"],
        "classification_record": {
            "evidence": ["ev-classification"],
            "reproduction_status": "REPRODUCED",
            "authoritative_expected_behavior": "X must produce Z.",
            "competing_explanations_tested": ["cache hypothesis"],
            "environment_findings": ["local base fixture"],
            "unresolved_ambiguities": [],
            "source_conflicts": [],
            "implementation_justified": True,
        },
        "reproduction": {
            "preconditions": ["base fixture"], "action": "run regression", "input": None,
            "expected": "Z", "actual": "Y", "environment": "local", "deterministic": True,
            "observed_frequency": "1/1", "affected_component": "app.py", "evidence_refs": ["ev-red"],
        },
        "root_cause": {
            "trigger": "X", "incorrect_state_or_assumption": "wrong branch", "propagation": ["app.py"],
            "observable_failure": "Y", "affected_source": ["app.py"], "evidence_refs": ["ev-root"],
        },
        "rejected_hypotheses": [{"hypothesis": "cache", "disposition": "REJECTED", "evidence_refs": ["ev-cache"]}],
        "hypothesis_tests": [{"hypothesis": "cache", "test": "invalidate cache and rerun oracle", "result": "cache hypothesis rejected", "evidence_refs": ["ev-cache"]}],
        "blast_radius": {"direct": ["app.py"], "adjacent": ["tests"], "security_boundaries": [], "data_boundaries": [], "coverage": _blast_coverage()},
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
            "file_reasons": {
                "app.py": {
                    "why": "The faulty branch is in the implementation file.",
                    "root_cause_mechanism": "The branch selects Y instead of Z.",
                    "validation": "The exact regression oracle proves the corrected result.",
                },
                "tests/test_bug.py": {
                    "why": "The regression oracle must encode the reported defect.",
                    "root_cause_mechanism": "The oracle exercises the faulty branch.",
                    "validation": "The same oracle fails on base and passes on candidate.",
                },
            },
        },
    })
    return case


def test_initialize_problem_case_is_read_only_and_marks_local_evidence(tmp_path):
    repo = _repo(tmp_path)
    before = (repo / "app.py").read_bytes()
    case = initialize_problem_case(repo, report="Observed problem")
    assert case["state"] == "UNVERIFIED_REPORT"
    assert case["local_evidence_notice"] == LOCAL_EVIDENCE_NOTICE
    assert case["protected_ref"] == "main"
    assert case["protected_ref_resolved"] is True
    assert case["base_sha"] == case["local_head_sha"]
    assert (repo / "app.py").read_bytes() == before
    assert not validate_problem_case(case, SCHEMA)


def test_divergent_local_branch_binds_case_to_protected_main(tmp_path):
    repo = _repo(tmp_path)
    protected = _git_output(repo, "rev-parse", "main")
    _git(repo, "switch", "-c", "work-in-progress")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "local work")
    local = _git_output(repo, "rev-parse", "HEAD")
    case = initialize_problem_case(repo, report="Reported from a divergent branch", protected_ref="main")
    assert case["base_sha"] == protected
    assert case["local_head_sha"] == local
    assert case["base_sha"] != case["local_head_sha"]
    assert case["worktree_status"]["diverged_from_protected_base"] is True


def test_problem_isolation_preserves_divergent_dirty_user_worktree(tmp_path):
    import shutil
    import subprocess

    repo = _repo(tmp_path)
    protected = _git_output(repo, "rev-parse", "main")
    _git(repo, "switch", "-c", "owner-local-work")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "owner local commit")
    (repo / "owner-notes.txt").write_text("uncommitted owner scratch\n", encoding="utf-8")
    original_head = _git_output(repo, "rev-parse", "HEAD")
    original_status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        check=True, capture_output=True,
    ).stdout
    original_app = (repo / "app.py").read_bytes()
    original_notes = (repo / "owner-notes.txt").read_bytes()

    case = initialize_problem_case(repo, report="Reported while owner has local work", protected_ref="main")
    assert case["base_sha"] == protected
    assert case["worktree_status"]["dirty"] is True
    assert case["worktree_status"]["diverged_from_protected_base"] is True

    isolated = isolate_problem_case(case)
    try:
        worktree = Path(isolated["worktree"])
        assert not worktree.is_relative_to(repo.resolve())
        assert _git_output(worktree, "rev-parse", "HEAD") == protected
        assert _git_output(repo, "rev-parse", "HEAD") == original_head
        after_status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            check=True, capture_output=True,
        ).stdout
        assert after_status == original_status
        assert (repo / "app.py").read_bytes() == original_app
        assert (repo / "owner-notes.txt").read_bytes() == original_notes
        assert isolated["problem_case"]["worktree_status"]["user_worktree_preserved"] is True
        assert isolated["problem_case"]["worktree_status"]["isolated_clean_worktree"] is True
        assert isolated["evidence"]["original_status_unchanged"] is True
    finally:
        _git(repo, "worktree", "remove", "--force", isolated["worktree"])
        _git(repo, "worktree", "prune")
        shutil.rmtree(isolated["managed_root"], ignore_errors=True)


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
    assert contract["governance"]["human_decisions"][1]["value"] == handed["base_sha"]


def test_unresolved_external_dependency_blocks_handoff(tmp_path):
    case = _proven_case(tmp_path)
    case["external_dependencies"] = ["protected production approval"]
    decision = can_transition(case, "HANDOFF_READY", SCHEMA)
    assert not decision["allowed"]
    assert any("external" in item.lower() for item in decision["reasons"])
