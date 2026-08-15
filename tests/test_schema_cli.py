import json
from pathlib import Path

from ztad.cli import build_parser, execute
from ztad.problem import initialize_problem_case
from ztad.schema_validation import validate_file, validate_instance
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def test_example_contract_matches_schema():
    errors = validate_file(ROOT/"templates/repository/.delivery/change-contract.example.yaml", ROOT/"schemas/change-contract.schema.json")
    assert errors == []


def test_example_agent_result_matches_schema():
    data = load_data(ROOT/"examples/agent-result.json")
    schema = load_data(ROOT/"schemas/agent-result.schema.json")
    errors = validate_instance(data, schema)
    assert errors == []


def test_cli_parser_has_expected_commands():
    parser = build_parser()
    help_text = parser.format_help()
    assert "classify-risk" in help_text
    assert "release-readiness" in help_text
    assert "build-distribution" in help_text
    assert "validate-distribution" in help_text
    assert "verify-checksums" in help_text
    assert "problem-init" in help_text
    assert "problem-validate" in help_text
    assert "problem-transition" in help_text
    assert "problem-contract" in help_text
    assert "release-fingerprint" in help_text


def test_cli_contract_only_risk():
    parser = build_parser()
    args = parser.parse_args(["classify-risk","--contract",str(ROOT/"templates/repository/.delivery/change-contract.example.yaml")])
    result, code = execute(args)
    assert code == 3
    assert result["mode"] == "CONTRACT_ONLY"
    assert result["blocked"]


def test_cli_problem_init_is_read_only():
    parser = build_parser()
    args = parser.parse_args(["problem-init", "--repo", str(ROOT), "--report", "Observed problem", "--expected", "Expected behavior"])
    result, code = execute(args)
    assert code == 0
    assert result["problem_case"]["state"] == "UNVERIFIED_REPORT"
    assert result["problem_case"]["local_evidence_notice"].startswith("LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE")


def test_cli_problem_contract_dispatches_to_canonical_validator(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    commands = (
        ("init", "-b", "main"),
        ("config", "user.email", "test@example.invalid"),
        ("config", "user.name", "ZTAD Test"),
    )
    for command in commands:
        subprocess.run(["git", "-C", str(repo), *command], check=True, text=True, capture_output=True)
    (repo / "src").mkdir()
    (repo / "src/example.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "src/example.py"], check=True, text=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "base"], check=True, text=True, capture_output=True)

    case = initialize_problem_case(repo, report="X produces Y", expected_behavior="X produces Z")
    base = case["base_sha"]
    assert case["protected_ref_resolved"] is True
    assert base
    case["worktree_status"].update({
        "diverged_from_protected_base": False,
        "user_worktree_preserved": True,
        "isolated_clean_worktree": True,
        "evidence_refs": ["ev-isolated-clean-worktree"],
    })
    case.update({
        "state": "HANDOFF_READY",
        "authoritative_sources": [{"source": "src", "authority": "EXECUTABLE_SOURCE", "authority_reason": "Executable source controls observed behavior.", "evidence_ref": "ev-source"}],
        "classification": "CONFIRMED_BUG",
        "classification_evidence": ["ev-classification"],
        "reproduction": {
            "preconditions": ["known bad base"], "action": "run regression", "input": None,
            "expected": "Z", "actual": "Y", "environment": "local", "deterministic": True,
            "observed_frequency": "1/1", "affected_component": "src/example.py", "evidence_refs": ["ev-red"],
        },
        "root_cause": {
            "trigger": "X", "incorrect_state_or_assumption": "wrong condition", "propagation": ["src"],
            "observable_failure": "Y", "affected_source": ["src/example.py"], "evidence_refs": ["ev-root"],
        },
        "rejected_hypotheses": [],
        "hypothesis_tests": [{"hypothesis": "cache", "test": "invalidate cache", "result": "not causal", "evidence_refs": ["ev-cache"]}],
        "blast_radius": {"direct": ["src/example.py"], "adjacent": ["tests"], "security_boundaries": [], "data_boundaries": []},
        "invariants": ["Unrelated behavior remains unchanged."],
        "risk": "R1",
        "regression_baseline": {
            "base_sha": base, "test_or_oracle": "pytest tests/test_example.py", "bad_result": "FAIL",
            "patched_result": None, "same_oracle": True, "exception_reason": None, "evidence_refs": ["ev-red"],
        },
        "change_plan": {
            "root_cause_summary": "wrong condition", "intended_fix": "correct the condition",
            "expected_files": ["src/example.py", "tests/test_example.py"], "tests": ["pytest tests/test_example.py"],
            "forbidden_scope": ["infra/production"], "database_impact": "none", "external_side_effects": "none",
            "rollback_or_containment": "restore the prior verified artifact",
        },
        "external_dependencies": [],
    })
    case_file = tmp_path / "case.json"
    case_file.write_text(json.dumps(case), encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(["problem-contract", "--case", str(case_file)])
    result, code = execute(args)
    assert code == 0
    assert result["errors"] == []
    assert result["contract"]["governance"]["requested_risk"] == "R1"


def test_check_example_is_intentionally_inactive():
    data = json.loads((ROOT/"templates/repository/.delivery/ztad/config.example.json").read_text())
    assert data["configured"] is False


def test_capability_report_matches_schema(tmp_path):
    from ztad.capabilities import detect_capabilities
    report = detect_capabilities(tmp_path)
    schema = load_data(ROOT / "schemas/capability-report.schema.json")
    assert validate_instance(report, schema) == []
    assert report["maximum_permitted_mode"] == "AUDIT_ONLY"


def test_skill_openai_metadata_uses_current_supported_policy_shape():
    import yaml
    for path in ROOT.glob("skills/*/agents/openai.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert set(data.get("policy", {})) == {"allow_implicit_invocation"}
        assert data["policy"]["allow_implicit_invocation"] is False
        assert f"${path.parent.parent.name}" in data["interface"]["default_prompt"]
