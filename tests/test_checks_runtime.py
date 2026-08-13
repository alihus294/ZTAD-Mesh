from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
import yaml

from conftest import commit_files, init_git_repo, valid_contract
from ztad.checks import classify_check_history, run_checks
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def _python_launcher(monkeypatch: pytest.MonkeyPatch) -> str:
    """Use the running interpreter without depending on a pre-existing PATH entry."""
    executable = Path(sys.executable).resolve()
    current_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", str(executable.parent) + os.pathsep + current_path)
    name = executable.name.lower()
    if name.startswith("python3"):
        return "python3"
    return "python"


def _write_controls(repo: Path, *, check_argv: list[str]) -> tuple[Path, Path]:
    contract = repo / ".delivery/change-contract.yaml"
    contract.parent.mkdir(parents=True, exist_ok=True)
    contract.write_text(yaml.safe_dump(valid_contract()), encoding="utf-8")
    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1,
        "configured": True,
        "environment_allowlist": [],
        "max_output_bytes": 100000,
        "checks": [{
            "id": "pytest",
            "argv": check_argv,
            "cwd": ".",
            "timeout_seconds": 120,
            "evidence_type": "LOCAL_TEST_PASSED",
            "fail_fast": True,
        }],
    }), encoding="utf-8")
    return contract, config


def test_run_checks_dry_run_does_not_create_evidence(tmp_path, monkeypatch):
    repo, base = init_git_repo(tmp_path / "repo")
    python = _python_launcher(monkeypatch)
    contract, config = _write_controls(repo, check_argv=[python, "-m", "compileall", "-q", "."])
    output = repo / ".delivery/ztad/evidence/local"
    result = run_checks(
        repo,
        base=base,
        head=base,
        contract_path=contract,
        config_path=config,
        command_policy_path=ROOT / "policies/command-policy.yaml",
        policy_bundle_hash="sha256:" + "a" * 64,
        output_dir=output,
        dry_run=True,
    )
    assert result["decision"] == "DRY_RUN_ONLY"
    assert result["repository_mutated"] is False
    assert not output.exists()


def test_run_checks_sanitizes_environment_and_output(tmp_path, monkeypatch):
    repo, _ = init_git_repo(tmp_path / "repo")
    python = _python_launcher(monkeypatch)
    original_home = tmp_path / "original-home"
    original_home.mkdir()
    (original_home / "credential-marker").write_text("must-not-be-readable", encoding="utf-8")
    monkeypatch.setenv("HOME", str(original_home))
    head = commit_files(repo, {"tests/test_env_guard.py": f"""
import os
from pathlib import Path

def test_environment_is_sanitized():
    print('token=supersecret')
    print('leak=' + str(os.getenv('ZTAD_SECRET_TOKEN')))
    assert os.getenv('ZTAD_SECRET_TOKEN') is None
    assert Path(os.environ['HOME']) != Path({str(original_home)!r})
    assert not (Path(os.environ['HOME']) / 'credential-marker').exists()
"""})
    contract, config = _write_controls(repo, check_argv=[python, "-m", "pytest", "-q", "-s", "-p", "no:cacheprovider", "tests/test_env_guard.py"])
    monkeypatch.setenv("ZTAD_SECRET_TOKEN", "must-not-leak")
    output = repo / ".delivery/ztad/evidence/local"
    result = run_checks(
        repo,
        base=head,
        head=head,
        contract_path=contract,
        config_path=config,
        command_policy_path=ROOT / "policies/command-policy.yaml",
        policy_bundle_hash="sha256:" + "b" * 64,
        output_dir=output,
    )
    assert not result["blocked"]
    evidence_path = Path(result["results"][0]["evidence_path"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    tail = evidence["metadata"]["stdout_stderr_tail"]
    assert "supersecret" not in tail
    assert "must-not-leak" not in tail
    assert "token=<redacted>" in tail
    assert "leak=None" in tail
    assert "ZTAD_SECRET_TOKEN" not in evidence["metadata"]["environment_names_included"]
    assert evidence["trust_level"] == "E2"
    assert result["execution_boundary"]["home_isolated"] is True
    assert result["execution_boundary"]["credentials_inherited"] is False
    assert result["execution_boundary"]["network_isolation"] == "EXTERNAL_SANDBOX_REQUIRED"


def test_run_checks_rejects_unknown_selection(tmp_path, monkeypatch):
    repo, base = init_git_repo(tmp_path / "repo")
    python = _python_launcher(monkeypatch)
    contract, config = _write_controls(repo, check_argv=[python, "-m", "compileall", "-q", "."])
    with pytest.raises(ValueError, match="Unknown selected check ids"):
        run_checks(
            repo,
            base=base,
            head=base,
            contract_path=contract,
            config_path=config,
            command_policy_path=ROOT / "policies/command-policy.yaml",
            policy_bundle_hash="sha256:" + "c" * 64,
            output_dir=repo / "evidence",
            selected_ids={"not-configured"},
        )


def test_check_history_fail_then_pass_remains_blocking():
    head = "1" * 40
    records = [
        {"evidence_id": "ev-fail", "head_sha": head, "command_id": "pytest", "status": "FAILED", "created_at": "2026-01-01T00:00:00Z", "metadata": {"check_id": "pytest"}},
        {"evidence_id": "ev-pass", "head_sha": head, "command_id": "pytest", "status": "PASSED", "created_at": "2026-01-01T00:01:00Z", "metadata": {"check_id": "pytest"}},
    ]
    result = classify_check_history(records, "pytest", head)
    assert result["classification"] == "FLAKY_OR_ENVIRONMENT_DEPENDENT"
    assert result["blocking"]


def test_run_checks_blocks_persistent_repository_mutation(tmp_path, monkeypatch):
    repo, _ = init_git_repo(tmp_path / "repo")
    python = _python_launcher(monkeypatch)
    head = commit_files(repo, {"tests/test_mutates.py": """
from pathlib import Path

def test_mutates_repository():
    Path('generated-by-test.txt').write_text('mutation\\n', encoding='utf-8')
"""})
    contract, config = _write_controls(
        repo,
        check_argv=[
            python, "-m", "pytest", "-q", "-s",
            "-p", "no:cacheprovider", "tests/test_mutates.py",
        ],
    )
    result = run_checks(
        repo,
        base=head,
        head=head,
        contract_path=contract,
        config_path=config,
        command_policy_path=ROOT / "policies/command-policy.yaml",
        policy_bundle_hash="sha256:" + "d" * 64,
        output_dir=repo / ".delivery/ztad/evidence/local",
    )
    assert result["blocked"]
    assert result["repository_mutated"] is True
    assert result["results"][0]["status"] == "REPOSITORY_MUTATED"
    evidence = json.loads(Path(result["results"][0]["evidence_path"]).read_text(encoding="utf-8"))
    assert evidence["status"] == "REPOSITORY_MUTATED"
    assert evidence["metadata"]["repository_mutated"] is True
    assert evidence["metadata"]["worktree_before_hash"] != evidence["metadata"]["worktree_after_hash"]
