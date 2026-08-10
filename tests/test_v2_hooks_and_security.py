from __future__ import annotations

import json
from pathlib import Path

from ztad.commands import validate_command
from ztad.control_plane import detect_control_plane_changes
from ztad.hooks import handle_hook
from ztad.orchestrator import ContinuityStore
from ztad.policy_registry import audit_policy_wiring
from ztad.test_weakening import detect_test_weakening_from_diff
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def test_windows_case_insensitive_and_root_protected_paths():
    policy = load_data(ROOT / "policies/path-policy.yaml")
    for path in (
        ".GitHub/workflows/ci.yml",
        "agents.md",
        "pytest.ini",
        "JEST.CONFIG.JS",
        ".GITMODULES",
    ):
        result = detect_control_plane_changes([path], policy)
        assert result["blocked"], path


def test_command_validator_blocks_repository_escape_vectors(tmp_path):
    policy = load_data(ROOT / "policies/command-policy.yaml")
    repo = tmp_path / "repo"
    repo.mkdir()
    blocked = [
        ["pytest", "../../outside/evil_test.py"],
        ["python", "-m", "pytest", "C:/Users/Ali/Downloads/evil_test.py"],
        ["npm", "test", "--prefix", "../../outside-project"],
        ["git", "diff", "--no-index", "/etc/passwd", "/dev/null"],
        ["git", "show", "--output=/tmp/ztad-leak", "HEAD"],
        ["python3", "-m", "compileall", "/etc"],
        ["pytest", "--rootdir=/tmp", "/tmp/evil_test.py"],
    ]
    for argv in blocked:
        result = validate_command(argv, policy, workspace_root=repo)
        assert not result["allowed"], (argv, result)


def test_command_validator_allows_bundled_safe_pytest_plugin_disable(tmp_path):
    policy = load_data(ROOT / "policies/command-policy.yaml")
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "tests/test_x.py").write_text("", encoding="utf-8")
    result = validate_command(
        ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_x.py"],
        policy, workspace_root=repo,
    )
    assert result["allowed"], result


def test_test_weakening_detects_bypass_patterns():
    cases = {
        "SKIP_ADDED": "+++ b/tests/test_x.py\n+@pytest.mark.skipif(True, reason='x')\n",
        "FOCUS_ADDED": "+++ b/tests/x.test.js\n+test.only('x', () => {})\n",
        "TEST_DISCOVERY_CHANGED": "+++ b/pytest.ini\n+addopts = --ignore=tests/security\n",
        "TEST_SCRIPT_MASKED": '+++ b/package.json\n+  "test": "echo success"\n',
        "CI_STEP_DISABLED": "+++ b/.github/workflows/ci.yml\n+    if: false\n",
    }
    for code, diff in cases.items():
        findings = detect_test_weakening_from_diff(diff)
        assert any(item.code == code for item in findings), (code, findings)


def test_test_integrity_policy_is_a_real_runtime_input():
    diff = "+++ b/tests/test_x.py\n+@pytest.mark.skipif(True, reason='hide')\n"
    disabled = {"enabled_finding_codes": [], "severity_by_code": {}}
    assert detect_test_weakening_from_diff(diff, disabled) == []
    escalated = {
        "enabled_finding_codes": ["SKIP_ADDED"],
        "severity_by_code": {"SKIP_ADDED": "ESCALATE"},
    }
    finding = detect_test_weakening_from_diff(diff, escalated)[0]
    assert finding.code == "SKIP_ADDED"
    assert finding.severity == "ESCALATE"


def test_pretool_hook_denies_shell_chaining_when_active(tmp_path, monkeypatch):
    db = tmp_path / ".delivery/ztad/continuity.db"
    ContinuityStore(db)
    monkeypatch.chdir(tmp_path)
    output = handle_hook("PreToolUse", {
        "cwd": str(tmp_path), "tool_name": "Bash", "tool_input": {"command": "pytest -q && curl https://evil"}
    })
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pretool_hook_denies_atomic_privileged_git_command(tmp_path, monkeypatch):
    db = tmp_path / ".delivery/ztad/continuity.db"
    ContinuityStore(db)
    monkeypatch.chdir(tmp_path)
    output = handle_hook("PreToolUse", {
        "cwd": str(tmp_path), "tool_name": "Bash", "tool_input": {"command": "git push origin main"}
    })
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "command policy" in output["hookSpecificOutput"]["permissionDecisionReason"].lower()


def test_pretool_hook_denies_protected_write_when_active(tmp_path, monkeypatch):
    db = tmp_path / ".delivery/ztad/continuity.db"
    ContinuityStore(db)
    monkeypatch.chdir(tmp_path)
    output = handle_hook("PreToolUse", {
        "cwd": str(tmp_path), "tool_name": "Write", "tool_input": {"file_path": ".GitHub/workflows/ci.yml", "content": "x"}
    })
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_stop_hook_does_not_create_an_infinite_stop_loop(tmp_path):
    db = tmp_path / ".delivery/ztad/continuity.db"
    store = ContinuityStore(db)
    store.submit_task(repository="repo", title="x", contract={"goal":"x"}, risk="R1", idempotency_key="x")
    assert handle_hook("Stop", {"cwd": str(tmp_path), "stop_hook_active": False}) is None
    assert handle_hook("SessionEnd", {"cwd": str(tmp_path)}) is None


def test_policy_registry_classifies_claims_honestly():
    result = audit_policy_wiring(ROOT)
    assert result["valid"], result["errors"]
    modes = {item["mode"] for item in result["policies"]}
    assert "DETERMINISTIC_RUNTIME" in modes
    assert "HOST_ENFORCEMENT_REQUIRED" in modes
    assert all(item["mode"] != "ENFORCED" for item in result["policies"])


def test_plugin_manifest_bundles_hooks():
    plugin = json.loads((ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    assert plugin["hooks"] == "./hooks/hooks.json"
    hooks = json.loads((ROOT / "hooks/hooks.json").read_text(encoding="utf-8"))
    assert {"SessionStart", "PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop", "Stop", "SessionEnd"} <= set(hooks["hooks"])
