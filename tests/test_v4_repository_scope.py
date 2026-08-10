from __future__ import annotations

from pathlib import Path

from ztad.repository import GitRepository
from ztad.repository_index import assess_context_sufficiency, build_repository_index
from ztad.scope_guard import ScopeEnvelope

from conftest import commit_files, init_git_repo, valid_contract


def test_repository_index_tracks_reverse_dependencies_tests_and_security_signals(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {
        "src/core.py": "def calculate():\n    return 1\n",
        "src/api.py": "from .core import calculate\n\ndef handler(): return calculate()\n",
        "src/plugins.py": "import importlib\ndef load(name): return importlib.import_module(name)\n",
        "tests/test_core.py": "from src.core import calculate\ndef test_calculate(): assert calculate() == 1\n",
        "db/policy.sql": "alter table orders enable row level security; create policy p on orders using (true);\n",
        "web/routes.ts": "router.get('/orders', handler); fetch('/api/orders');\n",
    })
    index = build_repository_index(GitRepository(repo_path), head)
    assert "src/api.py" in index.reverse_imports.get("src/core.py", ())
    related = {item["path"] for item in index.related_files(["src/core.py"], depth=2)}
    assert "src/api.py" in related
    assert "tests/test_core.py" in related
    assert "db/policy.sql" in index.signals["authorization"]
    assert any(item["path"] == "src/plugins.py" for item in index.dynamic_gaps)


def test_context_sufficiency_is_stricter_for_high_risk_dynamic_paths(tmp_path):
    repo_path, _ = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {
        "src/core.py": "def x(): return 1\n",
        "src/plugin.py": "import importlib\ndef load(x): return importlib.import_module(x)\n",
        "src/caller.py": "from .plugin import load\n",
    })
    index = build_repository_index(GitRepository(repo_path), head)
    result = assess_context_sufficiency(index, changed_paths=["src/plugin.py"], included_paths=["src/plugin.py"], risk="R3")
    assert not result["sufficient"]
    assert "dynamic_runtime_gap_requires_targeted_scout_or_runtime_evidence" in result["errors"]
    included = [item["path"] for item in index.related_files(["src/plugin.py"], depth=3)]
    low = assess_context_sufficiency(index, changed_paths=["src/plugin.py"], included_paths=included, risk="R1")
    assert low["sufficient"]


def test_scope_guard_is_case_insensitive_and_never_auto_expands():
    contract = valid_contract()
    envelope = ScopeEnvelope.from_contract(
        task_id="task-1", contract=contract,
        allowed_patterns=["src/orders/**", "tests/orders/**"],
        must_not_touch=["Auth/**", ".github/**"],
    )
    assert envelope.verify_paths(["src/orders/service.py"])["allowed"]
    blocked = envelope.verify_paths(["AUTH/login.py", "src/billing.py"])
    assert not blocked["allowed"]
    assert "AUTH/login.py" in blocked["prohibited_paths"]
    assert "src/billing.py" in blocked["outside_scope_paths"]
    child = envelope.child_task_proposal(["src/billing.py"], reason="new dependency")
    assert child["requested_action"] == "NEW_CHILD_TASK"
    assert child["mutation_authority"] is False


def test_scope_guard_detects_goal_or_contract_change():
    contract = valid_contract()
    envelope = ScopeEnvelope.from_contract(task_id="t", contract=contract, allowed_patterns=["src/**"], must_not_touch=[])
    changed = valid_contract()
    changed["outcome"]["user_or_system_value"] = "different goal"
    errors = envelope.verify_contract(changed)
    assert "contract_hash_changed" in errors
    assert "parent_goal_changed" in errors
