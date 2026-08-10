from __future__ import annotations

import json
from pathlib import Path

from ztad.bundle import validate_bundle
from ztad.cli import build_parser, execute
from ztad.policy_registry import audit_policy_wiring

ROOT = Path(__file__).resolve().parents[1]


def test_v4_version_and_manifest_are_consistent():
    version = (ROOT / "VERSION").read_text().strip()
    plugin = json.loads((ROOT / ".codex-plugin/plugin.json").read_text())
    pyproject = (ROOT / "toolkit/pyproject.toml").read_text()
    assert version == "4.2.0"
    assert plugin["version"] == version
    assert 'version = "4.2.0"' in pyproject


def test_new_cli_commands_parse():
    parser = build_parser()
    commands = [
        ["repository-index", "--repo", "."],
        ["model-route", "--task-family", "review", "--role", "supervisor", "--risk", "R2"],
        ["provider-probe"],
        ["host-acceptance", "--skip-plugin-state"],
        ["mesh-init", "--database", "x.db"],
        ["mesh-status", "--database", "x.db"],
    ]
    for argv in commands:
        assert parser.parse_args(argv).command == argv[0]


def test_model_route_cli_uses_frontier_for_supervisor():
    parser = build_parser()
    result, code = execute(parser.parse_args(["model-route", "--task-family", "review", "--role", "supervisor", "--risk", "R2"]))
    assert code == 0
    assert result["selected"]["tier"] == "frontier"


def test_policy_registry_does_not_overclaim_all_policies_as_enforced():
    result = audit_policy_wiring(ROOT)
    assert result["valid"], result["errors"]
    modes = result["mode_counts"]
    assert modes["DETERMINISTIC_RUNTIME"] >= 10
    assert modes["HOST_ENFORCEMENT_REQUIRED"] >= 1
    assert any(item["mode"].startswith("REFERENCE") for item in result["policies"])


def test_bundle_contains_new_mesh_components():
    result = validate_bundle(ROOT)
    assert result["valid"], result["errors"]
    for relative in (
        "toolkit/ztad/model_router.py", "toolkit/ztad/providers.py", "toolkit/ztad/mesh_store.py",
        "toolkit/ztad/mesh_runtime.py", "toolkit/ztad/repository_index.py", "toolkit/ztad/scope_guard.py",
        "policies/model-catalog.yaml", "policies/mesh-policy.yaml", "policies/host-acceptance-policy.yaml",
    ):
        assert (ROOT / relative).is_file()


def test_cryptography_lock_uses_reviewed_supported_release():
    requirements = (ROOT / "toolkit/requirements.lock.txt").read_text(encoding="utf-8")
    assert requirements.splitlines().count("cryptography==49.0.0") == 1
    assert "cryptography==46.0.4" not in requirements
    pyproject = (ROOT / "toolkit/pyproject.toml").read_text(encoding="utf-8")
    assert "cryptography>=48.0.1,<51" in pyproject
