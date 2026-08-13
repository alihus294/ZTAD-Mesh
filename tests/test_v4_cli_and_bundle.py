from __future__ import annotations

import json
import importlib.util
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import ztad
from ztad.bundle import validate_bundle
from ztad.cli import build_parser, execute
from ztad.policy_registry import audit_policy_wiring

ROOT = Path(__file__).resolve().parents[1]


def _run_identity_verifier(profile: str) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "scripts/verify_version_identity.py", "--profile", profile],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["valid"] is True
    assert result["profile"] == profile
    assert len(set(result["identities"].values())) == 1
    return result


def test_v4_version_and_manifest_are_consistent():
    version = (ROOT / "VERSION").read_text().strip()
    plugin = json.loads((ROOT / ".codex-plugin/plugin.json").read_text())
    pyproject = tomllib.loads((ROOT / "toolkit/pyproject.toml").read_text())
    assert plugin["version"] == version
    assert pyproject["project"]["version"] == version
    assert ztad.__version__ == version


def test_release_version_identity_verifier_covers_live_surfaces():
    # This profile is required to pass inside the published Plugin/Marketplace,
    # where repository-only .github metadata is intentionally absent.
    _run_identity_verifier("distribution")


def test_source_version_identity_verifier_covers_repository_only_surfaces():
    if not (ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml").is_file():
        pytest.skip("source-only GitHub metadata is intentionally omitted from distributions")
    _run_identity_verifier("source")


def test_release_version_identity_verifier_covers_all_current_surfaces():
    profile = "source" if (ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml").is_file() else "distribution"
    result = _run_identity_verifier(profile)
    assert {
        "README.md", "QUICKSTART.md", "docs/PLUGIN_INSTALLATION.md",
        "traceability/TRACEABILITY_MATRIX.md", "CHANGELOG.md",
        "docs/ARCHITECTURE.md", "docs/EVALS.md", "docs/LIMITATIONS.md",
        "docs/CONTROL_COVERAGE.md", "docs/HOST_ACCEPTANCE.md",
        "docs/CAPABILITY_MATRIX.md", "docs/FINAL_OPERATING_POLICY.md",
        "docs/MODEL_SELECTION.md", "docs/OPERATING_GUIDE.md",
        "docs/VALIDATION_REPORT.md", "references/MASTER_PLAN.md",
        "docs/SECURITY_CONTROLS.md", "docs/THREAT_MODEL.md",
    } <= set(result["checked_packaged_surfaces"])
    expected_source_surfaces = [".github/ISSUE_TEMPLATE/bug_report.yml"] if profile == "source" else []
    assert result["checked_source_only_surfaces"] == expected_source_surfaces


def test_release_version_identity_verifier_fails_closed_on_malformed_metadata(tmp_path):
    verifier_path = ROOT / "scripts/verify_version_identity.py"
    spec = importlib.util.spec_from_file_location("verify_version_identity_under_test", verifier_path)
    assert spec and spec.loader
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    relative_files = {
        "VERSION", ".codex-plugin/plugin.json", "toolkit/pyproject.toml", "toolkit/ztad/__init__.py",
        "scripts/generate_traceability.py", "docs/SOURCE_MAPPING.md", *verifier.PACKAGED_MARKERS,
        *verifier.CURRENT_HEADING_PREFIXES, *verifier.SOURCE_ONLY_MARKERS,
    }
    for relative in relative_files:
        source = ROOT / relative
        if not source.is_file():
            continue
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    distribution_result = verifier.verify(tmp_path, profile="distribution")
    assert distribution_result["valid"], distribution_result["errors"]

    plugin_path = tmp_path / ".codex-plugin/plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["version"] = {"not": "a string"}
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    malformed_result = verifier.verify(tmp_path, profile="distribution")
    assert malformed_result["valid"] is False
    assert any("invalid version metadata" in error for error in malformed_result["errors"])


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
    assert requirements.splitlines().count("cryptography==50.0.0") == 1
    assert "cryptography==49.0.0" not in requirements
    pyproject = (ROOT / "toolkit/pyproject.toml").read_text(encoding="utf-8")
    assert "cryptography>=50.0.0,<51" in pyproject
