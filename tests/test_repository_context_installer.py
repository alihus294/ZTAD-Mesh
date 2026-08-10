import json
from pathlib import Path

import pytest

from ztad.bundle import validate_bundle
from ztad.context import build_context_manifest
from ztad.diff_limits import evaluate_diff_limits
from ztad.installer import apply_install, plan, uninstall
from ztad.ledger import append_record, verify_ledger
from ztad.patch_broker import validate_patch
from ztad.repository import GitRepository
from ztad.util import load_data, sha256_file

from conftest import commit_files, init_git_repo

ROOT = Path(__file__).resolve().parents[1]


def test_repository_changed_paths_and_numstat(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {"src/app.py":"print('x')\n"})
    repo = GitRepository(repo_path)
    assert [item.path for item in repo.changed_paths(base, head)] == ["src/app.py"]
    assert repo.numstat(base, head)[0].additions == 1


def test_diff_limit_passes_small_change(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {"src/app.py":"print('x')\n"})
    result = evaluate_diff_limits(GitRepository(repo_path), base, head, "R1", load_data(ROOT/"policies/diff-limits.yaml"))
    assert result["passed"]


def test_diff_limit_blocks_many_files(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {f"src/f{i}.py":"x=1\n" for i in range(7)})
    result = evaluate_diff_limits(GitRepository(repo_path), base, head, "R1", load_data(ROOT/"policies/diff-limits.yaml"))
    assert not result["passed"]


def test_context_manifest_excludes_secret_path(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {"src/app.py":"x=1\n", ".env":"SECRET=x\n"})
    manifest = build_context_manifest(GitRepository(repo_path), base, head, "R2", contract_hash="sha256:"+"a"*64, policy_hash="sha256:"+"b"*64)
    paths = {item["path"] for item in manifest["included"]}
    assert ".env" not in paths
    assert any(item["path"] == ".env" for item in manifest["excluded"])


def test_context_id_is_stable_for_same_subject(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo_path, {"src/app.py":"x=1\n"})
    repo = GitRepository(repo_path)
    first = build_context_manifest(repo, base, head, "R1", contract_hash="sha256:"+"a"*64, policy_hash="sha256:"+"b"*64)
    second = build_context_manifest(repo, base, head, "R1", contract_hash="sha256:"+"a"*64, policy_hash="sha256:"+"b"*64)
    assert first["context_id"] == second["context_id"]


def test_ledger_detects_tampering(tmp_path):
    import sqlite3
    ledger = tmp_path / "ledger.sqlite3"
    append_record(ledger, {"a": 1})
    append_record(ledger, {"b": 2})
    assert verify_ledger(ledger)["valid"]
    conn = sqlite3.connect(ledger)
    conn.execute("UPDATE ledger_entries SET payload_json=? WHERE sequence=2", ('{"b":3}',))
    conn.commit()
    conn.close()
    assert not verify_ledger(ledger)["valid"]


def test_patch_broker_validates_clean_patch(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    tracked = repo_path / "README.md"
    tracked.write_text(tracked.read_text() + "validated patch\n")
    import subprocess
    patch = tmp_path / "change.patch"
    patch.write_text(subprocess.run(["git", "diff", "--binary"], cwd=repo_path, text=True, capture_output=True, check=True).stdout)
    result = validate_patch(GitRepository(repo_path), patch, expected_base=base, path_policy=load_data(ROOT / "policies/path-policy.yaml"))
    assert result["valid"], result


def test_dry_run_does_not_mutate(tmp_path):
    repo = tmp_path / "target"; repo.mkdir()
    before = sorted(str(p.relative_to(repo)) for p in repo.rglob('*'))
    result = plan(repo)
    after = sorted(str(p.relative_to(repo)) for p in repo.rglob('*'))
    assert before == after
    assert result["would_mutate"]


def test_install_is_idempotent(tmp_path):
    repo = tmp_path / "target"; repo.mkdir()
    first = apply_install(repo)
    second = apply_install(repo)
    assert first["applied"]
    assert second["idempotent_noop"]
    assert (repo/".delivery/ztad/installation.json").exists()


def test_install_preserves_unmanaged_conflict(tmp_path):
    repo = tmp_path / "target"; repo.mkdir()
    target = repo/".delivery/change-contract.example.yaml"
    target.parent.mkdir(parents=True)
    target.write_text("user content\n")
    result = apply_install(repo)
    assert target.read_text() == "user content\n"
    assert any(item["action"] == "WRITE_CANDIDATE" for item in result["applied_actions"])


def test_uninstall_preserves_modified_managed_file(tmp_path):
    repo = tmp_path / "target"; repo.mkdir()
    apply_install(repo)
    managed = repo/".delivery/ztad/policies/risk-policy.yaml"
    managed.write_text(managed.read_text()+"\n# local change\n")
    result = uninstall(repo)
    assert result["partial"]
    assert managed.exists()


def test_bundle_validates_distribution(tmp_path):
    import shutil
    clean_root = tmp_path / "bundle"
    shutil.copytree(
        ROOT,
        clean_root,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )
    result = validate_bundle(clean_root)
    assert result["valid"], result["errors"]


def test_marketplace_validator_accepts_official_nested_layout(tmp_path):
    import shutil
    from ztad.marketplace import validate_marketplace

    market = tmp_path / "market"
    plugin = market / "plugins/zero-trust-agentic-delivery"
    shutil.copytree(ROOT, plugin, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".coverage"))
    manifest = market / ".agents/plugins/marketplace.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({
        "name": "ztad-local",
        "interface": {"displayName": "ZTAD Local"},
        "plugins": [{
            "name": "zero-trust-agentic-delivery",
            "source": {"source": "local", "path": "./plugins/zero-trust-agentic-delivery"},
            "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
            "category": "Developer Tools",
        }],
    }), encoding="utf-8")
    result = validate_marketplace(market)
    assert result["valid"], result["errors"]


def test_marketplace_validator_rejects_root_and_escape_paths(tmp_path):
    from ztad.marketplace import validate_marketplace

    for raw in ("./", "../plugin", "../../plugin"):
        market = tmp_path / raw.replace("/", "_").replace(".", "dot")
        manifest = market / ".agents/plugins/marketplace.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "name": "ztad-local",
            "interface": {"displayName": "ZTAD Local"},
            "plugins": [{
                "name": "zero-trust-agentic-delivery",
                "source": {"source": "local", "path": raw},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Developer Tools",
            }],
        }), encoding="utf-8")
        assert not validate_marketplace(market)["valid"]


def test_patch_broker_blocks_gitmodules(tmp_path):
    import subprocess

    repo_path, base = init_git_repo(tmp_path / "repo")
    (repo_path / ".gitmodules").write_text('[submodule "evil"]\n\tpath = vendor/evil\n\turl = https://example.invalid/evil.git\n', encoding="utf-8")
    patch = tmp_path / "gitmodules.patch"
    patch.write_text(subprocess.run(["git", "diff", "--binary", "--no-index", "/dev/null", ".gitmodules"], cwd=repo_path, text=True, capture_output=True).stdout, encoding="utf-8")
    result = validate_patch(GitRepository(repo_path), patch, expected_base=base, path_policy=load_data(ROOT / "policies/path-policy.yaml"))
    assert not result["valid"]
    assert any(item["code"] == "PROHIBITED_PATCH_PATH" for item in result["findings"])


def test_patch_broker_rejects_symlink_patch_file(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    real = tmp_path / "real.patch"
    real.write_text("not a patch\n", encoding="utf-8")
    link = tmp_path / "link.patch"
    link.symlink_to(real)
    result = validate_patch(GitRepository(repo_path), link, expected_base=base, path_policy=load_data(ROOT / "policies/path-policy.yaml"))
    assert not result["valid"]
    assert result["findings"][0]["code"] == "PATCH_NOT_REGULAR_FILE"


def test_installer_rejects_symlink_ancestor(tmp_path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (repo_path / ".delivery").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this host")
    result = apply_install(repo_path)
    assert result["applied"] is False
    assert result["decision"] == "FAIL_CLOSED"
    assert not list(outside.iterdir())


def test_repeated_unmanaged_conflict_reuses_same_candidate(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    target = repo / ".delivery/change-contract.example.yaml"
    target.parent.mkdir(parents=True)
    target.write_text("user content\n", encoding="utf-8")

    first = apply_install(repo)
    candidate = repo / ".delivery/change-contract.example.yaml.ztad.new"
    assert candidate.is_file()
    first_candidate_hash = sha256_file(candidate)

    second = apply_install(repo)
    assert second["idempotent_noop"]
    assert sha256_file(candidate) == first_candidate_hash
    assert not (repo / ".delivery/change-contract.example.yaml.ztad.new.1").exists()
    assert target.read_text(encoding="utf-8") == "user content\n"


def test_repeated_modified_agents_conflict_reuses_same_candidate(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    apply_install(repo)
    agents = repo / "AGENTS.md"
    original = agents.read_text(encoding="utf-8")
    agents.write_text(original.replace("Persist workflow state", "Persist locally modified workflow state", 1), encoding="utf-8")

    first_conflict = apply_install(repo)
    candidate = repo / "AGENTS.md.ztad.new"
    assert candidate.is_file()
    assert any(item["action"] == "WRITE_CANDIDATE" for item in first_conflict["applied_actions"])

    second_conflict = apply_install(repo)
    assert second_conflict["idempotent_noop"]
    assert not (repo / "AGENTS.md.ztad.new.1").exists()
    assert "Persist locally modified workflow state" in agents.read_text(encoding="utf-8")


def test_repository_reader_disables_local_fsmonitor_execution(tmp_path):
    import os
    import subprocess

    repo_path, _ = init_git_repo(tmp_path / "repo")
    marker = tmp_path / "fsmonitor-executed"
    hook = tmp_path / "fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
    hook.chmod(0o700)
    subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=repo_path, check=True)
    repository = GitRepository(repo_path)
    repository.status_porcelain()
    assert not marker.exists()


def test_installer_requires_regular_semantic_version(monkeypatch, tmp_path):
    import ztad.installer as installer
    from ztad.errors import ConfigurationError

    root = tmp_path / "plugin"
    root.mkdir()
    monkeypatch.setattr(installer, "distribution_root", lambda: root)

    with pytest.raises(ConfigurationError, match="Missing regular VERSION"):
        installer._plugin_version()

    (root / "VERSION").write_text("not-a-version\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Invalid plugin VERSION"):
        installer._plugin_version()

    (root / "VERSION").write_text("4.2.0\n", encoding="utf-8")
    assert installer._plugin_version() == "4.2.0"
