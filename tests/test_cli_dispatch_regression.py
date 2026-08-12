from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.cli import build_parser, execute

ROOT = Path(__file__).resolve().parents[1]
CLI_SOURCE = ROOT / "toolkit/ztad/cli.py"
SCRIPT = ROOT / "scripts/ztad.py"


def _status(repo: Path) -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout


@pytest.mark.parametrize("command", ["audit", "dry-run"])
def test_installer_preview_dispatch_is_structured_and_non_mutating(tmp_path: Path, command: str) -> None:
    repo, _ = init_git_repo(tmp_path / "repo")
    before = _status(repo)
    args = build_parser().parse_args([command, "--repo", str(repo)])

    result, exit_code = execute(args)

    assert exit_code == 0
    assert result["mode"] == command.upper().replace("-", "_")
    assert result["repository_mutated"] is False
    assert _status(repo) == before == ""


@pytest.mark.parametrize("command", ["audit", "dry-run"])
def test_installer_preview_real_entrypoint_round_trip(tmp_path: Path, command: str) -> None:
    repo, _ = init_git_repo(tmp_path / "repo")
    before = _status(repo)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    proc = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), command, "--repo", str(repo)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["mode"] == command.upper().replace("-", "_")
    assert payload["repository_mutated"] is False
    assert _status(repo) == before == ""


def test_cli_uses_module_qualified_installer_namespace() -> None:
    source = CLI_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "from .installer import" not in source
    assert "from . import installer" in source
    assert not any(
        isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == "installer"
        for node in tree.body
    )


def test_mesh_plan_cli_dry_run_remains_non_mutating(tmp_path: Path) -> None:
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    contract = valid_contract(risk="R0", components=["src/component.py"])
    contract_path = repo / "change-contract.json"
    contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
    before = _status(repo)

    args = build_parser().parse_args([
        "mesh-plan", "--repo", str(repo), "--task-id", "REGRESSION-1",
        "--risk", "R0", "--contract", str(contract_path), "--dry-run",
    ])
    result, exit_code = execute(args)

    assert exit_code == 0
    assert result["dry_run"] is True
    assert result["repository_mutated"] is False
    assert result["plan"]["task_id"] == "REGRESSION-1"
    assert _status(repo) == before
