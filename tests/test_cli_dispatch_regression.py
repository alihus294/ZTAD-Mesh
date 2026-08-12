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
CLI_PATH = ROOT / "toolkit/ztad/cli.py"
ENTRYPOINT = ROOT / "scripts/ztad.py"


def _snapshot(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    snapshot: dict[str, tuple[str, bytes | str | None]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            snapshot[relative] = ("symlink", os.readlink(path))
        elif path.is_file():
            snapshot[relative] = ("file", path.read_bytes())
        elif path.is_dir():
            snapshot[relative] = ("dir", None)
    return snapshot


def _target_repo(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("user-owned content\n", encoding="utf-8")
    custom = target / ".delivery/custom"
    custom.mkdir(parents=True)
    (custom / "keep.txt").write_text("do not mutate\n", encoding="utf-8")
    return target


def test_execute_does_not_shadow_module_import_bindings():
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            imported.update(alias.asname or alias.name for alias in node.names)
    execute_node = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "execute"
    )
    locals_bound = {
        node.id for node in ast.walk(execute_node)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    assert sorted(imported & locals_bound) == []


@pytest.mark.parametrize("command", ["audit", "dry-run"])
def test_installer_preview_dispatch_returns_structured_non_mutating_result(tmp_path: Path, command: str):
    target = _target_repo(tmp_path)
    before = _snapshot(target)
    args = build_parser().parse_args([command, "--repo", str(target)])
    result, code = execute(args)
    assert code == 0
    assert result["mode"] == command.upper().replace("-", "_")
    assert result["repository_mutated"] is False
    assert _snapshot(target) == before


@pytest.mark.parametrize("command", ["audit", "dry-run"])
def test_real_cli_entrypoint_preview_commands_are_non_mutating(tmp_path: Path, command: str):
    target = _target_repo(tmp_path)
    before = _snapshot(target)
    proc = subprocess.run(
        [sys.executable, "-B", str(ENTRYPOINT), command, "--repo", str(target)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["mode"] == command.upper().replace("-", "_")
    assert payload["repository_mutated"] is False
    assert _snapshot(target) == before


def test_mesh_plan_dry_run_still_uses_non_mutating_dispatch(tmp_path: Path):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    contract = valid_contract(risk="R0", components=["src/component.py"])
    contract_path = repo / ".delivery/change-contract.json"
    contract_path.parent.mkdir(parents=True, exist_ok=True)
    contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
    before = _snapshot(repo)
    args = build_parser().parse_args([
        "mesh-plan", "--repo", str(repo), "--task-id", "dispatch-regression",
        "--risk", "R0", "--contract", str(contract_path), "--dry-run",
    ])
    result, code = execute(args)
    assert code == 0
    assert result["dry_run"] is True
    assert result["repository_mutated"] is False
    assert result["plan"]["task_id"] == "dispatch-regression"
    assert _snapshot(repo) == before


def test_mesh_autopilot_dry_run_remains_non_mutating_after_dispatch_refactor(tmp_path: Path):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    contract = valid_contract(risk="R0", components=["src/component.py"])
    contract_path = repo / ".delivery/change-contract.json"
    contract_path.parent.mkdir(parents=True, exist_ok=True)
    contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
    before = _snapshot(repo)
    args = build_parser().parse_args([
        "mesh-autopilot", "--repo", str(repo), "--contract", str(contract_path), "--dry-run",
    ])
    result, code = execute(args)
    assert code == 0
    assert result["dry_run"] is True
    assert result["repository_mutated"] is False
    assert result["database_mutated"] is False
    assert _snapshot(repo) == before
