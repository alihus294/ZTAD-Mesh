from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_runner(root: Path):
    script = root / "validation" / "run_v42_mutations.py"
    spec = importlib.util.spec_from_file_location("ztad_isolated_mutation_runner", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mutation_runner_never_mutates_its_source_tree(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    (repository / "tests").mkdir(parents=True)
    (repository / "validation").mkdir()
    guarded = repository / "guarded.txt"
    guarded.write_text("SAFE\n", encoding="utf-8")
    (repository / "tests" / "test_guard.py").write_text(
        "from pathlib import Path\n"
        "def test_guard():\n"
        "    root = Path(__file__).resolve().parents[1]\n"
        "    assert (root / 'guarded.txt').read_text(encoding='utf-8') == 'SAFE\\n'\n",
        encoding="utf-8",
    )

    project_root = Path(__file__).resolve().parents[1]
    runner = _load_runner(project_root)
    runner.ROOT = repository
    runner.MUTATIONS = [{
        "id": "isolation-regression",
        "file": "guarded.txt",
        "old": "SAFE\n",
        "new": "MUTATED\n",
        "tests": ["tests/test_guard.py"],
    }]

    assert runner.main() == 0
    assert guarded.read_text(encoding="utf-8") == "SAFE\n"
    summary = json.loads((repository / "validation" / "mutation-v42.json").read_text(encoding="utf-8"))
    assert summary["source_tree_preserved"] is True
    assert summary["unexpected_source_changes"] == []
    assert summary["killed"] == 1
