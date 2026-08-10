from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLKIT = ROOT / "toolkit"
if str(TOOLKIT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT))


def valid_contract(*, risk: str = "R0", data_class: str = "C0", criticality: str = "tier_3", components: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "change_id": "FEAT-100",
        "title": "Deliver a bounded verified feature",
        "outcome": {"user_or_system_value": "Provide a measurable system behavior", "success_metric": "acceptance passes"},
        "requirements": {
            "acceptance_criteria": [{"id": "AC-01", "statement": "The expected behavior is observable"}],
            "non_goals": ["No unrelated refactoring"],
            "invariants": [{"id": "INV-01", "statement": "Existing authorization remains enforced"}],
            "assumptions": [{"id": "ASM-01", "statement": "The fixture is synthetic", "status": "verified", "evidence_ref": "ev-fixture"}],
        },
        "scope": {
            "expected_components": components or ["component"],
            "prohibited_components": [".github/workflows"],
            "public_contract_change": False,
            "data_migration_expected": False,
            "service_criticality": criticality,
            "data_classification": data_class,
        },
        "quality_attributes": {
            "security": "Preserve authorization",
            "privacy": "No personal data",
            "performance": "No material regression",
            "availability": "Preserve availability",
            "accessibility": "Preserve accessibility",
            "compatibility": "Preserve supported contracts",
        },
        "verification": {
            "test_oracles": [{"acceptance_test": "black-box acceptance", "expected_evidence": "machine result"}],
            "observability": [{"metric": "error_rate", "threshold": "no regression"}],
            "negative_cases": ["invalid input is rejected"],
        },
        "release": {
            "feature_flag_required": False,
            "rollback_strategy": "Promote the previously verified artifact",
            "data_reversal_required": False,
            "stop_conditions": ["critical transaction failure"],
        },
        "governance": {
            "product_owner": "owner",
            "engineering_owner": "engineer",
            "requested_risk": risk,
            "policy_risk": None,
            "human_decisions": [],
        },
        "budget": {"max_implementation_runs": 1, "max_repair_cycles": 2, "max_review_runs": 2},
    }


def run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=True)


def init_git_repo(path: Path) -> tuple[Path, str]:
    path.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-b", "main"], path)
    run(["git", "config", "user.name", "ZTAD Tests"], path)
    run(["git", "config", "user.email", "ztad-tests@example.invalid"], path)
    (path / "README.md").write_text("baseline\n", encoding="utf-8")
    run(["git", "add", "."], path)
    run(["git", "commit", "-m", "baseline"], path)
    base = run(["git", "rev-parse", "HEAD"], path).stdout.strip()
    return path, base


def commit_files(repo: Path, files: dict[str, str | bytes], message: str = "change") -> str:
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    run(["git", "add", "."], repo)
    run(["git", "commit", "-m", message], repo)
    return run(["git", "rev-parse", "HEAD"], repo).stdout.strip()


@pytest.fixture
def contract() -> dict[str, Any]:
    return copy.deepcopy(valid_contract())
