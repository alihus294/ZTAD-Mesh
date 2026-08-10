from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS: list[dict[str, Any]] = [
    {
        "id": "path-traversal-guard",
        "file": "toolkit/ztad/path_security.py",
        "old": '        if part == "..":\n',
        "new": '        if False and part == "..":  # MUTANT\n',
        "tests": ["tests/test_v42_hardening.py::test_normalize_repo_path_rejects_direct_and_nested_traversal"],
    },
    {
        "id": "provider-stale-artifact-guard",
        "file": "toolkit/ztad/providers.py",
        "old": "        if path.exists() or path.is_symlink():\n",
        "new": "        if False:  # MUTANT\n",
        "tests": ["tests/test_v4_router_providers.py::test_provider_rejects_replayed_run_artifact"],
    },
    {
        "id": "benchmark-temp-cleanup",
        "file": "toolkit/ztad/model_benchmark.py",
        "old": "                temporary.cleanup()\n",
        "new": "                temporary._finalizer.detach()  # MUTANT: leak benchmark artifacts\n",
        "tests": ["tests/test_v4_router_providers.py::test_benchmark_artifacts_default_to_temporary_directory"],
    },
    {
        "id": "catalog-reliability-range",
        "file": "toolkit/ztad/model_router.py",
        "old": "        if not 0.0 <= reliability <= 1.0:\n",
        "new": "        if False:  # MUTANT\n",
        "tests": ["tests/test_v4_router_providers.py::test_router_rejects_unsafe_or_nonsensical_catalog_values"],
    },
    {
        "id": "same-session-approval-separation",
        "file": "toolkit/ztad/orchestrator.py",
        "old": '            if conflict and role in {"supervisor", "closure"} and decision == "APPROVE":\n',
        "new": "            if False:  # MUTANT\n",
        "tests": ["tests/test_v2_continuity.py::test_same_session_cannot_implement_and_approve_same_sha"],
    },
    {
        "id": "takeover-closure-requirement",
        "file": "toolkit/ztad/orchestrator.py",
        "old": '            if takeover and decision == "APPROVE" and role != "closure":\n',
        "new": "            if False:  # MUTANT\n",
        "tests": ["tests/test_v2_continuity.py::test_supervisor_takeover_requires_fresh_closure_reviewer"],
    },
    {
        "id": "actual-diff-risk-escalation",
        "file": "toolkit/ztad/mesh_runtime.py",
        "old": '            risk_escalated = RISK_ORDER[actual_risk.risk] > RISK_ORDER[str(node["risk"])]\n',
        "new": "            risk_escalated = False  # MUTANT\n",
        "tests": ["tests/test_v42_autopilot_redteam.py::test_actual_diff_risk_escalation_is_contained_before_review"],
    },
    {
        "id": "duplicate-attempt-signature",
        "file": "toolkit/ztad/mesh_store.py",
        "old": '            if conn.execute("SELECT 1 FROM mesh_attempts WHERE signature=?", (fingerprint.signature,)).fetchone():\n',
        "new": "            if False:  # MUTANT\n",
        "tests": ["tests/test_v4_mesh_store.py::test_attempt_guard_rejects_identical_retry_and_detects_no_progress"],
    },
    {
        "id": "write-scope-overlap",
        "file": "toolkit/ztad/mesh_store.py",
        "old": '    return left == right or left.startswith(right + "/") or right.startswith(left + "/")\n',
        "new": "    return False  # MUTANT\n",
        "tests": ["tests/test_v4_mesh_store.py::test_mesh_dependencies_and_scope_locks_are_transactional"],
    },
    {
        "id": "machine-check-block",
        "file": "toolkit/ztad/mesh_runtime.py",
        "old": '            if report.get("blocked") or risk_escalated:\n',
        "new": "            if False:  # MUTANT\n",
        "tests": ["tests/test_v42_autopilot_redteam.py::test_check_runner_blocked_report_cannot_be_recorded_as_success"],
    },
    {
        "id": "codex-provider-schema-errors-affect-success",
        "file": "toolkit/ztad/providers.py",
        "old": "        success = exit_code == 0 and output is not None and not errors\n",
        "new": "        success = exit_code == 0 and output is not None  # MUTANT\n",
        "occurrence": 1,
        "tests": ["tests/test_v4_router_providers.py::test_codex_provider_locally_rejects_schema_invalid_output"],
    },
    {
        "id": "generic-provider-schema-errors-affect-success",
        "file": "toolkit/ztad/providers.py",
        "old": "        success = exit_code == 0 and output is not None and not errors\n",
        "new": "        success = exit_code == 0 and output is not None  # MUTANT\n",
        "occurrence": 2,
        "tests": ["tests/test_v42_hardening.py::test_generic_provider_rejects_shell_templates_and_validates_output"],
    },
    {
        "id": "evidence-signature-verification",
        "file": "toolkit/ztad/crypto.py",
        "old": "        public_key.verify(signature, evidence_signing_payload(record))\n",
        "new": "        pass  # MUTANT: signature not verified\n",
        "tests": ["tests/test_v2_crypto_mutation_guards.py"],
    },
    {
        "id": "hook-shell-composition-rejection",
        "file": "toolkit/ztad/commands.py",
        "old": "    if SHELL_META.search(command) or WINDOWS_ENV.search(command):\n",
        "new": "    if False:  # MUTANT\n",
        "tests": ["tests/test_commands_injection.py::test_split_hook_command_rejects_shell_composition_and_expansion"],
    },
]

_COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".pytest_cache", "__pycache__", ".coverage", ".coverage.*",
    "*.pyc", "*.pyo", "dist", "build-output", "mutation-v42.json",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _apply_mutation(workspace: Path, mutation: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    file_path = workspace / str(mutation["file"])
    original = file_path.read_text(encoding="utf-8")
    old = str(mutation["old"])
    occurrence = int(mutation.get("occurrence", 1))
    count = original.count(old)
    required_count = occurrence if "occurrence" in mutation else 1
    if count < required_count or ("occurrence" not in mutation and count != 1):
        return False, {
            "id": mutation["id"],
            "status": "INVALID_MUTATION",
            "match_count": count,
            "requested_occurrence": occurrence,
        }

    cursor = 0
    start = -1
    for _ in range(occurrence):
        start = original.find(old, cursor)
        if start < 0:
            break
        cursor = start + len(old)
    mutated = original[:start] + str(mutation["new"]) + original[cursor:]
    file_path.write_text(mutated, encoding="utf-8")
    return True, {}


def main() -> int:
    guarded_files = sorted({str(item["file"]) for item in MUTATIONS})
    source_hashes_before = {relative: _sha256(ROOT / relative) for relative in guarded_files}
    results: list[dict[str, Any]] = []

    for mutation in MUTATIONS:
        print("START", mutation["id"], flush=True)
        with tempfile.TemporaryDirectory(prefix="ztad-mutant-") as temporary:
            workspace = Path(temporary) / "repo"
            shutil.copytree(ROOT, workspace, ignore=_COPY_IGNORE)
            valid, invalid_result = _apply_mutation(workspace, mutation)
            if not valid:
                results.append(invalid_result)
                continue

            command = [sys.executable, "-B", "-m", "pytest", "-q", *mutation["tests"]]
            try:
                proc = subprocess.run(
                    command,
                    cwd=workspace,
                    text=True,
                    capture_output=True,
                    timeout=20,
                    env={
                        **os.environ,
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    },
                )
                killed = proc.returncode != 0
                results.append({
                    "id": mutation["id"],
                    "status": "KILLED" if killed else "SURVIVED",
                    "exit_code": proc.returncode,
                    "tests": mutation["tests"],
                    "output_tail": (proc.stdout + "\n" + proc.stderr)[-2000:],
                })
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout if isinstance(exc.stdout, str) else ""
                stderr = exc.stderr if isinstance(exc.stderr, str) else ""
                results.append({
                    "id": mutation["id"],
                    "status": "KILLED_TIMEOUT",
                    "exit_code": 124,
                    "tests": mutation["tests"],
                    "output_tail": (stdout + "\n" + stderr)[-2000:],
                })

    source_hashes_after = {relative: _sha256(ROOT / relative) for relative in guarded_files}
    changed_sources = sorted(
        relative for relative in guarded_files
        if source_hashes_before[relative] != source_hashes_after[relative]
    )
    killed = sum(1 for item in results if item["status"] in {"KILLED", "KILLED_TIMEOUT"})
    survived = [item["id"] for item in results if item["status"] == "SURVIVED"]
    invalid = [item["id"] for item in results if item["status"] == "INVALID_MUTATION"]
    summary = {
        "schema_version": 1,
        "selected_mutants": len(MUTATIONS),
        "killed": killed,
        "survived": survived,
        "invalid": invalid,
        "score_percent": round(100.0 * killed / len(MUTATIONS), 2),
        "source_tree_preserved": not changed_sources,
        "unexpected_source_changes": changed_sources,
        "claim_boundary": "This score applies only to the explicit selected critical mutants listed here. Each mutant runs in an isolated temporary copy, so interruption cannot leave the source tree mutated.",
        "results": results,
    }
    output = ROOT / "validation" / "mutation-v42.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        key: summary[key]
        for key in (
            "selected_mutants", "killed", "survived", "invalid",
            "score_percent", "source_tree_preserved", "unexpected_source_changes",
        )
    }, sort_keys=True))
    return 0 if not survived and not invalid and not changed_sources else 1


if __name__ == "__main__":
    raise SystemExit(main())
