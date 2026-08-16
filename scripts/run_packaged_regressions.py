#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "toolkit"))

from ztad.distribution import (  # noqa: E402
    MARKETPLACE_NAME,
    PLUGIN_NAME,
    safe_extract_archive,
    validate_distribution_archive,
)

LEGACY_INSTALL_CRITICAL_TESTS = (
    "tests/test_v4_cli_and_bundle.py",
    "tests/test_checks_runtime.py",
    "tests/test_cli_dispatch_regression.py",
    "tests/test_v43_guarded_fast_path.py",
    "tests/test_v43_runtime_controls.py",
)

PACKAGED_TEST_MANIFEST = (
    "tests/test_checks_runtime.py",
    "tests/test_cli_dispatch_regression.py",
    "tests/test_commands_injection.py",
    "tests/test_context_footprint.py",
    "tests/test_control_test_integrity.py",
    "tests/test_distribution.py",
    "tests/test_evidence_agent.py",
    "tests/test_repository_context_installer.py",
    "tests/test_risk.py",
    "tests/test_schema_cli.py",
    "tests/test_state_budget_release.py",
    "tests/test_structured_input_security.py",
    "tests/test_v2_continuity.py",
    "tests/test_v2_crypto_mutation_guards.py",
    "tests/test_v2_hooks_and_security.py",
    "tests/test_v42_autopilot_redteam.py",
    "tests/test_v42_hardening.py",
    "tests/test_v42_mutation_runner_safety.py",
    "tests/test_v42_operational_hardening.py",
    "tests/test_v4310_control_plane_adversarial.py",
    "tests/test_v4310_fail_closed_adversarial.py",
    "tests/test_v4311_delivery_model.py",
    "tests/test_v436_blocker_requests.py",
    "tests/test_v436_problem_isolation.py",
    "tests/test_v436_problem_lifecycle.py",
    "tests/test_v436_provider_and_release_contracts.py",
    "tests/test_v436_provider_role_boundary.py",
    "tests/test_v437_approval_integration.py",
    "tests/test_v437_bug_protocol.py",
    "tests/test_v437_bundle_and_wiring.py",
    "tests/test_v437_cli_portable.py",
    "tests/test_v437_high_risk_domain_guard.py",
    "tests/test_v437_protected_lifecycle_evidence.py",
    "tests/test_v438_skill_protocol_wiring.py",
    "tests/test_v439_fail_closed_protocol.py",
    "tests/test_v439_release_evidence.py",
    "tests/test_v43_final_hardening.py",
    "tests/test_v43_guarded_fast_path.py",
    "tests/test_v43_last_gaps.py",
    "tests/test_v43_runtime_controls.py",
    "tests/test_v4_cli_and_bundle.py",
    "tests/test_v4_mesh_runtime.py",
    "tests/test_v4_mesh_store.py",
    "tests/test_v4_repository_scope.py",
    "tests/test_v4_router_providers.py",
    "tests/test_v4_scheduler_platform_hooks.py",
)


def packaged_test_inventory(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in (root / "tests").glob("test_*.py")
        if path.is_file() and not path.is_symlink()
    )


def validate_packaged_test_inventory(inventory: list[str]) -> list[str]:
    """Reject a packaged archive whose required regression set changed."""

    actual = sorted(str(item) for item in inventory)
    expected = sorted(PACKAGED_TEST_MANIFEST)
    errors: list[str] = []
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing:
        errors.append("missing packaged tests: " + ", ".join(missing))
    if unexpected:
        errors.append("unexpected packaged tests: " + ", ".join(unexpected))
    if actual != expected:
        errors.append(
            f"packaged test inventory changed: expected {len(expected)} files, found {len(actual)}"
        )
    return errors


def _summary(output: str) -> dict[str, int]:
    values = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "deselected": 0}
    for label in values:
        match = re.search(rf"(\d+) {label}", output)
        if match:
            values[label] = int(match.group(1))
    collected = re.search(r"(\d+) tests? collected", output)
    if collected:
        values["collected"] = int(collected.group(1))
    return values


def _run(archive: Path, kind: str, scope: str) -> int:
    validation = validate_distribution_archive(archive, kind)
    if not validation["valid"]:
        print(json.dumps({"valid": False, "stage": "archive-validation", "details": validation}, indent=2, sort_keys=True))
        return 1

    expected_top = PLUGIN_NAME if kind == "plugin" else MARKETPLACE_NAME
    with tempfile.TemporaryDirectory(prefix="ztad-packaged-regression-") as temporary:
        extracted = safe_extract_archive(
            archive.resolve(),
            Path(temporary) / "extract",
            expected_top_level=expected_top,
        )
        plugin_root = extracted if kind == "plugin" else extracted / "plugins" / PLUGIN_NAME
        if not plugin_root.is_dir() or plugin_root.is_symlink():
            print(json.dumps({"valid": False, "stage": "plugin-root", "path": str(plugin_root)}, indent=2, sort_keys=True))
            return 1

        inventory = packaged_test_inventory(plugin_root)
        required_inventory = list(PACKAGED_TEST_MANIFEST)
        inventory_errors = validate_packaged_test_inventory(inventory)
        if inventory_errors:
            print(json.dumps({"valid": False, "stage": "packaged-test-inventory", "errors": inventory_errors}, indent=2, sort_keys=True))
            return 1

        env = os.environ.copy()
        env["PYTHONPATH"] = str(plugin_root / "toolkit")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        argv = [sys.executable, "-B", "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider"]
        if scope == "full":
            argv.append("tests")
        else:
            argv.extend(required_inventory)

        collection = subprocess.run(
            [*argv, "--collect-only"],
            cwd=plugin_root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        collection_output = (collection.stdout or "") + (collection.stderr or "")
        collection_summary = _summary(collection_output)
        completed = subprocess.run(argv, cwd=plugin_root, env=env, check=False, capture_output=True, text=True)
        output = (completed.stdout or "") + (completed.stderr or "")
        print(output, end="")
        execution_summary = _summary(output)
        executed_count = sum(execution_summary.get(label, 0) for label in ("passed", "failed", "skipped", "xfailed", "xpassed"))
        skip_reasons = [
            line.strip()
            for line in output.splitlines()
            if line.strip().startswith("SKIPPED")
        ]
        result = {
            "valid": collection.returncode == 0 and completed.returncode == 0,
            "kind": kind,
            "scope": scope,
            "archive": str(archive.resolve()),
            "plugin_root": str(plugin_root),
            "legacy_install_critical_inventory": list(LEGACY_INSTALL_CRITICAL_TESTS),
            "requested_test_paths": ["tests"] if scope == "full" else required_inventory,
            "packaged_test_inventory": inventory,
            "collected_count": collection_summary.get("collected", len(inventory)),
            "executed_count": executed_count,
            "excluded_test_paths": [],
            "skip_reasons": skip_reasons,
            "execution_summary": execution_summary,
            "pytest_exit_code": completed.returncode,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run regressions from the exact packaged ZTAD archive")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--kind", choices=("plugin", "marketplace"), required=True)
    parser.add_argument("--scope", choices=("install-critical", "full"), default="install-critical")
    args = parser.parse_args(argv)
    return _run(args.archive, args.kind, args.scope)


if __name__ == "__main__":
    raise SystemExit(main())
