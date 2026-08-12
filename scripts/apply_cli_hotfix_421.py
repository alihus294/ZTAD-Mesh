from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:120]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_cli() -> None:
    path = ROOT / "toolkit/ztad/cli.py"
    cli = path.read_text(encoding="utf-8")

    old_import = "from .installer import apply_install, distribution_root, plan, uninstall\n"
    if cli.count(old_import) != 1:
        raise SystemExit("Unexpected installer import shape")
    cli = cli.replace(old_import, "from . import installer\n", 1)
    cli = cli.replace("distribution_root()", "installer.distribution_root()")

    helpers = '''\n\ndef _execute_installer_preview(args: argparse.Namespace, command: str) -> tuple[dict[str, Any], int]:\n    \"\"\"Run the installer planner without mutating the target repository.\"\"\"\n    result = installer.plan(\n        args.repo,\n        activate_ci=args.activate_ci,\n        install_repo_skills=not args.no_repo_skills,\n    )\n    result.update({\"mode\": command.upper().replace(\"-\", \"_\"), \"repository_mutated\": False})\n    return result, 0\n\n\ndef _execute_installer_apply(args: argparse.Namespace, command: str) -> tuple[dict[str, Any], int]:\n    \"\"\"Apply a bounded installer mutation through the installer module boundary.\"\"\"\n    result = installer.apply_install(\n        args.repo,\n        activate_ci=args.activate_ci,\n        install_repo_skills=not args.no_repo_skills,\n    )\n    result[\"mode\"] = command.upper()\n    return result, 0 if result.get(\"applied\") else 15\n\n\ndef _execute_installer_uninstall(args: argparse.Namespace) -> tuple[dict[str, Any], int]:\n    return installer.uninstall(args.repo), 0\n\n\ndef _execute_mesh_plan(args: argparse.Namespace) -> tuple[dict[str, Any], int]:\n    \"\"\"Build or persist a mesh plan without sharing names with installer APIs.\"\"\"\n    repo = GitRepository(args.repo)\n    contract_path = _repo_path(repo, args.contract)\n    contract = _data(contract_path)\n    mesh_plan = build_mesh_plan(\n        task_id=args.task_id, risk=args.risk, contract=contract,\n        prompt_root=args.prompt_root, output_schema=str(Path(args.output_schema).resolve()),\n        check_config=args.check_config, command_policy=str(Path(args.command_policy).resolve()),\n        risk_policy=str(Path(args.risk_policy).resolve()),\n        maximum_parallel_writers=args.max_parallel_writers,\n        maximum_plan_candidates=args.max_plan_candidates,\n    )\n    payload = mesh_plan.to_dict()\n    if args.dry_run:\n        return {\"dry_run\": True, \"repository_mutated\": False, \"plan\": payload}, 0\n    written = write_mesh_plan(mesh_plan, repository=repo.root, output_file=Path(args.plan_output))\n    return {\"dry_run\": False, \"repository_mutated\": True, \"plan\": payload, \"written\": written}, 0\n'''

    marker = "\n\ndef execute(args: argparse.Namespace) -> tuple[Any, int]:\n"
    if cli.count(marker) != 1:
        raise SystemExit("Unexpected execute() declaration shape")
    cli = cli.replace(marker, helpers + marker, 1)

    old_mesh = '''    if command == "mesh-plan":\n        repo = GitRepository(args.repo)\n        contract_path = _repo_path(repo, args.contract)\n        contract = _data(contract_path)\n        plan = build_mesh_plan(\n            task_id=args.task_id, risk=args.risk, contract=contract,\n            prompt_root=args.prompt_root, output_schema=str(Path(args.output_schema).resolve()),\n            check_config=args.check_config, command_policy=str(Path(args.command_policy).resolve()),\n            risk_policy=str(Path(args.risk_policy).resolve()),\n            maximum_parallel_writers=args.max_parallel_writers,\n            maximum_plan_candidates=args.max_plan_candidates,\n        )\n        payload = plan.to_dict()\n        if args.dry_run:\n            return {"dry_run": True, "repository_mutated": False, "plan": payload}, 0\n        written = write_mesh_plan(plan, repository=repo.root, output_file=Path(args.plan_output))\n        return {"dry_run": False, "repository_mutated": True, "plan": payload, "written": written}, 0\n'''
    new_mesh = '''    if command == "mesh-plan":\n        return _execute_mesh_plan(args)\n'''
    if cli.count(old_mesh) != 1:
        raise SystemExit("Unexpected mesh-plan dispatch shape")
    cli = cli.replace(old_mesh, new_mesh, 1)

    old_installer = '''    if command in {"audit", "dry-run"}:\n        result = plan(args.repo, activate_ci=args.activate_ci, install_repo_skills=not args.no_repo_skills)\n        result.update({"mode": command.upper().replace("-", "_"), "repository_mutated": False})\n        return result, 0\n    if command in {"install", "update"}:\n        result = apply_install(args.repo, activate_ci=args.activate_ci, install_repo_skills=not args.no_repo_skills)\n        result["mode"] = command.upper()\n        return result, 0 if result.get("applied") else 15\n    if command == "uninstall":\n        return uninstall(args.repo), 0\n'''
    new_installer = '''    if command in {"audit", "dry-run"}:\n        return _execute_installer_preview(args, command)\n    if command in {"install", "update"}:\n        return _execute_installer_apply(args, command)\n    if command == "uninstall":\n        return _execute_installer_uninstall(args)\n'''
    if cli.count(old_installer) != 1:
        raise SystemExit("Unexpected installer dispatch shape")
    cli = cli.replace(old_installer, new_installer, 1)

    forbidden = [
        "from .installer import",
        "        plan = build_mesh_plan(",
        "result = plan(args.repo",
        "result = apply_install(args.repo",
        "return uninstall(args.repo)",
    ]
    for token in forbidden:
        if token in cli:
            raise SystemExit(f"Forbidden legacy dispatch token remains: {token}")

    path.write_text(cli, encoding="utf-8")


def patch_versions_and_docs() -> None:
    replace_once(ROOT / "VERSION", "4.2.0\n", "4.2.1\n")
    replace_once(ROOT / "toolkit/ztad/__init__.py", '__version__ = "4.2.0"', '__version__ = "4.2.1"')
    replace_once(ROOT / "toolkit/pyproject.toml", 'version = "4.2.0"', 'version = "4.2.1"')

    plugin_path = ROOT / ".codex-plugin/plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    if plugin.get("version") != "4.2.0":
        raise SystemExit("Unexpected plugin version")
    plugin["version"] = "4.2.1"
    plugin_path.write_text(json.dumps(plugin, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    test_path = ROOT / "tests/test_v4_cli_and_bundle.py"
    replace_once(test_path, 'assert version == "4.2.0"', 'assert version == "4.2.1"')
    replace_once(test_path, 'assert \'version = "4.2.0"\' in pyproject', 'assert \'version = "4.2.1"\' in pyproject')

    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    if "# Zero-Trust Agentic Delivery Mesh 4.2.0" not in text or "## What 4.2.0 actually implements" not in text:
        raise SystemExit("Unexpected README version markers")
    text = text.replace("# Zero-Trust Agentic Delivery Mesh 4.2.0", "# Zero-Trust Agentic Delivery Mesh 4.2.1", 1)
    text = text.replace("## What 4.2.0 actually implements", "## What 4.2.1 actually implements", 1)
    readme.write_text(text, encoding="utf-8")

    quickstart = ROOT / "QUICKSTART.md"
    text = quickstart.read_text(encoding="utf-8")
    if "4.2.0" not in text:
        raise SystemExit("Unexpected QUICKSTART version marker")
    quickstart.write_text(text.replace("4.2.0", "4.2.1"), encoding="utf-8")

    issue_template = ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml"
    replace_once(issue_template, "placeholder: 4.2.0", "placeholder: 4.2.1")

    ci = ROOT / ".github/workflows/ci.yml"
    ci_text = ci.read_text(encoding="utf-8")
    for old, new in (
        ("zero-trust-agentic-delivery-plugin-4.2.0.zip", "zero-trust-agentic-delivery-plugin-4.2.1.zip"),
        ("zero-trust-agentic-delivery-marketplace-4.2.0.zip", "zero-trust-agentic-delivery-marketplace-4.2.1.zip"),
    ):
        if old not in ci_text:
            raise SystemExit(f"Missing CI archive marker: {old}")
        ci_text = ci_text.replace(old, new)
    ci.write_text(ci_text, encoding="utf-8")

    changelog = ROOT / "CHANGELOG.md"
    changelog_text = changelog.read_text(encoding="utf-8")
    heading = "# Changelog\n\n"
    if not changelog_text.startswith(heading):
        raise SystemExit("Unexpected changelog heading")
    release_notes = '''## 4.2.1 — 2026-08-12\n\n- Fixed `audit` and installer `dry-run` CLI dispatch failing with `UnboundLocalError` before installer planning could run.\n- Replaced direct installer symbol imports with a module-qualified `installer` boundary and renamed the mesh-plan local to `mesh_plan`, eliminating the name-collision class that caused the defect.\n- Split installer preview/apply/uninstall and mesh-plan dispatch into focused helpers so unrelated command branches no longer share ambiguous local names inside the central dispatcher.\n- Added direct-dispatch and real `scripts/ztad.py` subprocess regressions proving `audit` and `dry-run` return structured output without mutating the target repository.\n- Added an AST regression guard that rejects imported names rebound inside `execute()`, plus mesh-plan and mesh-autopilot dry-run non-mutation regressions.\n\n'''
    changelog.write_text(heading + release_notes + changelog_text[len(heading):], encoding="utf-8")

    install_doc = ROOT / "docs/PLUGIN_INSTALLATION.md"
    doc = install_doc.read_text(encoding="utf-8")
    required = [
        "# Codex Plugin Installation — 4.2.0",
        "zero-trust-agentic-delivery-marketplace-4.2.0.zip",
        "zero-trust-agentic-delivery-plugin-4.2.0.zip",
    ]
    if any(marker not in doc for marker in required):
        raise SystemExit("Unexpected plugin installation documentation markers")
    doc = doc.replace("# Codex Plugin Installation — 4.2.0", "# Codex Plugin Installation — 4.2.1", 1)
    doc = doc.replace("zero-trust-agentic-delivery-marketplace-4.2.0.zip", "zero-trust-agentic-delivery-marketplace-4.2.1.zip")
    doc = doc.replace("zero-trust-agentic-delivery-plugin-4.2.0.zip", "zero-trust-agentic-delivery-plugin-4.2.1.zip")
    doc = doc.replace("- `ZTAD_MESH_4.2.0_Final_Release.zip` — complete release, reports, evidence, and checksums.\n", "")
    install_doc.write_text(doc, encoding="utf-8")


def main() -> int:
    patch_cli()
    patch_versions_and_docs()
    print("ZTAD 4.2.1 CLI hotfix applied deterministically")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
