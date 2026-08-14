from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OLD = "4.3.5"
NEW = "4.3.6"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8", newline="\n")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if new in text and old not in text:
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected exactly one {old!r}; found {count}")
    write(path, text.replace(old, new, 1))


def bump_release_identity() -> None:
    write("VERSION", NEW + "\n")
    replace_once(".codex-plugin/plugin.json", '"version": "4.3.5"', '"version": "4.3.6"')
    replace_once("toolkit/pyproject.toml", 'version = "4.3.5"', 'version = "4.3.6"')
    replace_once("toolkit/ztad/__init__.py", '__version__ = "4.3.5"', '__version__ = "4.3.6"')
    replace_once(".github/ISSUE_TEMPLATE/bug_report.yml", "placeholder: 4.3.5", "placeholder: 4.3.6")
    for path, old, new in [
        ("README.md", "# Zero-Trust Agentic Delivery Mesh 4.3.5", "# Zero-Trust Agentic Delivery Mesh 4.3.6"),
        ("README.md", "## What 4.3.5 implements", "## What 4.3.6 implements"),
        ("QUICKSTART.md", "# ZTAD Mesh 4.3.5 Quick Start", "# ZTAD Mesh 4.3.6 Quick Start"),
        ("QUICKSTART.md", "`v4.3.5` GitHub Release", "`v4.3.6` GitHub Release"),
        ("docs/PLUGIN_INSTALLATION.md", "# Codex Plugin Installation — 4.3.5", "# Codex Plugin Installation — 4.3.6"),
        ("docs/PLUGIN_INSTALLATION.md", "zero-trust-agentic-delivery-marketplace-4.3.5.zip", "zero-trust-agentic-delivery-marketplace-4.3.6.zip"),
        ("docs/PLUGIN_INSTALLATION.md", "zero-trust-agentic-delivery-plugin-4.3.5.zip", "zero-trust-agentic-delivery-plugin-4.3.6.zip"),
        ("docs/PLUGIN_INSTALLATION.md", "plugin version `4.3.5`", "plugin version `4.3.6`"),
        ("traceability/TRACEABILITY_MATRIX.md", "# ZTAD Mesh 4.3.5 Traceability Matrix", "# ZTAD Mesh 4.3.6 Traceability Matrix"),
    ]:
        replace_once(path, old, new)
    live = [
        "docs/ARCHITECTURE.md", "docs/EVALS.md", "docs/LIMITATIONS.md", "docs/CONTROL_COVERAGE.md",
        "docs/HOST_ACCEPTANCE.md", "docs/CAPABILITY_MATRIX.md", "docs/FINAL_OPERATING_POLICY.md",
        "docs/MODEL_SELECTION.md", "docs/OPERATING_GUIDE.md", "docs/VALIDATION_REPORT.md",
        "docs/SECURITY_CONTROLS.md", "docs/THREAT_MODEL.md", "references/MASTER_PLAN.md",
    ]
    for path in live:
        text = read(path)
        lines = text.splitlines()
        original = lines[0]
        lines[0] = re.sub(r"(?<![0-9])4\.3\.5(?![0-9])", NEW, original)
        if lines[0] == original:
            raise RuntimeError(f"{path}: live heading does not carry {OLD}")
        write(path, "\n".join(lines) + ("\n" if text.endswith("\n") else ""))


def harden_bundle_and_docs() -> None:
    text = read("toolkit/ztad/bundle.py")
    if '"problem-investigation",' not in text:
        text = text.replace('    "zero-trust-delivery",\n', '    "zero-trust-delivery",\n    "problem-investigation",\n', 1)
    for required in ('    "schemas/problem-case.schema.json",\n', '    "docs/BUG_TO_PRODUCTION_PROTOCOL.md",\n'):
        if required not in text:
            text = text.replace('    "scripts/verify_release.py",\n', '    "scripts/verify_release.py",\n' + required, 1)
    write("toolkit/ztad/bundle.py", text)

    path = ROOT / "schemas/problem-case.schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if "state" not in data["required"]:
        data["required"].insert(2, "state")
    data["properties"]["state"] = {"enum": [
        "UNVERIFIED_REPORT", "SOURCE_OF_TRUTH_RESOLVED", "ISSUE_CLASSIFIED", "BUG_REPRODUCED",
        "ROOT_CAUSE_PROVEN", "BLAST_RADIUS_MAPPED", "CHANGE_PLANNED", "REGRESSION_BASELINE_PROVEN",
        "HANDOFF_READY", "WAITING_EXTERNAL_DEPENDENCY", "RESOLVED_NO_CODE", "QUARANTINED",
    ]}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    text = read("skills/code-change-verification/SKILL.md")
    text = text.replace(
        "7. A fail-then-pass history is `FLAKY_OR_ENVIRONMENT_DEPENDENT`, not a pass.",
        "7. A FAIL→PASS rerun on the same SHA/configuration is `FLAKY_OR_ENVIRONMENT_DEPENDENT`, not a pass. Valid RED→GREEN proof binds the same regression oracle to a failing known-bad base SHA and a passing candidate SHA.",
    )
    write("skills/code-change-verification/SKILL.md", text)
    write("docs/HOST_ACCEPTANCE.md", read("docs/HOST_ACCEPTANCE.md").replace("all 13 explicit-only skills", "all 14 explicit-only skills"))

    text = read("README.md")
    marker = "## What 4.3.6 implements\n"
    addition = "\n- fail-closed problem investigation before patching, with source-of-truth resolution, classification, reproduction/root-cause proof, blast-radius mapping, clean isolation, and RED→GREEN regression evidence;\n"
    if addition.strip() not in text:
        text = text.replace(marker, marker + addition, 1)
    write("README.md", text)


def harden_provider_contract() -> None:
    text = read("toolkit/ztad/providers.py")
    old = "    errors: tuple[str, ...]\n    argv: tuple[str, ...]\n\n    def to_dict(self) -> dict[str, Any]:\n"
    new = "    errors: tuple[str, ...]\n    argv: tuple[str, ...]\n    request_fingerprint: str | None = None\n    receipt_hash: str | None = None\n\n    def to_dict(self) -> dict[str, Any]:\n"
    if "request_fingerprint: str | None = None" not in text:
        if old not in text:
            raise RuntimeError("ProviderRunResult anchor changed")
        text = text.replace(old, new, 1)
    if '"request_fingerprint": self.request_fingerprint' not in text:
        text = text.replace(
            '            "argv": list(self.argv),\n        }\n',
            '            "argv": list(self.argv),\n            "request_fingerprint": self.request_fingerprint,\n            "receipt_hash": self.receipt_hash,\n        }\n',
            1,
        )
    install = (
        "\n\n# Strict structured-output/provider evidence contract is installed after provider classes exist.\n"
        "from .provider_contract import install_provider_contracts as _install_provider_contracts\n"
        "_install_provider_contracts(__import__(__name__, fromlist=[\"*\"]))\n"
    )
    if "_install_provider_contracts" not in text:
        text = text.rstrip() + install + "\n"
    write("toolkit/ztad/providers.py", text)

    text = read("toolkit/ztad/agent_output.py")
    if "AGENT_ROLE_ALIASES" not in text:
        text = text.replace(
            "SHA_RE = re.compile",
            'AGENT_ROLE_ALIASES = {"test_designer": "planner", "test_oracle": "planner", "reviewer": "independent_reviewer", "worker": "implementer"}\n\n'
            'def normalize_agent_role(value: str | None) -> str | None:\n    return None if value is None else AGENT_ROLE_ALIASES.get(value, value)\n\n'
            "SHA_RE = re.compile",
            1,
        )
        text = text.replace(
            "    errors = validate_instance(result, schema)\n",
            '    normalized = dict(result)\n    normalized["agent_role"] = normalize_agent_role(result.get("agent_role"))\n    result = normalized\n'
            '    if expected and expected.get("agent_role") is not None:\n        expected = dict(expected)\n        expected["agent_role"] = normalize_agent_role(expected.get("agent_role"))\n'
            "    errors = validate_instance(result, schema)\n",
            1,
        )
    write("toolkit/ztad/agent_output.py", text)


def strengthen_release_policy() -> None:
    path = ROOT / "policies/release-policy.yaml"
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    policy["version"] = 3
    gates = policy["gates"]
    for item in ["RELEASE_FINGERPRINT_VERIFIED", "SIGNED_RELEASE_MANIFEST", "ARTIFACT_ATTESTATION_VERIFIED", "SBOM_VERIFIED"]:
        if item not in gates["STAGING"]["required_evidence"]:
            gates["STAGING"]["required_evidence"].append(item)
    for item in ["ROLLBACK_REHEARSAL_VERIFIED", "OBSERVABILITY_READY"]:
        if item not in gates["RELEASE"]["required_evidence"]:
            gates["RELEASE"]["required_evidence"].append(item)
    for risk, items in {
        "R3": ["STAGED_RESTORE_REHEARSAL"],
        "R4": ["STAGED_RESTORE_REHEARSAL", "BACKUP_RESTORE_EVIDENCE", "REHEARSAL_EVIDENCE"],
    }.items():
        target = gates["RELEASE"]["by_risk"].setdefault(risk, {}).setdefault("required_evidence", [])
        for item in items:
            if item not in target:
                target.append(item)
    if "PROTECTED_RELEASE_AUTHORIZATION" not in gates["PRODUCTION"]["required_evidence"]:
        gates["PRODUCTION"]["required_evidence"].insert(0, "PROTECTED_RELEASE_AUTHORIZATION")
    path.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8")


def add_cli() -> None:
    text = read("toolkit/ztad/cli.py")
    if "from .problem import " not in text:
        marker = "from .providers import "
        at = text.index(marker)
        line_end = text.index("\n", at)
        imports = (
            "from .problem import initialize_problem_case, validate_problem_case, advance_problem_case, problem_case_to_change_contract\n"
            "from .release_fingerprint import compute_release_fingerprint\n"
        )
        text = text[: line_end + 1] + imports + text[line_end + 1 :]
    parser_anchor = '    p = sub.add_parser("classify-risk", help="Classify contract-only, intended-path, or actual-diff risk")\n'
    if 'sub.add_parser("problem-init"' not in text:
        parser_block = '''    p = sub.add_parser("problem-init", help="Capture an unverified problem read-only")
    _repo_args(p)
    p.add_argument("--report", required=True)
    p.add_argument("--expected")

    p = sub.add_parser("problem-validate", help="Validate a structured problem case")
    p.add_argument("--case", required=True)

    p = sub.add_parser("problem-transition", help="Apply one evidence-gated local problem-case transition")
    p.add_argument("--case", required=True)
    p.add_argument("--state", required=True)

    p = sub.add_parser("problem-contract", help="Generate a Change Contract only from HANDOFF_READY problem evidence")
    p.add_argument("--case", required=True)

    p = sub.add_parser("release-fingerprint", help="Compute a deterministic non-authoritative candidate release fingerprint")
    p.add_argument("--release-manifest", required=True)

'''
        if parser_anchor not in text:
            raise RuntimeError("CLI parser anchor changed")
        text = text.replace(parser_anchor, parser_block + parser_anchor, 1)
    execute_anchor = '    if command == "classify-risk":\n'
    if 'if command == "problem-init":' not in text:
        execute_block = '''    if command == "problem-init":
        case = initialize_problem_case(Path(args.repo), report=args.report, expected_behavior=args.expected)
        schema = _data(_root_file("schemas/problem-case.schema.json"))
        errors = validate_problem_case(case, schema)
        return {"problem_case": case, "errors": errors, "claim_boundary": "Local E2 intake only; no patch/release authority."}, 0 if not errors else 2
    if command == "problem-validate":
        case = _data(args.case)
        schema = _data(_root_file("schemas/problem-case.schema.json"))
        errors = validate_problem_case(case, schema)
        return {"valid": not errors, "problem_case": case, "errors": errors}, 0 if not errors else 2
    if command == "problem-transition":
        case = _data(args.case)
        schema = _data(_root_file("schemas/problem-case.schema.json"))
        updated = advance_problem_case(case, args.state, schema)
        return {"problem_case": updated, "claim_boundary": "Local E2 progression only; protected authority is unchanged."}, 0
    if command == "problem-contract":
        case = _data(args.case)
        schema = _data(_root_file("schemas/problem-case.schema.json"))
        contract = problem_case_to_change_contract(case, schema)
        errors = validate_instance(contract, _data(_root_file("schemas/change-contract.schema.json")))
        return {"contract": contract, "errors": errors}, 0 if not errors else 2
    if command == "release-fingerprint":
        manifest = _data(args.release_manifest)
        result = compute_release_fingerprint(manifest, _data(_root_file("schemas/release-manifest.schema.json")))
        return result, 0
'''
        if execute_anchor not in text:
            raise RuntimeError("CLI execute anchor changed")
        text = text.replace(execute_anchor, execute_block + execute_anchor, 1)
    write("toolkit/ztad/cli.py", text)


def changelog() -> None:
    text = read("CHANGELOG.md")
    if "## 4.3.6 — 2026-08-14" in text:
        return
    entry = """## 4.3.6 — 2026-08-14

- Added deterministic fail-closed problem investigation before Change Contract creation: source-of-truth resolution, classification, reproduction/proof, root cause, blast radius, minimal plan, clean isolation, and regression baseline.
- Added autonomous owner-interaction rules so routine technical decisions remain agent/controller work while protected authority and irreducible business decisions remain external.
- Added strict model-output schema preflight and provider request/receipt binding so invalid schemas fail before model execution and are not misreported as missing structured output.
- Added deterministic local release fingerprints and strengthened protected gates for signed manifests, SBOM/attestation/provenance, restore/rollback rehearsal, observability, protected release authorization, runtime health, synthetic transactions, and observation windows.
- Made dependency-audit, migration-ledger, dirty/divergent worktree, provider-output, schema, and external-evidence failures explicit fail-closed workflow concerns.
- Preserved v4.3.5 and all earlier releases/validation artifacts as immutable historical evidence.

"""
    write("CHANGELOG.md", text.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1))


def cleanup_staging() -> None:
    shutil.rmtree(ROOT / ".ztad-upgrade", ignore_errors=True)
    (ROOT / ".github/workflows/v436-upgrade-gate-v2.yml").unlink(missing_ok=True)
    Path(__file__).unlink(missing_ok=True)


def main() -> None:
    bump_release_identity()
    harden_bundle_and_docs()
    harden_provider_contract()
    strengthen_release_policy()
    add_cli()
    changelog()
    cleanup_staging()


if __name__ == "__main__":
    main()
