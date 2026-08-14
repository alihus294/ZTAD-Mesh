from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8", newline="\n")


def bundle_and_identity() -> None:
    text = read("toolkit/ztad/bundle.py")
    if '"schemas/blocker-request.schema.json",' not in text:
        anchor = '    "schemas/problem-case.schema.json",\n'
        if anchor not in text:
            raise RuntimeError("problem-case required-file anchor was not materialized")
        text = text.replace(anchor, anchor + '    "schemas/blocker-request.schema.json",\n', 1)
    write("toolkit/ztad/bundle.py", text)

    text = read("scripts/verify_version_identity.py")
    marker = '    "docs/THREAT_MODEL.md": "# Threat Model",\n'
    addition = '    "docs/BUG_TO_PRODUCTION_PROTOCOL.md": "# Autonomous Fail-Closed Bug-to-Production Protocol",\n'
    if addition not in text:
        if marker not in text:
            raise RuntimeError("version identity current-heading anchor changed")
        text = text.replace(marker, marker + addition, 1)
    write("scripts/verify_version_identity.py", text)


def cli_blocker_request() -> None:
    text = read("toolkit/ztad/cli.py")
    import_anchor = "from .release_fingerprint import compute_release_fingerprint\n"
    import_line = "from .blocker_requests import prepare_blocker_request\n"
    if import_line not in text:
        if import_anchor not in text:
            raise RuntimeError("release fingerprint import was not materialized")
        text = text.replace(import_anchor, import_anchor + import_line, 1)

    if 'sub.add_parser("prepare-blocker-request"' not in text:
        anchor = '''    p = sub.add_parser("release-fingerprint", help="Compute a deterministic non-authoritative candidate release fingerprint")
    p.add_argument("--release-manifest", required=True)

'''
        addition = '''    p = sub.add_parser("prepare-blocker-request", help="Prepare an exact local remediation or protected evidence request without fabricating success")
    p.add_argument("--blocker", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--reason", required=True)

'''
        if anchor not in text:
            raise RuntimeError("release-fingerprint parser anchor was not materialized")
        text = text.replace(anchor, anchor + addition, 1)

    if 'if command == "prepare-blocker-request":' not in text:
        anchor = '''    if command == "release-fingerprint":
        manifest = _data(args.release_manifest)
        result = compute_release_fingerprint(manifest, _data(_root_file("schemas/release-manifest.schema.json")))
        return result, 0
'''
        addition = '''    if command == "prepare-blocker-request":
        subject = _data(args.subject)
        schema = _data(_root_file("schemas/blocker-request.schema.json"))
        request = prepare_blocker_request(args.blocker, subject=subject, reason=args.reason, schema=schema)
        return request, 0
'''
        if anchor not in text:
            raise RuntimeError("release-fingerprint execution anchor was not materialized")
        text = text.replace(anchor, anchor + addition, 1)
    write("toolkit/ztad/cli.py", text)


def master_plan_and_traceability() -> None:
    path = "references/MASTER_PLAN.md"
    text = read(path)
    if "## 27. Autonomous problem-to-production intake" not in text:
        section = '''

## 27. Autonomous problem-to-production intake

- Every reported defect MUST begin as an unverified report rather than an assumed bug.
- Investigation MUST resolve the current source of truth read-only before implementation begins.
- A code-affecting report MUST be classified, reproduced or equivalently proven, causally explained, blast-radius mapped, and planned before a Change Contract is created.
- A known-bad regression baseline SHOULD use the same oracle that later validates the candidate.
- A same-SHA or same-configuration fail-then-pass rerun MUST NOT be represented as RED-to-GREEN regression proof.
- A dirty or protected-base-divergent user worktree MUST be preserved untouched while task work proceeds in an isolated clean worktree from the exact protected base.
- Routine technical choices MUST NOT be delegated to a non-programmer owner when the controller can safely derive and execute them.
- Missing local evidence files SHOULD be created as explicitly non-authoritative local evidence rather than stopping all progress.
- An identical no-progress provider, test, or repair attempt MUST NOT be repeated.
- Missing external authority MUST block only the affected protected transition while unrelated safe runnable work continues.
- A model MUST NOT convert its own text, confidence, review, or agreement into merge, release, deployment, signing, attestation, or production evidence.
- Strict model-output schemas MUST be validated before provider execution; an invalid schema MUST NOT be misreported as missing structured output.
- Test/orchestration role aliases MUST be normalized only at the provider/validation boundary and MUST NOT weaken the canonical structured-output schema.
- Every candidate release MUST have a deterministic fingerprint bound to its exact manifest subject before protected promotion.
- A local release fingerprint or blocker request MUST NOT be represented as a protected signature, attestation, approval, staging result, runtime health result, or production success.
- Missing protected evidence SHOULD produce a subject-bound protected evidence request naming the required evidence type, trust level, expected producer, and next action.
- Artifact promotion MUST require the applicable signed manifest, SBOM, provenance/attestation, exact digest, protected CI/review evidence, and rollback material.
- High-risk release MUST require applicable staged restore and rollback rehearsal evidence before production progression.
- Production verification MUST bind runtime health, a production-safe synthetic transaction, and the observation window to the exact deployed digest.
- Migration ledger/history guard failures MUST be repaired at the migration/history root cause and MUST NOT be bypassed by weakening the guard.
- Dependency-audit failures MUST be repaired on a clean protected-base candidate with regenerated lock state and exact-head protected CI.
- Production database mutation MUST NOT be performed from a normal coding-agent shell or ad-hoc direct database session.
- Production release MUST use only the repository's canonical protected release path and exact validated artifact.
'''
        text = text.rstrip() + section + "\n"
    write(path, text)

    path = "scripts/generate_traceability.py"
    text = read(path)
    if "27: (\"DETERMINISTIC_AND_PLATFORM\"" not in text:
        anchor = '    26: ("CONTROL_SPECIFIC", "toolkit/ztad/; policies/; hooks/; tests/; docs/GITHUB_ENFORCEMENT.md", "requirement-specific local tests and target-platform evidence"),\n'
        addition = '    27: ("DETERMINISTIC_AND_PLATFORM", "schemas/problem-case.schema.json; schemas/blocker-request.schema.json; toolkit/ztad/problem.py; toolkit/ztad/problem_isolation.py; toolkit/ztad/blocker_requests.py; toolkit/ztad/provider_contract.py; skills/problem-investigation; docs/BUG_TO_PRODUCTION_PROTOCOL.md", "problem-lifecycle, isolation, provider-contract, release-evidence, and protected-platform tests"),\n'
        if anchor not in text:
            raise RuntimeError("traceability section map anchor changed")
        text = text.replace(anchor, anchor + addition, 1)
    write(path, text)


def control_docs() -> None:
    path = "docs/CONTROL_COVERAGE.md"
    text = read(path)
    marker = "## Deterministically enforced locally\n\n"
    additions = (
        "- fail-closed problem intake, source-of-truth/classification/root-cause/blast-radius gates before Change Contract creation;\n"
        "- protected-base resolution and autonomous clean-worktree isolation without mutating dirty/divergent user work;\n"
        "- RED→GREEN base/candidate oracle semantics distinct from same-SHA flakiness;\n"
        "- strict provider-schema preflight, request fingerprints, stderr/event/receipt preservation, and boundary-only role normalization;\n"
        "- deterministic non-authoritative release fingerprints and exact blocker evidence/remediation requests;\n"
    )
    if "fail-closed problem intake" not in text:
        if marker not in text:
            raise RuntimeError("control coverage insertion anchor changed")
        text = text.replace(marker, marker + additions, 1)
    write(path, text)

    path = "docs/EVALS.md"
    text = read(path)
    marker = "Evaluation is divided into independently reported categories:\n\n"
    additions = (
        "- unverified-report intake, protected-base resolution, classification, reproduction/root-cause/blast-radius gates, and clean worktree isolation;\n"
        "- RED→GREEN regression-baseline proof versus same-SHA flakiness;\n"
        "- strict provider-schema preflight, provider receipts, and role-alias normalization at the validation boundary;\n"
        "- release fingerprints and all prior blocker remediation/protected-evidence request mappings;\n"
    )
    if "unverified-report intake" not in text:
        if marker not in text:
            raise RuntimeError("eval insertion anchor changed")
        text = text.replace(marker, marker + additions, 1)
    write(path, text)


def skill_blocker_command() -> None:
    path = "skills/zero-trust-delivery/SKILL.md"
    text = read(path)
    marker = "# Output\n"
    block = '''# Protected evidence request preparation

When a mandatory blocker remains, prepare a precise subject-bound request rather than asking the owner a generic technical question or claiming success:

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py prepare-blocker-request --blocker <BLOCKER> --subject <SUBJECT.json> --reason "<observed missing evidence>"
```

The request itself is local/non-authoritative and cannot satisfy the gate it requests.

'''
    if "# Protected evidence request preparation" not in text:
        if marker not in text:
            raise RuntimeError("skill output anchor changed")
        text = text.replace(marker, block + marker, 1)
    write(path, text)


def cleanup() -> None:
    Path(__file__).unlink(missing_ok=True)


def main() -> None:
    bundle_and_identity()
    cli_blocker_request()
    master_plan_and_traceability()
    control_docs()
    skill_blocker_command()
    cleanup()


if __name__ == "__main__":
    main()
