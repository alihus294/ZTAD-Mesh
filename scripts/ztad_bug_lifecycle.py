#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
TOOLKIT = ROOT / "toolkit"
if not TOOLKIT.is_dir():
    raise SystemExit(f"ZTAD toolkit not found at {TOOLKIT}")
sys.path.insert(0, str(TOOLKIT))

from ztad.bug_lifecycle import (
    advance_bug_lifecycle,
    bind_artifact,
    bind_candidate,
    evaluate_bug_transition,
    initialize_bug_lifecycle,
)
from ztad.evidence import load_evidence_records
from ztad.schema_validation import validate_instance
from ztad.util import atomic_write, load_data

POLICY = ROOT / "policies/bug-to-production-policy.yaml"
LIFECYCLE_SCHEMA = ROOT / "schemas/bug-lifecycle.schema.json"
EVIDENCE_SCHEMA = ROOT / "schemas/evidence.schema.json"


def _read(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError(f"Expected an object in {path}")
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    atomic_write(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _records(path: Path | None) -> list[dict[str, Any]]:
    return [] if path is None else load_evidence_records(path)


def _trust_roots(path: Path | None) -> dict[str, Any] | None:
    return None if path is None else _read(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZTAD exact fail-closed bug-to-production lifecycle")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--problem-case", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--profile", choices=("generic", "workshopos"), default="generic")
    init.add_argument("--mode", choices=("NORMAL", "HOTFIX"), default="NORMAL")
    init.add_argument("--remote-repository")
    init.add_argument("--domain", action="append", default=[])

    bind = sub.add_parser("bind-candidate")
    bind.add_argument("--lifecycle", type=Path, required=True)
    bind.add_argument("--contract", type=Path, required=True)
    bind.add_argument("--head-sha", required=True)
    bind.add_argument("--diff-hash", required=True)
    bind.add_argument("--policy-bundle-hash", required=True)
    bind.add_argument("--toolchain-hash", required=True)
    bind.add_argument("--artifact-digest")

    artifact = sub.add_parser("bind-artifact")
    artifact.add_argument("--lifecycle", type=Path, required=True)
    artifact.add_argument("--artifact-digest", required=True)

    for name in ("evaluate", "advance"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--lifecycle", type=Path, required=True)
        cmd.add_argument("--target", required=True)
        cmd.add_argument("--problem-case", type=Path)
        cmd.add_argument("--evidence", type=Path)
        cmd.add_argument("--trust-roots", type=Path)

    args = parser.parse_args(argv)
    policy = _read(POLICY)
    lifecycle_schema = _read(LIFECYCLE_SCHEMA)
    evidence_schema = _read(EVIDENCE_SCHEMA)

    if args.command == "init":
        case = _read(args.problem_case)
        domains = args.domain or ["GENERAL"]
        record = initialize_bug_lifecycle(
            problem_case=case,
            policy=policy,
            profile=args.profile,
            mode=args.mode,
            remote_repository=args.remote_repository,
            domains=domains,
        )
        errors = validate_instance(record, lifecycle_schema)
        if errors:
            raise ValueError("Invalid initialized lifecycle: " + "; ".join(errors))
        _write(args.output, record)
        print(json.dumps(record, indent=2, sort_keys=True))
        return 0

    if args.command == "bind-candidate":
        record = _read(args.lifecycle)
        updated = bind_candidate(
            record,
            contract_path=args.contract,
            head_sha=args.head_sha,
            diff_hash=args.diff_hash,
            policy_bundle_hash=args.policy_bundle_hash,
            toolchain_hash=args.toolchain_hash,
            artifact_digest=args.artifact_digest,
        )
        _write(args.lifecycle, updated)
        print(json.dumps(updated, indent=2, sort_keys=True))
        return 0

    if args.command == "bind-artifact":
        record = _read(args.lifecycle)
        updated = bind_artifact(record, args.artifact_digest)
        _write(args.lifecycle, updated)
        print(json.dumps(updated, indent=2, sort_keys=True))
        return 0

    record = _read(args.lifecycle)
    case = _read(args.problem_case) if args.problem_case else None
    records = _records(args.evidence)
    roots = _trust_roots(args.trust_roots)
    if args.command == "evaluate":
        result = evaluate_bug_transition(
            record,
            args.target,
            policy=policy,
            lifecycle_schema=lifecycle_schema,
            problem_case=case,
            evidence_records=records,
            evidence_schema=evidence_schema,
            trust_roots=roots,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["allowed"] else 2

    updated = advance_bug_lifecycle(
        record,
        args.target,
        policy=policy,
        lifecycle_schema=lifecycle_schema,
        problem_case=case,
        evidence_records=records,
        evidence_schema=evidence_schema,
        trust_roots=roots,
    )
    _write(args.lifecycle, updated)
    print(json.dumps(updated, indent=2, sort_keys=True))
    return 0 if updated["state"] == args.target else 2


if __name__ == "__main__":
    raise SystemExit(main())
