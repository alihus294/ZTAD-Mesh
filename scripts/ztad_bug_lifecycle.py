#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
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
    commit_bug_lifecycle_transition,
    evaluate_bug_transition,
    initialize_bug_lifecycle,
    initialize_authoritative_bug_lifecycle,
)
from ztad.evidence import load_evidence_records
from ztad.diff_forensics import collect_git_diff_inventory
from ztad.lifecycle_store import LifecycleStore
from ztad.schema_validation import validate_instance
from ztad.trust import load_host_accepted_trust_roots
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


def _trust_roots(path: Path | None) -> Any:
    if path is None:
        return None
    accepted_digest = os.environ.get("ZTAD_HOST_TRUST_ROOTS_DIGEST")
    acceptance_id = os.environ.get("ZTAD_HOST_TRUST_ROOTS_ACCEPTANCE_ID")
    if not accepted_digest or not acceptance_id:
        raise ValueError(
            "Lifecycle trust roots require host-provided ZTAD_HOST_TRUST_ROOTS_DIGEST and "
            "ZTAD_HOST_TRUST_ROOTS_ACCEPTANCE_ID"
        )
    return load_host_accepted_trust_roots(
        path,
        accepted_digest=accepted_digest,
        acceptance_id=acceptance_id,
    )


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
    init.add_argument("--store", type=Path, help="Controller-owned lifecycle database")
    init.add_argument("--export-only", action="store_true", help="Write a non-authoritative JSON export explicitly")

    bind = sub.add_parser("bind-candidate")
    bind.add_argument("--lifecycle", type=Path, required=True)
    bind.add_argument("--contract", type=Path, required=True)
    bind.add_argument("--head-sha", required=True)
    bind.add_argument("--diff-hash", required=True)
    bind.add_argument("--policy-bundle-hash", required=True)
    bind.add_argument("--toolchain-hash", required=True)
    bind.add_argument("--artifact-digest")
    bind.add_argument("--store", type=Path, required=True, help="Controller-owned lifecycle database")

    artifact = sub.add_parser("bind-artifact")
    artifact.add_argument("--lifecycle", type=Path, required=True)
    artifact.add_argument("--artifact-digest", required=True)
    artifact.add_argument("--store", type=Path, required=True, help="Controller-owned lifecycle database")

    for name in ("evaluate", "advance"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--lifecycle", type=Path, required=True)
        cmd.add_argument("--target", required=True)
        cmd.add_argument("--problem-case", type=Path)
        cmd.add_argument("--evidence", type=Path)
        cmd.add_argument("--trust-roots", type=Path)
        cmd.add_argument("--transition-authorization", type=Path)
        cmd.add_argument("--repository-root", type=Path, help="Git repository used for independent diff enumeration")
        cmd.add_argument("--store", type=Path, required=True, help="Controller-owned lifecycle database")

    args = parser.parse_args(argv)
    policy = _read(POLICY)
    lifecycle_schema = _read(LIFECYCLE_SCHEMA)
    evidence_schema = _read(EVIDENCE_SCHEMA)

    if args.command == "init":
        if not args.store and not args.export_only:
            raise ValueError("Authoritative initialization requires --store; use --export-only only for an explicit non-authoritative export")
        if args.store and args.export_only:
            raise ValueError("--store and --export-only are mutually exclusive")
        case = _read(args.problem_case)
        domains = args.domain or ["GENERAL"]
        if args.store:
            record = initialize_authoritative_bug_lifecycle(
                store=LifecycleStore(args.store),
                problem_case=case,
                policy=policy,
                profile=args.profile,
                mode=args.mode,
                remote_repository=args.remote_repository,
                domains=domains,
            )
        else:
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
        store = LifecycleStore(args.store)
        export = _read(args.lifecycle)
        record = store.get(str(export["case_id"]), verify=True)
        updated = bind_candidate(
            record,
            contract_path=args.contract,
            head_sha=args.head_sha,
            diff_hash=args.diff_hash,
            policy_bundle_hash=args.policy_bundle_hash,
            toolchain_hash=args.toolchain_hash,
            artifact_digest=args.artifact_digest,
        )
        updated = store.transition(
            str(record["case_id"]),
            updated,
            expected_version=int(record["store_version"]),
            requested_state=str(updated.get("blocked_target") or updated.get("state")),
            decision="SUBJECT_BOUND",
            rejected_evidence=list((updated.get("historical_evidence_refs") or {}).keys()),
            policy_hash=updated.get("policy_bundle_hash"),
            toolchain_hash=updated.get("toolchain_hash"),
        )
        _write(args.lifecycle, store.export(str(record["case_id"])))
        print(json.dumps(updated, indent=2, sort_keys=True))
        return 0

    if args.command == "bind-artifact":
        store = LifecycleStore(args.store)
        export = _read(args.lifecycle)
        record = store.get(str(export["case_id"]), verify=True)
        updated = bind_artifact(record, args.artifact_digest)
        updated = store.transition(
            str(record["case_id"]),
            updated,
            expected_version=int(record["store_version"]),
            requested_state=str(updated.get("blocked_target") or updated.get("state")),
            decision="ARTIFACT_BOUND",
            rejected_evidence=list((updated.get("historical_evidence_refs") or {}).keys()),
            policy_hash=updated.get("policy_bundle_hash"),
            toolchain_hash=updated.get("toolchain_hash"),
        )
        _write(args.lifecycle, store.export(str(record["case_id"])))
        print(json.dumps(updated, indent=2, sort_keys=True))
        return 0

    export = _read(args.lifecycle)
    case = _read(args.problem_case) if args.problem_case else None
    records = _records(args.evidence)
    roots = _trust_roots(args.trust_roots)
    store = LifecycleStore(args.store, authority_trust_roots=roots)
    record = store.get(str(export["case_id"]), verify=True)
    repository_root = args.repository_root
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
            repository_root=repository_root,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["allowed"] else 2

    updated = commit_bug_lifecycle_transition(
        store,
        record,
        args.target,
        expected_version=int(record["store_version"]),
        policy=policy,
        lifecycle_schema=lifecycle_schema,
        problem_case=case,
        evidence_records=records,
        evidence_schema=evidence_schema,
        trust_roots=roots,
        repository_root=repository_root,
        transition_authorization=_read(args.transition_authorization) if args.transition_authorization else None,
    )
    _write(args.lifecycle, store.export(str(record["case_id"])))
    print(json.dumps(updated, indent=2, sort_keys=True))
    return 0 if updated["state"] == args.target else 2


if __name__ == "__main__":
    raise SystemExit(main())
