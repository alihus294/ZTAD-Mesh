from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .problem import LOCAL_EVIDENCE_NOTICE, SHA_RE, problem_case_fingerprint
from .repository import GitRepository
from .util import canonical_json, sha256_bytes, utc_now
from .worktrees import WorktreeManager


def isolate_problem_case(case: dict[str, Any]) -> dict[str, Any]:
    """Create a managed detached worktree from the exact recorded protected base.

    This operation intentionally does not stash, reset, commit, checkout, or edit
    the user's original worktree. The only original-repository mutation is Git's
    managed worktree metadata plus the gitignored `.delivery/ztad/worktrees` tree.
    Returned evidence is local E2 evidence and cannot grant approval/release.
    """
    repository = Path(str(case.get("repository") or "")).resolve()
    base_sha = str(case.get("base_sha") or "")
    if not SHA_RE.fullmatch(base_sha):
        raise ValueError("Problem case must contain an exact protected base SHA")
    if case.get("protected_ref_resolved") is not True:
        raise ValueError("Protected/current base must be resolved before isolation")

    repo = GitRepository(repository)
    exact_base = repo.rev_parse(base_sha)
    if exact_base != base_sha:
        raise ValueError("Problem base SHA did not resolve to the recorded exact commit")

    original_head = repo.current_head()
    original_case_fingerprint = problem_case_fingerprint(case)
    node_id = f"problem-{str(case.get('case_id') or 'case').lower()}-{base_sha[:12]}"
    manager = WorktreeManager(repo)
    worktree = manager.create(node_id, base_sha)
    isolated_repo = GitRepository(worktree)
    isolated_head = isolated_repo.current_head()
    if isolated_head != base_sha:
        manager.remove(worktree)
        raise RuntimeError("Isolated worktree head does not match the protected base SHA")
    if repo.current_head() != original_head:
        manager.remove(worktree)
        raise RuntimeError("Original worktree HEAD changed during isolation")

    evidence_payload = {
        "schema_version": 1,
        "evidence_type": "ISOLATED_CLEAN_WORKTREE",
        "authority": "LOCAL_NON_AUTHORITATIVE",
        "can_grant_merge_release_or_production": False,
        "case_id": case.get("case_id"),
        "problem_case_fingerprint": original_case_fingerprint,
        "repository": str(repo.root),
        "protected_base_sha": base_sha,
        "original_head_sha": original_head,
        "isolated_head_sha": isolated_head,
        "worktree": str(worktree),
        "created_at": utc_now(),
        "local_evidence_notice": LOCAL_EVIDENCE_NOTICE,
    }
    evidence_id = sha256_bytes(canonical_json(evidence_payload))

    updated = copy.deepcopy(case)
    status = updated.setdefault("worktree_status", {})
    status["user_worktree_preserved"] = True
    status["isolated_clean_worktree"] = True
    refs = list(status.get("evidence_refs") or [])
    if evidence_id not in refs:
        refs.append(evidence_id)
    status["evidence_refs"] = refs
    return {
        "problem_case": updated,
        "worktree": str(worktree),
        "evidence_id": evidence_id,
        "evidence": evidence_payload,
        "claim_boundary": "Local clean-worktree evidence is E2 only; protected CI/review/release authority remains external.",
    }
