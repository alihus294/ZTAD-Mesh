from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Iterable

from .util import canonical_json, safe_relative_path, sha256_bytes


def _matches(path: str, pattern: str) -> bool:
    normalized = safe_relative_path(path).casefold()
    raw_pattern = pattern.replace("\\", "/").strip("/").casefold()
    if not raw_pattern:
        return False
    # Match root-level files as well as nested files for patterns beginning with **/.
    patterns = {raw_pattern}
    if raw_pattern.startswith("**/"):
        patterns.add(raw_pattern[3:])
    return any(fnmatch.fnmatchcase(normalized, candidate) for candidate in patterns)


@dataclass(frozen=True)
class ScopeEnvelope:
    task_id: str
    parent_goal_hash: str
    contract_hash: str
    acceptance_ids: tuple[str, ...]
    allowed_patterns: tuple[str, ...]
    must_not_touch: tuple[str, ...]

    @classmethod
    def from_contract(
        cls,
        *,
        task_id: str,
        contract: dict[str, Any],
        allowed_patterns: Iterable[str],
        must_not_touch: Iterable[str],
    ) -> "ScopeEnvelope":
        goal = {
            "outcome": contract.get("outcome"),
            "acceptance_criteria": ((contract.get("requirements") or {}).get("acceptance_criteria") or []),
        }
        ids = tuple(sorted(
            str(item.get("id")) for item in goal["acceptance_criteria"]
            if isinstance(item, dict) and item.get("id")
        ))
        return cls(
            task_id=task_id,
            parent_goal_hash=sha256_bytes(canonical_json(goal)),
            contract_hash=sha256_bytes(canonical_json(contract)),
            acceptance_ids=ids,
            allowed_patterns=tuple(sorted(set(str(x) for x in allowed_patterns))),
            must_not_touch=tuple(sorted(set(str(x) for x in must_not_touch))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "parent_goal_hash": self.parent_goal_hash,
            "contract_hash": self.contract_hash,
            "acceptance_ids": list(self.acceptance_ids),
            "allowed_patterns": list(self.allowed_patterns),
            "must_not_touch": list(self.must_not_touch),
        }

    def verify_contract(self, contract: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        current_contract = sha256_bytes(canonical_json(contract))
        if current_contract != self.contract_hash:
            errors.append("contract_hash_changed")
        current_goal = sha256_bytes(canonical_json({
            "outcome": contract.get("outcome"),
            "acceptance_criteria": ((contract.get("requirements") or {}).get("acceptance_criteria") or []),
        }))
        if current_goal != self.parent_goal_hash:
            errors.append("parent_goal_changed")
        return errors

    def verify_paths(self, paths: Iterable[str]) -> dict[str, Any]:
        normalized = [safe_relative_path(path) for path in paths]
        prohibited = sorted(path for path in normalized if any(_matches(path, pattern) for pattern in self.must_not_touch))
        outside = sorted(
            path for path in normalized
            if self.allowed_patterns and not any(_matches(path, pattern) for pattern in self.allowed_patterns)
        )
        return {
            "allowed": not prohibited and not outside,
            "paths": sorted(set(normalized)),
            "prohibited_paths": prohibited,
            "outside_scope_paths": outside,
            "decision": "CONTINUE" if not prohibited and not outside else "CREATE_CHILD_TASK_OR_REPLAN",
        }

    def child_task_proposal(self, paths: Iterable[str], *, reason: str) -> dict[str, Any]:
        normalized = sorted(set(safe_relative_path(path) for path in paths))
        return {
            "parent_task_id": self.task_id,
            "parent_goal_hash": self.parent_goal_hash,
            "contract_hash": self.contract_hash,
            "implements": list(self.acceptance_ids),
            "discovered_paths": normalized,
            "reason": reason,
            "requested_action": "NEW_CHILD_TASK",
            "mutation_authority": False,
        }
