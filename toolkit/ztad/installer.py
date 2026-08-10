from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capabilities import detect_capabilities
from .errors import ConfigurationError, PolicyViolation
from .util import atomic_write, is_within, sha256_bytes, sha256_file, utc_now, walk_regular_files


BEGIN_MARKER = "<!-- ZTAD:BEGIN MANAGED AGENT RULES -->"
END_MARKER = "<!-- ZTAD:END MANAGED AGENT RULES -->"
MANAGED_ROOT = Path(".delivery/ztad")
MANIFEST_REL = MANAGED_ROOT / "installation.json"


@dataclass(frozen=True)
class PlannedAction:
    action: str
    path: str
    reason: str
    candidate_path: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {"action": self.action, "path": self.path, "reason": self.reason, "candidate_path": self.candidate_path}


def distribution_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _plugin_version() -> str:
    path = distribution_root() / "VERSION"
    if not path.is_file() or path.is_symlink():
        raise ConfigurationError(f"Missing regular VERSION file: {path}")
    version = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ConfigurationError(f"Invalid plugin VERSION value: {version!r}")
    return version


def _relative_files(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in walk_regular_files(root):
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or relative.endswith(".pyc"):
            continue
        result[relative] = path.read_bytes()
    return result


def _desired_files(*, activate_ci: bool, install_repo_skills: bool) -> dict[str, tuple[bytes, str]]:
    root = distribution_root()
    desired: dict[str, tuple[bytes, str]] = {}

    def add_tree(source_root: Path, target_root: str, *, skip: set[str] | None = None) -> None:
        for relative, data in _relative_files(source_root).items():
            if skip and relative in skip:
                continue
            target = f"{target_root.rstrip('/')}/{relative}"
            desired[target] = (data, f"{source_root.relative_to(root).as_posix()}/{relative}")

    add_tree(root / "policies", f"{MANAGED_ROOT.as_posix()}/policies")
    add_tree(root / "schemas", f"{MANAGED_ROOT.as_posix()}/schemas")
    add_tree(root / "toolkit", f"{MANAGED_ROOT.as_posix()}/toolkit", skip={"pyproject.toml"})
    add_tree(root / "templates", f"{MANAGED_ROOT.as_posix()}/templates")
    add_tree(root / "skills", f"{MANAGED_ROOT.as_posix()}/skills")

    for filename in ("VERSION", "LICENSE"):
        source = root / filename
        if source.exists():
            desired[f"{MANAGED_ROOT.as_posix()}/{filename}"] = (source.read_bytes(), filename)
    wrapper = root / "scripts/ztad.py"
    if wrapper.exists():
        desired[f"{MANAGED_ROOT.as_posix()}/bin/ztad.py"] = (wrapper.read_bytes(), "scripts/ztad.py")
    requirements = root / "toolkit/requirements.lock.txt"
    if requirements.exists():
        desired[f"{MANAGED_ROOT.as_posix()}/requirements.lock.txt"] = (requirements.read_bytes(), "toolkit/requirements.lock.txt")

    repository_templates = root / "templates/repository"
    for relative, data in _relative_files(repository_templates).items():
        if relative == "AGENTS.md":
            continue
        if relative.startswith(".delivery/ztad/"):
            # Runtime files already live under the managed root; copy project-specific templates there.
            desired[relative] = (data, f"templates/repository/{relative}")
        elif relative.startswith(".github/"):
            if activate_ci:
                desired[relative] = (data, f"templates/repository/{relative}")
            else:
                target = f"{MANAGED_ROOT.as_posix()}/generated/{relative}"
                desired[target] = (data, f"templates/repository/{relative}")
        else:
            desired[relative] = (data, f"templates/repository/{relative}")

    if install_repo_skills:
        for relative, data in _relative_files(root / "skills").items():
            desired[f".agents/skills/{relative}"] = (data, f"skills/{relative}")
    return desired


def _load_manifest(repo: Path) -> dict[str, Any]:
    path = repo / MANIFEST_REL
    if not path.exists():
        return {"schema_version": 1, "managed_files": {}, "plugin_version": None}
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"Installation manifest is not a regular file: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Installation manifest is invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("managed_files", {}), dict):
        raise ConfigurationError("Installation manifest has an invalid structure")
    return data


def _managed_agents_source() -> str:
    path = distribution_root() / "templates/repository/AGENTS.md"
    if not path.is_file():
        raise ConfigurationError("Missing templates/repository/AGENTS.md")
    return path.read_text(encoding="utf-8").strip()


def _managed_agents_block() -> str:
    return f"{BEGIN_MARKER}\n{_managed_agents_source()}\n{END_MARKER}"


def _extract_agents_block(existing: str) -> str | None:
    if BEGIN_MARKER not in existing or END_MARKER not in existing:
        return None
    before, remainder = existing.split(BEGIN_MARKER, 1)
    _ = before
    body, _after = remainder.split(END_MARKER, 1)
    return f"{BEGIN_MARKER}{body}{END_MARKER}"


def _replace_agents_block(existing: str, block: str) -> str:
    if BEGIN_MARKER in existing and END_MARKER in existing:
        before, remainder = existing.split(BEGIN_MARKER, 1)
        _old, after = remainder.split(END_MARKER, 1)
        return before.rstrip() + "\n\n" + block + after
    if existing.strip():
        return existing.rstrip() + "\n\n" + block + "\n"
    return block + "\n"


def _remove_agents_block(existing: str) -> str:
    if BEGIN_MARKER not in existing or END_MARKER not in existing:
        return existing
    before, remainder = existing.split(BEGIN_MARKER, 1)
    _old, after = remainder.split(END_MARKER, 1)
    combined = before.rstrip() + ("\n" if before.strip() and after.strip() else "") + after.lstrip()
    return combined.rstrip() + ("\n" if combined.strip() else "")


def _candidate_relative(repo: Path, relative: str, desired: bytes) -> tuple[str, bool]:
    """Return a conflict-candidate path and whether identical content already exists.

    Reusing an identical candidate keeps repeated INSTALL/UPDATE operations
    idempotent even when an unmanaged or locally modified target is preserved.
    Existing non-regular candidates are never overwritten.
    """
    base = relative + ".ztad.new"
    candidate = base
    index = 1
    desired_hash = sha256_bytes(desired)
    while True:
        target = repo / candidate
        if not target.exists() and not target.is_symlink():
            return candidate, False
        if target.is_file() and not target.is_symlink() and sha256_file(target) == desired_hash:
            return candidate, True
        candidate = f"{base}.{index}"
        index += 1


def _assert_safe_target(repo: Path, relative: str) -> Path:
    target = repo / relative
    if not is_within(target, repo):
        raise PolicyViolation(f"Managed target escapes repository root: {relative}")
    current = repo
    for part in Path(relative).parts[:-1]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise PolicyViolation(f"Managed target has a symlink ancestor: {current}")
    if target.exists() and target.is_symlink():
        raise PolicyViolation(f"Managed target is a symlink: {relative}")
    return target


def _agents_plan(repo: Path, manifest: dict[str, Any]) -> PlannedAction:
    target = repo / "AGENTS.md"
    if target.exists() and (target.is_symlink() or not target.is_file()):
        return PlannedAction("BLOCK", "AGENTS.md", "AGENTS.md is not a regular file")
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    current_block = _extract_agents_block(existing)
    desired_block = _managed_agents_block()
    desired_hash = sha256_bytes(desired_block.encode("utf-8"))
    if current_block is None:
        return PlannedAction("MERGE", "AGENTS.md", "Add a bounded managed rule block")
    current_hash = sha256_bytes(current_block.encode("utf-8"))
    if current_hash == desired_hash:
        return PlannedAction("NOOP", "AGENTS.md", "Managed rule block is current")
    prior_hash = manifest.get("agents_managed_block_hash")
    if prior_hash and current_hash == prior_hash:
        return PlannedAction("UPDATE_BLOCK", "AGENTS.md", "Previously managed rule block is unchanged locally")
    candidate, already_current = _candidate_relative(repo, "AGENTS.md", (desired_block + "\n").encode("utf-8"))
    return PlannedAction(
        "PRESERVE_AGENTS_CONFLICT_NOOP" if already_current else "PRESERVE_AGENTS_CONFLICT",
        "AGENTS.md",
        "Managed AGENTS block was modified locally and will not be overwritten",
        candidate,
    )


def plan(repo_path: Path | str, *, activate_ci: bool = False, install_repo_skills: bool = True) -> dict[str, Any]:
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        raise ConfigurationError(f"Repository directory does not exist: {repo}")
    desired = _desired_files(activate_ci=activate_ci, install_repo_skills=install_repo_skills)
    manifest = _load_manifest(repo)
    old_managed = manifest.get("managed_files", {}) or {}
    actions: list[PlannedAction] = []

    for relative, (data, _source) in sorted(desired.items()):
        try:
            target = _assert_safe_target(repo, relative)
        except PolicyViolation as exc:
            actions.append(PlannedAction("BLOCK", relative, str(exc)))
            continue
        desired_hash = sha256_bytes(data)
        if not target.exists():
            actions.append(PlannedAction("CREATE", relative, "Managed file is absent"))
            continue
        if not target.is_file():
            actions.append(PlannedAction("BLOCK", relative, "Target is not a regular file"))
            continue
        current_hash = sha256_file(target)
        if current_hash == desired_hash:
            actions.append(PlannedAction("NOOP", relative, "Already at desired content"))
        elif old_managed.get(relative, {}).get("sha256") == current_hash:
            actions.append(PlannedAction("UPDATE", relative, "Previously managed file is unchanged locally"))
        else:
            candidate, already_current = _candidate_relative(repo, relative, data)
            actions.append(PlannedAction(
                "PRESERVE_CONFLICT_NOOP" if already_current else "PRESERVE_CONFLICT",
                relative,
                "Existing or locally modified file will not be overwritten",
                candidate,
            ))

    for relative, record in sorted(old_managed.items()):
        if relative not in desired:
            try:
                target = _assert_safe_target(repo, relative)
            except PolicyViolation as exc:
                actions.append(PlannedAction("BLOCK", relative, str(exc)))
                continue
            if target.exists() and target.is_file() and sha256_file(target) == record.get("sha256"):
                actions.append(PlannedAction("REMOVE_STALE", relative, "Previously managed file is no longer distributed"))
            elif target.exists():
                actions.append(PlannedAction("PRESERVE_STALE_MODIFIED", relative, "Stale managed file was modified locally"))

    actions.append(_agents_plan(repo, manifest))
    blocked = any(item.action == "BLOCK" for item in actions)
    mutation_actions = {"CREATE", "UPDATE", "REMOVE_STALE", "MERGE", "UPDATE_BLOCK", "PRESERVE_CONFLICT", "PRESERVE_AGENTS_CONFLICT"}
    # PRESERVE_*_NOOP actions reuse an existing identical candidate and do not mutate.
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "repository": str(repo),
        "activate_ci": activate_ci,
        "install_repo_skills": install_repo_skills,
        "blocked": blocked,
        "would_mutate": any(item.action in mutation_actions for item in actions),
        "actions": [item.to_dict() for item in actions],
        "capabilities": detect_capabilities(repo),
        "claim_boundary": "Generated files and local checks do not prove remote platform enforcement.",
    }


def apply_install(repo_path: Path | str, *, activate_ci: bool = False, install_repo_skills: bool = True) -> dict[str, Any]:
    repo = Path(repo_path).resolve()
    plan_result = plan(repo, activate_ci=activate_ci, install_repo_skills=install_repo_skills)
    if plan_result["blocked"]:
        return {**plan_result, "applied": False, "decision": "FAIL_CLOSED"}
    desired = _desired_files(activate_ci=activate_ci, install_repo_skills=install_repo_skills)
    manifest = _load_manifest(repo)
    old_managed = manifest.get("managed_files", {}) or {}
    managed: dict[str, dict[str, str]] = {}
    applied_actions: list[dict[str, Any]] = []
    action_by_path = {item["path"]: item for item in plan_result["actions"]}

    for relative, (data, source) in sorted(desired.items()):
        action_record = action_by_path[relative]
        action = action_record["action"]
        target = _assert_safe_target(repo, relative)
        if action in {"CREATE", "UPDATE"}:
            atomic_write(target, data)
            applied_actions.append({"action": action, "path": relative})
            managed[relative] = {"sha256": sha256_bytes(data), "source": source}
        elif action == "NOOP":
            managed[relative] = {"sha256": sha256_file(target), "source": source}
        elif action == "PRESERVE_CONFLICT":
            candidate = _assert_safe_target(repo, str(action_record["candidate_path"]))
            atomic_write(candidate, data)
            applied_actions.append({"action": "WRITE_CANDIDATE", "path": candidate.relative_to(repo).as_posix()})
            if relative in old_managed:
                managed[relative] = old_managed[relative]
        elif action == "PRESERVE_CONFLICT_NOOP":
            # The desired candidate already exists byte-for-byte; preserve it and
            # avoid creating numbered duplicates on repeated updates.
            if relative in old_managed:
                managed[relative] = old_managed[relative]

    for relative, record in sorted(old_managed.items()):
        if relative in desired:
            continue
        target = _assert_safe_target(repo, relative)
        if target.exists() and target.is_file() and sha256_file(target) == record.get("sha256"):
            target.unlink()
            applied_actions.append({"action": "REMOVE_STALE", "path": relative})
        elif target.exists():
            managed[relative] = record

    agents_action = action_by_path["AGENTS.md"]
    agents_path = _assert_safe_target(repo, "AGENTS.md")
    existing = agents_path.read_text(encoding="utf-8") if agents_path.exists() else ""
    desired_block = _managed_agents_block()
    if agents_action["action"] in {"MERGE", "UPDATE_BLOCK"}:
        atomic_write(agents_path, _replace_agents_block(existing, desired_block).encode("utf-8"))
        applied_actions.append({"action": agents_action["action"], "path": "AGENTS.md"})
    elif agents_action["action"] == "PRESERVE_AGENTS_CONFLICT":
        candidate = _assert_safe_target(repo, str(agents_action["candidate_path"]))
        atomic_write(candidate, (desired_block + "\n").encode("utf-8"))
        applied_actions.append({"action": "WRITE_CANDIDATE", "path": candidate.relative_to(repo).as_posix()})
    elif agents_action["action"] == "PRESERVE_AGENTS_CONFLICT_NOOP":
        # Identical proposal already exists; do not create another candidate.
        pass

    now = utc_now()
    new_manifest = {
        "schema_version": 1,
        "product": "zero-trust-agentic-delivery",
        "plugin_version": _plugin_version(),
        "installed_at": manifest.get("installed_at") or now,
        "last_updated_at": now,
        "settings": {"activate_ci": activate_ci, "install_repo_skills": install_repo_skills},
        "managed_files": managed,
        "agents_managed_block_hash": sha256_bytes(desired_block.encode("utf-8")),
        "remote_enforcement_verified": False,
    }
    manifest_path = _assert_safe_target(repo, MANIFEST_REL.as_posix())
    existing_manifest_text = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else None
    if not applied_actions and existing_manifest_text is not None:
        # Preserve byte-for-byte idempotence when nothing changed.
        return {
            **plan_result,
            "applied": True,
            "idempotent_noop": True,
            "applied_actions": [],
            "installation_manifest": str(manifest_path),
        }
    atomic_write(manifest_path, (json.dumps(new_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return {
        **plan_result,
        "applied": True,
        "idempotent_noop": False,
        "applied_actions": applied_actions,
        "installation_manifest": str(manifest_path),
    }


def uninstall(repo_path: Path | str) -> dict[str, Any]:
    repo = Path(repo_path).resolve()
    manifest = _load_manifest(repo)
    managed = manifest.get("managed_files", {}) or {}
    removed: list[str] = []
    preserved: list[str] = []
    remaining: dict[str, Any] = {}

    for relative, record in sorted(managed.items()):
        target = _assert_safe_target(repo, relative)
        if not target.exists():
            continue
        if target.is_file() and sha256_file(target) == record.get("sha256"):
            target.unlink()
            removed.append(relative)
        else:
            preserved.append(relative)
            remaining[relative] = record

    agents_path = _assert_safe_target(repo, "AGENTS.md")
    agents_preserved = False
    if agents_path.exists() and agents_path.is_file():
        existing = agents_path.read_text(encoding="utf-8")
        block = _extract_agents_block(existing)
        if block is not None:
            current_hash = sha256_bytes(block.encode("utf-8"))
            if current_hash == manifest.get("agents_managed_block_hash"):
                updated = _remove_agents_block(existing)
                if updated:
                    atomic_write(agents_path, updated.encode("utf-8"))
                else:
                    agents_path.unlink()
                removed.append("AGENTS.md managed block")
            else:
                agents_preserved = True
                preserved.append("AGENTS.md managed block")

    manifest_path = repo / MANIFEST_REL
    if remaining or agents_preserved:
        updated_manifest = dict(manifest)
        updated_manifest["managed_files"] = remaining
        updated_manifest["partial_uninstall_at"] = utc_now()
        atomic_write(manifest_path, (json.dumps(updated_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        complete = False
    else:
        if manifest_path.exists():
            manifest_path.unlink()
            removed.append(MANIFEST_REL.as_posix())
        complete = True

    # Remove empty managed directories only; never recurse through user content.
    candidates = [repo / ".agents/skills", repo / ".agents", repo / MANAGED_ROOT / "bin", repo / MANAGED_ROOT, repo / ".delivery"]
    for directory in sorted(candidates, key=lambda item: len(item.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass
    return {
        "uninstalled": complete,
        "partial": not complete,
        "removed": removed,
        "preserved_modified": preserved,
        "installation_manifest_retained": not complete,
    }
