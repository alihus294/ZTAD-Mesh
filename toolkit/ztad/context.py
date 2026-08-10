from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from .repository import GitRepository
from .risk import RISK_ORDER
from .util import sha256_bytes, sha256_json, utc_now, unique_preserve_order


SECRET_PATTERNS = (
    re.compile(r"(^|/)\.env(?:\.|$)", re.IGNORECASE),
    re.compile(r"\.(?:pem|key|p12|pfx|jks)$", re.IGNORECASE),
    re.compile(r"(^|/)(?:credentials?|secrets?)(?:\.|/|$)", re.IGNORECASE),
    re.compile(r"(^|/)id_(?:rsa|ed25519)(?:\.|$)", re.IGNORECASE),
)

SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php"}


def is_secret_path(path: str) -> bool:
    return any(pattern.search(path) for pattern in SECRET_PATTERNS)


def _resolve_relative_import(source_path: str, import_path: str, known_paths: set[str]) -> list[str]:
    source = PurePosixPath(source_path)
    if import_path.startswith("."):
        base = source.parent
        raw = import_path
        while raw.startswith("../"):
            base = base.parent
            raw = raw[3:]
        raw = raw.removeprefix("./")
        candidate = (base / raw).as_posix()
    else:
        candidate = import_path
    variants = [candidate]
    for extension in (".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs"):
        variants.append(candidate + extension)
    variants.extend((PurePosixPath(candidate) / name).as_posix() for name in ("index.ts", "index.tsx", "index.js", "__init__.py"))
    return [variant for variant in variants if variant in known_paths]


def _extract_imports(path: str, text: str, known_paths: set[str]) -> list[str]:
    imports: list[str] = []
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        patterns = [
            r"(?:import|export)\s+(?:[^'\"]+?\s+from\s+)?['\"]([^'\"]+)['\"]",
            r"require\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"import\(\s*['\"]([^'\"]+)['\"]\s*\)",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, text):
                imports.extend(_resolve_relative_import(path, match, known_paths))
    elif suffix == ".py":
        for module in re.findall(r"^\s*from\s+([.\w]+)\s+import|^\s*import\s+([.\w]+)", text, re.MULTILINE):
            raw = next((item for item in module if item), "")
            if not raw:
                continue
            candidate = raw.replace(".", "/") + ".py"
            if candidate in known_paths:
                imports.append(candidate)
    return unique_preserve_order(imports)


def _test_candidates(path: str, known_paths: set[str]) -> list[str]:
    source = PurePosixPath(path)
    stem = source.stem
    candidates = []
    for known in known_paths:
        lower = known.lower()
        if any(token in lower for token in ("/test", "/tests/", "/spec", "__tests__")) and stem.lower() in PurePosixPath(known).stem.lower():
            candidates.append(known)
    return sorted(candidates)[:10]


def build_context_manifest(
    repo: GitRepository,
    base: str,
    head: str,
    risk: str,
    *,
    contract_hash: str,
    policy_hash: str,
    max_files_by_risk: dict[str, int] | None = None,
    use_repository_index: bool = True,
    max_index_files: int = 5000,
) -> dict[str, Any]:
    base_sha = repo.rev_parse(base)
    head_sha = repo.rev_parse(head)
    changed = repo.changed_paths(base_sha, head_sha)
    modes = repo.ls_tree_modes(head_sha)
    known_paths = set(modes)
    limits = max_files_by_risk or {"R0": 5, "R1": 10, "R2": 20, "R3": 60, "R4": 120}
    max_files = limits.get(risk, 20)

    include_reasons: dict[str, list[str]] = {}
    gaps: list[str] = []
    excluded: list[dict[str, str]] = []

    def add(path: str, reason: str) -> None:
        if is_secret_path(path):
            excluded.append({"path": path, "reason": "secret_or_credential_pattern"})
            return
        if path not in known_paths:
            return
        include_reasons.setdefault(path, []).append(reason)

    for item in changed:
        if not item.status.startswith("D"):
            add(item.path, "changed")
        if item.old_path:
            add(item.old_path, "rename_source")

    always = ["AGENTS.md", ".github/CODEOWNERS", ".delivery/service-map.yaml", ".delivery/test-map.yaml"]
    for path in always:
        if path in known_paths:
            add(path, "governance_or_mapping")

    repository_index = None
    index_hash = None
    if use_repository_index:
        # Local import avoids a module-import cycle: repository_index reuses
        # is_secret_path from this module. The index supplies reverse callers,
        # transitive dependencies, runtime/config signals and dynamic-gap flags.
        from .repository_index import build_repository_index

        repository_index = build_repository_index(
            repo, head_sha, max_files=max_index_files
        )
        index_hash = repository_index.index_hash
        depth = 2 if risk in {"R0", "R1", "R2"} else 3
        related_limit = max(max_files * 4, 50)
        for item in repository_index.related_files(
            [entry.path for entry in changed if not entry.status.startswith("D")],
            depth=depth,
            max_files=related_limit,
        ):
            path = str(item["path"])
            reasons = item.get("reasons", [])
            for reason in reasons:
                mapped = {
                    "seed": "index_seed",
                    "dependency": "transitive_dependency",
                    "reverse_dependency": "reverse_dependency",
                    "name_related_test": "index_related_test",
                }.get(str(reason), f"index_{reason}")
                add(path, mapped)
        for category in (
            "runtime_config", "database", "authorization", "database_triggers",
            "api_routes", "api_clients", "event_producers", "event_consumers",
            "feature_flags", "background_jobs",
        ):
            for path in repository_index.signals.get(category, ()):
                # Include high-impact cross-cutting files only when the change
                # already touches the same subsystem or risk is high. This keeps
                # low-risk context bounded while preventing silent omission in R3/R4.
                changed_roots = {PurePosixPath(item.path).parts[0].casefold() for item in changed if item.path}
                path_root = PurePosixPath(path).parts[0].casefold() if PurePosixPath(path).parts else ""
                if risk in {"R3", "R4"} or path_root in changed_roots:
                    add(path, f"repository_signal_{category}")
        for gap in repository_index.dynamic_gaps:
            if gap.get("path") in include_reasons:
                gaps.append(
                    f"Static index gap in {gap.get('path')}: {gap.get('reason')}; "
                    "targeted scout or runtime evidence is required"
                )

    initial = list(include_reasons)
    for path in initial:
        if PurePosixPath(path).suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            text = repo.show_text(head_sha, path)
        except Exception:
            continue
        for imported in _extract_imports(path, text, known_paths):
            add(imported, "direct_import")
        for test_path in _test_candidates(path, known_paths):
            add(test_path, "related_test")
        if re.search(r"import\s*\(|__import__|reflection|Class\.forName|plugin\s*loader", text, re.IGNORECASE):
            gaps.append(f"Dynamic loading or reflection detected in {path}; static graph may be incomplete")

    priority = {
        "changed": 0, "rename_source": 1, "index_seed": 1,
        "governance_or_mapping": 2, "reverse_dependency": 3,
        "transitive_dependency": 4, "direct_import": 4,
        "index_related_test": 5, "related_test": 5,
    }
    ordered = sorted(
        include_reasons,
        key=lambda path: (min(priority.get(reason, 99) for reason in include_reasons[path]), path),
    )
    if len(ordered) > max_files:
        for path in ordered[max_files:]:
            excluded.append({"path": path, "reason": f"context_limit_{max_files}"})
        gaps.append(f"Context truncated from {len(ordered)} to {max_files} files; split or escalate if omitted files are material")
        ordered = ordered[:max_files]

    included: list[dict[str, Any]] = []
    for path in ordered:
        content = repo.show_bytes(head_sha, path)
        included.append(
            {
                "path": path,
                "hash": sha256_bytes(content),
                "reason": sorted(set(include_reasons[path])),
                "trust_label": "REPOSITORY_DATA",
            }
        )

    sufficiency = None
    if repository_index is not None:
        from .repository_index import assess_context_sufficiency

        sufficiency = assess_context_sufficiency(
            repository_index,
            changed_paths=[item.path for item in changed if not item.status.startswith("D")],
            included_paths=[item["path"] for item in included],
            risk=risk,
        )
        if not sufficiency["sufficient"]:
            gaps.append(
                "Context sufficiency gate failed: " + ", ".join(sufficiency["errors"])
            )

    manifest = {
        "schema_version": 1,
        "context_id": "pending",
        "repository": str(repo.root),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "risk": risk,
        "change_contract_hash": contract_hash,
        "policy_hash": policy_hash,
        "generated_at": utc_now(),
        "included": included,
        "excluded": sorted(excluded, key=lambda item: item["path"]),
        "known_gaps": sorted(set(gaps)),
        "repository_index_hash": index_hash,
        "context_sufficiency": sufficiency,
        "requested_action": "CONTINUE" if not sufficiency or sufficiency.get("sufficient") else "REQUEST_CONTEXT_EXPANSION",
        "claim_boundary": "Static context is risk-bounded; runtime reflection and external systems still require targeted evidence.",
    }
    manifest["context_id"] = sha256_json({key: value for key, value in manifest.items() if key not in {"context_id", "generated_at"}})
    return manifest
