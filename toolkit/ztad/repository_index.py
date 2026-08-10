from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable

from .context import is_secret_path
from .repository import GitRepository
from .util import sha256_json, utc_now

TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt",
    ".cs", ".rb", ".php", ".sql", ".yaml", ".yml", ".json", ".toml", ".ini", ".md",
}
TEST_MARKERS = ("/test/", "/tests/", "__tests__", ".test.", ".spec.", "test_", "_test.")
CONFIG_MARKERS = (".github/", "deploy/", "infra/", "docker", "helm/", "k8s/", "terraform", "pyproject.toml", "package.json")


def _resolve_js_import(source: str, imported: str, known: set[str]) -> list[str]:
    if not imported.startswith("."):
        return []
    base = PurePosixPath(source).parent
    candidate = (base / imported).as_posix()
    variants = [candidate]
    for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"):
        variants.append(candidate + ext)
    variants.extend((PurePosixPath(candidate) / name).as_posix() for name in ("index.ts", "index.tsx", "index.js"))
    return [item for item in variants if item in known]


def _resolve_python_import(source: str, module: str, level: int, known: set[str]) -> list[str]:
    base = PurePosixPath(source).parent
    if level:
        for _ in range(max(0, level - 1)):
            base = base.parent
        candidate = (base / module.replace(".", "/")).as_posix() if module else base.as_posix()
    else:
        candidate = module.replace(".", "/")
    variants = [candidate + ".py", (PurePosixPath(candidate) / "__init__.py").as_posix()]
    return [item for item in variants if item in known]


def _extract_edges(path: str, text: str, known: set[str]) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    dynamic: set[str] = set()
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        for match in re.findall(r"(?:import|export)\s+(?:[^'\"]+?\s+from\s+)?['\"]([^'\"]+)['\"]", text):
            imports.update(_resolve_js_import(path, match, known))
        for match in re.findall(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", text):
            imports.update(_resolve_js_import(path, match, known))
        if re.search(r"import\(\s*[^'\"]|require\(\s*[^'\"]", text):
            dynamic.add("dynamic_import")
    elif suffix == ".py":
        for raw in re.findall(r"^\s*import\s+([\w.]+)", text, re.MULTILINE):
            imports.update(_resolve_python_import(path, raw, 0, known))
        for dots, module in re.findall(r"^\s*from\s+(\.*)([\w.]*)\s+import\s+", text, re.MULTILINE):
            imports.update(_resolve_python_import(path, module, len(dots), known))
        if "__import__(" in text or "importlib.import_module" in text:
            dynamic.add("dynamic_import")
    if re.search(r"reflection|Class\.forName|eval\(|exec\(|plugin[_ -]?loader", text, re.IGNORECASE):
        dynamic.add("reflection_or_runtime_loading")
    return imports, dynamic


def _extract_symbols(path: str, text: str) -> list[str]:
    suffix = PurePosixPath(path).suffix.casefold()
    patterns: list[str] = []
    if suffix == ".py":
        patterns = [r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", r"^\s*class\s+([A-Za-z_]\w*)"]
    elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        patterns = [r"\b(?:function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)", r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*="]
    elif suffix in {".go", ".rs", ".java", ".kt", ".cs"}:
        patterns = [r"\b(?:func|fn|class|interface|struct|enum)\s+([A-Za-z_]\w*)"]
    found: list[str] = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text, re.MULTILINE))
    return sorted(set(found))[:500]


def _classify_signals(path: str, text: str) -> dict[str, list[str]]:
    signals: dict[str, list[str]] = defaultdict(list)
    lower_path = path.casefold()
    if any(marker in lower_path for marker in TEST_MARKERS):
        signals["tests"].append(path)
    if any(marker in lower_path for marker in CONFIG_MARKERS):
        signals["runtime_config"].append(path)
    if PurePosixPath(path).suffix.casefold() == ".sql":
        signals["database"].append(path)
        if re.search(r"\b(?:policy|row\s+level\s+security|enable\s+rls|grant|revoke)\b", text, re.IGNORECASE):
            signals["authorization"].append(path)
        if re.search(r"\btrigger\b", text, re.IGNORECASE):
            signals["database_triggers"].append(path)
    if re.search(r"\b(?:route|router|app)\.(?:get|post|put|patch|delete)\s*\(", text, re.IGNORECASE) or re.search(r"@(get|post|put|patch|delete)\b", text, re.IGNORECASE):
        signals["api_routes"].append(path)
    if re.search(r"\b(?:fetch|axios|httpClient|requests\.|client\.(?:get|post|put|patch|delete))\b", text):
        signals["api_clients"].append(path)
    if re.search(r"\b(?:publish|emit|dispatch|sendMessage|enqueue|produce)\s*\(", text):
        signals["event_producers"].append(path)
    if re.search(r"\b(?:subscribe|on|consume|handler|dequeue)\s*\(", text):
        signals["event_consumers"].append(path)
    if re.search(r"\b(?:feature[_-]?flag|isEnabled|toggle|launchdarkly|unleash)\b", text, re.IGNORECASE):
        signals["feature_flags"].append(path)
    if re.search(r"\b(?:cron|schedule|celery|background[_ -]?job|queue)\b", text, re.IGNORECASE):
        signals["background_jobs"].append(path)
    return dict(signals)


@dataclass(frozen=True)
class RepositoryIndex:
    repository: str
    revision: str
    generated_at: str
    files: tuple[str, ...]
    imports: dict[str, tuple[str, ...]]
    reverse_imports: dict[str, tuple[str, ...]]
    symbols: dict[str, tuple[str, ...]]
    signals: dict[str, tuple[str, ...]]
    dynamic_gaps: tuple[dict[str, str], ...]
    skipped: tuple[dict[str, str], ...]
    index_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "revision": self.revision,
            "generated_at": self.generated_at,
            "files": list(self.files),
            "imports": {k: list(v) for k, v in self.imports.items()},
            "reverse_imports": {k: list(v) for k, v in self.reverse_imports.items()},
            "symbols": {k: list(v) for k, v in self.symbols.items()},
            "signals": {k: list(v) for k, v in self.signals.items()},
            "dynamic_gaps": list(self.dynamic_gaps),
            "skipped": list(self.skipped),
            "index_hash": self.index_hash,
            "claim_boundary": "The index is a deterministic static approximation; runtime reflection and external systems require explicit evidence.",
        }

    def related_files(self, seeds: Iterable[str], *, depth: int = 2, max_files: int = 200) -> list[dict[str, Any]]:
        queue = deque((path, 0) for path in seeds if path in set(self.files))
        reasons: dict[str, set[str]] = defaultdict(set)
        for path in seeds:
            if path in set(self.files):
                reasons[path].add("seed")
        while queue and len(reasons) < max_files:
            current, level = queue.popleft()
            if level >= depth:
                continue
            neighbours = [(item, "dependency") for item in self.imports.get(current, ())]
            neighbours += [(item, "reverse_dependency") for item in self.reverse_imports.get(current, ())]
            for path, reason in neighbours:
                first = path not in reasons
                reasons[path].add(reason)
                if first:
                    queue.append((path, level + 1))
            stem = PurePosixPath(current).stem.casefold()
            for test_path in self.signals.get("tests", ()):
                if stem and stem in PurePosixPath(test_path).stem.casefold():
                    reasons[test_path].add("name_related_test")
        ordered = sorted(reasons, key=lambda path: (0 if "seed" in reasons[path] else 1, path.casefold()))[:max_files]
        return [{"path": path, "reasons": sorted(reasons[path])} for path in ordered]


def build_repository_index(
    repo: GitRepository,
    revision: str = "HEAD",
    *,
    max_files: int = 5000,
    max_file_bytes: int = 1_000_000,
) -> RepositoryIndex:
    sha = repo.rev_parse(revision)
    modes = repo.ls_tree_modes(sha)
    all_paths = sorted(modes)
    known = set(all_paths)
    selected: list[str] = []
    skipped: list[dict[str, str]] = []
    for path in all_paths:
        if len(selected) >= max_files:
            skipped.append({"path": path, "reason": "max_files_exceeded"})
            continue
        if is_secret_path(path):
            skipped.append({"path": path, "reason": "secret_path"})
            continue
        if PurePosixPath(path).suffix.casefold() not in TEXT_EXTENSIONS:
            continue
        selected.append(path)
    imports: dict[str, tuple[str, ...]] = {}
    reverse: dict[str, set[str]] = defaultdict(set)
    symbols: dict[str, tuple[str, ...]] = {}
    signals: dict[str, set[str]] = defaultdict(set)
    gaps: list[dict[str, str]] = []
    for path in selected:
        try:
            raw = repo.show_bytes(sha, path)
        except Exception as exc:
            skipped.append({"path": path, "reason": f"read_failed:{type(exc).__name__}"})
            continue
        if len(raw) > max_file_bytes:
            skipped.append({"path": path, "reason": "file_too_large"})
            continue
        if b"\x00" in raw:
            skipped.append({"path": path, "reason": "binary_content"})
            continue
        text = raw.decode("utf-8", errors="replace")
        edges, dynamic = _extract_edges(path, text, known)
        imports[path] = tuple(sorted(edges))
        for target in edges:
            reverse[target].add(path)
        symbols[path] = tuple(_extract_symbols(path, text))
        for category, paths in _classify_signals(path, text).items():
            signals[category].update(paths)
        for gap in sorted(dynamic):
            gaps.append({"path": path, "reason": gap})
    material = {
        "repository": str(repo.root), "revision": sha, "files": selected,
        "imports": {k: list(v) for k, v in sorted(imports.items())},
        "reverse_imports": {k: sorted(v) for k, v in sorted(reverse.items())},
        "symbols": {k: list(v) for k, v in sorted(symbols.items())},
        "signals": {k: sorted(v) for k, v in sorted(signals.items())},
        "dynamic_gaps": gaps, "skipped": skipped,
    }
    return RepositoryIndex(
        repository=str(repo.root), revision=sha, generated_at=utc_now(), files=tuple(selected),
        imports=imports, reverse_imports={k: tuple(sorted(v)) for k, v in reverse.items()},
        symbols=symbols, signals={k: tuple(sorted(v)) for k, v in signals.items()},
        dynamic_gaps=tuple(gaps), skipped=tuple(skipped), index_hash=sha256_json(material),
    )


def assess_context_sufficiency(
    index: RepositoryIndex,
    *,
    changed_paths: Iterable[str],
    included_paths: Iterable[str],
    risk: str,
) -> dict[str, Any]:
    changed = {path for path in changed_paths}
    included = {path for path in included_paths}
    required = {item["path"] for item in index.related_files(changed, depth=2 if risk in {"R0", "R1", "R2"} else 3, max_files=500)}
    missing_changed = sorted(changed - included)
    missing_related = sorted(required - included)
    relevant_gaps = [item for item in index.dynamic_gaps if item["path"] in required or item["path"] in changed]
    errors: list[str] = []
    if missing_changed:
        errors.append("changed_files_missing")
    tolerance = {"R0": 0.45, "R1": 0.35, "R2": 0.25, "R3": 0.10, "R4": 0.0}.get(risk, 0.25)
    ratio = len(missing_related) / max(1, len(required))
    if ratio > tolerance:
        errors.append("related_context_below_risk_threshold")
    if risk in {"R3", "R4"} and relevant_gaps:
        errors.append("dynamic_runtime_gap_requires_targeted_scout_or_runtime_evidence")
    return {
        "sufficient": not errors,
        "risk": risk,
        "required_related_count": len(required),
        "included_count": len(included),
        "missing_changed": missing_changed,
        "missing_related": missing_related,
        "relevant_dynamic_gaps": relevant_gaps,
        "errors": errors,
        "requested_action": "CONTINUE" if not errors else "REQUEST_CONTEXT_EXPANSION",
        "claim_boundary": "Sufficiency is risk-bounded, not proof that every runtime coupling was discovered.",
    }
