from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .repository import GitRepository
from .util import load_data

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "test-integrity-policy.yaml"


@dataclass(frozen=True)
class IntegrityFinding:
    code: str
    severity: str
    path: str | None
    line: str
    message: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "line": self.line[:300],
            "message": self.message,
        }


TEST_ADDED_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("SKIP_ADDED", r"\b(?:it|test|describe)\.(?:skip|todo)\b|\b(?:xit|xdescribe)\b|@pytest\.mark\.(?:skip|skipif)\b|@unittest\.(?:skip|skipIf|skipUnless)\b|pytest\.param\([^\n]*marks\s*=\s*pytest\.mark\.(?:skip|skipif)", "A test skip or todo marker was added."),
    ("FOCUS_ADDED", r"\b(?:it|test|describe)\.only\b|\bfit\b|\bfdescribe\b", "A focused-test marker was added and can exclude the rest of the suite."),
    ("XFAIL_ADDED", r"@pytest\.mark\.xfail\b|\bpytest\.xfail\b", "An expected-failure marker was added."),
    ("TEST_RETRY_ADDED", r"(?:retries|retry|reruns)\s*[:=]\s*[1-9]", "A retry was added and may hide flakiness."),
    ("ALLOW_NO_TESTS_ADDED", r"--passWithNoTests\b|allowNoTests\s*[:=]\s*true", "A no-tests success path was added."),
    ("EXCEPTION_SWALLOWED", r"except\s+(?:Exception|BaseException)?\s*:\s*(?:pass|return\s+None)|catch\s*\([^)]*\)\s*\{\s*\}", "A broad exception is swallowed in test code."),
)
CI_ADDED_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("CI_CONTINUE_ON_ERROR", r"continue-on-error\s*:\s*true", "A CI step was made non-blocking."),
    ("CI_STEP_DISABLED", r"\bif\s*:\s*(?:false|\$\{\{\s*false\s*\}\})\b", "A CI step or job was unconditionally disabled."),
    ("SHELL_FAILURE_MASKED", r"\|\|\s*true\b|;\s*exit\s+0\b|\|\|\s*echo\b", "A command failure may be masked."),
)
REMOVED_ASSERTION_PATTERN = re.compile(r"\bassert\b|\bexpect\s*\(|\bshould\b|assert[A-Z]\w*\s*\(")
TEST_PATH_PATTERN = re.compile(r"(^|/)(tests?|spec|__tests__)(/|$)|(?:^|[._-])(test|spec)\.", re.IGNORECASE)
CI_PATH_PATTERN = re.compile(r"(^|/)(\.github/workflows|\.gitlab|ci|scripts/(?:ci|test))(/|$)|(?:^|/)(?:Jenkinsfile|azure-pipelines\.yml)$", re.IGNORECASE)
TEST_CONFIG_PATTERN = re.compile(
    r"(^|/)(pytest\.ini|tox\.ini|setup\.cfg|pyproject\.toml|package\.json|jest\.config\.[^/]+|vitest\.config\.[^/]+|playwright\.config\.[^/]+|\.github/workflows/[^/]+\.ya?ml)$",
    re.IGNORECASE,
)
COVERAGE_PATTERN = re.compile(r"coverageThreshold|fail-under|minimum_coverage|coverage\s*[:=]", re.IGNORECASE)
DISCOVERY_WEAKENING = re.compile(
    r"--ignore(?:-glob)?\b|testpaths\s*=|python_files\s*=|testMatch\s*[:=]|testRegex\s*[:=]|exclude\s*[:=]|include\s*[:=]|--passWithNoTests\b|--runInBand\b",
    re.IGNORECASE,
)
SCRIPT_SUCCESS_MASK = re.compile(r'"(?:test|lint|check)[^"]*"\s*:\s*"(?:echo\s+[^";]*(?:success|ok)|exit\s+0|true)"', re.IGNORECASE)


def _path_for_diff_line(current_path: str | None, line: str) -> str | None:
    if line.startswith("+++ b/"):
        return line[6:].split("\t", 1)[0]
    return current_path


def _effective_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    if policy is not None:
        return policy
    loaded = load_data(DEFAULT_POLICY_PATH)
    if not isinstance(loaded, dict):
        raise ValueError("Test-integrity policy must be a mapping")
    return loaded


def _apply_policy(findings: Iterable[IntegrityFinding], policy: dict[str, Any]) -> list[IntegrityFinding]:
    configured = policy.get("enabled_finding_codes")
    enabled = {str(item) for item in configured} if isinstance(configured, list) else None
    severity_map = policy.get("severity_by_code", {})
    if not isinstance(severity_map, dict):
        raise ValueError("severity_by_code must be a mapping")
    result: list[IntegrityFinding] = []
    for item in findings:
        if enabled is not None and item.code not in enabled:
            continue
        severity = str(severity_map.get(item.code, item.severity)).upper()
        if severity not in {"BLOCK", "ESCALATE", "ADVISORY"}:
            raise ValueError(f"Invalid severity for {item.code}: {severity}")
        result.append(IntegrityFinding(item.code, severity, item.path, item.line, item.message))
    return result


def detect_test_weakening_from_diff(diff_text: str, policy: dict[str, Any] | None = None) -> list[IntegrityFinding]:
    policy = _effective_policy(policy)
    findings: list[IntegrityFinding] = []
    current_path: str | None = None
    snapshot_additions = 0
    snapshot_deletions = 0
    for line in diff_text.splitlines():
        current_path = _path_for_diff_line(current_path, line)
        is_test = bool(current_path and TEST_PATH_PATTERN.search(current_path))
        is_ci = bool(current_path and CI_PATH_PATTERN.search(current_path))
        is_config = bool(current_path and TEST_CONFIG_PATTERN.search(current_path))
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            if is_test:
                for code, pattern, message in TEST_ADDED_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(IntegrityFinding(code, "BLOCK", current_path, content, message))
            if is_ci:
                for code, pattern, message in CI_ADDED_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(IntegrityFinding(code, "BLOCK", current_path, content, message))
            if is_config and DISCOVERY_WEAKENING.search(content):
                findings.append(IntegrityFinding("TEST_DISCOVERY_CHANGED", "BLOCK", current_path, content, "Test discovery or exclusion configuration changed."))
            if current_path and current_path.casefold().endswith("package.json") and SCRIPT_SUCCESS_MASK.search(content):
                findings.append(IntegrityFinding("TEST_SCRIPT_MASKED", "BLOCK", current_path, content, "A package test/check script was replaced with unconditional success."))
            if current_path and current_path.endswith((".snap", ".snapshot")):
                snapshot_additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            content = line[1:]
            if is_test and REMOVED_ASSERTION_PATTERN.search(content):
                findings.append(IntegrityFinding("ASSERTION_REMOVED", "BLOCK", current_path, content, "An assertion was removed from a test file."))
            if (is_test or is_ci or is_config) and COVERAGE_PATTERN.search(content):
                findings.append(IntegrityFinding("COVERAGE_CONTROL_REMOVED", "BLOCK", current_path, content, "A coverage control or threshold line was removed."))
            if current_path and current_path.endswith((".snap", ".snapshot")):
                snapshot_deletions += 1
    if snapshot_additions + snapshot_deletions > 200:
        findings.append(IntegrityFinding(
            "BROAD_SNAPSHOT_UPDATE", "ESCALATE", None,
            f"{snapshot_additions} additions / {snapshot_deletions} deletions",
            "A broad snapshot update requires independent review and protected acceptance evidence.",
        ))
    # Stable, deterministic de-duplication.
    unique: dict[tuple[str, str | None, str], IntegrityFinding] = {}
    for item in findings:
        unique[(item.code, item.path, item.line)] = item
    return _apply_policy(unique.values(), policy)


def detect_deleted_or_moved_tests(changed: Iterable[Any]) -> list[IntegrityFinding]:
    findings: list[IntegrityFinding] = []
    for item in changed:
        path = item.path
        old_path = getattr(item, "old_path", None)
        if item.status.startswith("D") and TEST_PATH_PATTERN.search(path):
            findings.append(IntegrityFinding("TEST_FILE_DELETED", "BLOCK", path, "", "A test file was deleted."))
        if item.status.startswith("R") and old_path and TEST_PATH_PATTERN.search(old_path) and not TEST_PATH_PATTERN.search(path):
            findings.append(IntegrityFinding("TEST_MOVED_OUT_OF_DISCOVERY", "BLOCK", path, old_path, "A test was moved outside recognized test discovery locations."))
    return findings


def _count_test_symbols(text: str) -> int:
    patterns = (
        r"(?m)^\s*def\s+test_[A-Za-z0-9_]+\s*\(",
        r"(?m)^\s*(?:async\s+)?function\s+test[A-Za-z0-9_]*\s*\(",
        r"\b(?:it|test)\s*\(",
        r"\[Test\]",
    )
    return sum(len(re.findall(pattern, text)) for pattern in patterns)


def inspect_repository_test_integrity(
    repo: GitRepository,
    base: str,
    head: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = _effective_policy(policy)
    diff_text = repo.diff(base, head, unified=2)
    findings = detect_test_weakening_from_diff(diff_text, policy)
    changed = repo.changed_paths(base, head)
    findings.extend(detect_deleted_or_moved_tests(changed))
    # Detect silent loss of test cases even when a file remains present.
    for item in changed:
        candidates = [item.path]
        if item.old_path:
            candidates.append(item.old_path)
        if not any(TEST_PATH_PATTERN.search(path) for path in candidates):
            continue
        try:
            before = repo.show_text(base, item.old_path or item.path)
        except Exception:
            before = ""
        try:
            after = repo.show_text(head, item.path)
        except Exception:
            after = ""
        before_count = _count_test_symbols(before)
        after_count = _count_test_symbols(after)
        if before_count > after_count:
            findings.append(IntegrityFinding(
                "TEST_CASE_COUNT_DECREASED", "BLOCK", item.path,
                f"before={before_count}, after={after_count}",
                "The number of recognized test cases decreased.",
            ))
    unique: dict[tuple[str, str | None, str], IntegrityFinding] = {}
    for item in findings:
        unique[(item.code, item.path, item.line)] = item
    final = _apply_policy(unique.values(), policy)
    return {
        "blocked": any(item.severity == "BLOCK" for item in final),
        "requires_escalation": any(item.severity == "ESCALATE" for item in final),
        "findings": [item.to_dict() for item in final],
        "claim_boundary": "Static diff and test-symbol checks cannot prove semantic test adequacy; protected black-box tests remain required for high-risk changes.",
    }
