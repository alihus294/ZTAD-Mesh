#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "references/MASTER_PLAN.md"
OUT_DIR = ROOT / "traceability"
NORM = re.compile(r"\b(MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|MAY(?:\s+NOT)?)\b", re.IGNORECASE)
SECTION = re.compile(r"^##\s+(\d+)\.\s+(.+)$")

SECTION_MAP: dict[int, tuple[str, str, str]] = {
    1: ("DOCUMENTED_BOUNDARY", "README.md; docs/LIMITATIONS.md", "claim-boundary review"),
    2: ("DETERMINISTIC", "toolkit/ztad/; policies/; hooks/; tests/", "unit, adversarial, and selected mutation tests"),
    3: ("DETERMINISTIC", "schemas/evidence*.json; toolkit/ztad/evidence.py; toolkit/ztad/approval_controller.py", "evidence trust and subject-binding tests"),
    4: ("CAPABILITY_GATED", "toolkit/ztad/host_acceptance.py; docs/CAPABILITY_MATRIX.md", "target-host acceptance"),
    5: ("DETERMINISTIC", "schemas/change-contract.schema.json; toolkit/ztad/scope_guard.py", "contract and scope tests"),
    6: ("DETERMINISTIC", "policies/risk-policy.yaml; toolkit/ztad/risk.py", "contract/path/actual-diff risk tests"),
    7: ("DETERMINISTIC", "toolkit/ztad/repository_index.py; toolkit/ztad/context.py", "repository-index and context tests"),
    8: ("HOST_AND_DETERMINISTIC", "policies/model-catalog.yaml; toolkit/ztad/model_router.py; toolkit/ztad/model_benchmark.py; toolkit/ztad/providers.py", "routing, provider, benchmark, and host tests"),
    9: ("DETERMINISTIC", "toolkit/ztad/mesh_plan.py; toolkit/ztad/mesh_store.py", "DAG width and scope-lock tests"),
    10: ("DETERMINISTIC", "toolkit/ztad/mesh_store.py; toolkit/ztad/mesh_runtime.py", "transaction, lease, artifact, and recovery tests"),
    11: ("DETERMINISTIC", "toolkit/ztad/mesh_plan.py; schemas/mesh-plan.schema.json", "plan generation and dependency tests"),
    12: ("HOST_AND_DETERMINISTIC", "toolkit/ztad/providers.py; policies/provider-policy.yaml", "provider isolation, replay, and structured-output tests"),
    13: ("DETERMINISTIC", "toolkit/ztad/worktrees.py; toolkit/ztad/patch_broker.py; toolkit/ztad/scope_guard.py", "worktree, patch, and scope tests"),
    14: ("DETERMINISTIC_AND_PLATFORM", "toolkit/ztad/checks.py; toolkit/ztad/test_weakening.py; policies/risk-policy.yaml", "machine-check and protected-CI tests"),
    15: ("DETERMINISTIC", "toolkit/ztad/findings.py; skills/independent-review", "finding and adversarial review tests"),
    16: ("PROTECTED_CONTROLLER", "toolkit/ztad/mesh_runtime.py; toolkit/ztad/approval_controller.py", "takeover and closure-separation tests"),
    17: ("PROTECTED_CONTROLLER", "toolkit/ztad/approval_controller.py; toolkit/ztad/orchestrator.py", "stored-run/SHA/diff/evidence approval tests"),
    18: ("DETERMINISTIC", "toolkit/ztad/loop_guard.py; toolkit/ztad/mesh_store.py", "attempt fingerprint and no-progress tests"),
    19: ("DETERMINISTIC_AND_HOST", "toolkit/ztad/mesh_store.py; toolkit/ztad/autopilot.py; toolkit/ztad/scheduler.py", "service, retry, quarantine, and restart-boundary tests"),
    20: ("POLICY_AND_PLATFORM", "policies/database-policy.yaml; toolkit/ztad/risk.py; docs/RUNBOOKS.md", "migration and destructive-change tests"),
    21: ("PLATFORM_REQUIRED", "toolkit/ztad/github_adapter.py; toolkit/ztad/platform.py; toolkit/ztad/progressive_delivery.py", "target Git/CI/artifact/deployment acceptance"),
    22: ("HOST_ENFORCED", "hooks/hooks.json; toolkit/ztad/hooks.py; scripts/ztad_hook.py", "hook tests and Codex host acceptance"),
    23: ("DETERMINISTIC", "policies/budget-policy.yaml; toolkit/ztad/budget.py; toolkit/ztad/model_router.py", "budget and parallelism tests"),
    24: ("DETERMINISTIC_AND_EXTERNAL", "tests/; evals/; validation/; toolkit/ztad/distribution.py", "source/extracted tests, fuzz, concurrency, mutation, and reproducibility"),
    25: ("CAPABILITY_GATED", "docs/CAPABILITY_MATRIX.md; docs/LIMITATIONS.md; toolkit/ztad/host_acceptance.py", "release-status and target-host review"),
    26: ("CONTROL_SPECIFIC", "toolkit/ztad/; policies/; hooks/; tests/; docs/GITHUB_ENFORCEMENT.md", "requirement-specific local tests and target-platform evidence"),
}


def normalize(text: str) -> str:
    text = re.sub(r"^\s*(?:[-*+]\s+|\d+\.\s+)", "", text.strip())
    return re.sub(r"\s+", " ", text)


def main() -> int:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    section_num = 0
    section_title = "Document Control"
    rows: list[dict[str, str]] = []
    for number, line in enumerate(lines, 1):
        match = SECTION.match(line)
        if match:
            section_num = int(match.group(1))
            section_title = match.group(2).strip()
        norm = NORM.search(line)
        if not norm:
            continue
        requirement = normalize(line)
        if not requirement:
            continue
        enforcement, artifacts, verification = SECTION_MAP.get(
            section_num,
            ("DOCUMENTED_AND_TESTED", "references/MASTER_PLAN.md", "source review and targeted tests"),
        )
        rows.append({
            "requirement_id": f"ACD-{len(rows)+1:04d}",
            "source_line": str(number),
            "section": f"{section_num}. {section_title}",
            "normative_level": norm.group(1).upper().replace("  ", " "),
            "requirement": requirement,
            "enforcement_class": enforcement,
            "implementing_artifacts": artifacts,
            "verification": verification,
        })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = ["requirement_id", "source_line", "section", "normative_level", "requirement", "enforcement_class", "implementing_artifacts", "verification"]
    with (OUT_DIR / "requirements.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    by_class = Counter(row["enforcement_class"] for row in rows)
    by_section = Counter(row["section"] for row in rows)
    md = [
        "# ZTAD Mesh 4.2.0 Traceability Matrix", "",
        f"Active normative requirements: **{len(rows)}**.", "",
        "This matrix maps active 4.2.0 requirements to implementation and verification. External controls are not considered active until target-platform evidence verifies them.", "",
        "## Coverage by enforcement class", "", "| Class | Count |", "|---|---:|",
    ]
    md.extend(f"| {name} | {count} |" for name, count in sorted(by_class.items()))
    md += ["", "## Coverage by section", "", "| Section | Requirements |", "|---|---:|"]
    for section, count in sorted(by_section.items(), key=lambda item: int(item[0].split('.', 1)[0])):
        md.append(f"| {section} | {count} |")
    md += [
        "", "## Interpretation", "",
        "- `DETERMINISTIC`: enforced by local/protected code and tests.",
        "- `PROTECTED_CONTROLLER`: requires a protected non-model controller and private-key boundary.",
        "- `HOST_ENFORCED` / `HOST_ACCEPTANCE`: requires verified Codex host behavior.",
        "- `PLATFORM_REQUIRED`: requires verified source-control, CI, artifact, deployment, or runtime enforcement.",
        "- `CAPABILITY_GATED`: autonomy is capped until the capability is independently verified.",
        "- `OPERATIONAL` / `DOCUMENTED_*`: governed by runbook, architecture, or scenario testing.",
        "", "The row-level source of truth is `requirements.csv`.",
    ]
    (OUT_DIR / "TRACEABILITY_MATRIX.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"generated {len(rows)} active requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
