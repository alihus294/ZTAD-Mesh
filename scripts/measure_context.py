#!/usr/bin/env python3
"""Measure the static context footprint of the skill suite without loading references."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def measure(path: Path) -> dict[str, int | str]:
    text = path.read_text(encoding="utf-8")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes_utf8": len(text.encode("utf-8")),
        "characters": len(text),
        "words": len(re.findall(r"\S+", text)),
        "lines": len(text.splitlines()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "validation/context-footprint.json"))
    parser.add_argument("--max-skill-words", type=int, default=1800)
    args = parser.parse_args()

    skills = [measure(path) for path in sorted((ROOT / "skills").glob("*/SKILL.md"))]
    references = [measure(path) for path in sorted((ROOT / "references").glob("*.md"))]
    violations = [item["path"] for item in skills if int(item["words"]) > args.max_skill_words]
    report = {
        "schema_version": 1,
        "measurement": "exact UTF-8 bytes, Unicode characters, whitespace-delimited words, and lines; not provider token billing",
        "normal_operation_scope": "Only the explicitly invoked SKILL.md and task-selected artifacts are expected to load. references/MASTER_PLAN.md remains separate.",
        "max_skill_words": args.max_skill_words,
        "skill_count": len(skills),
        "skill_totals": {
            "bytes_utf8": sum(int(item["bytes_utf8"]) for item in skills),
            "words": sum(int(item["words"]) for item in skills),
            "lines": sum(int(item["lines"]) for item in skills),
        },
        "skills": skills,
        "references": references,
        "violations": violations,
        "passed": not violations,
        "claim_boundary": "Hosted-model input/output tokens and cache behavior must be measured in the target runtime; this report is a deterministic static footprint only.",
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
