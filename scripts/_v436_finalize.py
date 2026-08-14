from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8", newline="\n")


def provider_role_boundary() -> None:
    path = "toolkit/ztad/provider_contract.py"
    text = read(path)
    old = '''    if output is not None:
        errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
'''
    new = '''    if output is not None:
        # Test/orchestration role aliases are normalized only at the provider boundary.
        # The canonical model schema remains intentionally narrow and strict.
        from .agent_output import normalize_agent_role
        if "agent_role" in output:
            output = dict(output)
            output["agent_role"] = normalize_agent_role(output.get("agent_role"))
        errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
'''
    if "Test/orchestration role aliases are normalized only at the provider boundary" not in text:
        if old not in text:
            raise RuntimeError("provider contract schema-validation anchor changed")
        text = text.replace(old, new, 1)
    write(path, text)


def cli_autonomy() -> None:
    path = "toolkit/ztad/cli.py"
    text = read(path)
    problem_import = "from .problem import initialize_problem_case, validate_problem_case, advance_problem_case, problem_case_to_change_contract\n"
    if problem_import not in text:
        raise RuntimeError("base problem CLI import was not materialized")
    isolation_import = "from .problem_isolation import isolate_problem_case\n"
    if isolation_import not in text:
        text = text.replace(problem_import, problem_import + isolation_import, 1)

    if 'p.add_argument("--protected-ref", default="main")' not in text:
        old = '''    p = sub.add_parser("problem-init", help="Capture an unverified problem read-only")
    _repo_args(p)
    p.add_argument("--report", required=True)
    p.add_argument("--expected")
'''
        new = '''    p = sub.add_parser("problem-init", help="Capture an unverified problem read-only")
    _repo_args(p)
    p.add_argument("--report", required=True)
    p.add_argument("--expected")
    p.add_argument("--protected-ref", default="main")
'''
        if old not in text:
            raise RuntimeError("problem-init parser anchor changed")
        text = text.replace(old, new, 1)

    if 'sub.add_parser("problem-isolate"' not in text:
        anchor = '''    p = sub.add_parser("problem-validate", help="Validate a structured problem case")
    p.add_argument("--case", required=True)

'''
        addition = '''    p = sub.add_parser("problem-isolate", help="Create a managed clean worktree from the exact protected problem base")
    p.add_argument("--case", required=True)

'''
        if anchor not in text:
            raise RuntimeError("problem-isolate parser anchor changed")
        text = text.replace(anchor, anchor + addition, 1)

    old_call = "case = initialize_problem_case(Path(args.repo), report=args.report, expected_behavior=args.expected)"
    new_call = "case = initialize_problem_case(Path(args.repo), report=args.report, expected_behavior=args.expected, protected_ref=args.protected_ref)"
    if new_call not in text:
        if old_call not in text:
            raise RuntimeError("problem-init execution anchor changed")
        text = text.replace(old_call, new_call, 1)

    if 'if command == "problem-isolate":' not in text:
        anchor = '''    if command == "problem-validate":
        case = _data(args.case)
        schema = _data(_root_file("schemas/problem-case.schema.json"))
        errors = validate_problem_case(case, schema)
        return {"valid": not errors, "problem_case": case, "errors": errors}, 0 if not errors else 2
'''
        addition = '''    if command == "problem-isolate":
        case = _data(args.case)
        result = isolate_problem_case(case)
        return result, 0
'''
        if anchor not in text:
            raise RuntimeError("problem-isolate execution anchor changed")
        text = text.replace(anchor, anchor + addition, 1)
    write(path, text)


def skill_command_surface() -> None:
    path = "skills/zero-trust-delivery/SKILL.md"
    text = read(path)
    marker = "# Never-idle recovery\n"
    block = '''# Minimal owner entry

For a reported problem, the owner only needs to describe what happened and, if known, what was expected. ZTAD initializes the case against the protected ref, isolates dirty/divergent work automatically, proves the problem before patching, and carries the resulting Change Contract through governed delivery.

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py problem-init --repo <REPOSITORY> --protected-ref main --report "<what happened>" --expected "<expected behavior>"
python3 <PLUGIN_ROOT>/scripts/ztad.py problem-isolate --case <CASE.json>
```

'''
    if "# Minimal owner entry" not in text:
        if marker not in text:
            raise RuntimeError("zero-trust-delivery insertion anchor changed")
        text = text.replace(marker, block + marker, 1)
    write(path, text)


def cleanup() -> None:
    Path(__file__).unlink(missing_ok=True)


def main() -> None:
    provider_role_boundary()
    cli_autonomy()
    skill_command_surface()
    cleanup()


if __name__ == "__main__":
    main()
