from __future__ import annotations

import csv
import json
import ast
import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .util import load_data, strict_yaml_loads, walk_regular_files

FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)
FULL_SHA_USE = re.compile(r"^\s*uses:\s*[^\s@]+@([0-9a-fA-F]{40})\s*(?:#.*)?$", re.MULTILINE)
ANY_USE = re.compile(r"^\s*uses:\s*[^\s@]+@([^\s#]+)", re.MULTILINE)
REQUIRED_SKILLS = {
    "zero-trust-delivery",
    "problem-investigation",
    "multi-model-mesh",
    "delivery-bootstrap",
    "change-intake-risk",
    "implementation-strategy",
    "code-change-verification",
    "independent-review",
    "finding-verification-repair",
    "release-readiness",
    "delivery-retrospective",
    "autonomous-continuity",
    "supervisor-governance",
    "recovery-and-takeover",
}
REQUIRED_FILES = {
    ".codex-plugin/plugin.json",
    "README.md",
    "QUICKSTART.md",
    "SECURITY.md",
    "LICENSE",
    "VERSION",
    "scripts/ztad.py",
    "scripts/verify_release.py",
    "docs/BUG_TO_PRODUCTION_PROTOCOL.md",
    "schemas/problem-case.schema.json",
    "schemas/blocker-request.schema.json",
    "toolkit/pyproject.toml",
    "toolkit/ztad/distribution.py",
    "toolkit/requirements.lock.txt",
    "references/MASTER_PLAN.md",
    "traceability/requirements.csv",
    "traceability/TRACEABILITY_MATRIX.md",
    "evals/trigger-cases.json",
    "evals/run_evals.py",
    "templates/repository/AGENTS.md",
    "templates/repository/.github/workflows/ztad-policy.yml",
}


def _validate_skill(skill_dir: Path) -> list[str]:
    errors: list[str] = []
    manifest = skill_dir / "SKILL.md"
    if not manifest.is_file():
        return [f"{skill_dir.name}: missing SKILL.md"]
    text = manifest.read_text(encoding="utf-8")
    match = FRONTMATTER.match(text)
    if not match:
        return [f"{skill_dir.name}: invalid or missing YAML front matter"]
    try:
        metadata = strict_yaml_loads(match.group(1))
    except (yaml.YAMLError, ValueError) as exc:
        return [f"{skill_dir.name}: invalid front matter: {exc}"]
    if not isinstance(metadata, dict):
        return [f"{skill_dir.name}: front matter must be a mapping"]
    name = metadata.get("name")
    description = metadata.get("description")
    if not isinstance(name, str) or not name.strip():
        errors.append(f"{skill_dir.name}: name is required")
    elif name != skill_dir.name:
        errors.append(f"{skill_dir.name}: front matter name must match directory")
    elif len(name) > 64:
        errors.append(f"{skill_dir.name}: name exceeds 64 characters")
    if not isinstance(description, str) or not description.strip() or len(description) > 1024:
        errors.append(f"{skill_dir.name}: description must be 1-1024 characters")
    body = match.group(2).strip()
    if not body:
        errors.append(f"{skill_dir.name}: skill body is empty")
    if len(body.split()) > 1800:
        errors.append(f"{skill_dir.name}: SKILL.md exceeds the 1,800-word operational limit")
    agent_path = skill_dir / "agents/openai.yaml"
    if not agent_path.is_file():
        errors.append(f"{skill_dir.name}: missing agents/openai.yaml")
        return errors
    try:
        agent = load_data(agent_path)
    except Exception as exc:
        errors.append(f"{skill_dir.name}: invalid agents/openai.yaml: {exc}")
        return errors
    interface = agent.get("interface") if isinstance(agent, dict) else None
    if not isinstance(interface, dict):
        errors.append(f"{skill_dir.name}: agents/openai.yaml requires interface")
    else:
        allowed_interface = {"display_name", "short_description", "icon_small", "icon_large", "brand_color", "default_prompt"}
        extra = set(interface) - allowed_interface
        if extra:
            errors.append(f"{skill_dir.name}: unsupported interface fields: {sorted(extra)}")
        for field in ("display_name", "short_description"):
            if not isinstance(interface.get(field), str) or not interface[field].strip():
                errors.append(f"{skill_dir.name}: interface.{field} is required")
        short_description = interface.get("short_description")
        if isinstance(short_description, str) and not 25 <= len(short_description) <= 64:
            errors.append(f"{skill_dir.name}: interface.short_description must be 25-64 characters")
        default_prompt = interface.get("default_prompt")
        if not isinstance(default_prompt, str) or f"${skill_dir.name}" not in default_prompt:
            errors.append(f"{skill_dir.name}: interface.default_prompt must explicitly mention ${skill_dir.name}")
    policy = agent.get("policy", {}) if isinstance(agent, dict) else {}
    if set(policy) - {"allow_implicit_invocation"}:
        errors.append(f"{skill_dir.name}: unsupported policy fields")
    if policy.get("allow_implicit_invocation") is not False:
        errors.append(f"{skill_dir.name}: high-control suite requires explicit invocation")
    return errors


def _validate_workflow(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    uses = ANY_USE.findall(text)
    pinned = FULL_SHA_USE.findall(text)
    if uses and len(uses) != len(pinned):
        errors.append(f"Workflow has unpinned action references: {path}")
    if "merge_group:" not in text:
        errors.append("GitHub policy workflow must listen to merge_group")
    if "persist-credentials: false" not in text:
        errors.append("GitHub policy workflow must disable persisted checkout credentials")
    if re.search(r"permissions:\s*write-all", text):
        errors.append("GitHub policy workflow must not use write-all permissions")
    return errors


def validate_bundle(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    for required in sorted(REQUIRED_FILES):
        if not (root / required).is_file():
            errors.append(f"Missing required file: {required}")

    plugin_path = root / ".codex-plugin/plugin.json"
    plugin: dict[str, Any] = {}
    if plugin_path.is_file():
        try:
            loaded_plugin = load_data(plugin_path)
            if not isinstance(loaded_plugin, dict):
                errors.append("Plugin manifest root must be an object")
            else:
                plugin = loaded_plugin
        except Exception as exc:
            errors.append(f"Invalid plugin manifest: {exc}")
    allowed_plugin = {"name", "version", "description", "skills", "hooks"}
    extra_plugin = set(plugin) - allowed_plugin
    if extra_plugin:
        errors.append(f"Unsupported plugin manifest fields: {sorted(extra_plugin)}")
    for field in allowed_plugin:
        if not plugin.get(field):
            errors.append(f"Plugin manifest missing {field}")
    if plugin.get("name") != "zero-trust-agentic-delivery":
        errors.append("Unexpected plugin name")
    if plugin.get("skills") != "./skills/":
        errors.append("Plugin skills path must be ./skills/")
    if plugin.get("hooks") != "./hooks/hooks.json":
        errors.append("Plugin hooks path must be ./hooks/hooks.json")
    elif not (root / "hooks/hooks.json").is_file():
        errors.append("Plugin hooks file is missing")
    version_path = root / "VERSION"
    if version_path.is_file() and plugin.get("version") != version_path.read_text(encoding="utf-8").strip():
        errors.append("Plugin manifest version does not match VERSION")

    skills_root = root / "skills"
    skill_dirs = sorted(path for path in skills_root.iterdir() if path.is_dir() and not path.name.startswith(".")) if skills_root.is_dir() else []
    names = {item.name for item in skill_dirs}
    missing_skills = REQUIRED_SKILLS - names
    extra_skills = names - REQUIRED_SKILLS
    if missing_skills:
        errors.append("Missing required skills: " + ", ".join(sorted(missing_skills)))
    if extra_skills:
        warnings.append("Additional skills present: " + ", ".join(sorted(extra_skills)))
    for skill_dir in skill_dirs:
        errors.extend(_validate_skill(skill_dir))

    schema_count = 0
    for path in walk_regular_files(root / "schemas"):
        if path.suffix != ".json":
            continue
        schema_count += 1
        try:
            data = load_data(path)
            Draft202012Validator.check_schema(data)
        except (Exception, SchemaError) as exc:
            errors.append(f"Invalid JSON Schema {path.relative_to(root)}: {exc}")
    if schema_count < 10:
        errors.append("Expected at least ten JSON Schemas")

    policy_count = 0
    for path in walk_regular_files(root / "policies"):
        if path.suffix.lower() in {".yaml", ".yml"}:
            policy_count += 1
            try:
                data = load_data(path)
                if not isinstance(data, dict):
                    errors.append(f"Policy is not a mapping: {path.relative_to(root)}")
            except Exception as exc:
                errors.append(f"Invalid YAML {path.relative_to(root)}: {exc}")
        elif path.suffix == ".json":
            try:
                data = load_data(path)
                if not isinstance(data, dict):
                    errors.append(f"Policy is not a mapping: {path.relative_to(root)}")
            except Exception as exc:
                errors.append(f"Invalid JSON policy {path.relative_to(root)}: {exc}")
    if policy_count < 15:
        errors.append("Expected at least fifteen YAML policies")

    for path in root.rglob("*"):
        if path.is_symlink():
            errors.append(f"Symlink is not allowed in bundle: {path.relative_to(root)}")
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            warnings.append(f"Compiled cache will be excluded from packaging: {path.relative_to(root)}")

    for path in walk_regular_files(root / "toolkit") + walk_regular_files(root / "scripts") + walk_regular_files(root / "evals"):
        if path.suffix == ".py":
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except SyntaxError as exc:
                errors.append(f"Python syntax error {path.relative_to(root)}:{exc.lineno}: {exc.msg}")

    workflow = root / "templates/repository/.github/workflows/ztad-policy.yml"
    if workflow.is_file():
        errors.extend(_validate_workflow(workflow))

    requirements_csv = root / "traceability/requirements.csv"
    trace_rows: list[dict[str, str]] = []
    if requirements_csv.is_file():
        with requirements_csv.open(encoding="utf-8", newline="") as handle:
            trace_rows = list(csv.DictReader(handle))
        if not trace_rows:
            errors.append("Traceability matrix is empty")
        required_columns = {"requirement_id", "source_line", "section", "normative_level", "requirement", "enforcement_class", "implementing_artifacts", "verification"}
        if trace_rows and not required_columns.issubset(trace_rows[0]):
            errors.append("Traceability matrix lacks required columns")
        if any(row.get("enforcement_class") in {"", "UNMAPPED"} or not row.get("implementing_artifacts") for row in trace_rows):
            errors.append("Traceability matrix contains unmapped requirements")

    trigger_path = root / "evals/trigger-cases.json"
    positive_count = negative_count = 0
    if trigger_path.is_file():
        try:
            cases = load_data(trigger_path)
            if not isinstance(cases, dict):
                raise ValueError("trigger cases root must be an object")
            positive_count = len(cases.get("positive", []))
            negative_count = len(cases.get("negative", []))
            if positive_count < 5:
                errors.append("At least five positive trigger cases are required")
            if negative_count < 3:
                errors.append("At least three negative trigger cases are required")
        except Exception as exc:
            errors.append(f"Invalid trigger cases: {exc}")

    forbidden: list[str] = []
    excluded_markers = {"references/MASTER_PLAN.md"}
    for path in walk_regular_files(root):
        rel = path.relative_to(root).as_posix()
        if rel in excluded_markers or path.suffix.lower() not in {".md", ".py", ".yaml", ".yml", ".json", ".toml", ".csv"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"\b(?:" + "TO" + "DO|T" + "BD)\b", text):
            forbidden.append(rel)
    if forbidden:
        errors.append("Unresolved TODO/TBD markers found: " + ", ".join(forbidden[:20]))

    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
        "skills": sorted(names),
        "skill_count": len(names),
        "schema_count": schema_count,
        "policy_count": policy_count,
        "traceability_requirements": len(trace_rows),
        "positive_trigger_cases": positive_count,
        "negative_trigger_cases": negative_count,
        "file_count": sum(1 for _ in walk_regular_files(root)),
    }
