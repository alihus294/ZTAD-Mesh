from __future__ import annotations

import json
import re
import shutil
from typing import Any
from urllib.parse import quote

from .util import run_command, utc_now

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _gh_json(endpoint: str) -> tuple[Any | None, str | None]:
    proc = run_command(
        ["gh", "api", "--method", "GET", "-H", "Accept: application/vnd.github+json", endpoint],
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout).strip()[-1200:]
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON from GitHub CLI: {exc}"


def _control(status: str, *, evidence: Any | None = None, error: str | None = None, reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status}
    if evidence is not None:
        result["evidence"] = evidence
    if error:
        result["error"] = error
    if reason:
        result["reason"] = reason
    return result


def audit_github(repo_slug: str, branch: str = "main") -> dict[str, Any]:
    """Read GitHub settings without mutating them and make conservative derived claims."""
    if not REPO_RE.fullmatch(repo_slug):
        raise ValueError("repo-slug must be owner/repository")
    if not BRANCH_RE.fullmatch(branch) or ".." in branch:
        raise ValueError("Unsafe branch name")
    report: dict[str, Any] = {
        "schema_version": 1,
        "provider": "github",
        "repository": repo_slug,
        "branch": branch,
        "generated_at": utc_now(),
        "controls": {},
        "errors": [],
        "read_only": True,
    }
    if shutil.which("gh") is None:
        report["errors"].append("GitHub CLI is not installed")
        return report

    encoded_branch = quote(branch, safe="")
    branch_payload, branch_error = _gh_json(f"repos/{repo_slug}/branches/{encoded_branch}/protection")
    if branch_error:
        report["controls"]["branch_protection"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=branch_error)
        report["controls"]["required_checks"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=branch_error)
        report["controls"]["stale_review_dismissal"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=branch_error)
    else:
        protected = isinstance(branch_payload, dict) and bool(branch_payload)
        report["controls"]["branch_protection"] = _control(
            "VERIFIED_ACTIVE" if protected else "VERIFIED_ABSENT", evidence=branch_payload
        )
        checks = (branch_payload or {}).get("required_status_checks") if isinstance(branch_payload, dict) else None
        check_items: list[Any] = []
        if isinstance(checks, dict):
            check_items.extend(checks.get("checks") or [])
            check_items.extend(checks.get("contexts") or [])
        report["controls"]["required_checks"] = _control(
            "VERIFIED_ACTIVE" if check_items else "VERIFIED_ABSENT",
            evidence={"checks": check_items},
        )
        reviews = (branch_payload or {}).get("required_pull_request_reviews") if isinstance(branch_payload, dict) else None
        stale = bool((reviews or {}).get("dismiss_stale_reviews")) if isinstance(reviews, dict) else False
        latest_push = bool((reviews or {}).get("require_last_push_approval")) if isinstance(reviews, dict) else False
        report["controls"]["stale_review_dismissal"] = _control(
            "VERIFIED_ACTIVE" if stale and latest_push else "VERIFIED_ABSENT",
            evidence={"dismiss_stale_reviews": stale, "require_last_push_approval": latest_push},
            reason=None if stale and latest_push else "Both stale-review dismissal and latest-push approval are required by this profile.",
        )

    rulesets, rules_error = _gh_json(f"repos/{repo_slug}/rulesets")
    if rules_error:
        report["controls"]["rulesets"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=rules_error)
        report["controls"]["merge_queue"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=rules_error)
    else:
        report["controls"]["rulesets"] = _control("VERIFIED_ACTIVE" if rulesets else "VERIFIED_ABSENT", evidence=rulesets)
        merge_queue = False
        for item in rulesets or []:
            ruleset_id = item.get("id") if isinstance(item, dict) else None
            detail = item
            if ruleset_id:
                fetched, _ = _gh_json(f"repos/{repo_slug}/rulesets/{ruleset_id}")
                if fetched:
                    detail = fetched
            for rule in (detail or {}).get("rules", []) if isinstance(detail, dict) else []:
                if isinstance(rule, dict) and str(rule.get("type", "")).lower() == "merge_queue":
                    merge_queue = True
        report["controls"]["merge_queue"] = _control("VERIFIED_ACTIVE" if merge_queue else "VERIFIED_ABSENT")

    environments, environments_error = _gh_json(f"repos/{repo_slug}/environments")
    if environments_error:
        report["controls"]["environments"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=environments_error)
        report["controls"]["production_environment"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=environments_error)
    else:
        report["controls"]["environments"] = _control("VERIFIED_ACTIVE" if environments else "VERIFIED_ABSENT", evidence=environments)
        env_names = {
            str(item.get("name"))
            for item in (environments or {}).get("environments", [])
            if isinstance(item, dict) and item.get("name")
        } if isinstance(environments, dict) else set()
        if "production" not in env_names:
            report["controls"]["production_environment"] = _control("VERIFIED_ABSENT")
        else:
            prod, prod_error = _gh_json(f"repos/{repo_slug}/environments/production")
            if prod_error:
                report["controls"]["production_environment"] = _control("CONFIGURED_NOT_VERIFIED", error=prod_error)
            else:
                rules = (prod or {}).get("protection_rules", []) if isinstance(prod, dict) else []
                reviewers = any(isinstance(rule, dict) and rule.get("type") == "required_reviewers" for rule in rules)
                report["controls"]["production_environment"] = _control(
                    "VERIFIED_ACTIVE" if reviewers else "CONFIGURED_NOT_VERIFIED",
                    evidence=prod,
                    reason=None if reviewers else "Production environment exists but required reviewers were not proven.",
                )

    actions, actions_error = _gh_json(f"repos/{repo_slug}/actions/permissions")
    report["controls"]["actions_permissions"] = _control(
        "UNAVAILABLE_OR_UNAUTHORIZED" if actions_error else "VERIFIED_ACTIVE",
        evidence=None if actions_error else actions,
        error=actions_error,
    )
    oidc, oidc_error = _gh_json(f"repos/{repo_slug}/actions/oidc/customization/sub")
    if oidc_error:
        report["controls"]["oidc"] = _control("UNAVAILABLE_OR_UNAUTHORIZED", error=oidc_error)
    else:
        custom = isinstance(oidc, dict) and oidc.get("use_default") is False and bool(oidc.get("include_claim_keys"))
        report["controls"]["oidc"] = _control(
            "CONFIGURED_NOT_VERIFIED" if custom else "VERIFIED_ABSENT",
            evidence=oidc,
            reason="Repository subject customization does not prove the cloud provider trust policy." if custom else None,
        )
    return report
