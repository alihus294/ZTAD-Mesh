from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .repository import GitRepository
from .util import redact_url_credentials, utc_now

LANGUAGE_MARKERS = {
    "python": ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"),
    "javascript_typescript": ("package.json", "tsconfig.json"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "dotnet": ("*.sln", "*.csproj"),
    "go": ("go.mod",),
    "rust": ("Cargo.toml",),
    "ruby": ("Gemfile",),
    "php": ("composer.json",),
}
PACKAGE_MANAGERS = {
    "npm": ("package-lock.json",),
    "pnpm": ("pnpm-lock.yaml",),
    "yarn": ("yarn.lock",),
    "bun": ("bun.lock", "bun.lockb"),
    "pip": ("requirements.txt", "pyproject.toml"),
    "poetry": ("poetry.lock",),
    "uv": ("uv.lock",),
    "maven": ("pom.xml",),
    "gradle": ("gradlew", "build.gradle", "build.gradle.kts"),
    "go": ("go.mod",),
    "cargo": ("Cargo.lock", "Cargo.toml"),
}
TEST_FRAMEWORK_MARKERS = {
    "pytest": ("pytest.ini", "conftest.py", "pyproject.toml"),
    "jest": ("jest.config.js", "jest.config.ts", "jest.config.cjs"),
    "vitest": ("vitest.config.js", "vitest.config.ts", "vite.config.ts"),
    "playwright": ("playwright.config.ts", "playwright.config.js"),
    "cypress": ("cypress.config.ts", "cypress.config.js"),
    "junit": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "go-test": ("go.mod",),
    "cargo-test": ("Cargo.toml",),
}
PLATFORM_CONTROLS = (
    "branch_protection",
    "required_checks",
    "stale_review_dismissal",
    "merge_queue",
    "environment_protection",
    "oidc",
    "artifact_attestation",
)


def _exists_any(root: Path, markers: tuple[str, ...]) -> bool:
    return any(any(root.glob(marker)) if "*" in marker else (root / marker).exists() for marker in markers)


def _detect_ci(root: Path) -> list[str]:
    result: list[str] = []
    if (root / ".github/workflows").is_dir() and any((root / ".github/workflows").glob("*.y*ml")):
        result.append("github_actions_config_present_unverified")
    if (root / ".gitlab-ci.yml").exists():
        result.append("gitlab_ci_config_present_unverified")
    if (root / "azure-pipelines.yml").exists():
        result.append("azure_pipelines_config_present_unverified")
    if (root / "Jenkinsfile").exists():
        result.append("jenkins_config_present_unverified")
    return result


def _detect_deployment(root: Path) -> list[str]:
    markers = {
        "docker": ("Dockerfile", "docker-compose.yml", "compose.yaml"),
        "kubernetes": ("k8s", "kubernetes", "helm"),
        "terraform": ("*.tf",),
        "vercel": ("vercel.json",),
        "netlify": ("netlify.toml",),
        "supabase": ("supabase/config.toml",),
    }
    return [name for name, values in markers.items() if _exists_any(root, values)]


def detect_capabilities(repo_path: Path | str) -> dict[str, Any]:
    """Detect local capabilities without converting configuration into enforcement evidence."""
    root = Path(repo_path).resolve()
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "repository": str(root),
        "git": {"available": shutil.which("git") is not None, "repository": False},
        "languages": [],
        "package_managers": [],
        "test_frameworks": [],
        "ci": [],
        "deployment_markers": [],
        "local_tools": {},
        "platform_enforcement": {name: {"status": "UNKNOWN_NOT_VERIFIED"} for name in PLATFORM_CONTROLS},
        "host_capabilities": {
            "protected_repository_access": "UNKNOWN_NOT_VERIFIED",
            "protected_branch_rules": "UNKNOWN_NOT_VERIFIED",
            "protected_ci_result": "UNKNOWN_NOT_VERIFIED",
            "protected_supervisor_approval": "UNKNOWN_NOT_VERIFIED",
            "protected_staging_environment": "UNKNOWN_NOT_VERIFIED",
            "protected_production_release": "UNKNOWN_NOT_VERIFIED",
            "production_runtime_health": "UNKNOWN_NOT_VERIFIED",
            "protected_rollback_controller": "UNKNOWN_NOT_VERIFIED",
            "network_sandbox": "UNKNOWN_NOT_VERIFIED",
            "process_isolation": "UNKNOWN_NOT_VERIFIED",
            "secrets_availability": "UNKNOWN_NOT_VERIFIED",
            "protected_signing_key_custody": "UNKNOWN_NOT_VERIFIED",
            "actual_production_access": "UNKNOWN_NOT_VERIFIED",
        },
        "unproven_capabilities": [],
        "maximum_permitted_mode": "AUDIT_ONLY",
        "limitations": [],
    }
    for tool in ("python", "python3", "node", "npm", "pnpm", "yarn", "docker", "gh", "opa", "cosign"):
        report["local_tools"][tool] = shutil.which(tool) or None
    report["languages"] = [name for name, markers in LANGUAGE_MARKERS.items() if _exists_any(root, markers)]
    report["package_managers"] = [name for name, markers in PACKAGE_MANAGERS.items() if _exists_any(root, markers)]
    report["test_frameworks"] = [name for name, markers in TEST_FRAMEWORK_MARKERS.items() if _exists_any(root, markers)]
    report["ci"] = _detect_ci(root)
    report["deployment_markers"] = _detect_deployment(root)

    if report["git"]["available"]:
        try:
            repo = GitRepository(root)
            report["repository"] = str(repo.root)
            report["git"].update({
                "repository": True,
                "head_sha": repo.current_head(),
                "remotes": [redact_url_credentials(url) for url in repo.remote_urls()],
            })
        except Exception as exc:
            report["limitations"].append(f"Git repository inspection failed: {exc}")

    if report["git"]["repository"] and report["ci"]:
        report["maximum_permitted_mode"] = "LOCAL_AND_CONFIG_VERIFICATION"
        report["limitations"].append(
            "CI configuration exists locally, but required checks, branch rules, environments, identity, and runtime controls are not verified."
        )
    elif report["git"]["repository"]:
        report["maximum_permitted_mode"] = "LOCAL_VERIFICATION_ONLY"
        report["limitations"].append("No CI configuration was detected; merge and release controls cannot be claimed active.")
    else:
        report["limitations"].append("A Git repository is required for SHA-bound evidence and diff-based policy.")
    if report["local_tools"].get("gh") is None:
        report["limitations"].append("GitHub CLI is unavailable; remote GitHub controls cannot be audited in this run.")
    report["unproven_capabilities"] = sorted(
        name for name, status in report["host_capabilities"].items() if status != "PROVEN"
    )
    report["capability_decision"] = "HOST_CAPABILITY_UNPROVEN" if report["unproven_capabilities"] else "HOST_CAPABILITIES_PROVEN"
    return report
