from __future__ import annotations

import fnmatch
import os
import re
import shlex
from pathlib import Path
from typing import Any, Iterable, Sequence

from .path_security import command_path_token, resolve_within
from .util import load_data

DENIED_EXECUTABLES = {
    "curl", "wget", "nc", "netcat", "scp", "ssh", "ftp", "sftp", "telnet",
    "kubectl", "helm", "terraform", "ansible", "psql", "mysql", "sqlcmd",
    "twine", "npx", "bash", "sh", "zsh", "powershell", "pwsh", "cmd",
    "wsl", "mshta", "rundll32", "reg", "reg.exe", "certutil", "bitsadmin",
}
DENIED_IDS = {
    "git-push", "git-config", "git-remote", "git-clean", "git-reset", "git-checkout",
    "git-restore", "docker-login", "npm-publish", "gh-auth", "gh-secret",
}
SHELL_META = re.compile(r"(?:&&|\|\||[;&|><`$\n\r])")
WINDOWS_ENV = re.compile(r"%[^%]+%|\$env:", re.IGNORECASE)

# Flags that can redirect a normally read-only command to arbitrary host paths,
# load code/plugins, or alter repository resolution.
DENIED_FLAGS = {
    "git": {
        "-c", "--config-env", "--git-dir", "--work-tree", "--namespace", "--exec-path",
        "--output", "--no-index", "--src-prefix", "--dst-prefix", "--line-prefix",
    },
    "pytest": {
        "--pyargs", "--rootdir", "--confcutdir", "--basetemp", "--ignore", "--ignore-glob",
        "--override-ini", "--collect-in-virtualenv",
    },
    "python-pytest": {
        "--pyargs", "--rootdir", "--confcutdir", "--basetemp", "--ignore", "--ignore-glob",
        "--override-ini", "--collect-in-virtualenv",
    },
}

# For these commands, positional path-like tokens and explicit path flags must
# remain inside the workspace. The broker is intentionally conservative.
PATH_VALUE_FLAGS = {
    "pytest": {"-c", "--cache-clear-file"},
    "python-pytest": {"-c", "--cache-clear-file"},
    "python-compileall": {"-d", "-s", "-p"},
    "python-unittest": {},
    "npm-test": {"--prefix"},
    "npm-run": {"--prefix"},
    "pnpm-test": {"--dir", "-C"},
    "pnpm-lint": {"--dir", "-C"},
    "yarn-test": {"--cwd"},
    "yarn-lint": {"--cwd"},
    "dotnet-test": {"--results-directory", "--settings"},
}


def normalized_command_id(argv: Sequence[str]) -> str:
    if not argv:
        return ""
    executable = Path(argv[0]).name.lower().removesuffix(".exe").removesuffix(".cmd").removesuffix(".bat")
    if executable in {"python", "python3", "py"} and len(argv) >= 3 and argv[1] == "-m":
        return f"python-{argv[2].lower()}"
    if executable in {"git", "docker", "npm", "pnpm", "yarn", "gh", "cargo", "go", "dotnet", "mvn"} and len(argv) > 1:
        return f"{executable}-{argv[1].lower()}"
    return executable


def split_hook_command(command: str, *, windows: bool | None = None) -> list[str]:
    """Parse only simple single-command hook strings.

    This is not a shell parser. Any shell operator, command substitution, line
    break, or environment expansion is rejected before tokenization.
    """
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Command must be a non-empty string")
    if SHELL_META.search(command) or WINDOWS_ENV.search(command):
        raise ValueError("Shell operators, substitutions, and environment expansion are prohibited")
    windows = os.name == "nt" if windows is None else windows
    return shlex.split(command, posix=not windows)


def _flag_name(arg: str) -> str:
    return arg.split("=", 1)[0]


def _path_values(argv: Sequence[str], command_id: str) -> list[str]:
    result: list[str] = []
    value_flags = PATH_VALUE_FLAGS.get(command_id, set())
    i = 1
    after_separator = False
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            after_separator = True
            i += 1
            continue
        name = _flag_name(arg)
        if name in value_flags:
            if "=" in arg:
                result.append(arg.split("=", 1)[1])
            elif i + 1 < len(argv):
                result.append(argv[i + 1])
                i += 1
            i += 1
            continue
        # Revision expressions and ordinary non-path identifiers are not path
        # candidates. Anything path-shaped must resolve inside the workspace.
        if after_separator or (not arg.startswith("-") and command_path_token(arg)):
            result.append(arg)
        i += 1
    return result


def _policy_matches(argv: Sequence[str], policy: dict[str, Any]) -> bool:
    patterns = policy.get("allowed_argv", []) or []
    joined = " ".join(argv)
    return any(fnmatch.fnmatchcase(joined, pattern) for pattern in patterns)


def validate_command(
    argv: Sequence[str],
    policy: dict[str, Any],
    *,
    workspace_root: Path | None = None,
    scratch_roots: Iterable[Path] = (),
) -> dict[str, Any]:
    reasons: list[str] = []
    if not argv:
        return {"allowed": False, "command_id": "", "argv": [], "reasons": ["Empty command"]}
    if any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
        reasons.append("Arguments must be NUL-free strings")
    if any(SHELL_META.search(arg) or WINDOWS_ENV.search(arg) for arg in argv):
        reasons.append("Shell metacharacters, substitutions, and environment expansion are prohibited")
    if any(arg.startswith("@") for arg in argv):
        reasons.append("Response-file expansion is prohibited")

    command_id = normalized_command_id(argv)
    executable = Path(argv[0]).name.lower().removesuffix(".exe").removesuffix(".cmd").removesuffix(".bat")
    denied = set(policy.get("denied_command_ids", []) or []) | DENIED_IDS
    if executable in DENIED_EXECUTABLES or command_id in denied:
        reasons.append(f"Command is denied: {command_id or executable}")
    if not _policy_matches(argv, policy):
        reasons.append("Command does not match an approved argv pattern")

    denied_flags = set(policy.get("denied_flags", {}).get(executable, []) or [])
    denied_flags |= DENIED_FLAGS.get(executable, set())
    denied_flags |= DENIED_FLAGS.get(command_id, set())
    for arg in argv[1:]:
        if _flag_name(arg) in denied_flags:
            reasons.append(f"Flag is prohibited for {command_id}: {_flag_name(arg)}")

    # Pytest plugin loading is executable code. Permit only the built-in
    # cacheprovider disable used by the bundled verification runner.
    if command_id in {"pytest", "python-pytest"}:
        for index, arg in enumerate(argv[1:], start=1):
            if arg == "-p":
                value = argv[index + 1] if index + 1 < len(argv) else ""
                if value != "no:cacheprovider":
                    reasons.append("Only '-p no:cacheprovider' is permitted")
            elif arg.startswith("-p=") and arg != "-p=no:cacheprovider":
                reasons.append("Only '-p no:cacheprovider' is permitted")

    checked_paths: list[str] = []
    if workspace_root is not None:
        for raw in _path_values(argv, command_id):
            try:
                resolved = resolve_within(workspace_root, raw, extra_roots=scratch_roots)
                checked_paths.append(str(resolved))
            except (OSError, ValueError) as exc:
                reasons.append(str(exc))

    return {
        "allowed": not reasons,
        "command_id": command_id,
        "argv": list(argv),
        "workspace_root": str(workspace_root.resolve()) if workspace_root else None,
        "checked_paths": checked_paths,
        "reasons": sorted(set(reasons)),
    }


def validate_command_file(
    argv: Sequence[str],
    policy_path: Path,
    *,
    workspace_root: Path | None = None,
    scratch_roots: Iterable[Path] = (),
) -> dict[str, Any]:
    policy = load_data(policy_path)
    if not isinstance(policy, dict):
        return {"allowed": False, "command_id": "", "argv": list(argv), "reasons": ["Command policy must be a mapping"]}
    return validate_command(argv, policy, workspace_root=workspace_root, scratch_roots=scratch_roots)
