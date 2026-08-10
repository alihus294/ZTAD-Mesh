from __future__ import annotations

import concurrent.futures
import json
import os
import random
import sqlite3
import string
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "toolkit"))
sys.path.insert(0, str(ROOT / "tests"))

from conftest import valid_contract  # type: ignore
from ztad.commands import validate_command
from ztad.errors import ConfigurationError
from ztad.ledger import append_record, verify_ledger
from ztad.model_router import AdaptiveModelRouter, TaskProfile
from ztad.path_security import normalize_repo_path
from ztad.risk import classify_risk
from ztad.util import load_data

SEED = 420042
RNG = random.Random(SEED)
ALPHABET = string.ascii_letters + string.digits + "_-./\\:$%[](){} ;&|\x00éإ"


def random_text(min_len: int = 0, max_len: int = 80) -> str:
    return "".join(RNG.choice(ALPHABET) for _ in range(RNG.randint(min_len, max_len)))


def ledger_worker(args: tuple[str, int]) -> dict:
    path, index = args
    return append_record(Path(path), {"index": index}, idempotency_key=f"item-{index}")


def run() -> dict:
    policy = load_data(ROOT / "policies/command-policy.yaml")
    risk_policy = load_data(ROOT / "policies/risk-policy.yaml")
    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")
    summary = {
        "schema_version": 1,
        "seed": SEED,
        "fuzz": {},
        "concurrency": {},
        "errors": [],
    }

    command_cases = 10000
    command_exceptions = 0
    for _ in range(command_cases):
        argc = RNG.randint(0, 10)
        argv = [random_text(0, 40) for _ in range(argc)]
        try:
            result = validate_command(argv, policy, workspace_root=ROOT)
            if not isinstance(result, dict) or "allowed" not in result:
                summary["errors"].append("command_invalid_result_shape")
        except (ValueError, OSError):
            command_exceptions += 1
        except Exception as exc:  # pragma: no cover - external validation guard
            summary["errors"].append(f"command_unhandled:{type(exc).__name__}:{exc}")
    summary["fuzz"]["command_policy"] = {
        "cases": command_cases, "expected_validation_exceptions": command_exceptions,
    }

    path_cases = 10000
    accepted_paths = 0
    rejected_paths = 0
    for _ in range(path_cases):
        raw = random_text(0, 100)
        try:
            normalized = normalize_repo_path(raw, case_insensitive=bool(RNG.getrandbits(1)))
            if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
                summary["errors"].append("path_normalizer_accepted_invalid_shape")
            accepted_paths += 1
        except ValueError:
            rejected_paths += 1
        except Exception as exc:
            summary["errors"].append(f"path_unhandled:{type(exc).__name__}:{exc}")
    summary["fuzz"]["path_normalization"] = {
        "cases": path_cases, "accepted": accepted_paths, "rejected": rejected_paths,
    }

    risk_cases = 10000
    risks = {f"R{i}": 0 for i in range(5)}
    for _ in range(risk_cases):
        parts = [random_text(1, 12).replace("\x00", "x").replace("/", "x").replace("\\", "x") for _ in range(RNG.randint(1, 4))]
        path = "/".join(parts) + RNG.choice([".py", ".sql", ".json", ".yml", ".md", ""])
        diff = RNG.choice([
            f"+++ b/{path}\n+safe = True\n",
            f"+++ b/{path}\n+DROP TABLE accounts;\n",
            f"+++ b/{path}\n+UPDATE accounts SET enabled=false;\n",
            f"+++ b/{path}\n+GRANT ALL ON accounts TO public;\n",
        ])
        try:
            result = classify_risk(valid_contract(), changed_paths=[path], diff_text=diff, policy=risk_policy)
            if result.risk not in risks:
                summary["errors"].append(f"risk_invalid:{result.risk}")
            else:
                risks[result.risk] += 1
        except Exception as exc:
            summary["errors"].append(f"risk_unhandled:{type(exc).__name__}:{exc}")
    summary["fuzz"]["risk_engine"] = {"cases": risk_cases, "distribution": risks}

    route_cases = 10000
    routed = 0
    unavailable = 0
    families = ["repository_navigation", "context_scout", "implementation", "repair", "review", "security", "database", "release", random_text(1, 20)]
    roles = ["worker", "repairer", "context_scout", "supervisor", "closure", "security_reviewer", "release_advisor"]
    for _ in range(route_cases):
        profile = TaskProfile(
            RNG.choice(families), RNG.choice(roles), f"R{RNG.randint(0,4)}",
            complexity=RNG.randint(0, 5), ambiguity=RNG.randint(0, 5), prior_failures=RNG.randint(0, 6),
            preferred_provider=RNG.choice([None, "codex", "missing"]),
        )
        try:
            decision = router.route(profile)
            if decision.candidate.registry_id not in {x.registry_id for x in router.candidates}:
                summary["errors"].append("router_unknown_candidate")
            routed += 1
        except LookupError:
            unavailable += 1
        except Exception as exc:
            summary["errors"].append(f"router_unhandled:{type(exc).__name__}:{exc}")
    summary["fuzz"]["model_router"] = {"cases": route_cases, "routed": routed, "no_qualified_candidate": unavailable}

    structured_cases = 3000
    expected_rejections = 0
    with tempfile.TemporaryDirectory(prefix="ztad-structured-fuzz-") as td:
        root = Path(td)
        for index in range(structured_cases):
            path = root / f"case-{index}.json"
            mode = RNG.randint(0, 4)
            if mode == 0:
                path.write_text(json.dumps({"value": random_text(0, 50), "n": index}), encoding="utf-8")
            elif mode == 1:
                path.write_text('{"x":1,"x":2}', encoding="utf-8")
            elif mode == 2:
                path.write_bytes(os.urandom(RNG.randint(0, 128)))
            elif mode == 3:
                path.write_text("[" * RNG.randint(1, 300) + "0" + "]" * RNG.randint(1, 300), encoding="utf-8")
            else:
                path.write_text(random_text(0, 200), encoding="utf-8", errors="ignore")
            try:
                load_data(path)
            except (ValueError, OSError, UnicodeError, ConfigurationError):
                expected_rejections += 1
            except Exception as exc:
                summary["errors"].append(f"structured_unhandled:{type(exc).__name__}:{exc}")
    summary["fuzz"]["structured_inputs"] = {"cases": structured_cases, "expected_rejections": expected_rejections}

    rounds = []
    with tempfile.TemporaryDirectory(prefix="ztad-ledger-concurrency-") as td:
        for round_index in range(5):
            ledger = Path(td) / f"round-{round_index}.sqlite3"
            with concurrent.futures.ProcessPoolExecutor(max_workers=32) as pool:
                records = list(pool.map(ledger_worker, [(str(ledger), i) for i in range(64)]))
            verified = verify_ledger(ledger)
            unique = len({item["sequence"] for item in records})
            round_result = {"round": round_index + 1, "writers": 64, "unique_sequences": unique, "valid": verified["valid"], "records": verified["records"]}
            rounds.append(round_result)
            if unique != 64 or not verified["valid"] or verified["records"] != 64:
                summary["errors"].append(f"ledger_concurrency_failure_round_{round_index + 1}")
    summary["concurrency"]["ledger_processes"] = rounds

    summary["totals"] = {
        "fuzz_cases": command_cases + path_cases + risk_cases + route_cases + structured_cases,
        "ledger_process_writes": 5 * 64,
        "error_count": len(summary["errors"]),
    }
    summary["passed"] = not summary["errors"]
    return summary


if __name__ == "__main__":
    result = run()
    output = ROOT / "validation" / "external-validation-v42.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["totals"], sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
