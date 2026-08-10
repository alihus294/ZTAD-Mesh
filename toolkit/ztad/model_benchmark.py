from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .agent_output import validate_agent_result
from .model_router import AdaptiveModelRouter, ModelCandidate
from .providers import ProviderRegistry, ProviderRunRequest
from .schema_validation import validate_instance
from .util import canonical_json, load_data, sha256_bytes, utc_now


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    task_family: str
    role: str
    risk: str
    prompt: str
    output_schema: Path
    assertions: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: dict[str, Any], *, root: Path) -> "BenchmarkCase":
        required = {"case_id", "task_family", "role", "risk", "prompt", "output_schema"}
        missing = sorted(required - set(value))
        if missing:
            raise ValueError("Benchmark case missing: " + ", ".join(missing))
        schema = Path(str(value["output_schema"]))
        if not schema.is_absolute():
            schema = root / schema
        if not schema.is_file():
            raise ValueError(f"Benchmark output schema does not exist: {schema}")
        return cls(
            case_id=str(value["case_id"]), task_family=str(value["task_family"]),
            role=str(value["role"]), risk=str(value["risk"]), prompt=str(value["prompt"]),
            output_schema=schema.resolve(), assertions=dict(value.get("assertions", {})),
        )


def load_benchmark_cases(path: Path) -> list[BenchmarkCase]:
    raw = load_data(path)
    values = raw.get("cases", []) if isinstance(raw, dict) else raw
    if not isinstance(values, list) or not values:
        raise ValueError("Benchmark file must contain a non-empty cases array")
    return [BenchmarkCase.from_mapping(item, root=path.resolve().parent) for item in values]




def benchmark_suite_hash(cases: Iterable[BenchmarkCase]) -> str:
    material = [
        {
            "case_id": case.case_id, "task_family": case.task_family, "role": case.role,
            "risk": case.risk, "prompt": case.prompt, "schema": str(case.output_schema),
            "assertions": case.assertions,
        }
        for case in cases
    ]
    return sha256_bytes(canonical_json(material))

def _score_output(output: dict[str, Any] | None, assertions: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: Any = None) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    if output is None:
        return {"score": 0.0, "checks": [{"name": "structured_output", "passed": False}]}
    add("structured_output", True)
    if "result_type_in" in assertions:
        allowed = set(assertions["result_type_in"])
        add("result_type_in", output.get("result_type") in allowed, output.get("result_type"))
    if "requested_action_in" in assertions:
        allowed = set(assertions["requested_action_in"])
        add("requested_action_in", output.get("requested_action") in allowed, output.get("requested_action"))
    if "max_findings" in assertions:
        count = len(output.get("findings", []) or [])
        add("max_findings", count <= int(assertions["max_findings"]), count)
    if "minimum_files_read" in assertions:
        count = len(output.get("files_read", []) or [])
        add("minimum_files_read", count >= int(assertions["minimum_files_read"]), count)
    serialized = canonical_json(output).decode("utf-8").casefold()
    for phrase in assertions.get("required_substrings", []) or []:
        add(f"required:{phrase}", str(phrase).casefold() in serialized)
    for phrase in assertions.get("forbidden_substrings", []) or []:
        add(f"forbidden:{phrase}", str(phrase).casefold() not in serialized)
    passed = sum(1 for item in checks if item["passed"])
    return {"score": passed / max(1, len(checks)), "checks": checks}


class ModelBenchmarkRunner:
    """Run explicit, bounded task-family evaluations against configured providers.

    Benchmark scores are local routing inputs, not proof of general intelligence or
    production correctness. The benchmark never grants merge/deploy authority.
    """

    def __init__(self, router: AdaptiveModelRouter, providers: ProviderRegistry):
        self.router = router
        self.providers = providers

    def _reasoning(self, candidate: ModelCandidate) -> str:
        preference = ["high", "medium", "xhigh", "max", "low", "none", "ultra"]
        return next((item for item in preference if item in candidate.reasoning_efforts), candidate.reasoning_efforts[0])

    def run(
        self,
        cases: Iterable[BenchmarkCase],
        *,
        cwd: Path,
        registry_ids: Iterable[str] | None = None,
        timeout_seconds: int = 600,
        artifact_dir: Path | None = None,
    ) -> dict[str, Any]:
        selected = set(registry_ids or [])
        candidates = [
            item for item in self.router.candidates
            if item.enabled and (not selected or item.registry_id in selected)
        ]
        results: list[dict[str, Any]] = []
        cases = list(cases)
        temporary: tempfile.TemporaryDirectory[str] | None = None
        if artifact_dir is None:
            temporary = tempfile.TemporaryDirectory(prefix="ztad-benchmark-runs-")
            benchmark_artifact_root = Path(temporary.name).resolve()
        else:
            benchmark_artifact_root = artifact_dir.resolve()
            benchmark_artifact_root.mkdir(parents=True, exist_ok=True)
        try:
            return self._run_candidates(
                candidates=candidates, cases=cases, cwd=cwd, timeout_seconds=timeout_seconds,
                benchmark_artifact_root=benchmark_artifact_root,
            )
        finally:
            if temporary is not None:
                temporary.cleanup()

    def _run_candidates(
        self, *, candidates: list[ModelCandidate], cases: list[BenchmarkCase], cwd: Path,
        timeout_seconds: int, benchmark_artifact_root: Path,
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for candidate in candidates:
            if not self.providers.has(candidate.provider):
                results.append({"registry_id": candidate.registry_id, "available": False, "reason": "provider_not_configured", "cases": []})
                continue
            provider = self.providers.get(candidate.provider)
            probe = provider.probe()
            if not probe.get("available"):
                results.append({"registry_id": candidate.registry_id, "available": False, "reason": "provider_probe_failed", "probe": probe, "cases": []})
                continue
            case_results: list[dict[str, Any]] = []
            for case in cases:
                quality = candidate.task_quality.get(case.task_family, candidate.task_quality.get("default", 0.0))
                if quality <= 0:
                    continue
                agent_role = {
                    "context_scout": "planner", "planner": "planner",
                    "supervisor": "independent_reviewer", "closure": "independent_reviewer",
                    "architecture_advisor": "architecture_advisor",
                    "release_advisor": "release_advisor",
                }.get(case.role, "planner")
                synthetic = {
                    "task_id": f"benchmark-{case.case_id}", "agent_role": agent_role,
                    "model_registry_id": candidate.registry_id, "prompt_version": "benchmark-v1",
                    "base_sha": "b" * 40, "head_sha": "b" * 40,
                    "context_id": "sha256:" + "c" * 64,
                }
                prompt = case.prompt + "\n\nBENCHMARK_REQUIRED_SUBJECT\n" + json.dumps(synthetic, sort_keys=True) + "\n"
                request = ProviderRunRequest(
                    task_id=f"benchmark-{case.case_id}", role=case.role, registry_id=candidate.registry_id,
                    model=candidate.model, reasoning_effort=self._reasoning(candidate), sandbox="read-only",
                    prompt=prompt, output_schema=case.output_schema, cwd=cwd,
                    timeout_seconds=timeout_seconds, artifact_dir=benchmark_artifact_root,
                )
                started = time.monotonic()
                run = provider.run(request)
                latency = max(0.001, time.monotonic() - started)
                score = _score_output(run.output, case.assertions)
                validation_errors = list(run.errors)
                if run.output is not None:
                    schema = load_data(case.output_schema)
                    validation_errors.extend(validate_instance(run.output, schema))
                    envelope_fields = {
                        "task_id", "agent_role", "model_registry_id", "prompt_version",
                        "base_sha", "head_sha", "context_id",
                    }
                    if envelope_fields <= set(schema.get("required", [])):
                        validation_errors.extend(validate_agent_result(run.output, schema, expected=synthetic))
                else:
                    validation_errors.append("benchmark_missing_structured_output")
                effective_success = run.success and not validation_errors
                if not effective_success:
                    score["score"] = 0.0
                case_results.append({
                    "case_id": case.case_id, "task_family": case.task_family,
                    "score": round(float(score["score"]), 6), "latency_seconds": latency,
                    "run_id": run.run_id, "success": effective_success, "checks": score["checks"],
                    "errors": sorted(set(validation_errors)), "input_tokens": run.input_tokens,
                    "output_tokens": run.output_tokens,
                })
            average = sum(item["score"] for item in case_results) / max(1, len(case_results))
            reliability = sum(1 for item in case_results if item["success"]) / max(1, len(case_results))
            results.append({
                "registry_id": candidate.registry_id, "provider": candidate.provider,
                "model": candidate.model, "available": True, "case_count": len(case_results),
                "quality": round(average, 6), "reliability": round(reliability, 6),
                "average_latency_seconds": (
                    sum(item["latency_seconds"] for item in case_results) / max(1, len(case_results))
                ),
                "cases": case_results,
            })
        return {
            "generated_at": utc_now(), "catalog_hash": sha256_bytes(canonical_json(self.router.catalog)),
            "benchmark_suite_hash": benchmark_suite_hash(cases),
            "results": results,
            "claim_boundary": (
                "Scores apply only to these explicit local cases and host configuration. "
                "They select execution resources but never replace deterministic evidence."
            ),
        }
