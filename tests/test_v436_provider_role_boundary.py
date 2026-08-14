import json
import sys
from pathlib import Path

from ztad.providers import GenericStructuredCommandProvider, ProviderRunRequest

ROOT = Path(__file__).resolve().parents[1]


def _agent_result(role: str) -> dict:
    return {
        "schema_version": 1,
        "task_id": "TEST-100",
        "agent_role": role,
        "model_registry_id": "test-registry",
        "prompt_version": "test-v1",
        "base_sha": "0" * 40,
        "head_sha": "1" * 40,
        "context_id": "sha256:" + "c" * 64,
        "result_type": "PLAN_READY",
        "claims": [],
        "findings": [],
        "files_read": [],
        "files_not_read": [],
        "uncertainties": [],
        "tested_scope": [],
        "untested_scope": [],
        "known_unknowns": [],
        "requested_action": "VALIDATE_PLAN",
        "patch_path": None,
        "risk_escalation": None,
    }


def test_test_designer_alias_is_normalized_before_strict_schema_validation(tmp_path):
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps(_agent_result("test_designer")), encoding="utf-8")
    script = tmp_path / "provider.py"
    script.write_text(
        "import json, pathlib, sys\n"
        "payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
        "pathlib.Path(sys.argv[2]).write_text(json.dumps(payload), encoding='utf-8')\n"
        "print(json.dumps({'session_id':'test-session','input_tokens':1,'output_tokens':1}))\n",
        encoding="utf-8",
    )
    artifacts = tmp_path / "artifacts"
    provider = GenericStructuredCommandProvider(
        name="test-provider",
        executable=sys.executable,
        argv_template=(str(script), str(payload), "{output}"),
        output_dir=artifacts,
    )
    request = ProviderRunRequest(
        task_id="TEST-100",
        role="planner",
        registry_id="test-registry",
        model="test-model",
        reasoning_effort="high",
        sandbox="read-only",
        prompt="Plan only.",
        output_schema=ROOT / "schemas/agent-result.schema.json",
        cwd=tmp_path,
        run_id="role-alias",
        artifact_dir=artifacts,
    )
    result = provider.run(request)
    assert result.success, result.errors
    assert result.output is not None
    assert result.output["agent_role"] == "planner"
    assert not any(item.startswith("schema:") for item in result.errors)
    assert result.request_fingerprint
    assert result.receipt_hash
