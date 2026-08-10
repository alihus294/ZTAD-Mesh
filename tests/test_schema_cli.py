import json
from pathlib import Path

from ztad.cli import build_parser, execute
from ztad.schema_validation import validate_file, validate_instance
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def test_example_contract_matches_schema():
    errors = validate_file(ROOT/"templates/repository/.delivery/change-contract.example.yaml", ROOT/"schemas/change-contract.schema.json")
    assert errors == []


def test_example_agent_result_matches_schema():
    data = load_data(ROOT/"examples/agent-result.json")
    schema = load_data(ROOT/"schemas/agent-result.schema.json")
    errors = validate_instance(data, schema)
    assert errors == []


def test_cli_parser_has_expected_commands():
    parser = build_parser()
    help_text = parser.format_help()
    assert "classify-risk" in help_text
    assert "release-readiness" in help_text
    assert "build-distribution" in help_text
    assert "validate-distribution" in help_text
    assert "verify-checksums" in help_text


def test_cli_contract_only_risk():
    parser = build_parser()
    args = parser.parse_args(["classify-risk","--contract",str(ROOT/"templates/repository/.delivery/change-contract.example.yaml")])
    result, code = execute(args)
    # Template intentionally contains an unverified assumption and therefore fails closed.
    assert code == 3
    assert result["mode"] == "CONTRACT_ONLY"
    assert result["blocked"]


def test_check_example_is_intentionally_inactive():
    data = json.loads((ROOT/"templates/repository/.delivery/ztad/config.example.json").read_text())
    assert data["configured"] is False


def test_capability_report_matches_schema(tmp_path):
    from ztad.capabilities import detect_capabilities
    report = detect_capabilities(tmp_path)
    schema = load_data(ROOT / "schemas/capability-report.schema.json")
    assert validate_instance(report, schema) == []
    assert report["maximum_permitted_mode"] == "AUDIT_ONLY"


def test_skill_openai_metadata_uses_current_supported_policy_shape():
    import yaml
    for path in ROOT.glob("skills/*/agents/openai.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert set(data.get("policy", {})) == {"allow_implicit_invocation"}
        assert data["policy"]["allow_implicit_invocation"] is False
        assert f"${path.parent.parent.name}" in data["interface"]["default_prompt"]
