from pathlib import Path

from ztad.risk import classify_risk, max_risk, score_to_risk
from ztad.repository import GitRepository
from ztad.risk import classify_repository_change

from conftest import commit_files, init_git_repo, valid_contract


def policy():
    from ztad.util import load_data
    return load_data(Path(__file__).resolve().parents[1] / "policies/risk-policy.yaml")


def test_risk_order_helpers():
    assert max_risk("R1", "R3", "R2") == "R3"
    assert score_to_risk(2) == "R0"
    assert score_to_risk(3) == "R1"
    assert score_to_risk(7) == "R2"
    assert score_to_risk(17) == "R4"


def test_contract_only_can_be_r0():
    result = classify_risk(valid_contract(), policy=policy())
    assert result.risk == "R0"
    assert not result.blocked


def test_requested_risk_is_floor():
    result = classify_risk(valid_contract(risk="R3"), policy=policy())
    assert result.risk == "R3"


def test_unverified_assumption_blocks_and_escalates():
    contract = valid_contract()
    contract["requirements"]["assumptions"][0]["status"] = "unverified"
    result = classify_risk(contract, policy=policy())
    assert result.blocked
    assert result.risk in {"R2", "R3", "R4"}


def test_missing_test_oracle_blocks():
    contract = valid_contract()
    contract["verification"]["test_oracles"] = []
    result = classify_risk(contract, policy=policy())
    assert result.blocked
    assert any("oracle" in item.lower() for item in result.blockers)


def test_auth_path_is_r3():
    result = classify_risk(valid_contract(), changed_paths=["auth/session.py"], policy=policy())
    assert result.risk == "R3"


def test_rls_path_is_r3():
    result = classify_risk(valid_contract(), changed_paths=["supabase/policies/accounts.sql"], policy=policy())
    assert result.risk == "R3"


def test_dependency_manifest_is_r3():
    result = classify_risk(valid_contract(), changed_paths=["requirements.txt"], policy=policy())
    assert result.risk == "R3"


def test_destructive_sql_is_r4():
    diff = "+++ b/migrations/002.sql\n+DROP TABLE accounts;\n"
    result = classify_risk(valid_contract(), changed_paths=["migrations/002.sql"], diff_text=diff, policy=policy())
    assert result.risk == "R4"


def test_unbounded_update_is_r4():
    diff = "+++ b/migrations/002.sql\n+UPDATE accounts SET enabled = false;\n"
    result = classify_risk(valid_contract(), changed_paths=["migrations/002.sql"], diff_text=diff, policy=policy())
    assert result.risk == "R4"


def test_mixed_control_and_application_is_r4():
    result = classify_risk(valid_contract(), changed_paths=[".github/workflows/ci.yml", "src/app.py"], policy=policy())
    assert result.risk == "R4"


def test_financial_contract_escalates():
    contract = valid_contract(data_class="C2", criticality="tier_1", components=["pricing", "invoice"])
    contract["title"] = "Correct invoice tax pricing"
    result = classify_risk(contract, policy=policy())
    assert result.risk in {"R3", "R4"}
    assert result.dimensions["financial_regulatory"] == 4


def test_repository_classification_uses_exact_diff(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo, {"auth/session.py": "def login():\n    return True\n"})
    result = classify_repository_change(GitRepository(repo), valid_contract(), base, head, Path(__file__).resolve().parents[1] / "policies/risk-policy.yaml")
    assert result.risk == "R3"


def test_where_in_later_statement_does_not_hide_unbounded_update():
    diff = """+++ b/migrations/003.sql
+UPDATE accounts SET enabled = false;
+UPDATE audit SET reviewed = true WHERE id = 1;
+"""
    result = classify_risk(valid_contract(), changed_paths=["migrations/003.sql"], diff_text=diff, policy=policy())
    assert result.risk == "R4"
    assert any("unbounded_update" in reason for reason in result.reasons)


def test_nested_agents_file_mixed_with_application_is_r4():
    result = classify_risk(valid_contract(), changed_paths=["src/AGENTS.md", "src/app.py"], policy=policy())
    assert result.risk == "R4"
    assert any("control-plane" in reason for reason in result.reasons)
