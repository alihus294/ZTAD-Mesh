from pathlib import Path

from ztad.bundle import validate_bundle
from ztad.policy_registry import audit_policy_wiring
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def test_v437_exact_lifecycle_surfaces_are_packaged_and_bundle_valid():
    required = [
        "policies/bug-to-production-policy.yaml",
        "schemas/bug-lifecycle.schema.json",
        "toolkit/ztad/bug_lifecycle.py",
        "scripts/ztad_bug_lifecycle.py",
        "docs/BUG_TO_PRODUCTION_PROTOCOL.md",
    ]
    for relative in required:
        assert (ROOT / relative).is_file(), relative
    report = validate_bundle(ROOT)
    assert report["valid"], report["errors"]


def test_v437_bug_lifecycle_policy_is_declared_and_wired():
    report = audit_policy_wiring(ROOT)
    assert report["valid"], report["errors"]
    matched = [item for item in report["policies"] if item["name"] == "bug-to-production-policy.yaml"]
    assert len(matched) == 1
    policy = matched[0]
    assert policy["mode"] == "DETERMINISTIC_AND_PLATFORM_RUNTIME"
    assert policy["consumers"] == ["ztad.bug_lifecycle", "ztad.bug_protocol", "ztad.evidence_bundle"]
    assert policy["consumer_modules_available"] is True


def test_v437_release_and_security_gates_match_protocol_and_traceability():
    policy = load_data(ROOT / "policies/bug-to-production-policy.yaml")
    targeted = policy["gates"]["TARGETED_VALIDATION_PASS"]["by_domain"]
    assert {"SECURITY_VALIDATION_PASSED", "SECRETS_SCAN_PASSED", "FAIL_CLOSED_BOUNDARY_PASSED"}.issubset(targeted["SECURITY"])
    assert policy["gates"]["STAGING_PASS"]["minimum_trust"] == "E5"
    assert "PROTECTED_SUPERVISOR_APPROVAL" in policy["gates"]["READY_FOR_OWNER_RELEASE"]["required_evidence"]
    assert "PROTECTED_RELEASE_AUTHORIZATION" in policy["gates"]["PRODUCTION_RELEASED"]["required_evidence"]

    matrix = (ROOT / "traceability/TRACEABILITY_MATRIX.md").read_text(encoding="utf-8")
    assert "Active normative requirements: **174**." in matrix
    assert "28. Exact fail-closed bug-to-production lifecycle | 15" in matrix
    assert "29. Machine-enforced fail-closed protocol completion | 19" in matrix
    assert "30. Immutable delivery subject and invalidation | 5" in matrix
    assert "31. Controller-owned lifecycle authority | 5" in matrix
    assert "32. Canonical risk, domain, and evidence enforcement | 6" in matrix
    assert "33. Terminal classes and exceptional release flows | 5" in matrix
