from pathlib import Path

from ztad.bundle import validate_bundle
from ztad.policy_registry import audit_policy_wiring

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
    assert policy["consumers"] == ["ztad.bug_lifecycle"]
    assert policy["consumer_modules_available"] is True
