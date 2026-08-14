from ztad.approval_controller import APPROVAL_TYPES


def test_protected_bug_lifecycle_supervisor_approval_has_controller_issuer():
    assert "PROTECTED_SUPERVISOR_APPROVAL" in APPROVAL_TYPES
