from pathlib import Path

from ztad.control_plane import detect_control_plane_changes, scan_patch_text
from ztad.test_weakening import detect_test_weakening_from_diff, inspect_repository_test_integrity
from ztad.util import load_data
from ztad.repository import GitRepository

from conftest import commit_files, init_git_repo

ROOT = Path(__file__).resolve().parents[1]
PATH_POLICY = load_data(ROOT / "policies/path-policy.yaml")


def test_protected_path_blocks():
    result = detect_control_plane_changes([".github/workflows/ci.yml"], PATH_POLICY)
    assert result["blocked"]
    assert result["protected_paths"] == [".github/workflows/ci.yml"]


def test_mixed_change_blocks():
    result = detect_control_plane_changes([".delivery/policy.yaml", "src/app.py"], PATH_POLICY)
    codes = {item["code"] for item in result["findings"]}
    assert "MIXED_CONTROL_AND_APPLICATION_CHANGE" in codes


def test_application_only_is_not_control_blocked():
    result = detect_control_plane_changes(["src/app.py"], PATH_POLICY)
    assert not result["blocked"]


def test_patch_traversal_detected():
    findings = scan_patch_text("--- a/ok\n+++ b/../escape\n")
    assert any(item["code"] == "UNSAFE_PATCH_PATH" for item in findings)


def test_binary_patch_detected():
    assert any(item["code"] == "BINARY_PATCH" for item in scan_patch_text("GIT binary patch\n"))


def test_symlink_mode_detected():
    findings = scan_patch_text("new file mode 120000\n")
    assert any(item["code"] == "SYMLINK_MODE_CHANGE" for item in findings)


def test_added_skip_blocks():
    diff = "+++ b/tests/test_x.py\n+@pytest.mark.skip\n+def test_x(): pass\n"
    findings = detect_test_weakening_from_diff(diff)
    assert any(item.code == "SKIP_ADDED" for item in findings)


def test_removed_assertion_blocks():
    diff = "+++ b/tests/test_x.py\n-    assert value == 1\n"
    findings = detect_test_weakening_from_diff(diff)
    assert any(item.code == "ASSERTION_REMOVED" for item in findings)


def test_continue_on_error_blocks():
    diff = "+++ b/.github/workflows/ci.yml\n+      continue-on-error: true\n"
    findings = detect_test_weakening_from_diff(diff)
    assert any(item.code == "CI_CONTINUE_ON_ERROR" for item in findings)


def test_repository_integrity_check(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    head = commit_files(repo, {"tests/test_x.py": "import pytest\n@pytest.mark.skip\ndef test_x(): pass\n"})
    result = inspect_repository_test_integrity(GitRepository(repo), base, head)
    assert result["blocked"]


def test_gitmodules_is_prohibited_even_without_application_mix():
    result = detect_control_plane_changes([".gitmodules"], PATH_POLICY)
    assert result["blocked"]
    assert result["prohibited_paths"] == [".gitmodules"]
