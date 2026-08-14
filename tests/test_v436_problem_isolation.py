import subprocess
from pathlib import Path

from ztad.problem import initialize_problem_case
from ztad.problem_isolation import isolate_problem_case


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "ZTAD Test")
    (repo / ".gitignore").write_text(".delivery/ztad/\n", encoding="utf-8")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", ".gitignore", "app.py")
    _git(repo, "commit", "-m", "protected base")
    return repo


def test_isolation_preserves_divergent_dirty_user_worktree(tmp_path):
    repo = _repo(tmp_path)
    protected = _git(repo, "rev-parse", "main")
    _git(repo, "switch", "-c", "user-work")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "user commit")
    (repo / "notes.local").write_text("uncommitted user work\n", encoding="utf-8")
    original_head = _git(repo, "rev-parse", "HEAD")
    original_status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    original_bytes = (repo / "app.py").read_bytes()

    case = initialize_problem_case(repo, report="Reported issue", protected_ref="main")
    assert case["base_sha"] == protected
    assert case["local_head_sha"] == original_head
    assert case["worktree_status"]["dirty"] is True
    assert case["worktree_status"]["diverged_from_protected_base"] is True

    isolated = isolate_problem_case(case)
    worktree = Path(isolated["worktree"])
    try:
        assert worktree.is_dir()
        assert _git(worktree, "rev-parse", "HEAD") == protected
        assert (worktree / "app.py").read_text(encoding="utf-8") == "VALUE = 1\n"
        assert isolated["problem_case"]["worktree_status"]["user_worktree_preserved"] is True
        assert isolated["problem_case"]["worktree_status"]["isolated_clean_worktree"] is True
        assert isolated["evidence"]["authority"] == "LOCAL_NON_AUTHORITATIVE"
        assert isolated["evidence"]["can_grant_merge_release_or_production"] is False
        assert _git(repo, "rev-parse", "HEAD") == original_head
        assert _git(repo, "status", "--porcelain=v1", "--untracked-files=all") == original_status
        assert (repo / "app.py").read_bytes() == original_bytes
        assert (repo / "notes.local").read_text(encoding="utf-8") == "uncommitted user work\n"
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)], check=False, text=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "prune"], check=False, text=True, capture_output=True)
