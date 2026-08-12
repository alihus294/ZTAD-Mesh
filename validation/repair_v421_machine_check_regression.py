from pathlib import Path

path = Path("tests/test_v42_autopilot_redteam.py")
text = path.read_text(encoding="utf-8")
start_marker = "\ndef test_failed_machine_check_blocks_all_review_nodes(tmp_path):"
end_marker = "\ndef test_write_mesh_plan_rejects_output_escape_and_conflict_without_partial_write(tmp_path):"
start = text.find(start_marker)
end = text.find(end_marker, start + 1)
if start < 0 or end < 0:
    raise SystemExit("Could not locate timing-sensitive regression boundaries")

replacement = r'''
def test_non_succeeded_dependency_never_unlocks_review(tmp_path):
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="check", task_id="task", title="check", task_family="verification",
            role="check_runner", risk="R2", write_access=False, scopes=(),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=100,
        ),
        MeshNodeSpec.create(
            node_id="review", task_id="task", title="review", task_family="review",
            role="supervisor", risk="R2", write_access=False, scopes=(),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=90,
            dependencies=("check",),
        ),
    ])
    claimed = mesh.claim_ready("check-owner", limit=1)
    assert [node["node_id"] for node in claimed] == ["check"]
    finished = mesh.finish_node(
        "check", owner="check-owner", success=False, run_id="check-run",
        registry_id="deterministic-check-runner", provider="local",
        error="machine_checks_blocked", quarantine=True,
    )
    assert finished["state"] == "QUARANTINED"
    assert mesh.get_node("review")["state"] == "READY"
    assert mesh.claim_ready("review-owner", limit=8) == []


def test_failed_machine_check_blocks_all_review_nodes(tmp_path):
    import subprocess

    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "component"], cwd=repo, check=True, capture_output=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

    output_root = tmp_path / "outputs"
    output_root.mkdir()
    (repo / "src/component.py").write_text("VALUE = 2   \n", encoding="utf-8")
    patch_path = output_root / "integrated.patch"
    patch_path.write_bytes(subprocess.check_output(
        ["git", "diff", "--binary", base, "--", "src/component.py"], cwd=repo
    ))
    assert patch_path.stat().st_size > 0
    subprocess.run(["git", "reset", "--hard", base], cwd=repo, check=True, capture_output=True)

    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60,
            "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")

    contract = valid_contract(risk="R2", components=["src/component.py"])
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(
        repository=str(repo), title="bad whitespace", contract=contract, risk="R2",
        task_id="task", idempotency_key="task",
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    nodes = [
        MeshNodeSpec.create(
            node_id="integrated", task_id=task["task_id"], title="integrated patch",
            task_family="integration", role="patch_integrator", risk="R2",
            write_access=False, scopes=("src/component.py",), prompt_path="unused.md",
            output_schema=str(SCHEMA), priority=100, metadata={"base_sha": base},
        ),
        MeshNodeSpec.create(
            node_id="machine-check", task_id=task["task_id"], title="machine check",
            task_family="verification", role="check_runner", risk="R2",
            write_access=False, scopes=("src/component.py",), prompt_path="unused.md",
            output_schema=str(SCHEMA), priority=90, dependencies=("integrated",),
            metadata={
                "base_sha": base, "max_attempts": 1,
                "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
                "risk_policy": str(ROOT / "policies/risk-policy.yaml"),
            },
        ),
    ]
    for dimension in ("scope", "correctness", "tests"):
        nodes.append(MeshNodeSpec.create(
            node_id=f"review-{dimension}", task_id=task["task_id"],
            title=f"{dimension} review", task_family="review", role="supervisor",
            risk="R2", write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=80,
            dependencies=("machine-check",),
        ))
    mesh.submit_graph(nodes)

    claimed = mesh.claim_ready("fixture-owner", limit=1)
    assert [node["node_id"] for node in claimed] == ["integrated"]
    mesh.finish_node(
        "integrated", owner="fixture-owner", success=True, run_id="fixture-integration",
        registry_id="deterministic-integrator", provider="local",
    )
    mesh.register_artifact(
        node_id="integrated", artifact_type="COMBINED_PATCH",
        path=str(patch_path.resolve()), sha256=sha256_file(patch_path),
        metadata={"base_sha": base, "fixture": True},
    )

    provider = _TrailingWhitespaceProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog()), providers=ProviderRegistry([provider]),
        worker_id="worker", output_root=output_root, global_parallel_cap=8,
    )
    runtime.run_once()

    check = mesh.get_node("machine-check")
    reviews = [mesh.get_node(f"review-{dimension}") for dimension in ("scope", "correctness", "tests")]
    assert check["state"] == "QUARANTINED"
    assert check["last_error"] == "machine_checks_blocked"
    assert all(node["state"] == "READY" for node in reviews)
    assert mesh.claim_ready("review-owner", limit=8) == []
    assert provider.review_calls == 0
'''

path.write_text(text[:start] + "\n" + replacement.strip() + "\n\n" + text[end + 1:], encoding="utf-8")
