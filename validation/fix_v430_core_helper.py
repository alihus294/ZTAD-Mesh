from pathlib import Path

helper = Path("validation/apply_v430_core.py")
text = helper.read_text(encoding="utf-8")
old = 'if cli.count(old_metrics) != 3:\n    raise SystemExit(f"cli.py: expected 3 benchmark metric persistence blocks, found {cli.count(old_metrics)}")'
new = 'if cli.count(old_metrics) != 1:\n    raise SystemExit(f"cli.py: expected 1 benchmark metric persistence block, found {cli.count(old_metrics)}")'
if text.count(old) != 1:
    raise SystemExit("Could not locate CLI metric assertion in core migration helper")
helper.write_text(text.replace(old, new), encoding="utf-8")

test = Path("tests/test_v4_router_providers.py")
test_text = test.read_text(encoding="utf-8")
old_test = '''def test_router_quality_floor_prevents_cheap_model_for_normal_feature():\n    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")\n    decision = router.route(TaskProfile("implementation", "worker", "R2", complexity=3))\n    assert decision.candidate.registry_id in {"codex-terra", "codex-sol"}\n    assert decision.candidate.registry_id != "codex-luna"\n'''
new_test = '''def test_router_quality_floor_allows_benchmarked_luna_for_r2_and_falls_back_safely():\n    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")\n    profile = TaskProfile("implementation", "worker", "R2", complexity=3, preferred_registry_id="codex-luna")\n    decision = router.route(profile)\n    assert decision.candidate.registry_id == "codex-luna"\n    fallback = router.route(profile, unavailable_registry_ids={"codex-luna"})\n    assert fallback.candidate.registry_id == "codex-terra"\n'''
if test_text.count(old_test) != 1:
    raise SystemExit("Could not locate legacy R2 router regression")
test.write_text(test_text.replace(old_test, new_test), encoding="utf-8")
