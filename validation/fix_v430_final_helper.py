from pathlib import Path

path = Path("validation/apply_v430_final_hardening.py")
text = path.read_text(encoding="utf-8")
old = '''        parent = self.continuity_store.get_task(node["task_id"])\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\n'''
new = '''        self._sync_continuity_phase(node)\n        parent = self.continuity_store.get_task(node["task_id"])\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate replan parent transition block")
path.write_text(text.replace(old, new), encoding="utf-8")
