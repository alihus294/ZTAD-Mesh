from pathlib import Path

path = Path("validation/apply_v430_final_hardening.py")
text = path.read_text(encoding="utf-8")
old = '''new_replan_parent = \'\'\'        parent = self.continuity_store.get_task(node["task_id"])\\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\\n'''
new = '''new_replan_parent = \'\'\'        self._sync_continuity_phase(node)\\n        parent = self.continuity_store.get_task(node["task_id"])\\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate new_replan_parent migration block")
path.write_text(text.replace(old, new), encoding="utf-8")
