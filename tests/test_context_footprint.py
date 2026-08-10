import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_context_measurement_keeps_master_plan_outside_operational_skills(tmp_path):
    output = tmp_path / "context.json"
    proc = subprocess.run(["python3", str(ROOT / "scripts/measure_context.py"), "--output", str(output)], cwd=ROOT, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["passed"]
    assert report["skill_count"] == 13
    assert all(item["words"] <= report["max_skill_words"] for item in report["skills"])
    assert any(item["path"] == "references/MASTER_PLAN.md" for item in report["references"])
    assert all(item["path"] != "references/MASTER_PLAN.md" for item in report["skills"])
