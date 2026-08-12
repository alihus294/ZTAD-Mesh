from pathlib import Path

path = Path("validation/apply_v430_core.py")
text = path.read_text(encoding="utf-8")
old = 'if cli.count(old_metrics) != 3:\n    raise SystemExit(f"cli.py: expected 3 benchmark metric persistence blocks, found {cli.count(old_metrics)}")'
new = 'if cli.count(old_metrics) != 1:\n    raise SystemExit(f"cli.py: expected 1 benchmark metric persistence block, found {cli.count(old_metrics)}")'
if text.count(old) != 1:
    raise SystemExit("Could not locate CLI metric assertion in core migration helper")
path.write_text(text.replace(old, new), encoding="utf-8")
