# Contributing

Changes to application-like documentation, toolkit code, policies, schemas, tests, skills, or CI templates must be isolated by purpose. Never combine a control-plane relaxation with unrelated functionality.

Run before submission:

```bash
python3 -m compileall -q toolkit scripts evals tests
python3 -m pytest -q
python3 evals/run_evals.py
python3 scripts/ztad.py validate-bundle --root .
```

A control change must update relevant tests, evals, traceability, documentation, and `CHANGELOG.md`. Security-critical behavior cannot rely only on natural-language skill instructions when deterministic enforcement is feasible.
