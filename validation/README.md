# Validation evidence

This directory contains the curated offline evidence for ZTAD Mesh 4.2.0.

- `unit-tests-v42-final.txt` — full unit and integration result.
- `coverage-v42-final.txt` — branch-aware repository coverage.
- `coverage-toolkit-v42-final.txt` — branch-aware `ztad` package coverage.
- `eval-summary-v42-final.json` — offline deterministic and adversarial evals.
- `bundle-validation-v42-final.json` — plugin bundle validation.
- `policy-wiring-v42-final.json` — policy consumer classification and availability.
- `external-validation-v42-final.json` — bounded fuzz and process-concurrency results.
- `mutation-v42.json` — selected critical mutation results and source-preservation proof.
- `release-validation-v42-final.json` — reproducibility and extracted-distribution test summary.
- `runtime-environment-v42-final.json` — exact local interpreter/package evidence and the unresolved exact-lock boundary.
- `run_v42_external_validation.py` and `run_v42_mutations.py` — reproducible local validation runners.

These files prove only the recorded offline checks. They do not prove hosted model quality, Codex host discovery, GitHub enforcement, CI protection, deployment, canary health, rollback, or production safety on a target system.
