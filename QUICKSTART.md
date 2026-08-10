# ZTAD Mesh 4.2.0 Quick Start

1. Install the versioned Codex Marketplace package.
2. Close the installation session and start a fresh Codex session.
3. Verify the plugin, hooks, and thirteen explicit-only skills.
4. In the target repository invoke `$zero-trust-delivery`.
5. Run host acceptance, provider probes, and task-family benchmarks.
6. Run repository `AUDIT`, then `DRY_RUN`.
7. Create a validated Change Contract.
8. Run `mesh-autopilot --dry-run` and inspect the planned DAG, scopes, routes, checks, and risk policy.
9. Start bounded operation only after dry-run and target-host gates pass.

Local package validation:

```bash
python -B scripts/ztad.py validate-bundle --root .
python -B scripts/ztad.py policy-wiring --root .
python -B -m pytest -q
python -B evals/run_evals.py --output validation/eval-results.json
```

Practical local flow:

```bash
python -B scripts/ztad.py host-acceptance --plugin-root . --repo <REPOSITORY>
python -B scripts/ztad.py provider-probe
python -B scripts/ztad.py model-benchmark --repo <REPOSITORY>
python -B scripts/ztad.py mesh-autopilot --repo <REPOSITORY> --contract <CONTRACT.json> --dry-run
python -B scripts/ztad.py mesh-autopilot --repo <REPOSITORY> --contract <CONTRACT.json>
```

For a persistent local worker process, use `mesh-service` with explicit database, continuity database, worker ID, time bounds, and poll interval. An external process manager is required to restart that service after host or process failure.
