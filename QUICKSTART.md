# ZTAD Mesh 4.3.3 Quick Start

1. Download the versioned Marketplace archive from the `v4.3.3` GitHub Release.
2. Download `CHECKSUMS.sha256` and verify the release files before installation.
3. Extract the Marketplace archive to a stable local path and install `zero-trust-agentic-delivery@ztad-local` through the official Codex plugin flow.
4. Close the installation session and start a fresh Codex session.
5. Confirm the plugin, hooks, and thirteen explicit-only skills are discovered and trusted.
6. In the target repository invoke `$zero-trust-delivery` explicitly.
7. Run host acceptance and provider probes. Run task-family benchmarks only when provider/model access is available.
8. Run repository `AUDIT`, then `DRY_RUN`; both must be structured and non-mutating.
9. Create a validated Change Contract.
10. Run `mesh-autopilot --dry-run` and inspect risk, model-call count, route preview, scopes, checks, and escalation behavior.
11. Start bounded operation only after dry-run and target-host gates pass.

Release verification:

```bash
python scripts/verify_release.py CHECKSUMS.sha256
```

Extracted package validation:

```bash
python -B scripts/verify_version_identity.py --profile distribution
python -B scripts/ztad.py validate-bundle --root .
python -B scripts/ztad.py policy-wiring --root .
python -B -m pytest -q
```

On Windows, run packaged checks from the active virtual environment. The v4.3.3 regression helper preserves the active `sys.executable` directory and must not resolve a venv launcher to the base Python runtime.

Source-checkout validation uses the stricter source profile:

```bash
python -B scripts/verify_version_identity.py --profile source
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

Normal routing intent:

- R0/R1: deterministic index → Luna implementation → deterministic integration/checks and actual-diff risk → one Sol final guard.
- R2: bounded topology with Luna as preferred worker and Terra as focused support/fallback.
- R3/R4: full independent Mesh.
- Every Sol invocation is hard-capped at `HIGH` reasoning.

Any upward actual-diff risk invalidates the weaker path and requires the stronger risk topology before approval may continue. A model result never grants merge or production authority.

For a persistent local worker process, use `mesh-service` with explicit database, continuity database, worker ID, time bounds, and poll interval. An external process manager is required to restart that service after host or process failure.
