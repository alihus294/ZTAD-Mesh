# ZTAD Mesh 4.3.11 Quick Start

1. Download the versioned Marketplace archive from the `v4.3.11` GitHub Release.
2. Download `CHECKSUMS.sha256` and verify the release files before installation.
3. Extract the Marketplace archive to a stable local path and install `zero-trust-agentic-delivery@ztad-local` through the official Codex plugin flow.
4. Close the installation session and start a fresh Codex session.
5. Confirm the plugin, hooks, and fourteen explicit-only skills are discovered and trusted.
6. In the target repository invoke `$zero-trust-delivery` explicitly.
7. Run host acceptance and provider probes. Run task-family benchmarks only when provider/model access is available.
8. Run repository `AUDIT`, then `DRY_RUN`; both must be structured and non-mutating.
9. For a reported problem, initialize the `problem-case`, isolate dirty/divergent owner work, and initialize `scripts/ztad_bug_lifecycle.py`. The authoritative bug case must progress through the exact fail-closed lifecycle and cannot use scheduler `DONE` as closure.
10. Create a validated Change Contract only after `CHANGE_PLANNED`.
11. Run `mesh-autopilot --dry-run` and inspect risk, model-call count, route preview, scopes, checks, and escalation behavior.
12. Start bounded operation only after dry-run and target-host gates pass.

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

On Windows, packaged install-critical validation must also pass from a fresh isolated virtual environment under Python isolated mode. Since v4.3.5, policy-approved `python` and `python3` checks are bound to the exact active interpreter before process creation, avoiding ambiguous base-runtime selection.

Source-checkout validation uses the stricter source profile:

```bash
python -B scripts/verify_version_identity.py --profile source
python -B evals/run_evals.py --output validation/eval-results.json
```

Problem flow:

```bash
python -B scripts/ztad.py problem-init --repo <REPOSITORY> --protected-ref main --report "<what happened>" --expected "<expected behavior>"
python -B scripts/ztad.py problem-isolate --case <CASE.json>
python -B scripts/ztad_bug_lifecycle.py init --problem-case <CASE.json> --output <LIFECYCLE.json> --profile workshopos --remote-repository alihus294/WorkshopOS
```

Practical local delivery flow:

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

Any upward actual-diff risk invalidates the weaker path and requires the stronger risk topology before approval may continue. A model result never grants merge or production authority. A bug is not `CLOSED` until protected production release and post-deploy verification are independently proven. Since v4.3.10, the protocol is also enforced by deterministic lifecycle, evidence-bundle, host-boundary, and adversarial-evaluation controls.

For a persistent local worker process, use `mesh-service` with explicit database, continuity database, worker ID, time bounds, and poll interval. An external process manager is required to restart that service after host or process failure.
