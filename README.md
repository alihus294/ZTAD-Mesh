# Zero-Trust Agentic Delivery Mesh 4.3.10

ZTAD Mesh is a Codex plugin and deterministic control toolkit for bounded software delivery. Version 4.3 makes orchestration proportional to verified risk: trivial and low-risk work uses a guarded fast path, normal feature work uses a bounded mesh, and sensitive/high-risk work retains the full independent mesh.

## Operating objective

ZTAD targets **never idle while safe runnable work exists** without turning model confidence into authority. A blocked task is repaired, re-planned, re-routed, reconstructed, delayed, or quarantined while unrelated ready work continues. State is durable on one host and can be resumed after process interruption.

## Risk-proportional topology

| Risk | Normal topology | Intended model calls |
|---|---|---:|
| R0 / R1 | deterministic index → Luna worker → deterministic integration/checks → actual-diff risk → one Sol final guard | 2 |
| R2 | deterministic index → focused Terra scout → Luna worker → deterministic integration/checks → up to two focused Terra reviews | bounded |
| R3 / R4 | full context/plan/test/implementation/review mesh with frontier gates | risk-dependent |

The low-risk path is deliberately small. It does not run redundant scout, plan-adjudication, test-oracle, review-fan-out, synthesis, or release-advisor model calls. If the actual candidate diff raises risk, the lower-risk topology is invalidated and a stronger child plan must complete before approval can continue.

## What 4.3.10 implements

- fail-closed problem investigation before patching, with source-of-truth resolution, classification, reproduction/root-cause proof, blast-radius mapping, clean isolation, and mandatory exact bad-base/exact-candidate same-oracle RED→GREEN regression evidence for code-fix closure;
- an explicit authoritative bug-to-production lifecycle from `UNVERIFIED_REPORT` through `CLOSED`, with separate `PATCH_IMPLEMENTED`, `REGRESSION_TEST_PROVEN`, validation, review, CI, staging, owner-release, production-release, and post-deploy states;
- explicit skill-level authority separation: supervisor/model `APPROVE` is advisory only, cannot be converted mechanically into E6, independent review must bind a distinct-session `PASS`, and `PRODUCTION_VERIFIED` cannot substitute for `POST_DEPLOY_VERIFIED → CLOSED`;
- `DONE` is not a bug-lifecycle state; a code-fix case cannot close before `POST_DEPLOY_VERIFIED`;
- deterministic repository indexing before model calls;
- Luna as the preferred low/medium-risk implementation worker when it remains eligible;
- Terra as balanced fallback and focused R2 support;
- Sol as independent frontier consultant/reviewer with a **hard HIGH reasoning ceiling** on every invocation;
- exact model-call count and route preview in dry-run output;
- provider availability checks and qualified fallback;
- catalog/benchmark performance bound to catalog and provider-capability context;
- minimum repeated observations before measured performance can influence routing;
- writer quality updated from downstream integration/check outcomes instead of schema validity alone;
- bounded structured controls for blocking findings, context expansion, repair, replan, risk escalation, quarantine, and strong-supervisor requests;
- dedicated worktrees and non-overlapping scope locks for writers;
- deterministic patch integration into one candidate commit;
- machine-check gate before independent review;
- actual-diff risk reclassification with automatic upward replan;
- exact run/session/SHA/diff/evidence binding for approvals;
- no automatic transition to `MERGE_READY` from model success;
- loop fingerprints, measurable-progress requirements, bounded repair budgets, quarantine, and explicit reactivation;
- deterministic Plugin/Marketplace builds with post-publication checksum verification;
- canonical release-version verification split correctly between repository-only and packaged runtime/install surfaces;
- packaged regression execution from the exact release archives before publication, including cross-platform installation-critical checks;
- policy-approved `python`/`python3` checks are executed through the exact active Python interpreter instead of relying on ambiguous Windows executable search order;
- isolated Windows venv packaged-regression CI is executed with Python isolated mode to reproduce the clean-install boundary;
- conservative host-acceptance and platform-readiness reporting.

## Fourteen explicit-only skills

- `$zero-trust-delivery`
- `$problem-investigation`
- `$multi-model-mesh`
- `$delivery-bootstrap`
- `$change-intake-risk`
- `$implementation-strategy`
- `$code-change-verification`
- `$independent-review`
- `$finding-verification-repair`
- `$release-readiness`
- `$delivery-retrospective`
- `$autonomous-continuity`
- `$supervisor-governance`
- `$recovery-and-takeover`

## Authority model

```text
Models propose or write bounded patches
→ deterministic tools create facts
→ one candidate SHA is built and checked
→ independent review proposes a decision
→ approval controller validates exact run/SHA/diff/evidence identity
→ protected platform controllers merge or deploy
→ runtime evidence promotes or rolls back
```

A model response is never CI evidence, approval evidence, deployment evidence, or proof of production health.

## Verified release artifacts

The release workflow is CI-gated. After a successful `main` CI run it:

1. checks out the exact CI-approved commit and refuses stale-main publication;
2. validates canonical source version identity before distribution publication;
3. re-runs release-critical regressions with `ResourceWarning` treated as an error;
4. builds Plugin and Marketplace distributions twice and compares them byte-for-byte;
5. validates both archives and their internal manifests;
6. executes regressions from the exact packaged archives before any tag or release is created;
7. creates `CHECKSUMS.sha256`;
8. creates an exact commit-bound version tag and publishes without overwriting an existing release;
9. re-downloads the public assets and verifies checksums, archive validity, and packaged install-critical regressions again.

After downloading the release files, verify them before installation:

```bash
python scripts/verify_release.py CHECKSUMS.sha256
```

For an extracted Plugin/Marketplace package, use the distribution profile rather than requiring repository-only `.github` metadata:

```bash
python -B scripts/verify_version_identity.py --profile distribution
```

## Safe first run

```bash
python -B scripts/ztad.py validate-bundle --root .
python -B scripts/ztad.py policy-wiring --root .
python -B scripts/ztad.py host-acceptance --plugin-root . --repo /path/to/repository
python -B scripts/ztad.py provider-probe
python -B scripts/ztad.py model-benchmark --repo /path/to/repository
python -B scripts/ztad.py mesh-autopilot --repo /path/to/repository --contract /path/to/change-contract.json --dry-run
```

Inspect the dry-run execution mode, model-call count, route preview, scopes, check configuration, and risk policy before bounded operation.

## Claim boundary

The bundled SQLite stores provide durable single-host coordination, not multi-host high availability. Local validation and repository CI do not prove hosted model quality, provider credentials, GitHub rulesets, merge queue, deployment, canary health, or rollback on a target environment. Those remain mandatory target-host acceptance gates.

## Operational references

- `QUICKSTART.md` — installation and first-run sequence.
- `docs/ARCHITECTURE.md` — risk-proportional architecture and authority boundaries.
- `docs/MODEL_SELECTION.md` — model eligibility, preferences, benchmark freshness, and reasoning ceilings.
- `docs/OPERATING_GUIDE.md` — operating paths, escalation, and recovery.
- `docs/HOST_ACCEPTANCE.md` — mandatory target-host gates.
- `docs/PLUGIN_INSTALLATION.md` — versioned release installation.
- `docs/VALIDATION_REPORT.md` — executed validation evidence and claim boundaries.
