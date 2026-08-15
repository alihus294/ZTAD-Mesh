# Codex Plugin Installation — 4.3.9

Published release artifacts:

- `zero-trust-agentic-delivery-marketplace-4.3.9.zip` — recommended local Codex Marketplace archive;
- `zero-trust-agentic-delivery-plugin-4.3.9.zip` — standalone plugin archive;
- `CHECKSUMS.sha256` — SHA-256 list covering both archives.

Verify the downloaded release directory before installation:

```bash
python scripts/verify_release.py CHECKSUMS.sha256
```

Use the versioned Marketplace package for installation. Verify its SHA-256 and internal manifest, extract it to a stable local path, register the local Marketplace through official Codex plugin commands, install `zero-trust-agentic-delivery@ztad-local`, then start a fresh Codex session.

Do not copy only `SKILL.md` files. That omits hooks, providers, model routing, policies, schemas, controllers, tests, and references.

Before replacing an existing installation, the extracted archive itself should pass:

```bash
python -B scripts/verify_version_identity.py --profile distribution
python -B -m pytest -q
```

The release pipeline runs packaged regressions from the exact Plugin and Marketplace archives before publication; the Marketplace package is also exercised across Windows/Linux CI for installation-critical regressions. Since v4.3.5, policy-approved Python checks are bound to the exact active interpreter before process creation, and the Windows packaged regression gate is re-run from a fresh isolated venv under Python isolated mode.

After installation:

1. confirm plugin version `4.3.9` is enabled;
2. confirm fourteen explicit-only skills are present, including `$problem-investigation`;
3. confirm hook discovery/trust;
4. invoke `$zero-trust-delivery` explicitly;
5. run version-identity verification, bundle validation, host acceptance, provider probe, audit, and dry-run;
6. for reported defects, confirm the exact bug lifecycle policy/schema/controller is present and `DONE` is not a valid bug-lifecycle closure;
7. confirm the installed skill prompts require exact bad-base/candidate RED→GREEN, independent-review `PASS`, and protected non-model E6 authority rather than model `APPROVE` conversion;
8. inspect `mesh-autopilot --dry-run` and confirm the intended v4.3 topology and routes;
9. confirm every Sol route is capped at `HIGH` reasoning;
10. do not enable merge or production authority until external platform gates are verified.

Normal v4.3 routing intent is Luna-first for R0/R1 and the R2 implementation worker when eligible, Terra as balanced support/fallback, and Sol as the independent frontier guard/consultant. Actual-diff risk escalation always overrides the cheaper topology.
