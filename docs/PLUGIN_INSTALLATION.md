# Codex Plugin Installation — 4.3.3

Published release artifacts:

- `zero-trust-agentic-delivery-marketplace-4.3.3.zip` — recommended local Codex Marketplace archive;
- `zero-trust-agentic-delivery-plugin-4.3.3.zip` — standalone plugin archive;
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

The release pipeline runs packaged regressions from the exact Plugin and Marketplace archives before publication; the Marketplace package is also exercised across Windows/Linux CI for installation-critical regressions. In v4.3.3 the Windows check helper preserves the active virtual-environment interpreter directory and does not resolve the venv launcher to a base Python runtime.

After installation:

1. confirm plugin version `4.3.3` is enabled;
2. confirm thirteen explicit-only skills are present;
3. confirm hook discovery/trust;
4. invoke `$zero-trust-delivery` explicitly;
5. run version-identity verification, bundle validation, host acceptance, provider probe, audit, and dry-run;
6. inspect `mesh-autopilot --dry-run` and confirm the intended v4.3 topology and routes;
7. confirm every Sol route is capped at `HIGH` reasoning;
8. do not enable merge or production authority until external platform gates are verified.

Normal v4.3 routing intent is Luna-first for R0/R1 and the R2 implementation worker when eligible, Terra as balanced support/fallback, and Sol as the independent frontier guard/consultant. Actual-diff risk escalation always overrides the cheaper topology.
