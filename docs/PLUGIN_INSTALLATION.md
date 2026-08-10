# Codex Plugin Installation — 4.2.0

Distributed artifacts:

- `zero-trust-agentic-delivery-marketplace-4.2.0.zip` — recommended local Codex Marketplace;
- `zero-trust-agentic-delivery-plugin-4.2.0.zip` — standalone plugin source;
- `ZTAD_MESH_4.2.0_Final_Release.zip` — complete release, reports, evidence, and checksums.

Use the versioned Marketplace package for installation. Verify its SHA-256 and internal manifests, extract it to a stable local path, register the local Marketplace through official Codex plugin commands, install `zero-trust-agentic-delivery@ztad-local`, then start a fresh Codex session.

Do not copy only `SKILL.md` files. That omits hooks, providers, model router, policies, schemas, controllers, tests, and references.

After installation:

1. confirm the plugin is enabled;
2. confirm thirteen skills are present;
3. confirm hook discovery/trust;
4. invoke `$zero-trust-delivery` explicitly;
5. run host acceptance, provider probe, benchmark, audit, and dry-run;
6. do not enable merge or production authority until external platform gates are verified.
