---
name: delivery-bootstrap
description: Audit, dry-run, install, update, or uninstall the zero-trust delivery package in one software repository. Trigger only when explicitly invoked for lifecycle management; do not use for feature implementation.
---

# Modes

Use exactly one explicit mode: `AUDIT`, `DRY_RUN`, `INSTALL`, `UPDATE`, or `UNINSTALL`.

# Procedure

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py audit --repo <REPO>
python3 <PLUGIN_ROOT>/scripts/ztad.py dry-run --repo <REPO>
python3 <PLUGIN_ROOT>/scripts/ztad.py install --repo <REPO>
python3 <PLUGIN_ROOT>/scripts/ztad.py update --repo <REPO>
python3 <PLUGIN_ROOT>/scripts/ztad.py uninstall --repo <REPO>
```

1. Never overwrite an unmanaged or locally modified file.
2. Reject symlink targets and symlink ancestors.
3. `DRY_RUN` performs no mutation.
4. `UPDATE` changes only managed content whose current hash still matches the installation manifest. Conflicts are preserved and a candidate is written separately.
5. A modified managed `AGENTS.md` block is never silently replaced or removed.
6. Repeating an unchanged installation is byte-for-byte idempotent.
7. CI installation is off by default. `--activate-ci` is explicit and still reports remote enforcement as unverified.
8. File creation does not prove branch rules, required checks, merge queue, environments, OIDC, attestations, or runtime monitoring.

# Output

Return planned/applied actions, conflicts, mutation status, capability report, maximum permitted mode, and all controls that remain unverified.
