# Target Host Acceptance — ZTAD Mesh 4.2.0

The package is not production-authoritative merely because it installs. Run these gates on the target Windows/Codex/GitHub/deployment environment.

## Mandatory local gates

1. Verify release and distribution checksums.
2. Verify Python 3.11+ and locked dependency ranges. Governed signing requires `cryptography >=50.0.0,<51`.
3. Validate the installed bundle and all 13 explicit-only skills.
4. Trust and exercise the installed Codex hooks; verify their exact hash.
5. Probe every configured provider without exposing credentials.
6. Run the version-bound model benchmark suite.
7. Run repository `AUDIT`, then `DRY_RUN` with zero unexpected mutation.
8. Exercise one disposable fixture through index → plan → worktree → integration → checks → review.
9. Kill and restart the mesh service; verify lease recovery and no duplicate execution.
10. Verify all model artifacts stay outside application worktrees.

## GitHub/CI gates

- protected default branch and required checks;
- stale-review dismissal and merge queue behavior;
- exact-SHA CI evidence;
- immutable build artifact and provenance/attestation validation;
- least-privilege token/OIDC configuration;
- no Agent credential with direct merge or production authority.

## Deployment gates

- staging smoke and synthetic transactions;
- bounded canary progression;
- conclusive metric policy;
- automatic stop and rollback;
- rollback rehearsal against the exact deployment adapter;
- database expand/migrate/contract strategy for schema changes.

## Mode ceiling

| Verified capabilities | Maximum mode |
|---|---|
| package only | OFFLINE_DISTRIBUTION_ONLY |
| local host, providers and dry-run | GOVERNED_LOCAL_DEVELOPMENT |
| protected GitHub and CI | GOVERNED_PULL_REQUEST_CANDIDATE |
| staging/canary/rollback proven | GOVERNED_DELIVERY |

Any missing gate lowers the mode. Presence of `git`, `gh`, a template, a policy file or an adapter is not proof that the external control is enforced.
