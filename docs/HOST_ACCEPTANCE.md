# Target Host Acceptance — ZTAD Mesh 4.3.0

The package is not production-authoritative merely because it installs or because repository CI is green. Run these gates on the target Codex/GitHub/deployment environment.

## Mandatory local gates

1. Verify the published release with `CHECKSUMS.sha256`, then validate the extracted internal manifests.
2. Verify Python 3.11+ and the exact reviewed dependency locks. Governed signing requires the reviewed `cryptography` range.
3. Validate the installed bundle and all 13 explicit-only skills.
4. Trust and exercise the installed Codex hooks; verify their exact hash.
5. Probe every configured provider without exposing credentials.
6. Run the version/context-bound model benchmark suite when live provider access exists. Benchmark results are routing evidence, not authority.
7. Run repository `AUDIT`, then `DRY_RUN`; require structured output and zero unexpected repository mutation.
8. Inspect `mesh-autopilot --dry-run`: risk, route preview, model-call count, scopes, checks, and escalation path must match policy.
9. Exercise disposable fixtures for the v4.3 risk paths:
   - R0/R1 normal path: Luna implementation → deterministic integration/checks → one Sol final guard;
   - R2 bounded path: Luna preferred worker with Terra support/fallback;
   - R3/R4 full Mesh;
   - upward actual-diff risk must invalidate the weaker path and create the stronger replan.
10. Verify every Sol request is capped at `HIGH` reasoning or lower.
11. Kill and restart the mesh service; verify lease recovery and no duplicate execution.
12. Verify all model/provider artifacts remain outside application worktrees and that stale artifacts are rejected.

## GitHub/CI gates

- protected default branch or equivalent repository ruleset;
- no unreviewed direct push for governed delivery;
- required exact-SHA CI checks;
- stale-review dismissal where human reviews are authoritative;
- merge queue or equivalent current-main validation for high-assurance repositories;
- protected workflow/CODEOWNERS paths where required;
- least-privilege workflow tokens;
- release tags bound to exact CI-approved commits;
- deterministic release assets with independently verified checksums;
- protected build provenance/attestation where the target platform requires it;
- environment-scoped deployment credentials and OIDC where supported.

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

Any missing gate lowers the mode. Presence of `git`, `gh`, a template, a policy file, a release asset, or an adapter is not proof that the external control is enforced.
