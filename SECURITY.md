# Security Policy

## Reportable issues

Report command-policy escapes, writes outside the repository/worktree, stale provider-output replay, fabricated-evidence acceptance, run/SHA identity mismatch, scope-lock bypass, test weakening, approval-role collision, ledger corruption, archive extraction defects, secret exposure, or control-plane mutation through the project owner's private security channel. Do not include live credentials or production data.

## Non-waivable boundaries

- models receive no merge authority, production credentials, signing keys, or unrestricted network by default;
- provider output artifacts remain outside code worktrees;
- every writer uses a bounded scope and isolated worktree;
- one deterministic candidate SHA and successful machine checks are required before review;
- actual-diff risk can increase but cannot be silently downgraded;
- implementation runs cannot independently approve their own candidate;
- supervisor takeover requires a fresh closure review;
- evidence must bind to the exact task, contract, SHA, diff, policy, toolchain, artifact, and environment fields required by its gate;
- hosted enforcement is never inferred from generated files or local configuration;
- dangerous actions fail closed locally while unrelated safe runnable work continues.

## Supported version

Version 4.2.x receives security corrections. Model catalogs are routing priors, not security evidence. A model, prompt, provider adapter, hook, policy, or controller change must pass the relevant regression, adversarial, concurrency, scope, archive, and selected mutation tests before release.
