# Evaluation Strategy — 4.2.0

Evaluation is divided into independently reported categories:

- package, schema, policy, and skill validation;
- positive and negative skill activation;
- deterministic repository index and context sufficiency;
- model catalog validation, routing, provider fallback, benchmark freshness, and artifact isolation;
- DAG dependencies, leases, scope locks, worktrees, patch integration, candidate SHA, and machine gate;
- actual-diff risk escalation;
- fabricated/stale evidence, run identity, role separation, takeover closure, and approval binding;
- command/path escape, prompt injection, protected paths, and test weakening;
- no-progress loops, retry, quarantine, and reactivation;
- concurrency and transactional state;
- archive traversal, symlinks, collisions, checksums, and reproducibility;
- source and extracted-distribution tests;
- selected mutation tests for critical controls;
- fuzzing for structured inputs, paths, risk, routing, and command policy.

Counts and categories are reported exactly. “All possible tests” is not a valid claim. Mutation percentage applies only to the explicit selected mutants. Coverage is supporting evidence, not proof of correctness. Hosted Codex, GitHub, CI, and deployment acceptance remain separate.
