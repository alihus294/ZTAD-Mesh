# Security Controls — 4.2.0

## Model distrust

Every model result starts as untrusted. Models cannot create authoritative test, CI, approval, build, deployment, or runtime evidence.

## Model/provider execution

Provider adapters use argument arrays with `shell=False`, an allowlisted environment, unique run IDs, explicit output schemas, local schema validation, output artifacts outside worktrees, and stale-file rejection. Generic provider commands require separate host acceptance.

## Repository and scope

A deterministic index precedes model work. Writers run in dedicated Git worktrees under durable non-overlapping scope locks. Patches are validated, combined deterministically, committed once, and checked before review.

## Approval

The supervisor emits a proposal. The Approval Controller looks up the stored model run, validates independent identity, exact task/contract/SHA/diff/risk/evidence bindings, and signs only after all predicates pass. Takeover requires a fresh Closure Reviewer.

## Hooks

PreToolUse and PermissionRequest hooks add defense in depth. Stop hooks do not trap a session in a loop; continuity belongs to the durable scheduler and an external process manager.

## Evidence/state

SQLite transactions, constraints, leases, idempotency, hash chains, and external checkpoints protect local concurrent state. Multi-host use requires a shared transactional backend.

## Test and control integrity

The detector covers skip/xfail/only/todo/retry/no-tests, CI bypass, failure masking, discovery changes, assertion loss, test deletion/move, collection reduction, snapshot changes, and unconditional-success scripts. Protected control-plane changes require separate review.

## Secret/network boundary

Models must not receive production credentials, signing keys, authentication files, or browser data. Network is denied by default and allowed only through explicit host policy and role need.
