# Operating Guide — ZTAD Mesh 4.2.0

## Modes

- `AUDIT`: inspect package, repository, and host without mutation.
- `DRY_RUN`: generate the exact mesh plan, routes, scopes, and intended controls without code mutation.
- `RESTRICTED_OPERATE`: execute local bounded worktrees and machine checks without merge/deploy authority.
- `GOVERNED_DELIVERY`: permitted only after target Git/CI/artifact/deployment/runtime controls are independently verified.

## First-time sequence

1. `validate-bundle` and `policy-wiring`.
2. `host-acceptance` for the installed plugin and target repository.
3. `provider-probe` for every configured provider.
4. `model-benchmark` using the current catalog and benchmark cases.
5. Repository `audit` and `dry-run`.
6. Validate the Change Contract and deterministic risk.
7. Run `mesh-autopilot --dry-run`.
8. Inspect planned nodes, write scopes, dependencies, model routes, check configuration, and risk policy.
9. Start bounded operation.
10. Use `mesh-service` only under an external process manager if continuous operation is required.

## Normal autonomous flow

- deterministic index and context seed;
- parallel read-only scouts;
- multiple plan candidates where risk justifies them;
- frontier adjudication;
- test oracle independent of implementation;
- isolated implementation shards;
- deterministic integration;
- machine checks;
- actual-diff risk reclassification;
- multidimensional review;
- supervisor and closure gates;
- platform readiness.

## Retry and escalation

A retry must change at least one material input: strategy, context, model/provider, evidence, failure set, or clean baseline. Otherwise the attempt is a no-progress cycle. The recovery ladder is:

1. targeted repair;
2. fresh worker with supervisor diagnosis;
3. qualified alternative model/provider;
4. alternative plan;
5. frontier re-plan;
6. frontier takeover;
7. fresh closure review;
8. clean reconstruction;
9. task-local quarantine;
10. scheduled reactivation after a verified condition changes.

## Scope discipline

Every writer receives an immutable parent goal, acceptance-criterion mapping, allowed scope, and must-not-touch scope. Material work outside scope becomes a new child task instead of expanding the current patch.

## Persistent service

`mesh-service` polls durable state and runs bounded batches. Use finite time/tick limits during acceptance. For continuous unattended operation, run it under a trusted OS service manager with restricted account permissions, explicit environment, restart/backoff policy, log rotation, and no production secrets in the model process.
