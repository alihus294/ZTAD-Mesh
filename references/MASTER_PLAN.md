# ZTAD Mesh 4.3.6 — Normative Master Plan

## 1. Mission

ZTAD Mesh coordinates multiple model runs to deliver software changes with high quality, bounded cost, durable progress, explicit scope, and evidence-gated platform actions.

The continuity promise is:

> While safe runnable work exists, the scheduler continues. A task that cannot proceed is repaired, re-planned, re-routed, reconstructed, delayed, or quarantined without converting uncertainty into success or blocking unrelated work.

ZTAD does not promise that every task completes under every condition. Missing credentials, unavailable providers, contradictory requirements, and irreversible unsafe operations can make one task temporarily or permanently non-runnable.

## 2. Non-negotiable principles

1. Models are untrusted compute resources.
2. A model statement is never machine, CI, approval, deployment, or runtime evidence.
3. Workflow state is owned by deterministic transactional controllers.
4. Deterministic risk cannot be silently downgraded.
5. Every writer has a bounded scope and dedicated worktree.
6. Overlapping writes are serialized.
7. One deterministic candidate SHA is checked before review.
8. Independent review binds to the exact candidate and actual evidence.
9. A run cannot independently approve the candidate it created.
10. Repeated attempts require measurable progress or material change.
11. Dangerous actions fail closed locally; global execution fails contained.
12. Hosted controls are not inferred from generated configuration.
13. Production transitions use exact artifacts and runtime evidence.

## 3. Trust levels

- **E0:** model output or untrusted text.
- **E1:** repository facts bound to a commit/hash.
- **E2:** local deterministic tool results.
- **E3:** protected CI or platform control evidence.
- **E4:** signed artifact/provenance evidence.
- **E5:** runtime and observation evidence.
- **E6:** protected approval-controller decision bound to the exact subject.

A higher number does not make a negative result positive. Signed `FAILED` evidence remains failure.

## 4. Operating modes

### AUDIT

Read-only capability and repository discovery. No repository mutation and no claim of remote enforcement.

### DRY_RUN

Produces the exact planned DAG, prompts, scopes, routes, checks, and state paths without model write execution.

### RESTRICTED_OPERATE

Allows bounded local model execution and machine checks. No merge or deployment authority.

### GOVERNED_DELIVERY

Enabled only after target-host acceptance verifies Git controls, protected CI, artifact provenance, environment protection, deployment adapter, canary analysis, rollback, and runtime evidence.

## 5. Immutable change contract

Every task requires a validated contract containing:

- stable task ID and parent goal;
- acceptance criteria with stable IDs;
- explicit non-goals;
- protected invariants;
- expected components;
- allowed and must-not-touch scopes;
- assumptions and their verification status;
- test oracle and negative cases;
- deployment/feature-flag strategy;
- rollback and observation requirements;
- risk inputs.

The goal, contract, and acceptance criteria are hash-addressed. Material new work becomes a child task rather than silently expanding the original change.

## 6. Deterministic risk

Risk is computed before execution from the contract and intended paths, then recomputed from the actual candidate diff.

- **R0:** non-behavioral documentation/formatting.
- **R1:** isolated low-impact behavior.
- **R2:** normal feature or business logic.
- **R3:** auth, authorization, RLS, API contracts, sensitive data, financial logic, workflow/control changes, or difficult rollback.
- **R4:** destructive/irreversible data or permission changes, major compliance impact, production infrastructure replacement, or credible data-loss risk.

The model may recommend escalation. It cannot lower deterministic risk. If actual diff risk exceeds the planned risk, the affected node quarantines, the review plan is regenerated, and unrelated runnable work continues.

## 7. Repository and context plane

Before the first model call, ZTAD builds a deterministic repository index containing bounded facts such as:

- tracked files and hashes;
- imports and reverse imports;
- definitions/references detectable by static analysis;
- API routes/clients;
- tests and source associations;
- migrations, schemas, SQL, RLS/security indicators;
- event producers/consumers;
- background jobs and schedules;
- feature flags and runtime configuration;
- deployment/control files;
- dynamic/reflection gaps and known unknowns.

The index is conservative. It does not claim complete runtime understanding. Context scouts are risk-proportional: omitted on the normal R0/R1 path, focused on R2, and parallelized on R3/R4 when independent dimensions justify them. Their structured outputs are stored as bounded, hash-addressed artifacts. If an artifact is truncated or insufficient, later nodes request targeted context expansion instead of guessing.

## 8. Model catalog and routing

### Catalog semantics

Catalog quality, reliability, cost, latency, and parallel limits are priors. They are not timeless truth and do not authorize actions.

Every candidate declares:

- registry ID;
- provider and exact model ID;
- tier (`economy`, `balanced`, `frontier`);
- supported reasoning efforts;
- supported sandboxes;
- task-family quality priors;
- reliability prior;
- cost/latency indices;
- maximum parallel calls.

Invalid tiers, efforts, sandboxes, probabilities, costs, latencies, or parallel values are rejected.

### Host probe

A candidate is eligible only when its provider is configured and its executable/API is available in the accepted host environment.

### Benchmark

Task-family benchmark cases use explicit schemas and assertions. Results bind to:

- catalog hash;
- benchmark-suite hash;
- provider/model identity;
- prompt/schema version;
- host/tool configuration.

Benchmark artifacts are written outside repositories and removed when temporary. A changed model, prompt, schema, toolchain, catalog, or case suite invalidates stale results.

Measured performance is blended with priors to avoid one small sample dominating routing.

### Route choice

The router considers:

- task family and role;
- risk, complexity, ambiguity, prior failures;
- quality floor;
- provider availability;
- measured quality/reliability/latency/tokens;
- cost/latency preference;
- provider diversity;
- exclusions from previous failed attempts;
- global, provider, model, and DAG parallel caps.

It selects the least expensive qualified resource, not the cheapest resource overall.

### Role tiers

- Economy: Luna is the preferred bounded implementation worker for R0/R1 and eligible R2 work.
- Balanced: Terra is the fallback/focused R2 context and review resource.
- Frontier: Sol handles required frontier consultation/review, with every Sol invocation hard-capped at HIGH reasoning.

## 9. Maximum useful parallelism

ZTAD parallelizes independent work only when the selected risk topology requires it:

- repository/context scout dimensions;
- plan candidates;
- test-oracle candidates;
- non-overlapping implementation scopes;
- independent review dimensions.

Parallelism is bounded by DAG width, scope independence, risk, provider/model limits, global cap, and budget.

Two writers cannot hold overlapping scope locks. A reviewer never writes the candidate. Platform transitions are serialized and evidence-gated.

## 10. DAG and durable state

The MeshStore uses transactional SQLite on one host to store:

- tasks and nodes;
- dependencies;
- statuses and priorities;
- leases/heartbeats/expiry;
- write scopes and locks;
- model routes and runs;
- bounded result artifacts;
- attempts and progress fingerprints;
- retries, quarantine, and reactivation;
- performance measurements and events.

Submission is idempotent. Claims use leases. Expired leases are recoverable. Events and artifacts are hash-addressed.

SQLite is not multi-host high availability. Distributed deployment requires a shared transactional backend or durable workflow engine with equivalent semantics.

## 11. Standard DAG

A risk-adaptive plan selects the smallest safe topology: R0/R1 guarded fast path, R2 bounded mesh, and R3/R4 full mesh. Depending on risk it contains some or all of:

1. deterministic repository index;
2. parallel context scouts;
3. independent plan candidates;
4. frontier plan adjudicator;
5. independent test-oracle designer;
6. independent implementation shards;
7. deterministic patch integrator;
8. candidate-commit/machine-check node;
9. independent review dimensions;
10. frontier supervisor;
11. fresh closure reviewer after takeover;
12. release advisor.

The number of nodes increases with risk and independent scope, not for cosmetic model voting.

## 12. Provider execution

Provider adapters must:

- build argv arrays without shell interpolation;
- use a minimal allowlisted environment;
- use explicit model, reasoning, sandbox, timeout, and schema;
- create unique run IDs;
- write outputs outside code worktrees;
- reject pre-existing/stale result paths;
- validate output schema locally;
- capture session/run identity and token/latency metadata;
- record factual exit/error state;
- never turn model output into evidence automatically.

Generic provider commands require host acceptance of their template, sandbox, credential scope, and structured-output behavior.

## 13. Worktrees and patch flow

Each writer receives:

- dedicated branch/worktree;
- exact base SHA;
- immutable allowed/must-not-touch scope;
- bounded prompt/context;
- no merge/deploy authority.

The Patch Broker validates changed paths, file types, symlinks, submodules, hooks/config, binaries, and protected controls. Accepted patches are combined deterministically into one integration worktree and candidate commit.

Provider/event/result artifacts are never part of the candidate diff.

## 14. Machine-check gate

Before any independent reviewer runs, the exact candidate commit must pass the reviewed check registry appropriate to the risk, such as:

- syntax/format/lint/type checks;
- targeted and affected unit tests;
- build;
- contract/schema tests;
- test-integrity and collection checks;
- secret/static/security scans;
- migration dry-run where applicable;
- scope/diff limits;
- actual-diff risk classification.

Local checks produce E2 evidence only. Protected CI must rerun required checks on the exact merge candidate for E3.

## 15. Independent review

Review dimensions are risk-adaptive and may include:

- scope and goal adherence;
- correctness;
- test adequacy;
- compatibility/API;
- security/authorization;
- data integrity/migration;
- runtime/operability;
- performance/concurrency;
- rollback.

A finding is a hypothesis until supported by location, violated requirement/invariant, evidence, blast radius, and reproduction/proof. Reviewers attempt falsification. Model agreement is not proof.

## 16. Supervisor, takeover, and closure

The frontier supervisor can propose:

- `APPROVE`;
- `REPAIR`;
- `REPLAN`;
- `TAKEOVER`;
- `ROLLBACK`;
- `QUARANTINE`.

If the supervisor implements code, that run cannot approve the candidate. A fresh independent closure run reviews the exact resulting SHA.

## 17. Approval controller

A model proposal becomes E6 only when the protected controller verifies:

- stored task/node/model run identity;
- independent implementation/review identities;
- contract hash;
- exact base/head/candidate SHA;
- exact diff hash;
- policy/toolchain hashes;
- evidence existence, trust, subject, status, expiry, and invalidation;
- no open blocking findings;
- required closure after takeover;
- permitted release strategy.

Invented or stale evidence invalidates the proposal. An E6 decision cannot override failed E3 checks.

## 18. Loop prevention and recovery

Every attempt fingerprints task, strategy, prompt, context, model/provider, SHA, diff, and failure evidence. A new attempt must materially change execution or demonstrate progress:

- new strategy;
- new verified context;
- new evidence;
- reduced failures;
- reduced uncertainty;
- different qualified resource;
- clean reconstruction.

Otherwise it is a `NO_PROGRESS_CYCLE` and escalates immediately.

Recovery ladder:

1. targeted repair;
2. fresh worker plus supervisor diagnosis;
3. alternative qualified model/provider;
4. alternative plan;
5. frontier re-plan;
6. frontier takeover;
7. fresh closure review;
8. clean reconstruction;
9. quarantine affected node/task;
10. continue another ready task;
11. reactivate only after a verified condition changes.

## 19. Continuity

The scheduler is responsible for continuation; hooks do not trap sessions. Status distinguishes:

- runnable now;
- delayed retry;
- waiting external dependency;
- quarantined;
- blocked by dependencies;
- terminal.

When one node is blocked, the scheduler claims another ready node. `mesh-service` needs an external process manager to restart after process/host failure.

## 20. Data/destructive changes

R4 work is decomposed into reversible phases where possible:

```text
expand
→ compatible code
→ bounded backfill
→ validate counts/checksums/invariants
→ switch gradually
→ observe
→ retain rollback path
→ contract later as a separate task
```

Irreducibly destructive operations are quarantined unless an authorized owner and platform policy explicitly approve them with backup/restore and rollback evidence. The rest of the queue continues.

## 21. Platform integration

### Source control

Governed merge requires verified branch/ruleset protection, no direct push, required exact-SHA checks, stale-review invalidation, protected control files, and merge queue when required.

### CI/build

Protected CI performs clean checkout, exact-subject checks, immutable dependency/action controls, least-privilege tokens, and build-once artifact generation.

### Artifact

Release evidence binds commit, digest, SBOM, provenance/attestation, policy, toolchain, and test records.

### Deployment

The same verified artifact is promoted through staging and progressive release. Metrics are evaluated automatically. Healthy results promote; unhealthy results roll back. Inconclusive metrics trigger bounded additional checks/observation and then safe rollback rather than indefinite suspension.

### Production

Production verification requires E5 health, synthetic/business transaction, deployed-digest, and observation-window evidence. Workflow success alone is insufficient.

## 22. Hooks

Plugin hooks cover session, pre/post tool, permission request, subagent, stop, and session end events. They enforce local denials and record observations where the host supports/trusts them.

Hooks are not the only security boundary. A trusted sandbox, protected CI, repository rules, and platform credentials remain authoritative.

## 23. Budget and cost

Budgets cover calls, tokens, cost, wall time, attempts, and parallelism. Luna handles qualified low/medium-risk implementation, Terra provides balanced fallback/focused R2 support, and Sol is reserved for frontier gates and hard recovery with a mandatory HIGH reasoning ceiling.

When budget approaches its limit, the system does not repeat low-value attempts. It reduces fan-out, switches to evidence collection, escalates once, or quarantines the task while continuing others.

## 24. Validation and release

Every release must report, without exaggeration:

- source test results;
- extracted plugin and marketplace test results;
- eval categories and counts;
- branch coverage overall and critical modules;
- concurrency tests;
- fuzz categories and counts;
- selected mutation results including survivors;
- archive/checksum/reproducibility results;
- policy wiring;
- known limitations;
- target-host tests not performed.

A release is never described as “tested in every possible way.”

## 25. Acceptance status

Before host/platform acceptance:

```text
OFFLINE_DISTRIBUTION_ACCEPTED_WITH_TARGET_HOST_ACCEPTANCE_REQUIRED
```

After Codex/provider/repository acceptance but before external delivery controls:

```text
RESTRICTED_LOCAL_OPERATION
```

Full governed delivery is available only when target-platform evidence validates each required external gate.

## 26. Normative control catalogue

### Contract, goal, and scope

- Every executable task MUST have a schema-valid Change Contract.
- The parent goal, acceptance criteria, non-goals, and invariants MUST be hash-addressed before execution.
- A model MUST NOT modify the authoritative parent goal.
- Every write node MUST declare allowed scopes and must-not-touch scopes.
- Overlapping write scopes MUST NOT execute concurrently.
- Material work outside the accepted scope MUST become a child task rather than silently expanding the current task.
- A child task MUST retain a verifiable link to the parent goal and the acceptance criterion that caused it.
- Scope validation MUST inspect both source and destination of renames.

### Risk

- Contract risk MUST be computed deterministically before model execution.
- Intended-path risk MUST be computed before worktree allocation.
- Actual-diff risk MUST be computed before independent review.
- A model MAY recommend a higher risk level.
- A model MUST NOT lower deterministic risk.
- If actual-diff risk exceeds planned risk, the affected review plan MUST be invalidated and regenerated.
- R4 destructive activation MUST NOT proceed without verified reversibility or an explicit authorized exception outside model authority.

### Context and repository facts

- A deterministic repository index MUST be built before the first model call for a task.
- Repository facts MUST bind to a repository revision or file hash.
- Context artifacts MUST declare included, excluded, truncated, and unknown information.
- A model MUST request targeted context expansion when a required fact is missing.
- A model MUST NOT invent a file, symbol, API, dependency, test result, or platform state.
- Dynamic/reflection gaps MUST remain explicit known unknowns.
- Context transfer between DAG nodes MUST use bounded hash-addressed artifacts.
- Provider result artifacts MUST NOT be stored inside code worktrees.

### Models and providers

- Catalog quality values MUST be treated as priors rather than authority.
- A provider MUST pass a host probe before routing.
- A model MUST meet the risk/role quality floor before assignment.
- Frontier roles MUST use a qualified frontier candidate.
- A preferred provider MUST remain a soft preference with a qualified fallback.
- Benchmark results MUST bind to the catalog hash and benchmark-suite hash.
- A changed model, prompt, schema, toolchain, catalog, or benchmark suite MUST invalidate stale benchmark applicability.
- Benchmark artifacts MUST be isolated from repositories and cleaned when temporary.
- Provider commands MUST use argument arrays without shell interpolation.
- Provider environments MUST be allowlisted and minimized.
- Provider output MUST be locally schema-validated.
- A provider run MUST reject pre-existing result artifacts for the same run ID.
- Model run identity MUST be recorded before its output can participate in approval.
- Model output MUST remain E0 until deterministic validation produces a separate evidence record.

### Parallelism and worktrees

- Parallelism MUST be bounded by independent DAG width, scope independence, provider limits, model limits, global policy, and budget.
- Read-only scouts and reviewers MAY execute concurrently when dependencies permit.
- Every writer MUST use a dedicated Git worktree and branch.
- A writer MUST NOT hold merge, deployment, production, or signing authority.
- Patch integration MUST be deterministic.
- Provider logs, events, and result files MUST NOT enter the candidate patch.
- One candidate commit MUST be created before machine checks and review.

### Checks, evidence, and approval

- Machine checks MUST run on the exact candidate commit before independent model review.
- Failed machine checks MUST NOT be converted into success by a model decision.
- Test weakening MUST be detected and treated according to risk policy.
- Local machine checks MUST be labelled E2 rather than protected CI evidence.
- Protected CI evidence MUST bind to the exact merge candidate.
- A blocking finding MUST include location, violated requirement or invariant, evidence, blast radius, and reproduction or proof.
- A reviewer SHOULD attempt to falsify a proposed blocking finding.
- Agreement among models MUST NOT be treated as proof.
- An implementation run MUST NOT independently approve the candidate it produced.
- Supervisor takeover MUST require a fresh independent closure review.
- Approval MUST bind to stored run identity, task, contract, exact SHA, diff hash, risk, and registered evidence.
- Invented, stale, expired, invalidated, weak, or mismatched evidence MUST invalidate approval.
- A signed negative result MUST remain negative.
- Model approval MUST NOT authorize merge or deployment directly.

### Loops, recovery, and continuity

- Every retry MUST have a new attempt fingerprint.
- A retry MUST add evidence, change strategy/context/resource, reduce failures/uncertainty, or rebuild from a clean baseline.
- An identical no-progress attempt MUST be rejected.
- Retries MUST be bounded by policy and budget.
- A transient provider failure SHOULD trigger bounded backoff and qualified fallback.
- A blocked node MUST NOT stop unrelated runnable nodes.
- Quarantine MUST preserve task state and evidence.
- Quarantine reactivation MUST require a non-replayable verified change token and reason.
- Delayed retry, quarantine, dependency blocking, and runnable-now states MUST be reported separately.
- Durable state MUST NOT depend on conversation memory.
- Long-running continuous operation MUST use an external process manager for restart after process or host failure.

### Platform and production

- Generated Git, CI, or deployment configuration MUST NOT be represented as active enforcement without platform evidence.
- Merge eligibility MUST require verified source-control and protected-CI controls appropriate to risk.
- Release MUST promote the exact tested artifact digest.
- Production MUST NOT rebuild a different artifact from the tested source.
- R2/R3 release SHOULD use progressive delivery appropriate to risk.
- Canary promotion MUST depend on defined health and business metrics.
- Unhealthy rollout MUST trigger stop or rollback according to verified policy.
- Inconclusive metrics MUST lead to bounded additional observation/checks and then a safe decision, not indefinite hidden waiting.
- Production success MUST require runtime evidence for the deployed digest and observation window.
- A model MUST NOT receive production credentials or private signing keys.
- Full governed delivery MUST remain disabled until target-host acceptance verifies every required external gate.

### Release truthfulness

- Release reports MUST state the exact test categories, counts, environments, and limitations.
- A release MUST NOT claim that every possible test was executed.
- Mutation percentages MUST identify the selected mutant set and any survivors.
- Coverage MUST NOT be represented as proof of correctness.
- Source tests and extracted-distribution tests MUST both pass before distribution acceptance.
- Checksums and manifests MUST be regenerated after every source change.
- Distribution archives MUST pass safe extraction and reproducibility checks.

## 27. Autonomous problem-to-production intake

- Every reported defect MUST begin as an unverified report rather than an assumed bug.
- Investigation MUST resolve the current source of truth read-only before implementation begins.
- A code-affecting report MUST be classified, reproduced or equivalently proven, causally explained, blast-radius mapped, and planned before a Change Contract is created.
- A known-bad regression baseline SHOULD use the same oracle that later validates the candidate.
- A same-SHA or same-configuration fail-then-pass rerun MUST NOT be represented as RED-to-GREEN regression proof.
- A dirty or protected-base-divergent user worktree MUST be preserved untouched while task work proceeds in an isolated clean worktree from the exact protected base.
- Routine technical choices MUST NOT be delegated to a non-programmer owner when the controller can safely derive and execute them.
- Missing local evidence files SHOULD be created as explicitly non-authoritative local evidence rather than stopping all progress.
- An identical no-progress provider, test, or repair attempt MUST NOT be repeated.
- Missing external authority MUST block only the affected protected transition while unrelated safe runnable work continues.
- A model MUST NOT convert its own text, confidence, review, or agreement into merge, release, deployment, signing, attestation, or production evidence.
- Strict model-output schemas MUST be validated before provider execution; an invalid schema MUST NOT be misreported as missing structured output.
- Test/orchestration role aliases MUST be normalized only at the provider/validation boundary and MUST NOT weaken the canonical structured-output schema.
- Every candidate release MUST have a deterministic fingerprint bound to its exact manifest subject before protected promotion.
- A local release fingerprint or blocker request MUST NOT be represented as a protected signature, attestation, approval, staging result, runtime health result, or production success.
- Missing protected evidence SHOULD produce a subject-bound protected evidence request naming the required evidence type, trust level, expected producer, and next action.
- Artifact promotion MUST require the applicable signed manifest, SBOM, provenance/attestation, exact digest, protected CI/review evidence, and rollback material.
- High-risk release MUST require applicable staged restore and rollback rehearsal evidence before production progression.
- Production verification MUST bind runtime health, a production-safe synthetic transaction, and the observation window to the exact deployed digest.
- Migration ledger/history guard failures MUST be repaired at the migration/history root cause and MUST NOT be bypassed by weakening the guard.
- Dependency-audit failures MUST be repaired on a clean protected-base candidate with regenerated lock state and exact-head protected CI.
- Production database mutation MUST NOT be performed from a normal coding-agent shell or ad-hoc direct database session.
- Production release MUST use only the repository's canonical protected release path and exact validated artifact.
