# Capability Matrix — ZTAD Mesh 4.3.8

| Capability | Implemented locally | Requires target acceptance | Claim boundary |
|---|---:|---:|---|
| Exact bug-to-production lifecycle | Yes | Production states require protected evidence | `DONE` cannot close a bug; only `POST_DEPLOY_VERIFIED → CLOSED` |
| Contract/schema validation | Yes | No | Exact local files only |
| Deterministic risk classification | Yes | Project tuning | Risk may rise from actual diff; policy quality depends on paths/rules |
| Risk-proportional DAG | Yes | No | R0/R1 fast path, bounded R2, full R3/R4 |
| Repository index | Yes | Language-tool enrichment optional | Conservative static index, not proof of all runtime coupling |
| Luna-first model preference | Yes | Provider/model availability | Preference never lowers the risk quality floor |
| Terra support/fallback | Yes | Provider/model availability | Used only when eligible/needed by topology |
| Sol hard reasoning ceiling | Yes | Provider must honor supported reasoning parameter | Router/runtime reject any requested level above HIGH |
| Adaptive routing | Yes | Provider/model availability and benchmark | Catalog values are priors; learned overrides are context-bound and observation-gated |
| Multi-provider fallback | Yes | Host-approved provider commands/sandbox | Cannot create credentials or provider capacity |
| Dry-run route preview | Yes | Live provider state remains external | Preview performs no model calls and does not prove availability |
| Parallel read-only work | Yes | Provider quotas | Bounded by DAG and caps; low-risk fast paths avoid unnecessary fan-out |
| Parallel writers | Yes | Git availability | Only non-overlapping scopes in isolated worktrees |
| Candidate commit and machine gate | Yes | Project check config | Local checks are E2, not protected CI |
| RED→GREEN lifecycle gate | Yes | Protected baseline/candidate evidence where required | Same-SHA fail→pass is flaky; skill prompts contain no equivalent-evidence exception |
| Independent review lifecycle verdict | Yes | Reviewer/session execution | Distinct-session `PASS` is E3 review evidence at most, never E6 authority |
| Model/supervisor authority separation | Yes | Protected controller/owner authority | Model `APPROVE` cannot be translated mechanically into E6 |
| Domain-specific targeted gates | Yes | Repository commands/runtime boundaries | DB/auth/financial/ZATCA/provider/concurrency evidence required when tagged applicable |
| Downstream writer-quality feedback | Yes | Meaningful deterministic checks | Schema-valid output alone is not perfect quality |
| Actual-diff risk escalation/replan | Yes | Project risk policy | Lower-risk approval path is invalidated on upward risk |
| Blocking finding control | Yes | Finding quality still requires evidence | P0/P1 cannot silently pass |
| Loop detection/recovery | Yes | Correct retry policy | Prevents identical no-progress retries, not every conceptual loop |
| Bounded repair budgets | Yes | Policy tuning | Exhaustion quarantines rather than inventing progress |
| Durable single-host scheduler | Yes | OS process manager | SQLite is not multi-host HA |
| Continuity phase synchronization | Yes | No | Internal scheduler state never replaces bug-lifecycle state |
| Model-run/SHA approval binding | Yes | Protected signing/controller context | Model proposal alone is not approval |
| Codex hooks | Packaged | Codex host trust/discovery | Defense in depth only |
| Deterministic release packaging | Yes | GitHub Release publication | Two builds are compared byte-for-byte before publication |
| GitHub audit/PR integration | Adapter present | GitHub auth, rulesets, merge queue | Presence of `gh` is insufficient |
| Protected CI | Repository workflow present | Repository enforcement | A passing workflow is not branch protection by itself |
| Artifact provenance/SBOM/attestation | Validation support | Build platform | Must bind exact digest where required |
| Protected production release state | Policy/controller support | Protected environment/owner authority | Deployment command success alone does not prove fix success |
| Canary/rollback | Controller/policy support | Deployment adapter and live metrics | Must be rehearsal-tested |
| Production verification | Evidence schema/gate | Live environment | `PRODUCTION_VERIFIED` supports `POST_DEPLOY_VERIFIED`; closure still requires the separate lifecycle transition |
