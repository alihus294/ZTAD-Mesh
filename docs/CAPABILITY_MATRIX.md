# Capability Matrix — ZTAD Mesh 4.2.0

| Capability | Implemented locally | Requires target acceptance | Claim boundary |
|---|---:|---:|---|
| Contract/schema validation | Yes | No | Exact local files only |
| Deterministic risk classification | Yes | Project tuning | Risk may rise from actual diff; policy quality depends on paths/rules |
| Repository index | Yes | Language-tool enrichment optional | Conservative static index, not proof of all runtime coupling |
| Adaptive model routing | Yes | Provider/model availability and benchmark | Catalog values are priors |
| Multi-provider fallback | Yes | Host-approved provider commands/sandbox | Cannot create credentials or provider capacity |
| Parallel read-only scouts/reviewers | Yes | Provider quotas | Bounded by DAG and caps |
| Parallel writers | Yes | Git availability | Only non-overlapping scopes in isolated worktrees |
| Candidate commit and machine gate | Yes | Project check config | Local checks are E2, not protected CI |
| Actual-diff risk escalation | Yes | Project risk policy | Cannot silently downgrade |
| Loop detection/recovery | Yes | Correct retry policy | Prevents identical no-progress retries, not every conceptual loop |
| Durable single-host scheduler | Yes | OS process manager | SQLite is not multi-host HA |
| Model-run/SHA approval binding | Yes | Protected signing/controller context | Model proposal alone is not approval |
| Codex hooks | Packaged | Codex host trust/discovery | Defense in depth only |
| GitHub audit/PR integration | Adapter present | GitHub auth, rulesets, merge queue | Presence of `gh` is insufficient |
| Protected CI | No local substitute | Required | Must be proven by platform evidence |
| Artifact provenance/SBOM/attestation | Validation support | Build platform | Must bind exact digest |
| Canary/rollback | Controller/policy support | Deployment adapter and live metrics | Must be rehearsal-tested |
| Production verification | Evidence schema/gate | Live environment | Requires runtime and observation evidence |
