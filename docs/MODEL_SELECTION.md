# Model Selection and Work Distribution — ZTAD Mesh 4.2.0

## Principle

ZTAD does not declare one model universally best. It selects the least expensive eligible model that clears the measured quality floor for the exact task family, role, risk, sandbox and reasoning requirement. Catalog values are priors; host probes and version-bound benchmarks are required before governed use.

## Routing inputs

- task family and role;
- risk R0–R4 and structural complexity;
- write versus read-only authority;
- model/provider availability and concurrency limits;
- benchmark quality, reliability, latency and cost;
- project-specific execution history bound to catalog and benchmark-suite hashes;
- failure count, required independence and provider diversity;
- global and per-provider useful-parallelism caps.

## Default role classes

| Role | Minimum class | Typical reasoning | Authority |
|---|---|---|---|
| repository indexer | deterministic tool | none | read-only |
| context scout | economy/balanced | low–medium | read-only |
| plan candidate | balanced/frontier by risk | medium–high | read-only |
| plan adjudicator | frontier | high–max | read-only |
| implementation shard | cheapest qualified model | medium–high | isolated worktree only |
| test-oracle designer | balanced/frontier | medium–high | read-only proposal |
| security/data/release reviewer | frontier | high–max | read-only proposal |
| supervisor takeover | frontier | high–max | isolated worktree only |
| closure reviewer | fresh frontier session | high–max | read-only proposal |

## Maximum useful parallelism

Parallelism is bounded by DAG width, write-scope independence, provider limits, risk, budget and measured quality. Read-only scouts and review dimensions can fan out. Conflicting writers are serialized. More agents are never treated as evidence of correctness.

## Independence rules

- An implementing session cannot approve the same SHA.
- Supervisor takeover requires a fresh closure reviewer.
- Provider diversity is preferred when two providers pass the same quality floor, but unavailable diversity does not stop all work.
- Every model result is a proposal until schema, subject, SHA, diff and evidence checks pass.

## Benchmark freshness

A routing measurement is invalidated when any of these changes:

- model/provider identifier;
- prompt version;
- output schema;
- toolchain/policy hash;
- benchmark-suite hash;
- relevant host capability.

A small benchmark sample is blended with the catalog prior rather than replacing it. Production routing requires target-host benchmark execution; the offline release does not prove hosted-model superiority.
