# Model Selection and Work Distribution — ZTAD Mesh 4.3.0

## Principle

ZTAD selects the smallest eligible model topology that clears the exact task/role/risk gate. Model preference never overrides eligibility, machine evidence, independence, or actual-diff risk. Catalog quality values are priors; host probes and context-bound benchmark observations are routing inputs, not authority.

## Default v4.3 roles

| Path / role | Preferred resource | Reasoning ceiling | Authority |
|---|---|---|---|
| deterministic repository index | local deterministic tool | none | read-only fact generation |
| R0/R1 implementation worker | `codex-luna` | high | isolated worktree only |
| R0/R1 final guard | `codex-sol` | **high** | independent read-only proposal |
| R2 focused scout | `codex-terra` | high | read-only proposal |
| R2 implementation worker | `codex-luna`; Terra fallback if Luna is unavailable/ineligible | high | isolated worktree only |
| R2 focused reviewer | `codex-terra` | high | independent read-only proposal |
| R3/R4 planning, sensitive review, diagnosis, takeover, closure, release consultation | eligible frontier resource, normally `codex-sol` | **high** | bounded proposal/worktree according to role |
| deterministic integration/checks | local deterministic tools | none | fact generation |

No Sol route may request a reasoning effort above HIGH. This ceiling applies to every Sol role, including planning, adjudication, security/data review, diagnosis, takeover, closure, and release advice.

## Risk topology

- **R0/R1:** Luna performs the bounded write; deterministic integration/checks and actual-risk classification run next; exactly one independent Sol final guard follows on the normal path.
- **R2:** one focused Terra scout, one Luna writer, deterministic integration/checks, then one or two focused Terra reviews according to the contract review budget.
- **R3/R4:** full risk-adaptive mesh with independent planning/test/review dimensions and frontier gates.

If actual-diff risk rises, the lower-risk route is invalidated. The controller creates the stronger required child topology instead of allowing a cheap route to approve a more dangerous patch.

## Eligibility inputs

Routing considers:

- task family and role;
- risk, complexity, ambiguity, and prior failures;
- write versus read-only authority;
- minimum quality floor and required tier;
- explicit preferred registry only after eligibility filtering;
- provider availability and concurrency limits;
- current catalog hash;
- benchmark-suite/provider-executable capability fingerprint;
- repeated measured quality/reliability observations;
- normalized cost and latency indices;
- prior failed resources and required independence/diversity;
- global, provider, model, and DAG parallel caps;
- per-registry reasoning ceiling.

The quality floor is not lowered merely to keep Luna, Terra, or Sol selected.

## Benchmark and performance freshness

A routing measurement is usable only in its matching context. Context includes the current catalog and benchmark/provider capability fingerprint. Legacy or unbound measurements do not mix into a new context.

A configured minimum observation count must be reached before measured performance can override catalog priors. One successful run therefore remains shadow data rather than immediately steering routing.

A protocol-correct abstention can be useful behavior, but it cannot receive a perfect capability score. Likewise, schema-valid output alone does not establish implementation quality. Writer performance is updated from downstream deterministic integration and machine-check outcomes.

## Fallback and retry

A preferred registry is a preference, not a pin that bypasses safety. Provider/model failure or ineligibility triggers qualified fallback. A retry should materially change resource, strategy, verified context, evidence, or baseline where possible. Repeating the same resource with the same failure signature is not progress.

## Independence rules

- An implementing session cannot approve the same candidate SHA.
- The mandatory R0/R1 Sol guard is independent of the Luna writer.
- Supervisor takeover requires fresh independent closure before approval.
- Provider diversity is useful when eligible alternatives exist, but model agreement is never evidence.
- Every model result remains a proposal until exact subject, SHA, diff, schema, and evidence checks pass.
