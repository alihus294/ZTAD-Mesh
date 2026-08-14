# Final Operating Policy — ZTAD Mesh 4.3.8

1. Models propose; deterministic tools, protected controllers, and protected platforms create evidence and authority.
2. Every reported defect MUST begin as `UNVERIFIED_REPORT` and MUST use the authoritative bug-to-production lifecycle. Internal scheduler `DONE` MUST NOT close a bug case.
3. A code-fix case MUST progress explicitly through source truth, classification, reproduction, root cause, blast radius, plan, patch, RED→GREEN proof, targeted validation, full regression validation, diff forensics, independent review, protected CI, staging, `READY_FOR_OWNER_RELEASE`, `PRODUCTION_RELEASED`, `POST_DEPLOY_VERIFIED`, then `CLOSED`.
4. Missing mandatory evidence MUST route to `BLOCKED` before production exposure and `ROLLBACK_REQUIRED` after production exposure.
5. Orchestration cost MUST be proportional to verified risk: R0/R1 use the guarded fast path, R2 uses the bounded mesh, and R3/R4 use the full mesh.
6. Normal R0/R1 work MUST use deterministic index → Luna worker → deterministic integration/checks/actual-risk classification → exactly one independent Sol final guard.
7. The R0/R1 path MUST NOT add redundant model fan-out unless evidence triggers escalation.
8. R2 MUST remain bounded: focused context, one primary writer, deterministic gates, and only the independent reviews justified by the contract budget.
9. An upward actual-diff risk result MUST invalidate the lower-risk downstream topology and create the stronger required plan before approval can continue.
10. Every Sol invocation MUST be capped at HIGH reasoning. No role, retry, takeover, closure, or release path may bypass this ceiling.
11. Catalog and benchmark quality are routing inputs, never authority. Preferred models remain subject to quality, tier, sandbox, and provider-availability gates.
12. Performance observations MUST be bound to the current catalog and benchmark/provider capability context and MUST satisfy the configured minimum sample count before influencing routing.
13. Schema-valid model output alone MUST NOT be treated as perfect quality; writer quality is determined by downstream deterministic outcomes.
14. Index the repository before model work and request targeted context expansion rather than guess.
15. Every writer MUST use a dedicated worktree, immutable goal, bounded allowed scope, and must-not-touch scope. Overlapping writes MUST remain serialized.
16. Integrate accepted patches into one candidate commit and bind exact SHA/diff/contract/toolchain/policy identity before `PATCH_IMPLEMENTED`.
17. `REGRESSION_TEST_PROVEN` MUST use the same oracle failing on the exact bad base and passing on the exact candidate; same-SHA FAIL→PASS is flaky and blocking. No model judgment, controller-reviewed exception, or “equivalent evidence” may replace this code-fix gate.
18. P0/P1 findings and structured requests for context, repair, replan, risk escalation, quarantine, or stronger supervision MUST be handled as controller inputs and MUST NOT silently resolve to success.
19. Never approve a candidate from the same implementing run/session. Independent review MUST identify distinct implementation/review contexts and return an exact lifecycle verdict `PASS` before `INDEPENDENT_REVIEW_PASS`.
20. A model/supervisor `APPROVE` MUST remain advisory and MUST NOT itself become E6, protected supervisor approval, merge authority, release authority, or production authorization. A protected non-model controller MUST independently validate the configured protected authority before emitting E6.
21. Never accept evidence absent from the registry or mismatched to task, SHA, diff, artifact, policy, toolchain, or environment subject.
22. Every retry MUST demonstrate measurable progress or materially change strategy, context, resource, evidence, failure set, or clean baseline.
23. Repair cycles MUST be bounded. Exhausted repair budget MUST contain/quarantine the parent rather than leave an orphan repair state.
24. Dangerous or failed actions fail closed locally while unrelated safe runnable work continues globally.
25. Failed checks cannot be overridden by model consensus, frontier confidence, or an unrelated E6 decision.
26. `READY_FOR_OWNER_RELEASE` MUST require exact release fingerprint, protected signed manifest, SBOM, attestation/provenance, rollback readiness/rehearsal, observability, synthetic transaction definition, and risk-required restore evidence.
27. `PRODUCTION_RELEASED` MUST require protected production authority and evidence for the exact reviewed revision/digest. Deployment-command success is not fix success.
28. `POST_DEPLOY_VERIFIED` MUST separately prove the original problem fixed and production health/synthetic/observation evidence before `CLOSED`; any `PRODUCTION_VERIFIED` readiness result is not itself closure.
29. Promote only the exact tested artifact and roll back/contain on verified regression or unresolved critical uncertainty.
30. Do not claim governed delivery, hosted-model quality, GitHub enforcement, deployment success, production health, or bug closure from local files, hooks, adapters, scheduler state, model prose, or offline tests alone.
