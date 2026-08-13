# Final Operating Policy — ZTAD Mesh 4.3.5

1. Models propose; deterministic tools, protected controllers, and protected platforms create evidence and authority.
2. Orchestration cost MUST be proportional to verified risk: R0/R1 use the guarded fast path, R2 uses the bounded mesh, and R3/R4 use the full mesh.
3. Normal R0/R1 work MUST use deterministic index → Luna worker → deterministic integration/checks/actual-risk classification → exactly one independent Sol final guard.
4. The R0/R1 path MUST NOT add redundant model fan-out unless evidence triggers escalation.
5. R2 MUST remain bounded: focused context, one primary writer, deterministic gates, and only the independent reviews justified by the contract budget.
6. An upward actual-diff risk result MUST invalidate the lower-risk downstream topology and create the stronger required plan before approval can continue.
7. Every Sol invocation MUST be capped at HIGH reasoning. No role, retry, takeover, closure, or release path may bypass this ceiling.
8. Catalog and benchmark quality are routing inputs, never authority. Preferred models remain subject to quality, tier, sandbox, and provider-availability gates.
9. Performance observations MUST be bound to the current catalog and benchmark/provider capability context and MUST satisfy the configured minimum sample count before influencing routing.
10. Schema-valid model output alone MUST NOT be treated as perfect quality; writer quality is determined by downstream deterministic outcomes.
11. Index the repository before model work and request targeted context expansion rather than guess.
12. Every writer MUST use a dedicated worktree, immutable goal, bounded allowed scope, and must-not-touch scope. Overlapping writes MUST remain serialized.
13. Integrate accepted patches into one candidate commit and pass machine checks before independent review.
14. P0/P1 findings and structured requests for context, repair, replan, risk escalation, quarantine, or stronger supervision MUST be handled as controller inputs and MUST NOT silently resolve to success.
15. Never approve a candidate from the same implementing run/session. Takeover requires fresh independent closure before approval.
16. Never accept evidence absent from the registry or mismatched to task, SHA, diff, artifact, policy, toolchain, or environment subject.
17. Every retry MUST demonstrate measurable progress or materially change strategy, context, resource, evidence, failure set, or clean baseline.
18. Repair cycles MUST be bounded. Exhausted repair budget MUST contain/quarantine the parent rather than leave an orphan repair state.
19. Dangerous or failed actions fail closed locally while unrelated safe runnable work continues globally.
20. Mesh/model success MUST NOT auto-grant `MERGE_READY`; approval, merge, artifact promotion, deployment, canary, and rollback require their protected evidence path.
21. Failed checks cannot be overridden by model consensus, frontier confidence, or an E6 decision.
22. Promote only the exact tested artifact and roll back on verified regression.
23. Do not claim governed delivery, hosted-model quality, GitHub enforcement, deployment success, or production health from local files, hooks, adapters, or offline tests alone.
