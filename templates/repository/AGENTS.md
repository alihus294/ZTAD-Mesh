# ZTAD Autonomous Continuous Delivery Rules

- Invoke `$zero-trust-delivery` explicitly for governed repository changes.
- Persist workflow state in `.delivery/ztad/continuity.db`; conversation memory is not durable state.
- Use the economical worker for implementation, a fresh strong supervisor for review, and a fresh closure reviewer after supervisor takeover.
- The implementing session may not independently approve the same SHA.
- Run deterministic contract, risk, protected-path, test-integrity, command, evidence, and budget checks before model approval.
- A model may raise deterministic risk but may never lower it or invent evidence.
- Failure is task-local: repair, re-plan, take over, reconstruct, delay, or quarantine the task, then continue another runnable task.
- Preserve current behavior and reversibility under non-destructive ambiguity; use a disabled feature flag for uncertain activation.
- Never weaken tests, broaden permissions, delete data, bypass CI, access production secrets, or claim runtime health without exact evidence.
- R4 work must be transformed into reversible stages; an irreducibly destructive step is split and quarantined rather than executed blindly.
- Protected control-plane changes remain separate from application changes.
- Hooks are defense in depth; authoritative execution requires a disposable sandbox and protected CI.
