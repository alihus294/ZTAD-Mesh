---
name: autonomous-continuity
description: Operate the durable task queue, leases, bounded retries, task-local quarantine, and automatic continuation semantics for ZTAD. Invoke explicitly when starting, resuming, or recovering the autonomous scheduler.
---

# Purpose

Keep the delivery system productive while runnable work exists. Persist task state in SQLite, claim work with leases, recover expired leases, and contain one task's failure without stopping unrelated work.

# Procedure

1. Use `.delivery/ztad/continuity.db`; never use conversation memory as durable state.
2. Submit with a stable idempotency key.
3. Claim one task transactionally; heartbeat long-running work.
4. Record every transition or failure with an idempotency key.
5. Apply the recovery ladder: repair, re-plan, supervisor takeover, clean reconstruction, then task-local quarantine.
6. Route transient failures to bounded exponential retry and external prerequisites to `WAITING_EXTERNAL_DEPENDENCY`.
7. After containing a task, claim the next runnable task.
8. Verify the event hash chain and report runnable, delayed, quarantined, and terminal counts.

# Boundary

SQLite is the verified portable single-node backend. Multi-host execution requires a transactional shared database or durable workflow host with the same lease, idempotency, and optimistic-concurrency semantics.
