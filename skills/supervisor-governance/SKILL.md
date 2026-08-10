---
name: supervisor-governance
description: Perform strong-model planning, adversarial diff review, exact-SHA approval, takeover control, and independent closure review for ZTAD. Invoke explicitly for supervisor or closure decisions.
---

# Role separation

Use a read-only strong-model session. Review the Change Contract, exact diff, affected interfaces, protected tests, and machine evidence. Do not see or rely on the worker's persuasive narrative before the first independent pass.

# Decisions

Return exactly one structured decision: `APPROVE`, `REPAIR`, `REPLAN`, `TAKEOVER`, `ROLLBACK`, or `QUARANTINE`.

Every approval must bind the task ID, exact head SHA, diff hash, real evidence IDs, risk, open blocking-finding count, and release strategy. Evidence IDs that do not exist invalidate the approval automatically.

# Takeover rule

A supervisor may implement after repeated worker failure, but the takeover session cannot approve that SHA. Route the result to a separate fresh `closure` session with read-only access.

# Review standard

Attempt to falsify every proposed blocking finding. A finding requires a location, violated invariant, evidence, blast radius, and reproduction or proof. Agreement between models is not proof.
