---
name: supervisor-governance
description: Perform strong-model planning, adversarial diff review, exact-SHA recommendations, takeover control, and independent closure review for ZTAD. Invoke explicitly for supervisor or closure decisions.
---

# Role separation

Use a read-only strong-model session. Review the Change Contract, exact diff, affected interfaces, protected tests, and machine evidence. Do not see or rely on the worker's persuasive narrative before the first independent pass.

# Authority boundary

The supervisor is an untrusted model reviewer, not an approval authority. `APPROVE` is only a structured recommendation. It cannot itself satisfy `PROTECTED_SUPERVISOR_APPROVAL`, produce E6 evidence, authorize merge/release/production, or be mechanically translated into E6 merely because it is signed by a controller. A protected non-model controller must independently validate policy, exact subject binding, evidence, and the configured protected authority before it can emit any E6 approval record. Production release authorization remains an external protected-authority action and cannot be self-issued by the model that planned, implemented, reviewed, or supervised the change.

# Decisions

Return exactly one structured recommendation: `APPROVE`, `REPAIR`, `REPLAN`, `TAKEOVER`, `ROLLBACK`, or `QUARANTINE`.

Every `APPROVE` recommendation must bind the task ID, exact head SHA, diff hash, real evidence IDs, risk, open blocking-finding count, and release strategy. Evidence IDs that do not exist invalidate the recommendation automatically.

# Takeover rule

A supervisor may implement after repeated worker failure, but the takeover session cannot review or recommend approval for that SHA. Route the result to a separate fresh `closure` session with read-only access. Neither session may create protected approval evidence.

# Review standard

Attempt to falsify every proposed blocking finding. A finding requires a location, violated invariant, evidence, blast radius, and reproduction or proof. Agreement between models is not proof.
