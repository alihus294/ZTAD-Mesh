# Runbooks

## Worker fails repeatedly

Preserve evidence, start a fresh Worker once, replan, escalate to Supervisor takeover, require Closure Review, then reconstruct from a clean baseline. Quarantine only after the ladder is exhausted; continue the queue.

## Provider unavailable

Retry with bounded backoff, use an approved fallback, or put the task in WAITING_EXTERNAL_DEPENDENCY. Continue other tasks and resume automatically.

## Invalid or fabricated evidence

Reject the decision, invalidate dependent approvals, start a fresh Supervisor review, and create missing-evidence work. Do not block unrelated tasks.

## Lease or process crash

Allow lease expiry, reclaim transactionally, rebuild context from durable artifacts, and resume from the last verified state transition.

## Hook detects prohibited action

Deny the action, record the attempt, invalidate the session output if required, and route the task to replan or quarantine. Continue unaffected work.

## Runtime regression

Stop rollout, deploy the last verified artifact, verify health, create a repair task, and resume the queue.

## Suspected control-plane compromise

Freeze only work depending on affected trust roots, rotate keys, restore policies/hooks/controller from a verified artifact, invalidate affected evidence, and continue work whose trust chain remains intact.

## Database migration failure

Stop the batch, retain compatible schema, verify data invariants, rollback or forward-fix within expand/migrate/contract, and quarantine destructive cleanup.
