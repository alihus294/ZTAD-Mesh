---
name: recovery-and-takeover
description: Recover a failed ZTAD task through bounded repair, fresh-context re-planning, strong-model takeover, clean reconstruction, retry scheduling, rollback, or task-local quarantine. Invoke explicitly after a failed attempt or runtime regression.
---

# Recovery ladder

1. First worker failure: targeted repair with a regression test.
2. Second worker failure: fresh context and a materially different strategy.
3. Third worker failure: strong supervisor takeover.
4. Fourth worker failure: clean-branch reconstruction from requirements and verified evidence.
5. Continued failure: quarantine this task, preserve evidence, schedule a later retry, and continue another ready task.

Transient provider, runner, or CI failures use bounded exponential backoff. Missing credentials and external business decisions wait without consuming repeated model calls. Runtime regression triggers automatic rollback to the last verified artifact, then re-planning.

# Prohibitions

Do not repeat an identical prompt/strategy, convert a flaky test to pass, weaken a gate, invent missing evidence, or turn task-local quarantine into a global stop.
