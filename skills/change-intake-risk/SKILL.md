---
name: change-intake-risk
description: Validate a software Change Contract and calculate contract-only, intended, or actual-diff policy risk. Trigger only when explicitly invoked at intake or after scope changes; never use model judgment to downgrade risk.
---

# Inputs

- repository path;
- Change Contract path;
- optional base/head revisions for actual-diff classification;
- optional intended changed paths or diff file before implementation.

# Procedure

1. Run `validate-contract`. For repairable omissions, generate a deterministic remediation task and keep the queue moving. For an external business fact or credential that cannot be derived, place only this task in `WAITING_EXTERNAL_DEPENDENCY`; never stop unrelated work.
2. Run contract-only or intended-path `classify-risk` before planning.
3. Run actual-diff `classify-risk` before PR eligibility and after any scope-changing repair.
4. Use the highest result. Hard path and destructive-operation overrides always win.
5. The agent may request escalation with evidence. It may never lower risk, remove an override, or treat an unknown optimistically.
6. Auth, authorization/RLS, secrets, public contracts, production dependencies, payments/pricing/tax/ZATCA, CI/control plane, infrastructure, persistent schema, backups, protected tests, or coverage controls are at least `R3`.
7. Destructive migration, broad privilege expansion, credible data loss, unproven rollback, direct production data correction, or mixed control-plane/application changes are `R4`.

# Commands

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py validate-contract --contract <FILE>
python3 <PLUGIN_ROOT>/scripts/ztad.py classify-risk --repo <REPO> --contract <FILE>
python3 <PLUGIN_ROOT>/scripts/ztad.py classify-risk --repo <REPO> --contract <FILE> --changed-file <PATH>...
python3 <PLUGIN_ROOT>/scripts/ztad.py classify-risk --repo <REPO> --contract <FILE> --base <SHA> --head <SHA>
```

# Output

Return the generated JSON report. Preserve score, score-derived risk, hard minimum, unknowns, blockers, final risk, and the fact that an agent cannot downgrade it.
