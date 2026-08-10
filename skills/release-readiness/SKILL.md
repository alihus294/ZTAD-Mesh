---
name: release-readiness
description: Assess whether an exact revision and artifact satisfy merge, staging, release, or production evidence gates. Trigger only when explicitly invoked after platform evidence exists; never deploy or authorize production.
---

# Authority

This is read-only and advisory. Eligibility is decided by deterministic policy. A strong supervisor may issue a structured, SHA-bound recommendation, but the deployment controller executes transitions only after evidence validation.

# Procedure

1. Validate every record against the exact contract hash, repository, head/merge SHA, policy bundle hash, and artifact digest.
2. Require valid Ed25519 signatures from configured Trust Roots for all `E3`–`E6` evidence. Unsigned authoritative JSON is invalid.
3. Reject stale, expired, duplicated, invalidated, weak-trust, wrong-producer, wrong-artifact, non-affirmative, or malformed evidence. A valid signature over `FAILED` or `REJECTED` evidence is still a failure.
4. Verify build-once/promote-by-digest, SBOM, provenance, attestation verification, rollback target, staging, feature flags, observability, and stop conditions as applicable.
5. Require platform-control evidence for branch protection, required checks, merge queue, environment protection, and OIDC at the relevant gate.
6. Accept strong-supervisor merge/technical/release decisions only when a trusted approval controller converts the structured decision into signed E6 evidence bound to the exact task, SHA, diff hash, artifact, and evidence set. A model response alone is never E6 evidence.
7. Never claim Production success without signed `E5` health, synthetic-transaction, and observation-window evidence for the deployed digest.

# Command

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py release-readiness \
  --repo-id <OWNER/REPOSITORY> --contract <FILE> --base <BASE_SHA> --head <HEAD_SHA> \
  --policy-bundle-hash <SHA256> --toolchain-hash <SHA256> --risk <R0-R4> \
  --target <merge|staging|release|production> \
  --evidence-dir <DIR> --trust-roots <FILE> \
  [--release-manifest <FILE>]
```

# Output

Return one of `MERGE_ELIGIBLE`, `STAGING_ELIGIBLE`, `RELEASE_ELIGIBLE`, `PRODUCTION_VERIFIED`, `AUTO_GENERATE_EVIDENCE`, `AUTO_REPLAN`, `ROLLBACK`, `WAITING_EXTERNAL_DEPENDENCY`, or `QUARANTINE_AND_CONTINUE`, with exact missing and invalid controls. Never return a global stop while runnable work exists.
