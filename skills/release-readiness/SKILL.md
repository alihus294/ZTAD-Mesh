---
name: release-readiness
description: Assess whether an exact revision and artifact satisfy merge, staging, release, or production evidence gates. Trigger only when explicitly invoked after platform evidence exists; never deploy or authorize production.
---

# Authority

This is read-only and advisory. Eligibility is decided by deterministic policy. A strong supervisor may issue a structured, SHA-bound recommendation, but the recommendation is not approval evidence and the deployment controller executes transitions only after independent protected evidence validation.

# Procedure

1. Validate every record against the exact contract hash, repository, head/merge SHA, policy bundle hash, and artifact digest.
2. Require valid Ed25519 signatures from configured Trust Roots for all `E3`–`E6` evidence. Unsigned authoritative JSON is invalid.
3. Reject stale, expired, duplicated, invalidated, weak-trust, wrong-producer, wrong-artifact, non-affirmative, or malformed evidence. A valid signature over `FAILED` or `REJECTED` evidence is still a failure.
4. Verify build-once/promote-by-digest, SBOM, provenance, attestation verification, rollback target, staging, feature flags, observability, and stop conditions as applicable.
5. Require platform-control evidence for branch protection, required checks, merge queue, environment protection, and OIDC at the relevant gate.
6. Treat every model/supervisor `APPROVE` as advisory input only. A protected non-model approval controller must independently evaluate the exact subject, deterministic/protected evidence, policy, and configured protected authority before emitting E6. It must never create E6 by merely signing, wrapping, or translating a model recommendation. `PROTECTED_RELEASE_AUTHORIZATION` must reflect an authorized protected production action, not model consensus or self-approval.
7. Never claim production success without signed `E5` health, synthetic-transaction, and observation-window evidence for the deployed digest. `PRODUCTION_VERIFIED` means the exact production runtime evidence is sufficient for the `POST_DEPLOY_VERIFIED` claim only; it is not `CLOSED`. The authoritative bug lifecycle still requires the separate deterministic transition `POST_DEPLOY_VERIFIED → CLOSED`.

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

Return one of `MERGE_ELIGIBLE`, `STAGING_ELIGIBLE`, `RELEASE_ELIGIBLE`, `PRODUCTION_VERIFIED`, `AUTO_GENERATE_EVIDENCE`, `AUTO_REPLAN`, `ROLLBACK`, `WAITING_EXTERNAL_DEPENDENCY`, or `QUARANTINE_AND_CONTINUE`, with exact missing and invalid controls. Never return a global stop while runnable work exists. Never equate any readiness result with bug-lifecycle `CLOSED`.
