# ZTAD Mesh 4.3.10 Traceability Matrix

Active normative requirements: **174**.

This matrix maps the retained normative control catalogue to implementation and verification. Version 4.3 uses risk-proportional orchestration and model routing without weakening the existing authority, scope, evidence, recovery, and platform-boundary requirements. External controls are not considered active until target-platform evidence verifies them.

## Coverage by enforcement class

| Class | Count |
|---|---:|
| CONTROL_SPECIFIC | 87 |
| DETERMINISTIC | 5 |
| DETERMINISTIC_AND_EXTERNAL | 1 |
| DETERMINISTIC_AND_PLATFORM | 75 |
| HOST_AND_DETERMINISTIC | 1 |
| PROTECTED_CONTROLLER | 5 |

## Coverage by section

| Section | Requirements |
|---|---:|
| 5. Immutable change contract | 1 |
| 6. Deterministic risk | 1 |
| 12. Provider execution | 1 |
| 13. Worktrees and patch flow | 1 |
| 14. Machine-check gate | 2 |
| 15. Independent review | 1 |
| 18. Loop prevention and recovery | 1 |
| 24. Validation and release | 1 |
| 26. Normative control catalogue | 87 |
| 27. Autonomous problem-to-production intake | 23 |
| 28. Exact fail-closed bug-to-production lifecycle | 15 |
| 29. Machine-enforced fail-closed protocol completion | 19 |
| 30. Immutable delivery subject and invalidation | 5 |
| 31. Controller-owned lifecycle authority | 5 |
| 32. Canonical risk, domain, and evidence enforcement | 6 |
| 33. Terminal classes and exceptional release flows | 5 |

## Interpretation

- `DETERMINISTIC`: enforced by local/protected code and tests.
- `PROTECTED_CONTROLLER`: requires a protected non-model controller and private-key boundary.
- `HOST_ENFORCED` / `HOST_ACCEPTANCE`: requires verified Codex host behavior.
- `PLATFORM_REQUIRED`: requires verified source-control, CI, artifact, deployment, or runtime enforcement.
- `CAPABILITY_GATED`: autonomy is capped until the capability is independently verified.
- `OPERATIONAL` / `DOCUMENTED_*`: governed by runbook, architecture, or scenario testing.

The row-level source of truth is `requirements.csv`.

## v4.3.10 adversarial traceability

The following matrix records the hardening-specific adversarial requirements. A shared test is intentional when one test exercises the same invariant across several domains or mutation forms.

| Requirement | Verification | Coverage note |
|---|---|---|
| Candidate mutation after CI | `tests/test_v4310_fail_closed_adversarial.py::test_candidate_mutation_invalidates_ci_and_increments_epoch` | Subject epoch increments and current evidence is invalidated. |
| Artifact mutation after staging | `tests/test_v4310_fail_closed_adversarial.py::test_artifact_mutation_invalidates_staging_and_production_mutation_requires_rollback` | Artifact and production branches use different revalidation floors. |
| Contract, policy, and toolchain mutation after readiness | `tests/test_v4310_control_plane_adversarial.py::test_subject_epoch_policy_covers_candidate_contract_policy_toolchain_artifact_and_production` | One parameterized group covers all material subject categories. |
| PR head A to squash or rebase main B | `tests/test_v4310_control_plane_adversarial.py::test_squash_merge_preserves_pr_a_to_main_c_provenance` | Deterministic Git repository proves B and C remain distinct. |
| PR evidence A cannot prove production B | `tests/test_v4310_control_plane_adversarial.py::test_squash_merge_preserves_pr_a_to_main_c_provenance` | Pre-merge evidence is retained as history but rejected for the post-merge production subject. |
| R4 GENERAL is CRITICAL | `tests/test_v4310_fail_closed_adversarial.py::test_risk_mapping_and_monotonic_floors` | Risk mapping and monotonic floor. |
| Domain risk cannot downgrade | `tests/test_v4310_fail_closed_adversarial.py::test_risk_mapping_and_monotonic_floors` | High-risk domains retain their minimum class. |
| Complete FINANCIAL evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Full policy profile is a subset of the targeted gate. |
| Complete AUTH_TENANT evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Shared union invariant. |
| Complete DATABASE evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Shared union invariant. |
| Complete ZATCA evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Shared union invariant. |
| Complete PROVIDER evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Shared union invariant. |
| Complete CONCURRENCY evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Shared union invariant. |
| Complete SECURITY evidence union | `tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate` | Shared union invariant. |
| Progressive exposure uses effective risk | `tests/test_v4310_fail_closed_adversarial.py::test_progressive_critical_exposure_requires_write_and_owner_stop` | Critical exposure requires write gate and owner stop. |
| Classification record mandatory | `tests/test_v4310_fail_closed_adversarial.py::test_classification_blast_plan_targeted_and_diff_require_semantics` | Classification and investigation records are required. |
| Per-file plan reasons mandatory | `tests/test_v4310_fail_closed_adversarial.py::test_classification_blast_plan_targeted_and_diff_require_semantics` | Every planned path has a root-cause and validation reason. |
| Empty targeted-validation metadata rejected | `tests/test_v4310_fail_closed_adversarial.py::test_classification_blast_plan_targeted_and_diff_require_semantics` | Empty metadata fails the high-risk targeted gate. |
| Complete diff-forensics enumeration | `tests/test_v4310_control_plane_adversarial.py::test_git_inventory_omitting_one_actual_path_blocks_diff_forensics` | One omitted path and one extra path both fail. |
| Independent Git inventory is mandatory at the lifecycle gate | `tests/test_v4310_control_plane_adversarial.py::test_authoritative_inventory_is_collected_from_the_bound_revisions`; `tests/test_v4310_control_plane_adversarial.py::test_diff_transition_requires_independent_git_inventory` | The controller derives the inventory from the exact bound revisions; absent collection blocks the transition. |
| Fake E2 producer rejected | `tests/test_v4310_fail_closed_adversarial.py::test_fake_machine_evidence_cannot_claim_deterministic_execution` | Model-authored deterministic evidence cannot become authoritative. |
| Unsigned E3 through E6 rejected | `tests/test_v4310_control_plane_adversarial.py::test_unsigned_e3_to_e6_evidence_is_rejected` | Parameterized over every protected trust level. |
| Trust-root substitution and self-trust rejected | `tests/test_v4310_control_plane_adversarial.py::test_self_trusted_or_substituted_roots_cannot_authorize_closure` | Raw, fixture, and self-generated roots cannot authorize closure. |
| Stale approval rejected | `tests/test_v2_continuity.py::test_approval_rejects_invented_stale_and_weak_evidence` | Exact task, SHA, evidence, and stored run are required. |
| Self-review rejected | `tests/test_v2_continuity.py::test_same_session_cannot_implement_and_approve_same_sha` | Implementing session cannot approve the same subject. |
| Lifecycle payload, hash, fingerprint, and actor tampering detected | `tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable` | Parameterized direct SQL mutation suite. |
| Lifecycle event deletion detected | `tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable` | Append-only trigger bypass plus chain and MAC verification. |
| Lifecycle event reordering detected | `tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable` | Sequence and previous-hash continuity are checked. |
| Rollback lifecycle event tampering detected | `tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable` | The same replay verifier rejects an event changed to a rollback decision. |
| Stale concurrent write rejected | `tests/test_v4310_control_plane_adversarial.py::test_stale_concurrent_writer_and_wrong_case_binding_are_rejected` | Two writers with one expected version yield one success and one stale failure. |
| CLOSED field without transition ledger rejected | `tests/test_v4310_fail_closed_adversarial.py::test_closed_code_fix_bundle_without_gate_replay_is_invalid` | Manual terminal fields do not create authority. |
| CLOSED bundle wrong trust rejected | `tests/test_v4310_control_plane_adversarial.py::test_fraudulent_terminal_bundle_shapes_fail_independent_replay` | Terminal custody requires host-accepted roots. |
| RESOLVED_NO_CODE requires its own proof | `tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle` | Full authoritative replay and signed proof are required. |
| Database rollback recovery proof | `tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union` | Domain-specific recovery evidence is mandatory. |
| Financial rollback reconciliation | `tests/test_v4310_fail_closed_adversarial.py::test_financial_rollback_cannot_close_on_app_health_only` | Application health alone cannot close financial rollback. |
| ZATCA rollback reconciliation | `tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union` | Legal state recovery is required. |
| Provider rollback reconciliation | `tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union` | Provider reconciliation is required. |
| Concurrency and security rollback recovery | `tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union` | Shared domain-union test covers both domains. |
| Scheduler DONE cannot close a bug | `tests/test_v439_fail_closed_protocol.py::test_authoritative_scheduler_task_cannot_transition_to_done` | Scheduler state is subordinate to bug lifecycle authority. |
| Deployment success cannot close a bug | `tests/test_v4310_control_plane_adversarial.py::test_deployment_success_cannot_close_bug_without_terminal_lifecycle` | Runtime success without terminal replay is insufficient. |
| Hotfix cannot skip staging | `tests/test_v4310_control_plane_adversarial.py::test_hotfix_cannot_skip_staging_or_domain_gates` | Policy forbids state skipping and reduced breadth. |
| Hotfix cannot skip domain gates | `tests/test_v4310_control_plane_adversarial.py::test_hotfix_cannot_skip_staging_or_domain_gates` | Shared hotfix invariant. |
| Reported defect cannot bypass generic autopilot | `tests/test_v4310_fail_closed_adversarial.py::test_reported_defect_cannot_bypass_lifecycle_but_feature_can` | Reported defects require lifecycle handoff. |
| Feature path remains valid | `tests/test_v4310_fail_closed_adversarial.py::test_reported_defect_cannot_bypass_lifecycle_but_feature_can` | Feature intake remains available without bug closure semantics. |
| Unconsumed mandatory policy field fails wiring | `tests/test_v4310_control_plane_adversarial.py::test_unconsumed_mandatory_policy_field_fails_wiring` | Unknown mandatory fields are rejected by the policy registry. |
| Copied evidence from another task rejected | `tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle` | Protected evidence carries an exact lifecycle case binding. |
| Valid signature from wrong trust root rejected | `tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle` | Signature verification uses the accepted root set, not the record claim. |
| Unauthorized E6 controller class rejected | `tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle` | Controller type and signed event identity are checked together. |
| Replaced subject epoch rejected | `tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle` | Bundle and ledger epochs must agree. |
| Event ledger changed after evidence creation rejected | `tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle` | Event hash and subject replay checks fail. |
