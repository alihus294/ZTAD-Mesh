# WorkshopOS Bug-to-Production Protocol Mapping — ZTAD Mesh 4.3.8

This mapping makes the WorkshopOS Fail-Closed Bug-to-Production Protocol v1 directly traceable without relabeling historical validation evidence. The existing `requirements.csv` control catalogue remains intact; the exact lifecycle is an implementation refinement and composition of the problem-intake, evidence, test-integrity, approval, release, and production controls already catalogued there.

| Protocol state / rule | Deterministic implementation | Evidence / policy gate | Regression coverage |
|---|---|---|---|
| `UNVERIFIED_REPORT` | `ztad.problem`, `ztad.bug_lifecycle` | problem-case schema | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `SOURCE_OF_TRUTH_RESOLVED` | `ztad.problem`, `ztad.bug_lifecycle` | authoritative-source semantic checks | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `ISSUE_CLASSIFIED` | `ztad.problem`, `ztad.bug_lifecycle` | classification + evidence | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `BUG_REPRODUCED` | `ztad.problem`, `ztad.bug_lifecycle` | reproduction evidence | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `ROOT_CAUSE_PROVEN` | `ztad.problem`, `ztad.bug_lifecycle` | causal root evidence | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `BLAST_RADIUS_MAPPED` | `ztad.problem`, risk engine | blast radius + invariants + risk | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `CHANGE_PLANNED` | `ztad.problem`, clean isolation | explicit files/tests/non-goals + isolation | `test_v436_problem_lifecycle.py`, `test_v437_bug_protocol.py` |
| `PATCH_IMPLEMENTED` | `ztad.bug_lifecycle` | `CANDIDATE_PATCH_CREATED`; exact candidate identity | `test_v437_bug_protocol.py` |
| `REGRESSION_TEST_PROVEN` | `ztad.bug_lifecycle`, test-integrity controls | `REGRESSION_RED_GREEN_PROVEN` | `test_v437_bug_protocol.py` |
| exact RED→GREEN | `ztad.bug_lifecycle` | bad base SHA + candidate SHA + same oracle + FAIL/PASS metadata | `test_v437_bug_protocol.py` |
| no test weakening | `ztad.test_weakening` | `test-integrity-policy.yaml` | test-integrity suite |
| `TARGETED_VALIDATION_PASS` | `ztad.bug_lifecycle` | targeted evidence + domain-specific evidence | `test_v437_bug_protocol.py` |
| database profile | lifecycle domain gate + existing DB/release controls | ledger/history, fresh DB rebuild, recovery | `test_v437_bug_protocol.py` + database controls |
| auth/tenant profile | lifecycle domain gate + risk/security controls | authz/tenant matrix | `test_v437_bug_protocol.py` + security controls |
| financial profile | lifecycle domain gate | financial invariants | `test_v437_bug_protocol.py` |
| ZATCA profile | lifecycle domain gate | ZATCA invariants | `test_v437_bug_protocol.py` |
| provider profile | lifecycle domain gate + provider contract | provider semantics | provider tests + `test_v437_bug_protocol.py` |
| concurrency profile | lifecycle domain gate + transactional controls | concurrency invariants | concurrency tests + `test_v437_bug_protocol.py` |
| `REGRESSION_VALIDATION_PASS` | `ztad.bug_lifecycle`, configured checks | `FULL_REGRESSION_VALIDATION_PASSED` | lifecycle + existing full-suite CI |
| no pre-existing-failure shortcut | test-integrity/check-history controls | base-vs-candidate evidence | check/test-integrity suite |
| `DIFF_FORENSICS_PASS` | lifecycle + scope/test-integrity/risk controls | `DIFF_FORENSICS_PASSED` | lifecycle + scope/risk tests |
| `INDEPENDENT_REVIEW_PASS` | lifecycle + mesh/approval identity | `INDEPENDENT_REVIEW_COMPLETED`; distinct sessions; `PASS` | `test_v437_bug_protocol.py` + approval tests |
| `CI_PASS` | lifecycle + protected platform evidence | `PROTECTED_CI`, `REQUIRED_CHECKS_VERIFIED` | canonical GitHub CI |
| `STAGING_PASS` | lifecycle + release/progressive controls | `STAGING_SMOKE_PASSED`, `ORIGINAL_PROBLEM_STAGING_VERIFIED` | protected target-host evidence |
| `READY_FOR_OWNER_RELEASE` | lifecycle + release policy | fingerprint, signed manifest, SBOM, attestation/provenance, rollback/observability/synthetic and risk-specific restore evidence | lifecycle policy tests + protected evidence |
| `PRODUCTION_RELEASED` | lifecycle + protected release controller | protected authorization, release-completed evidence, expected digest | protected platform evidence |
| deployment success != fix success | separate lifecycle states | production release cannot transition directly to `CLOSED` | `test_v437_bug_protocol.py` |
| `POST_DEPLOY_VERIFIED` | lifecycle + runtime evidence | original problem verified, production health, synthetic transaction, observation window | protected runtime evidence |
| `CLOSED` | lifecycle controller | only from `POST_DEPLOY_VERIFIED`, or proven rollback closure | `test_v437_bug_protocol.py` |
| `BLOCKED` | lifecycle controller | missing pre-production mandatory evidence | `test_v437_bug_protocol.py` |
| `ROLLBACK_REQUIRED` | lifecycle controller | missing/conflicting/unhealthy post-production evidence | `test_v437_bug_protocol.py` |
| rollback closure | lifecycle controller | `ROLLBACK_COMPLETED`, `POST_ROLLBACK_HEALTH_VERIFIED` | lifecycle policy + protected runtime evidence |
| hotfix does not bypass states | lifecycle policy | `may_skip_states: false` | `test_v437_bug_protocol.py` |
| owner does not make routine coding decisions | zero-trust-delivery/problem-investigation skills | protected authority only when irreducible | skill/eval coverage |
| WorkshopOS canonical deploy path | `workshopos` lifecycle profile | `DEPLOYMENT.md → infra/docs/runbook.md → .github/workflows/deploy.yml` | `test_v437_bug_protocol.py` + host acceptance |
| internal scheduler `DONE` cannot close bug | separate outer lifecycle | `DONE` absent from policy | `test_v437_bug_protocol.py` |

The protected platform still has to prove its own branch, CI, staging, signing/attestation, deployment, rollback, and runtime controls. Presence of this mapping or the local policy is not external evidence.
