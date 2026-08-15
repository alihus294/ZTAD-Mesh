# Known Limitations — ZTAD Mesh 4.3.9

1. No system can guarantee completion of an impossible or externally blocked task. ZTAD guarantees containment, durable state, bounded recovery, and continuation of other safe runnable work.
2. The bundled SQLite stores are single-host. Multi-host execution requires a shared transactional backend or durable workflow platform with equivalent lease/idempotency semantics.
3. `mesh-service` needs an external process manager for restart after crash, logoff, or reboot.
4. Repository indexing is conservative. Reflection, generated code, runtime plugin loading, external queues, and database-side behavior may require language-specific tools or targeted context expansion.
5. Generic provider adapters do not create kernel-level sandboxes. Their commands and environments must be host-accepted.
6. Task-family benchmarks are bounded local samples. They must be rerun after model, prompt, schema, toolchain, provider executable, or case-suite changes and do not establish general model superiority.
7. Luna-first routing is a preference, not an authority override. Risk quality floors, provider availability, deterministic checks, actual-diff escalation, and failure recovery can force Terra or the stronger Mesh.
8. Sol is hard-capped at `HIGH` reasoning by ZTAD routing/runtime controls, but target-host acceptance must still confirm the provider honors the requested reasoning parameter.
9. More agents can increase cost and correlated error. v4.3 deliberately avoids unnecessary fan-out at R0/R1 and bounds R2; R3/R4 remain intentionally heavier.
10. Local machine checks are not protected CI evidence.
11. A green repository workflow does not by itself prove branch protection, required checks, merge queue, deployment controls, OIDC, or production authority.
12. Release checksums and deterministic builds establish integrity for the published files, not the security of a target download channel or workstation.
13. Codex hooks require host discovery/trust and must not be the only control.
14. Windows path/security behavior still requires native host acceptance on the target machine despite cross-platform repository CI.
15. Production autonomy remains conditional until target-host acceptance, protected release authority, rollback rehearsal, and observed production/canary evidence succeed. The bug lifecycle therefore cannot reach `CLOSED` from an internal scheduler terminal state alone.
