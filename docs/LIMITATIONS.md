# Known Limitations — ZTAD Mesh 4.2.0

1. No system can guarantee completion of an impossible or externally blocked task. ZTAD guarantees containment, durable state, retry scheduling, and continuation of other safe runnable work.
2. The bundled SQLite stores are single-host. Multi-host execution requires a shared transactional backend or durable workflow platform with equivalent lease/idempotency semantics.
3. `mesh-service` needs an external process manager for restart after crash, logoff, or reboot.
4. Repository indexing is conservative. Reflection, generated code, runtime plugin loading, external queues, and database-side behavior may require language-specific tools or targeted context expansion.
5. Generic provider adapters do not create kernel-level sandboxes. Their commands and environments must be host-accepted.
6. Task-family benchmarks are local samples. They must be rerun after model, prompt, schema, toolchain, or case-suite changes and do not establish general model superiority.
7. More agents can increase cost and correlated error. The router caps useful parallelism and frontier reviews remain evidence-gated.
8. Local machine checks are not protected CI evidence.
9. GitHub, CI, artifact, deployment, canary, and rollback controls are not active merely because templates or adapters exist.
10. Codex hooks require host discovery/trust and must not be the only control.
11. Windows path/security behavior still requires native host acceptance on the target machine.
12. Production autonomy remains conditional until target-host acceptance, rollback rehearsal, and observed canary behavior succeed.
