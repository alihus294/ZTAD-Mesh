# Source-Control and CI Enforcement

Full governed delivery requires remote enforcement outside the model session:

- protected main branch or ruleset;
- no direct push;
- required exact-SHA CI checks;
- stale-review invalidation;
- merge queue against current main;
- protected workflow and CODEOWNERS paths;
- least-privilege workflow tokens;
- immutable action and dependency references where policy requires;
- protected build and artifact provenance;
- environment-scoped deployment credentials;
- progressive release and automatic rollback.

ZTAD generates and validates evidence contracts for these controls but does not claim they are active until platform evidence verifies them.
