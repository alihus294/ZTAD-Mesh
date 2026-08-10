# Repository Control Files

This directory is a protected control plane. Normal application agents must not edit it.

- `config.json`: allowlisted local checks as argv arrays.
- `service-map.json`: service ownership and coupling hints.
- `test-map.json`: protected and component-specific test suites.
- `feature-flags.json`: flag ownership and expiry records.
- `trust-roots.json`: public keys used to verify authoritative evidence.
- `model-registry.yaml`: exact model, prompt, and eval registrations.

File presence means **configured**, not **remotely enforced**. Branch rules, required checks, merge queues, environments, OIDC, artifact attestations, and runtime monitors require separate platform verification.
