from __future__ import annotations

"""Trust-root value objects and the host custody boundary."""

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import ConfigurationError
from .schema_validation import validate_instance
from .util import canonical_json, load_data, sha256_bytes

_HOST_ACCEPTANCE_TOKEN = object()


@dataclass(frozen=True, init=False)
class TrustRootAuthority:
    """An immutable trust-root snapshot accepted by the host boundary.

    Signature verification is local functionality.  ``source`` and
    ``host_accepted`` describe the separate custody decision.  A plain mapping
    is intentionally not an authority object and cannot authorize lifecycle
    closure.
    """

    _roots: dict[str, Any]
    source: str
    host_accepted: bool
    config_digest: str
    acceptance_id: str

    def __init__(
        self,
        _roots: dict[str, Any],
        source: str,
        host_accepted: bool,
        config_digest: str,
        acceptance_id: str,
        *,
        _host_token: object | None = None,
    ) -> None:
        # A public dataclass constructor must not be another trust-root
        # acceptance API.  Without this guard a caller could instantiate
        # ``source=HOST_ACCEPTED`` directly and bypass the host loader.
        if host_accepted or source == "HOST_ACCEPTED":
            if _host_token is not _HOST_ACCEPTANCE_TOKEN:
                raise PermissionError(
                    "Only the host trust-root loader may create host-accepted authority"
                )
        roots = copy.deepcopy(_roots)
        object.__setattr__(self, "_roots", roots)
        actual = sha256_bytes(canonical_json(roots))
        if actual != config_digest:
            raise ValueError("Trust-root configuration digest does not match its immutable contents")
        if host_accepted and source != "HOST_ACCEPTED":
            raise ValueError("Only HOST_ACCEPTED trust roots may claim host acceptance")
        if host_accepted and not str(acceptance_id).strip():
            raise ValueError("Host-accepted trust roots require an acceptance identity")
        object.__setattr__(self, "source", str(source))
        object.__setattr__(self, "host_accepted", bool(host_accepted))
        object.__setattr__(self, "config_digest", str(config_digest))
        object.__setattr__(self, "acceptance_id", str(acceptance_id))

    @property
    def roots(self) -> dict[str, Any]:
        return copy.deepcopy(self._roots)

    @classmethod
    def from_host_accepted(
        cls,
        roots: Mapping[str, Any],
        *,
        accepted_digest: str,
        acceptance_id: str,
        _host_token: object | None = None,
    ) -> "TrustRootAuthority":
        snapshot = copy.deepcopy(dict(roots))
        if _host_token is not _HOST_ACCEPTANCE_TOKEN:
            raise PermissionError(
                "Only the host trust-root loader may create host-accepted authority; "
                "local callers can create verification fixtures but cannot self-authorize"
            )
        actual = sha256_bytes(canonical_json(snapshot))
        if actual != accepted_digest:
            raise PermissionError("Host-accepted trust-root digest does not match the supplied configuration")
        if not acceptance_id.strip():
            raise PermissionError("Host trust-root acceptance identity is required")
        return cls(
            _roots=snapshot,
            source="HOST_ACCEPTED",
            host_accepted=True,
            config_digest=actual,
            acceptance_id=acceptance_id,
            _host_token=_HOST_ACCEPTANCE_TOKEN,
        )

    @classmethod
    def from_test_fixture(cls, roots: Mapping[str, Any]) -> "TrustRootAuthority":
        """Create a non-production fixture authority for deterministic tests."""

        snapshot = copy.deepcopy(dict(roots))
        return cls(
            _roots=snapshot,
            source="TEST_FIXTURE",
            host_accepted=False,
            config_digest=sha256_bytes(canonical_json(snapshot)),
            acceptance_id="test-fixture",
        )

    def for_signature_verification(self) -> dict[str, Any]:
        return self.roots

    def is_authoritative(self, *, allow_test_fixture: bool = False) -> bool:
        return self.host_accepted or (allow_test_fixture and self.source == "TEST_FIXTURE")


def load_host_accepted_trust_roots(
    path: Path,
    *,
    accepted_digest: str,
    acceptance_id: str,
    host_acceptance_token: object | None = None,
) -> TrustRootAuthority:
    """Load roots only through an explicit host-owned acceptance boundary.

    The digest and acceptance identifier are claims, not custody.  A caller
    that only controls model input must not be able to turn a self-generated
    root set into an authority object by calling this loader directly.
    Target-host integrations provide the opaque token; local tests may use
    the private token solely to simulate that external boundary.
    """

    if host_acceptance_token is not _HOST_ACCEPTANCE_TOKEN:
        raise PermissionError(
            "Trust-root custody is HOST_CAPABILITY_UNPROVEN; only a host-owned acceptance boundary may authorize roots"
        )

    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"Host trust roots must be a regular non-symlink JSON file: {path}")
    if path.suffix.lower() != ".json":
        raise ConfigurationError("Host trust roots must use JSON")
    value = load_data(path)
    if not isinstance(value, dict):
        raise ConfigurationError("Host trust roots must be an object")
    schema_path = Path(__file__).resolve().parents[2] / "schemas/trust-roots.schema.json"
    errors = validate_instance(value, load_data(schema_path))
    if errors:
        raise ConfigurationError("Invalid host trust roots: " + "; ".join(errors))
    return TrustRootAuthority.from_host_accepted(
        value,
        accepted_digest=accepted_digest,
        acceptance_id=acceptance_id,
        _host_token=_HOST_ACCEPTANCE_TOKEN,
    )


def trust_root_payload(value: Any) -> dict[str, Any] | None:
    if isinstance(value, TrustRootAuthority):
        return value.for_signature_verification()
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return None


def is_host_accepted_trust_roots(value: Any) -> bool:
    return isinstance(value, TrustRootAuthority) and value.host_accepted
