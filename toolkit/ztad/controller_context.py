from __future__ import annotations

"""Controller identity used by the authoritative lifecycle store.

The model may describe a requested transition, but it does not choose the
identity that is recorded as the controller.  The protected lifecycle
authorization remains the cryptographic proof of authority; this context
provides the non-model identity that the store binds into every event.
"""

import hashlib
import os
import sys
from dataclasses import dataclass
from typing import Any, Mapping

from .util import canonical_json


LIFECYCLE_CONTROLLER_ID = "platform:lifecycle-controller"
LIFECYCLE_CONTROLLER_TYPE = "protected-lifecycle-controller"
MODEL_IDENTITY_PREFIXES = ("agent:", "model:", "assistant:")
_VERIFIED_CONTEXT_TOKEN = object()


@dataclass(frozen=True, init=False)
class ControllerRuntimeContext:
    """Immutable controller identity supplied by the runtime boundary.

    ``authenticated`` is deliberately not inferred from a caller-provided
    actor string.  A signed E6 transition authorization is the authentication
    mechanism for protected lifecycle states.  Local contexts therefore carry
    an explicit unproven source until the protected authorization is checked.
    """

    controller_id: str
    controller_type: str
    runtime_instance_id: str
    identity_source: str
    authentication_mechanism: str
    authenticated: bool = False

    def __init__(
        self,
        controller_id: str,
        controller_type: str,
        runtime_instance_id: str,
        identity_source: str,
        authentication_mechanism: str,
        authenticated: bool = False,
        *,
        _verified_token: object | None = None,
    ) -> None:
        if authenticated and _verified_token is not _VERIFIED_CONTEXT_TOKEN:
            raise PermissionError(
                "Only verified controller attestation may create an authenticated runtime context"
            )
        if _verified_token is not _VERIFIED_CONTEXT_TOKEN:
            raise PermissionError(
                "Only the runtime controller boundary may create a lifecycle controller context"
            )
        object.__setattr__(self, "controller_id", str(controller_id))
        object.__setattr__(self, "controller_type", str(controller_type))
        object.__setattr__(self, "runtime_instance_id", str(runtime_instance_id))
        object.__setattr__(self, "identity_source", str(identity_source))
        object.__setattr__(self, "authentication_mechanism", str(authentication_mechanism))
        object.__setattr__(self, "authenticated", bool(authenticated))

    @property
    def actor(self) -> str:
        return self.controller_id

    def event_identity(self) -> dict[str, Any]:
        return {
            "controller_id": self.controller_id,
            "controller_type": self.controller_type,
            "runtime_instance_id": self.runtime_instance_id,
            "identity_source": self.identity_source,
            "authentication_mechanism": self.authentication_mechanism,
        }

    @classmethod
    def local_unverified(cls) -> "ControllerRuntimeContext":
        """Return a fixed runtime identity for unprotected local operations.

        This identity is never sufficient for a protected terminal
        transition.  Its stable instance identifier lets replay verify the
        controller type without making a process restart invalidate the log.
        """

        executable = os.path.abspath(sys.executable).casefold()
        instance = hashlib.sha256(
            canonical_json(
                {
                    "controller_id": LIFECYCLE_CONTROLLER_ID,
                    "controller_type": LIFECYCLE_CONTROLLER_TYPE,
                    "executable": executable,
                }
            )
        ).hexdigest()
        return cls(
            controller_id=LIFECYCLE_CONTROLLER_ID,
            controller_type=LIFECYCLE_CONTROLLER_TYPE,
            runtime_instance_id=f"runtime:{instance}",
            identity_source="local-runtime-context",
            authentication_mechanism="protected-transition-signature-required",
            authenticated=False,
            _verified_token=_VERIFIED_CONTEXT_TOKEN,
        )

    @classmethod
    def from_verified_attestation(
        cls,
        attestation: Mapping[str, Any],
        *,
        host_attestation_token: object | None = None,
    ) -> "ControllerRuntimeContext":
        """Create a context only after the host has verified its attestation."""

        if host_attestation_token is not _VERIFIED_CONTEXT_TOKEN:
            raise PermissionError(
                "Controller attestation custody is HOST_CAPABILITY_UNPROVEN; a model cannot self-attest"
            )

        metadata = attestation.get("metadata") if isinstance(attestation, Mapping) else None
        if not isinstance(metadata, Mapping):
            raise ValueError("Controller attestation metadata is required")
        controller_id = str(metadata.get("controller_id") or "")
        controller_type = str(metadata.get("controller_type") or "")
        runtime_instance_id = str(metadata.get("runtime_instance_id") or "")
        if controller_id != LIFECYCLE_CONTROLLER_ID:
            raise PermissionError("Controller attestation has an unauthorized controller identity")
        if controller_type != LIFECYCLE_CONTROLLER_TYPE:
            raise PermissionError("Controller attestation has an unauthorized controller type")
        if not runtime_instance_id:
            raise ValueError("Controller attestation runtime_instance_id is required")
        return cls(
            controller_id=controller_id,
            controller_type=controller_type,
            runtime_instance_id=runtime_instance_id,
            identity_source="signed-controller-attestation",
            authentication_mechanism="signed-e6-controller-attestation",
            authenticated=True,
            _verified_token=_VERIFIED_CONTEXT_TOKEN,
        )


def validate_controller_identity(
    context: ControllerRuntimeContext,
    *,
    actor: str | None = None,
    authorization_metadata: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate identity binding without trusting model-supplied labels."""

    errors: list[str] = []
    if context.controller_id != LIFECYCLE_CONTROLLER_ID:
        errors.append("Controller identity is not the protected lifecycle controller")
    if context.controller_type != LIFECYCLE_CONTROLLER_TYPE:
        errors.append("Controller type is not the protected lifecycle controller")
    if actor is not None and actor != context.actor:
        errors.append("Caller-supplied actor does not match the runtime controller identity")
    if context.actor.startswith(MODEL_IDENTITY_PREFIXES):
        errors.append("Model identity cannot be used as lifecycle controller identity")
    if authorization_metadata is not None:
        expected = {
            "controller_id": context.controller_id,
            "controller_type": context.controller_type,
            "identity_source": context.identity_source,
            "authentication_mechanism": context.authentication_mechanism,
        }
        for field, value in expected.items():
            if authorization_metadata.get(field) != value:
                errors.append(f"Controller authorization metadata mismatch: {field}")
        if authorization_metadata.get("model_identity") in {context.controller_id, context.controller_type}:
            errors.append("Model identity and controller identity must remain separate")
    return sorted(set(errors))
