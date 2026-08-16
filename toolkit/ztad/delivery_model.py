from __future__ import annotations

"""Derive the delivery shape from repository source-of-truth markers.

The lifecycle must not let an agent choose a weaker delivery model in order to
skip runtime controls.  This module therefore derives the model from the
repository tree and returns a digest of the exact marker evidence used.
"""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from .util import canonical_json, sha256_bytes, sha256_file

PACKAGE_OR_PLUGIN = "PACKAGE_OR_PLUGIN"
HOSTED_RUNTIME_SERVICE = "HOSTED_RUNTIME_SERVICE"
HYBRID = "HYBRID"
UNDETERMINED = "UNDETERMINED"
DELIVERY_MODELS = frozenset({PACKAGE_OR_PLUGIN, HOSTED_RUNTIME_SERVICE, HYBRID})
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

PACKAGE_MARKERS = (
    ".codex-plugin/plugin.json",
    "toolkit/pyproject.toml",
    "scripts/ztad.py",
)
RUNTIME_MARKERS = (
    "DEPLOYMENT.md",
    "infra/docs/runbook.md",
    ".github/workflows/deploy.yml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "kubernetes",
    "k8s",
    "helm",
    "terraform",
)


@dataclass(frozen=True)
class DeliveryModelResult:
    model: str
    proof: dict[str, Any]
    proof_digest: str
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_model": self.model,
            "delivery_model_proof": self.proof,
            "delivery_model_proof_digest": self.proof_digest,
            "errors": list(self.errors),
        }


def _regular(root: Path, relative: str) -> Path | None:
    path = root / relative
    if path.is_file() and not path.is_symlink():
        return path
    return None


def _directory(root: Path, relative: str) -> Path | None:
    path = root / relative
    if path.is_dir() and not path.is_symlink():
        return path
    return None


def _marker_digests(root: Path, markers: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for marker in sorted(markers):
        path = _regular(root, marker)
        if path is not None:
            result[marker] = sha256_file(path)
    return result


def derive_delivery_model(repository_root: Path | str) -> DeliveryModelResult:
    """Derive a delivery model without accepting a caller-selected model.

    An absent or invalid source tree is deliberately ``UNDETERMINED``.  A
    lifecycle controller may conservatively retain the legacy hosted path, but
    it may never use an unavailable source tree to enable the package path.
    """

    supplied_root = Path(repository_root)
    root = supplied_root.resolve()
    errors: list[str] = []
    if supplied_root.is_symlink() or not root.is_dir():
        proof = {"proof_format": "source-of-truth-marker-set-v1", "package_markers": [], "runtime_markers": []}
        return DeliveryModelResult(
            UNDETERMINED,
            proof,
            sha256_bytes(canonical_json(proof)),
            ("Repository source tree is unavailable",),
        )

    package_markers = [marker for marker in PACKAGE_MARKERS if _regular(root, marker) is not None]
    runtime_markers = [
        marker
        for marker in RUNTIME_MARKERS
        if _regular(root, marker) is not None or _directory(root, marker) is not None
    ]
    package_complete = set(package_markers) == set(PACKAGE_MARKERS)
    has_runtime = bool(runtime_markers)
    if package_complete and has_runtime:
        model = HYBRID
    elif package_complete:
        model = PACKAGE_OR_PLUGIN
    elif has_runtime:
        model = HOSTED_RUNTIME_SERVICE
    else:
        model = UNDETERMINED
        errors.append("Repository has no supported package or runtime delivery markers")

    proof = {
        "proof_format": "source-of-truth-marker-set-v1",
        "package_markers": sorted(package_markers),
        "package_marker_digests": _marker_digests(root, package_markers),
        "runtime_markers": sorted(runtime_markers),
        "runtime_marker_digests": _marker_digests(root, runtime_markers),
        "package_markers_complete": package_complete,
        "runtime_markers_present": has_runtime,
        "derivation": "source-of-truth-marker-set-v1",
    }
    return DeliveryModelResult(
        model,
        proof,
        sha256_bytes(canonical_json(proof)),
        tuple(errors),
    )


def validate_delivery_model(
    repository_root: Path | str | None,
    *,
    model: str | None,
    proof: dict[str, Any] | None = None,
    proof_digest: str | None = None,
) -> list[str]:
    """Validate a recorded model against the current source tree.

    The recorded value is never authoritative by itself.  Missing source
    access fails closed for the package path and for any explicit model.
    """

    errors: list[str] = []
    if model is None:
        return errors
    if model not in DELIVERY_MODELS:
        return [f"Unsupported delivery model: {model}"]
    if repository_root is None:
        return ["Delivery model validation requires the repository source tree"]
    detected = derive_delivery_model(repository_root)
    errors.extend(detected.errors)
    if detected.model != model:
        errors.append(
            f"Delivery model does not match repository source of truth: recorded={model}, detected={detected.model}"
        )
    if proof_digest is not None and proof_digest != detected.proof_digest:
        errors.append("Delivery model proof digest does not match the repository source of truth")
    if proof is not None and proof != detected.proof:
        errors.append("Delivery model proof does not match the repository source of truth")
    return sorted(set(errors))


def validate_delivery_model_proof(
    model: str | None,
    proof: dict[str, Any] | None,
    proof_digest: str | None,
) -> list[str]:
    """Validate the self-consistency of a recorded source-marker proof.

    This does not claim host custody or replace re-derivation from a checkout;
    it only prevents a verifier from accepting a model/proof/digest tuple that
    contradicts itself.
    """

    errors: list[str] = []
    if model not in DELIVERY_MODELS:
        return [f"Unsupported delivery model proof subject: {model}"]
    if not isinstance(proof, dict):
        return ["Delivery model proof must be an object"]
    if proof.get("derivation") != "source-of-truth-marker-set-v1":
        errors.append("Delivery model proof uses an unsupported derivation")
    if proof_digest != sha256_bytes(canonical_json(proof)):
        errors.append("Delivery model proof digest does not match the proof content")
    package_markers = set(str(item) for item in proof.get("package_markers") or [])
    runtime_markers = set(str(item) for item in proof.get("runtime_markers") or [])
    if not package_markers.issubset(set(PACKAGE_MARKERS)):
        errors.append("Delivery model proof contains an unknown package marker")
    if not runtime_markers.issubset(set(RUNTIME_MARKERS)):
        errors.append("Delivery model proof contains an unknown runtime marker")
    package_complete = package_markers == set(PACKAGE_MARKERS)
    runtime_present = bool(runtime_markers)
    if proof.get("package_markers_complete") is not package_complete:
        errors.append("Delivery model proof package completeness flag is inconsistent")
    if proof.get("runtime_markers_present") is not runtime_present:
        errors.append("Delivery model proof runtime presence flag is inconsistent")
    package_digests = proof.get("package_marker_digests") if isinstance(proof.get("package_marker_digests"), dict) else {}
    runtime_digests = proof.get("runtime_marker_digests") if isinstance(proof.get("runtime_marker_digests"), dict) else {}
    if set(package_digests) != package_markers:
        errors.append("Delivery model proof package marker digests are incomplete or extra")
    if set(runtime_digests) != runtime_markers:
        errors.append("Delivery model proof runtime marker digests are incomplete or extra")
    for marker, digest in {**package_digests, **runtime_digests}.items():
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            errors.append(f"Delivery model proof marker digest is invalid: {marker}")
    expected_model = HYBRID if package_complete and runtime_present else (
        PACKAGE_OR_PLUGIN if package_complete else HOSTED_RUNTIME_SERVICE if runtime_present else UNDETERMINED
    )
    if expected_model != model:
        errors.append(f"Delivery model proof contradicts its model: recorded={model}, derived={expected_model}")
    return sorted(set(errors))
