from __future__ import annotations

import base64
import copy
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .schema_validation import validate_instance
from .util import canonical_json, load_data


def _crypto_imports():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised only without optional dependency
        raise ConfigurationError("cryptography is required for authoritative evidence signing and verification") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def evidence_signing_payload(record: dict[str, Any]) -> bytes:
    value = copy.deepcopy(record)
    value["signature_or_attestation"] = None
    return canonical_json(value)


def generate_ed25519_keypair(private_path: Path, public_path: Path) -> dict[str, str]:
    _invalid, serialization, Ed25519PrivateKey, _public = _crypto_imports()
    if private_path.exists() or public_path.exists():
        raise ConfigurationError("Refusing to overwrite an existing key file")
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_bytes)
    private_path.chmod(0o600)
    public_path.write_bytes(public_bytes)
    return {"private_key": str(private_path), "public_key": str(public_path)}


def sign_evidence(record: dict[str, Any], *, private_key_path: Path, key_id: str) -> dict[str, Any]:
    _invalid, serialization, Ed25519PrivateKey, _public = _crypto_imports()
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ConfigurationError("Only Ed25519 private keys are supported")
    signature = private_key.sign(evidence_signing_payload(record))
    signed = copy.deepcopy(record)
    signed["signature_or_attestation"] = f"ed25519:{key_id}:{base64.b64encode(signature).decode('ascii')}"
    return signed


def _matches_constraint(value: str, allowed: list[str]) -> bool:
    if "*" in allowed:
        return True
    return value in allowed


def verify_evidence_signature(record: dict[str, Any], trust_roots: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    token = record.get("signature_or_attestation")
    if not isinstance(token, str) or not token:
        return ["Authoritative evidence lacks a signature"]
    parts = token.split(":", 2)
    if len(parts) != 3 or parts[0] != "ed25519":
        return ["Unsupported evidence signature format"]
    _algorithm, key_id, encoded_signature = parts
    keys = trust_roots.get("keys", {}) if isinstance(trust_roots, dict) else {}
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, dict):
        return [f"Unknown evidence signing key: {key_id}"]
    if key.get("status", "ACTIVE") not in {"ACTIVE", "VERIFY_ONLY"}:
        errors.append(f"Evidence signing key is not trusted for verification: {key_id}")
    allowed_levels = list(key.get("allowed_trust_levels", []))
    allowed_producers = list(key.get("allowed_producers", []))
    allowed_types = list(key.get("allowed_types", ["*"]))
    allowed_environments = list(key.get("allowed_environments", ["*"]))
    if not _matches_constraint(str(record.get("trust_level", "")), allowed_levels):
        errors.append("Signing key is not authorized for this trust level")
    if not _matches_constraint(str(record.get("producer", "")), allowed_producers):
        errors.append("Signing key is not authorized for this producer")
    if not _matches_constraint(str(record.get("type", "")), allowed_types):
        errors.append("Signing key is not authorized for this evidence type")
    if not _matches_constraint(str(record.get("environment", "")), allowed_environments):
        errors.append("Signing key is not authorized for this environment")
    if errors:
        return errors
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except Exception:
        return ["Evidence signature is not valid base64"]
    try:
        _invalid, serialization, _private, Ed25519PublicKey = _crypto_imports()
        pem = key.get("public_key_pem")
        if not isinstance(pem, str) or not pem.strip():
            return [f"Trust root {key_id} lacks public_key_pem"]
        public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return ["Only Ed25519 public keys are supported"]
        public_key.verify(signature, evidence_signing_payload(record))
    except _invalid:
        return ["Evidence signature verification failed"]
    except (ValueError, TypeError) as exc:
        return [f"Invalid trust-root public key: {exc}"]
    return []


def load_trust_roots(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"Trust roots must be a regular non-symlink JSON file: {path}")
    if path.suffix.lower() != ".json":
        raise ConfigurationError("Trust roots must use JSON to preserve an unambiguous signed-control format")
    data = load_data(path)
    if not isinstance(data, dict):
        raise ConfigurationError("Trust roots must be an object")
    schema_path = Path(__file__).resolve().parents[2] / "schemas/trust-roots.schema.json"
    schema = load_data(schema_path)
    errors = validate_instance(data, schema)
    if errors:
        raise ConfigurationError("Invalid trust roots: " + "; ".join(errors))
    return data
