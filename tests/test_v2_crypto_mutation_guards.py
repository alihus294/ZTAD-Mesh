from pathlib import Path

from ztad.crypto import generate_ed25519_keypair, sign_evidence, verify_evidence_signature


def _record():
    return {
        "evidence_id": "ev-1",
        "type": "PROTECTED_CI",
        "trust_level": "E3",
        "producer": "ci:github",
        "environment": "ci",
        "signature_or_attestation": None,
        "metadata": {"value": 1},
    }


def test_crypto_verification_rejects_payload_signature_and_key_mutations(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    roots = {
        "keys": {
            "key-1": {
                "status": "ACTIVE",
                "public_key_pem": public.read_text(encoding="utf-8"),
                "allowed_trust_levels": ["E3"],
                "allowed_producers": ["ci:github"],
                "allowed_types": ["PROTECTED_CI"],
                "allowed_environments": ["ci"],
            }
        }
    }
    signed = sign_evidence(_record(), private_key_path=private, key_id="key-1")
    assert verify_evidence_signature(signed, roots) == []

    changed_payload = dict(signed)
    changed_payload["metadata"] = {"value": 2}
    assert verify_evidence_signature(changed_payload, roots)

    changed_signature = dict(signed)
    token = changed_signature["signature_or_attestation"]
    changed_signature["signature_or_attestation"] = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    assert verify_evidence_signature(changed_signature, roots)

    private2 = tmp_path / "private2.pem"
    public2 = tmp_path / "public2.pem"
    generate_ed25519_keypair(private2, public2)
    wrong_roots = {"keys": {"key-1": {**roots["keys"]["key-1"], "public_key_pem": public2.read_text(encoding="utf-8")}}}
    assert verify_evidence_signature(signed, wrong_roots)
