"""Public-key helpers used by the verifier.

Verification needs only the ability to fingerprint a public key — no signing
code lives in this repository.
"""
from __future__ import annotations

import hashlib

__all__ = ["spki_fingerprint"]


def spki_fingerprint(spki_der: bytes) -> str:
    """key fingerprint = lowercase-hex SHA-256 of the SubjectPublicKeyInfo DER."""
    return hashlib.sha256(spki_der).hexdigest()
