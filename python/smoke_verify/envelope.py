"""Attestation envelope + chain header.

The envelope is the stored/transported form (one JSONL line per event):

    {record, entry_hash, signature{alg,r,s,encoding}, public_key{key_id,alg,spki_sha256}}

The chain header is the first line of a log file and carries the FULL signing
public key (SPKI DER, hex) so the chain is self-verifying given trust in that
key. Per-envelope `public_key` carries only the fingerprint, bound to the
header by `spki_sha256` + `key_id`.

(This is the VERIFIER-side copy: parsing and shape validation only. The
envelope *producer* lives in the private writer SDK and is intentionally not
part of this repository.)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .schema import (
    SIGNATURE_ALG,
    VERSION,
    AttestationError,
    AttestationRecordV0,
)

HEADER_TYPE = "smoke-attest-header"
HASH_ALG = "SHA-256"


@dataclass(frozen=True)
class SignatureV0:
    alg: str
    r: str  # hex32
    s: str  # hex32
    encoding: str = "raw-rs"

    def to_dict(self) -> dict[str, str]:
        return {"alg": self.alg, "r": self.r, "s": self.s, "encoding": self.encoding}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignatureV0":
        for k in ("alg", "r", "s", "encoding"):
            if k not in d:
                raise AttestationError(f"signature missing {k!r}")
        return cls(alg=d["alg"], r=d["r"], s=d["s"], encoding=d["encoding"])


@dataclass(frozen=True)
class PublicKeyRefV0:
    key_id: str
    alg: str
    spki_sha256: str  # hex32 fingerprint

    def to_dict(self) -> dict[str, str]:
        return {"key_id": self.key_id, "alg": self.alg, "spki_sha256": self.spki_sha256}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PublicKeyRefV0":
        for k in ("key_id", "alg", "spki_sha256"):
            if k not in d:
                raise AttestationError(f"public_key missing {k!r}")
        return cls(key_id=d["key_id"], alg=d["alg"], spki_sha256=d["spki_sha256"])


@dataclass(frozen=True)
class AttestationEnvelopeV0:
    record: AttestationRecordV0
    entry_hash: str  # hex32 (recompute on verify; stored for convenience)
    signature: SignatureV0
    public_key: PublicKeyRefV0

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record.to_dict(),
            "entry_hash": self.entry_hash,
            "signature": self.signature.to_dict(),
            "public_key": self.public_key.to_dict(),
        }

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttestationEnvelopeV0":
        for k in ("record", "entry_hash", "signature", "public_key"):
            if k not in d:
                raise AttestationError(f"envelope missing {k!r}")
        return cls(
            record=AttestationRecordV0.from_dict(d["record"]),
            entry_hash=d["entry_hash"],
            signature=SignatureV0.from_dict(d["signature"]),
            public_key=PublicKeyRefV0.from_dict(d["public_key"]),
        )

    @classmethod
    def from_json_line(cls, line: str) -> "AttestationEnvelopeV0":
        return cls.from_dict(json.loads(line))


@dataclass(frozen=True)
class ChainHeaderV0:
    session_id: str
    key_id: str
    spki_der_hex: str
    spki_sha256: str
    alg: str = "P-256"
    hash: str = HASH_ALG
    sig_alg: str = SIGNATURE_ALG
    version: str = VERSION
    type: str = HEADER_TYPE

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "version": self.version,
            "session_id": self.session_id,
            "key_id": self.key_id,
            "alg": self.alg,
            "hash": self.hash,
            "sig_alg": self.sig_alg,
            "spki_der_hex": self.spki_der_hex,
            "spki_sha256": self.spki_sha256,
        }

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ChainHeaderV0":
        if d.get("type") != HEADER_TYPE:
            raise AttestationError(f"not a chain header (type={d.get('type')!r})")
        for k in ("version", "session_id", "key_id", "spki_der_hex", "spki_sha256"):
            if k not in d:
                raise AttestationError(f"header missing {k!r}")
        return cls(
            session_id=d["session_id"],
            key_id=d["key_id"],
            spki_der_hex=d["spki_der_hex"],
            spki_sha256=d["spki_sha256"],
            alg=d.get("alg", "P-256"),
            hash=d.get("hash", HASH_ALG),
            sig_alg=d.get("sig_alg", SIGNATURE_ALG),
            version=d["version"],
        )

    @classmethod
    def from_json_line(cls, line: str) -> "ChainHeaderV0":
        return cls.from_dict(json.loads(line))


__all__ = [
    "HEADER_TYPE",
    "SignatureV0",
    "PublicKeyRefV0",
    "AttestationEnvelopeV0",
    "ChainHeaderV0",
]
