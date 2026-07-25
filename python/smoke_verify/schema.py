"""Attestation wire contract (smoke.attestation.v0).

This module FREEZES the signed bytes for the Smoke agent attestation log.
Everything downstream (Python writer/verifier, CLI, Claude Code hook, and the
future TypeScript port) depends on this canonicalization being byte-identical
across languages and runs.

Contract summary
----------------
Record (all 14 fields ALWAYS present; nullable fields carry JSON null when
N/A — an absent field is NOT equivalent to null):

    version            "smoke.attestation.v0"   (const)
    event_id           string
    session_id         string
    sequence           uint64
    event_type         pre_tool_use | post_tool_use | session_start | session_end
    tool_name          string | null
    tool_input_sha256  hex32
    tool_output_sha256 hex32 | null
    timestamp_unix_ns  uint64
    actor              claude-code | sdk | user | system
    cwd                string | null
    repo               string | null
    prev_entry_hash    hex32 | null   (null only for the genesis record)
    signer_key_id      string

Canonicalization (RFC 8785 / JCS style):
    - UTF-8, object keys sorted, no insignificant whitespace.
    - integers are emitted as exact integer literals (NO floats anywhere).
    - binary fields are lowercase hex strings.

    !!! CROSS-LANGUAGE RULE !!!  `timestamp_unix_ns` and `sequence` routinely
    exceed 2**53. They are exact JSON integers. A verifier MUST parse them with
    arbitrary-precision integers (e.g. JS BigInt + an integer-preserving JSON
    parser), NEVER as IEEE-754 doubles, or the canonical bytes will differ and
    verification will wrongly fail. Python ints are arbitrary precision, so the
    reference serializer below is exact by construction.

Hashing:
    entry_hash    = SHA256(canonical_record_bytes)
    signed_digest = SHA256(b"SMOKE-AGENT-ATTESTATION-V0" || 0x00 || entry_hash)

The SIGNER signs `signed_digest` (32 bytes) via the existing P-256
sign_p256(digest) path. The domain tag + 0x00 separator prevent a Smoke
signature over an attestation digest from being replayed as a signature over
an arbitrary 32-byte value in some other context.

Chain rule:
    record.prev_entry_hash == previous_envelope.entry_hash
    (genesis: prev_entry_hash == null)
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Optional

# --- constants (part of the frozen contract) --------------------------------

VERSION = "smoke.attestation.v0"
DOMAIN_TAG = b"SMOKE-AGENT-ATTESTATION-V0"
DOMAIN_SEP = b"\x00"
SIGNATURE_ALG = "ECDSA-P256-SHA256"
PUBLIC_KEY_ALG = "P-256"

EVENT_TYPES = ("pre_tool_use", "post_tool_use", "session_start", "session_end")
ACTORS = ("claude-code", "sdk", "user", "system")

# Logical field order (irrelevant to canonical bytes — JCS sorts keys — but
# documents the record shape in one place).
RECORD_FIELDS = (
    "version",
    "event_id",
    "session_id",
    "sequence",
    "event_type",
    "tool_name",
    "tool_input_sha256",
    "tool_output_sha256",
    "timestamp_unix_ns",
    "actor",
    "cwd",
    "repo",
    "prev_entry_hash",
    "signer_key_id",
)

_HEX32_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_U64_MAX = (1 << 64) - 1


class AttestationError(ValueError):
    """Raised for any contract violation (bad field, non-canonical input)."""


def sha256_hex(data: bytes) -> str:
    """Lowercase-hex SHA-256 — the canonical encoding for all hash fields."""
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AttestationRecordV0:
    """One attestation record. Immutable. `version` is fixed by the contract.

    Construct via the keyword fields; `validate()` runs in __post_init__ and
    raises AttestationError on any contract violation, so an invalid record can
    never be canonicalized or signed.
    """

    event_id: str
    session_id: str
    sequence: int
    event_type: str
    tool_input_sha256: str
    timestamp_unix_ns: int
    actor: str
    signer_key_id: str
    tool_name: Optional[str] = None
    tool_output_sha256: Optional[str] = None
    cwd: Optional[str] = None
    repo: Optional[str] = None
    prev_entry_hash: Optional[str] = None
    version: str = VERSION

    def __post_init__(self) -> None:
        self.validate()

    # -- validation ----------------------------------------------------------

    def validate(self) -> None:
        if self.version != VERSION:
            raise AttestationError(f"version must be {VERSION!r}, got {self.version!r}")
        _require_str("event_id", self.event_id, allow_empty=False)
        _require_str("session_id", self.session_id, allow_empty=False)
        _require_str("signer_key_id", self.signer_key_id, allow_empty=False)
        _require_u64("sequence", self.sequence)
        _require_u64("timestamp_unix_ns", self.timestamp_unix_ns)
        if self.event_type not in EVENT_TYPES:
            raise AttestationError(f"event_type must be one of {EVENT_TYPES}, got {self.event_type!r}")
        if self.actor not in ACTORS:
            raise AttestationError(f"actor must be one of {ACTORS}, got {self.actor!r}")
        _require_hex32("tool_input_sha256", self.tool_input_sha256, nullable=False)
        _require_hex32("tool_output_sha256", self.tool_output_sha256, nullable=True)
        _require_hex32("prev_entry_hash", self.prev_entry_hash, nullable=True)
        _require_str_or_none("tool_name", self.tool_name)
        _require_str_or_none("cwd", self.cwd)
        _require_str_or_none("repo", self.repo)

    # -- canonical form ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """The full record as a plain dict — ALL 14 fields present, nullable
        ones as None. This is the object that gets canonicalized."""
        return {
            "version": self.version,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "tool_input_sha256": self.tool_input_sha256,
            "tool_output_sha256": self.tool_output_sha256,
            "timestamp_unix_ns": self.timestamp_unix_ns,
            "actor": self.actor,
            "cwd": self.cwd,
            "repo": self.repo,
            "prev_entry_hash": self.prev_entry_hash,
            "signer_key_id": self.signer_key_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AttestationRecordV0":
        missing = [f for f in RECORD_FIELDS if f not in d]
        if missing:
            raise AttestationError(f"record missing fields: {missing}")
        extra = [k for k in d if k not in RECORD_FIELDS]
        if extra:
            raise AttestationError(f"record has unknown fields: {extra}")
        return cls(
            version=d["version"],
            event_id=d["event_id"],
            session_id=d["session_id"],
            sequence=d["sequence"],
            event_type=d["event_type"],
            tool_name=d["tool_name"],
            tool_input_sha256=d["tool_input_sha256"],
            tool_output_sha256=d["tool_output_sha256"],
            timestamp_unix_ns=d["timestamp_unix_ns"],
            actor=d["actor"],
            cwd=d["cwd"],
            repo=d["repo"],
            prev_entry_hash=d["prev_entry_hash"],
            signer_key_id=d["signer_key_id"],
        )

    def canonical_bytes(self) -> bytes:
        return canonicalize(self.to_dict())

    def entry_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()

    def entry_hash_hex(self) -> str:
        return self.entry_hash().hex()

    def signed_digest(self) -> bytes:
        return signed_digest(self.entry_hash())


# --- canonicalization (RFC 8785 / JCS for our restricted value set) ---------

def canonicalize(obj: dict[str, Any]) -> bytes:
    """Deterministic canonical bytes for an attestation record dict.

    For our value set (str / int / None / nested str-keyed dicts of the same),
    `json.dumps(sort_keys, no-whitespace, ensure_ascii=False)` IS an RFC 8785
    serialization:
      - keys sorted (ASCII keys → code-point order == UTF-16 order),
      - no insignificant whitespace,
      - non-ASCII string values emitted as UTF-8 (not \\u-escaped),
      - integers as exact literals.
    We forbid floats and non-ASCII keys explicitly so we never silently drift
    from JCS.
    """
    _reject_non_canonical(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_non_canonical(value: Any, *, _depth: int = 0) -> None:
    if _depth > 8:
        raise AttestationError("record nested too deeply")
    if isinstance(value, bool):  # bool is an int subclass — JCS-legal, but we don't use it
        return
    if isinstance(value, float):
        raise AttestationError("floats are forbidden in canonical records (use integers)")
    if isinstance(value, int):
        if not (-(1 << 63) <= value <= _U64_MAX):
            raise AttestationError(f"integer out of contract range: {value}")
        return
    if value is None or isinstance(value, str):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not k.isascii():
                raise AttestationError(f"object keys must be ASCII strings, got {k!r}")
            _reject_non_canonical(v, _depth=_depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _reject_non_canonical(v, _depth=_depth + 1)
        return
    raise AttestationError(f"non-canonical value type: {type(value).__name__}")


def signed_digest(entry_hash: bytes) -> bytes:
    """Domain-separated digest the signer actually signs.

    signed_digest = SHA256( DOMAIN_TAG || 0x00 || entry_hash )
    """
    if len(entry_hash) != 32:
        raise AttestationError(f"entry_hash must be 32 bytes, got {len(entry_hash)}")
    return hashlib.sha256(DOMAIN_TAG + DOMAIN_SEP + entry_hash).digest()


# --- field validators -------------------------------------------------------

def _require_str(name: str, v: Any, *, allow_empty: bool) -> None:
    if not isinstance(v, str):
        raise AttestationError(f"{name} must be a string, got {type(v).__name__}")
    if not allow_empty and v == "":
        raise AttestationError(f"{name} must be non-empty")


def _require_str_or_none(name: str, v: Any) -> None:
    if v is not None and not isinstance(v, str):
        raise AttestationError(f"{name} must be string or null, got {type(v).__name__}")


def _require_u64(name: str, v: Any) -> None:
    if isinstance(v, bool) or not isinstance(v, int):
        raise AttestationError(f"{name} must be an integer, got {type(v).__name__}")
    if not (0 <= v <= _U64_MAX):
        raise AttestationError(f"{name} must fit uint64, got {v}")


def _require_hex32(name: str, v: Any, *, nullable: bool) -> None:
    if v is None:
        if nullable:
            return
        raise AttestationError(f"{name} must be a hex32 string, got null")
    if not isinstance(v, str) or not _HEX32_RE.match(v):
        raise AttestationError(f"{name} must be 64 lowercase hex chars, got {v!r}")


__all__ = [
    "VERSION",
    "DOMAIN_TAG",
    "DOMAIN_SEP",
    "SIGNATURE_ALG",
    "PUBLIC_KEY_ALG",
    "EVENT_TYPES",
    "ACTORS",
    "RECORD_FIELDS",
    "AttestationError",
    "AttestationRecordV0",
    "canonicalize",
    "signed_digest",
    "sha256_hex",
]
