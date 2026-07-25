"""Chain verification. Fail-closed.

A chain is valid only if EVERY entry passes EVERY check; the first failure
stops verification and is reported with its index + reason. Checks per entry i:

  1. sequence == i                                  (monotonic, no gaps/reorder)
  2. prev_entry_hash == prev recomputed entry_hash  (chain link; null at genesis)
  3. recomputed entry_hash == stored entry_hash     (record not mutated)
  4. ECDSA-P256 verify over signed_digest(entry_hash) under the header key
  5. envelope.public_key + record.signer_key_id bind to the header key
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

from .envelope import AttestationEnvelopeV0, ChainHeaderV0
from .schema import AttestationError
from .keys import spki_fingerprint

__all__ = ["VerifyResult", "verify_chain", "verify_log"]


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int                      # entries checked (excludes header)
    broken_index: Optional[int]     # 0-based entry index of first failure, else None
    reason: Optional[str]
    key_id: Optional[str] = None
    ended: bool = False             # last entry is a session_end record

    def __bool__(self) -> bool:
        return self.ok


def _fail(count: int, idx: Optional[int], reason: str, key_id: Optional[str] = None) -> VerifyResult:
    return VerifyResult(ok=False, count=count, broken_index=idx, reason=reason, key_id=key_id)


def verify_chain(
    header: ChainHeaderV0,
    envelopes: list[AttestationEnvelopeV0],
    *,
    trusted_spki_sha256: Optional[str] = None,
    trusted_key_id: Optional[str] = None,
) -> VerifyResult:
    """Verify a chain. Internal consistency only proves the log is consistent
    under WHATEVER key it carries — pass `trusted_spki_sha256` (and/or
    `trusted_key_id`) to also prove it was signed by the EXPECTED key. Without a
    pin, an attacker who rewrites the log and signs it with their own key
    produces a self-consistent but untrusted chain that internal checks accept.
    """
    # Trust-anchor pinning (external authenticity), checked before anything else.
    if trusted_spki_sha256 is not None and header.spki_sha256 != trusted_spki_sha256:
        return _fail(0, None,
                     f"header key {header.spki_sha256[:16]}… is not the trusted anchor "
                     f"{trusted_spki_sha256[:16]}…", header.key_id)
    if trusted_key_id is not None and header.key_id != trusted_key_id:
        return _fail(0, None,
                     f"header key_id {header.key_id!r} != trusted key_id {trusted_key_id!r}",
                     header.key_id)

    # Load the chain's public key from the header and sanity-check its fingerprint.
    try:
        spki_der = bytes.fromhex(header.spki_der_hex)
        pub = serialization.load_der_public_key(spki_der)
    except Exception as e:  # noqa: BLE001 - malformed header key is a hard fail
        return _fail(0, None, f"header public key unreadable: {e}", header.key_id)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return _fail(0, None, "header key is not an EC public key", header.key_id)
    if spki_fingerprint(spki_der) != header.spki_sha256:
        return _fail(0, None, "header spki_sha256 does not match spki_der", header.key_id)

    prev_eh: Optional[str] = None
    for i, env in enumerate(envelopes):
        rec = env.record

        if rec.sequence != i:
            return _fail(i, i, f"sequence {rec.sequence} != expected {i}", header.key_id)
        if rec.prev_entry_hash != prev_eh:
            return _fail(i, i, "prev_entry_hash does not link to previous entry", header.key_id)

        recomputed = rec.entry_hash_hex()
        if recomputed != env.entry_hash:
            return _fail(i, i, "stored entry_hash != recomputed (record mutated)", header.key_id)

        if env.public_key.spki_sha256 != header.spki_sha256:
            return _fail(i, i, "envelope public_key fingerprint != header key", header.key_id)
        if env.public_key.key_id != header.key_id or rec.signer_key_id != header.key_id:
            return _fail(i, i, "key_id mismatch (envelope/record vs header)", header.key_id)
        # The header is unsigned metadata; binding each signed record's session_id
        # to it makes a header swap an explicit failure rather than silent.
        if rec.session_id != header.session_id:
            return _fail(i, i, "record session_id != chain header session_id", header.key_id)

        try:
            der_sig = encode_dss_signature(int(env.signature.r, 16), int(env.signature.s, 16))
            pub.verify(der_sig, rec.signed_digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
        except InvalidSignature:
            return _fail(i, i, "signature does not verify", header.key_id)
        except Exception as e:  # noqa: BLE001 - malformed r/s etc.
            return _fail(i, i, f"signature check error: {e}", header.key_id)

        prev_eh = recomputed

    ended = bool(envelopes) and envelopes[-1].record.event_type == "session_end"
    return VerifyResult(ok=True, count=len(envelopes), broken_index=None,
                        reason=None, key_id=header.key_id, ended=ended)


def verify_log(
    path: Union[str, Path],
    *,
    trusted_spki_sha256: Optional[str] = None,
    trusted_key_id: Optional[str] = None,
) -> VerifyResult:
    """Verify a `.jsonl` attestation log: line 1 = header, rest = envelopes.

    A malformed/truncated line (bad JSON, partial last line) fails closed at
    that entry index (STRICT: a truncated final line is a verification
    failure, never silently ignored).

    Pass `trusted_spki_sha256` (and/or `trusted_key_id`) to require the log was
    signed by an externally-pinned key, not merely self-consistent under the
    key it carries. Callers making an authenticity claim SHOULD pin."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        return _fail(0, None, f"cannot read log: {e}")

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return _fail(0, None, "empty log (no header)")

    try:
        header = ChainHeaderV0.from_json_line(lines[0])
    except (AttestationError, ValueError) as e:
        return _fail(0, None, f"bad chain header: {e}")

    envelopes: list[AttestationEnvelopeV0] = []
    for j, line in enumerate(lines[1:]):
        try:
            envelopes.append(AttestationEnvelopeV0.from_json_line(line))
        except (AttestationError, ValueError) as e:
            # j is the entry index (0-based) of the offending envelope line.
            return _fail(len(envelopes), j, f"malformed/truncated entry: {e}", header.key_id)

    return verify_chain(
        header, envelopes,
        trusted_spki_sha256=trusted_spki_sha256,
        trusted_key_id=trusted_key_id,
    )
