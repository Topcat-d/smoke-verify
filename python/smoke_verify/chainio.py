"""Chain loading + version detection. v0-only, fail-closed.

This release verifies `smoke.attestation.v0` exactly. Later contract versions
(v0.1 commitments/grades, v0.2 authorization-join) exist but their specs and
cross-language golden fixtures have not been published — so this verifier
REFUSES them loudly rather than guessing. Publishing a verifier for an
unspecced wire format would be a conformance hole, not a feature.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Union

from .envelope import HEADER_TYPE, AttestationEnvelopeV0, ChainHeaderV0
from .schema import VERSION as VERSION_V0
from .schema import AttestationError
from .verify import VerifyResult, verify_log

__all__ = [
    "VERSION_V0",
    "UnknownVersionError",
    "detect_version",
    "pick_verifier",
    "verify_log_any",
    "load_chain",
]


class UnknownVersionError(ValueError):
    """The log's header names a contract version this release does not verify."""


def _header_version(path: Union[str, Path]) -> str:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise UnknownVersionError(f"cannot read log: {e}") from e
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        raise UnknownVersionError("empty log (no header)")
    try:
        head = json.loads(lines[0])
    except ValueError as e:
        raise UnknownVersionError(f"bad chain header: {e}") from e
    if not isinstance(head, dict) or head.get("type") != HEADER_TYPE:
        raise UnknownVersionError(f"not a chain header (type={head.get('type') if isinstance(head, dict) else head!r})")
    version = head.get("version")
    if not isinstance(version, str) or not version:
        raise UnknownVersionError("chain header carries no version")
    return version


def detect_version(path: Union[str, Path]) -> str:
    """Return the log's contract version, or raise UnknownVersionError if this
    release cannot verify it (fail-closed — never guess at an unknown format)."""
    version = _header_version(path)
    if version != VERSION_V0:
        raise UnknownVersionError(
            f"log version {version!r}: this release verifies {VERSION_V0!r} only "
            "(later versions ship with their published specs + golden fixtures)"
        )
    return version


def pick_verifier(version: str) -> Callable[..., VerifyResult]:
    if version != VERSION_V0:
        raise UnknownVersionError(
            f"log version {version!r}: this release verifies {VERSION_V0!r} only"
        )
    return verify_log


def verify_log_any(path: Union[str, Path], **kwargs) -> VerifyResult:
    """Verify a log after fail-closed version detection."""
    return pick_verifier(detect_version(path))(path, **kwargs)


def load_chain(path: Union[str, Path]) -> tuple[str, ChainHeaderV0, list[AttestationEnvelopeV0]]:
    """Parse a v0 log into (version, header, envelopes). Structural parse only —
    run the verifier for integrity/authenticity claims."""
    version = detect_version(path)
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    header = ChainHeaderV0.from_json_line(lines[0])
    envelopes = [AttestationEnvelopeV0.from_json_line(ln) for ln in lines[1:]]
    return version, header, envelopes
