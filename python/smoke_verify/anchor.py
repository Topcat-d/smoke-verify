"""Chain anchoring — append-only proof.

Tamper-evidence (signatures + hash chain) proves the log was not edited *without
the signing key*. It does NOT, by itself, stop the key holder from rewriting the
whole history and re-signing it. Anchoring closes that gap.

You publish the chain HEAD to an external, independently-timestamped place at
time T — a git commit, a transparency log (e.g. Sigstore Rekor), a notary, even a
dated public post. Because each `entry_hash` transitively commits to every
earlier entry (the hash chain: a record carries `prev_entry_hash`), the published
head pins the ENTIRE prefix as of T. After that, nobody — including the key
holder — can present a different history for those entries without contradicting
the public anchor.

    anchor = make_anchor("session.jsonl")     # publish this at time T
    ...
    check_anchor("session.jsonl", anchor).ok   # later: history still matches?

An anchor reveals no private material — only the public key fingerprint, the
entry count, and the head hash.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from . import chainio as _versions

__all__ = ["ANCHOR_TYPE", "AnchorResult", "make_anchor", "check_anchor"]

ANCHOR_TYPE = "smoke-attest-anchor"


@dataclass(frozen=True)
class AnchorResult:
    ok: bool
    reason: Optional[str]
    anchored_count: int
    log_count: int

    def __bool__(self) -> bool:
        return self.ok


def _read(path: Union[str, Path]) -> tuple[str, Any, list[Any]]:
    return _versions.load_chain(path)


def make_anchor(log_path: Union[str, Path]) -> dict[str, Any]:
    """Produce an anchor token for the current chain head. Refuses to anchor an
    inconsistent or empty chain (anchoring those would be meaningless)."""
    res = _versions.verify_log_any(log_path)
    if not res.ok:
        raise ValueError(f"refusing to anchor an inconsistent chain: {res.reason}")
    version, header, envs = _read(log_path)
    if not envs:
        raise ValueError("refusing to anchor an empty chain (no entries)")
    return {
        "type": ANCHOR_TYPE,
        "version": version,
        "session_id": header.session_id,
        "key_id": header.key_id,
        "spki_sha256": header.spki_sha256,
        "count": len(envs),
        "head_entry_hash": envs[-1].entry_hash,
    }


def check_anchor(log_path: Union[str, Path], anchor: dict[str, Any]) -> AnchorResult:
    """Check a log against a previously-published anchor.

    Passes iff the log is internally valid, belongs to the same session+key, has
    at least the anchored number of entries (later appends are fine), and its
    entry at the anchored index still has the anchored head hash. A rewrite of
    ANY anchored entry — even re-signed under the SAME key — changes that head
    hash and is caught here, which signature verification alone cannot do.
    """
    if not isinstance(anchor, dict) or anchor.get("type") != ANCHOR_TYPE:
        return AnchorResult(False, "not a smoke-attest-anchor", 0, 0)

    res = _versions.verify_log_any(log_path)  # an anchor over an inconsistent chain proves nothing
    version, header, envs = _read(log_path)
    n = int(anchor.get("count", 0))
    log_n = len(envs)

    if not res.ok:
        return AnchorResult(False, f"chain not internally valid: {res.reason}", n, log_n)
    # Fail closed on a version mismatch: an anchor minted over one schema
    # version must not silently validate a log of another.
    anchored_version = anchor.get("version")
    if anchored_version is not None and anchored_version != version:
        return AnchorResult(
            False, f"anchor version {anchored_version!r} does not match this log ({version!r})", n, log_n
        )
    if header.session_id != anchor.get("session_id"):
        return AnchorResult(False, "anchor session_id does not match this log", n, log_n)
    if header.spki_sha256 != anchor.get("spki_sha256"):
        return AnchorResult(False, "anchor key (spki_sha256) does not match this log", n, log_n)
    if n <= 0:
        return AnchorResult(False, "anchor records no entries", n, log_n)
    if log_n < n:
        return AnchorResult(
            False, f"log has {log_n} entries, fewer than the anchored {n} (truncated below anchor)", n, log_n
        )
    if envs[n - 1].entry_hash != anchor.get("head_entry_hash"):
        return AnchorResult(
            False, f"history diverges from the anchor at entry {n - 1} (chain rewritten since it was anchored)", n, log_n
        )
    return AnchorResult(True, None, n, log_n)
