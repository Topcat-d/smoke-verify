"""Reference diff — exact field diff of a chain against a trusted copy.

The localizer recovers low-entropy edits with NO backup. When you DO
have a trusted reference copy of the chain (a local backup, or a server that
ingested it), this gives the EXACT diff for EVERY field — including the
high-entropy ones (timestamps, the input/output `*_sha256` hashes, event_id)
that the no-reference localizer cannot recover.

It also catches structural tampering a single-entry check can't: a changed
signing key in the header, and appended/removed/truncated entries.

Alignment is by position (entry index): the common attack is an in-place edit
(same length) or a truncation, both of which position alignment reports exactly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

__all__ = ["FieldDelta", "ChainDiff", "diff_chains"]

# Header fields worth diffing (a signing-key change is the loud one).
_HEADER_FIELDS = ("type", "version", "session_id", "key_id", "alg", "hash", "sig_alg", "spki_sha256")


@dataclass(frozen=True)
class FieldDelta:
    sequence: int  # entry sequence, or -1 for a header field
    field: str
    reference: Any
    target: Any


@dataclass(frozen=True)
class ChainDiff:
    identical: bool
    header_changes: tuple[FieldDelta, ...]
    entry_changes: tuple[FieldDelta, ...]
    added: tuple[int, ...]    # entry positions present in target but not reference
    removed: tuple[int, ...]  # entry positions present in reference but not target
    note: str

    def __bool__(self) -> bool:
        return not self.identical


def _read(path: Union[str, Path]) -> tuple[dict, list[dict]]:
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        raise ValueError(f"empty log: {path}")
    return json.loads(lines[0]), [json.loads(ln) for ln in lines[1:]]


def _seq(env: dict, fallback: int) -> int:
    rec = env.get("record")
    if isinstance(rec, dict) and isinstance(rec.get("sequence"), int):
        return rec["sequence"]
    return fallback


def diff_chains(reference: Union[str, Path], target: Union[str, Path]) -> ChainDiff:
    """Exact field diff of `target` against the trusted `reference` chain."""
    ref_header, ref_envs = _read(reference)
    tgt_header, tgt_envs = _read(target)

    header_changes = [
        FieldDelta(-1, f, ref_header.get(f), tgt_header.get(f))
        for f in _HEADER_FIELDS
        if ref_header.get(f) != tgt_header.get(f)
    ]

    entry_changes: list[FieldDelta] = []
    n = min(len(ref_envs), len(tgt_envs))
    for i in range(n):
        ref_rec = ref_envs[i].get("record", {}) or {}
        tgt_rec = tgt_envs[i].get("record", {}) or {}
        seq = _seq(ref_envs[i], i)
        for key in sorted(set(ref_rec) | set(tgt_rec)):
            if ref_rec.get(key) != tgt_rec.get(key):
                entry_changes.append(FieldDelta(seq, key, ref_rec.get(key), tgt_rec.get(key)))

    removed = tuple(_seq(ref_envs[i], i) for i in range(n, len(ref_envs)))
    added = tuple(_seq(tgt_envs[i], i) for i in range(n, len(tgt_envs)))

    identical = not (header_changes or entry_changes or added or removed)
    note = (
        "target matches the reference chain"
        if identical
        else f"{len(header_changes)} header + {len(entry_changes)} field change(s); "
        f"{len(added)} added, {len(removed)} removed"
    )
    return ChainDiff(identical, tuple(header_changes), tuple(entry_changes), added, removed, note)
