"""Tamper localization — explain a broken entry to a human.

The verifier detects WHICH entry was mutated ("stored entry_hash !=
recomputed"). This adds WHAT changed, when it can be recovered.

How it can possibly work: when an attacker edits a record but does not (cannot,
without the key) re-sign it, the stored `entry_hash` is still the hash of the
ORIGINAL record. SHA-256 is one-way, so the original is not directly readable —
but for LOW-ENTROPY fields (a 4-value enum, a known tool name, the const
version, the header key_id) the candidate space is tiny. We hold every observed
field fixed, substitute each candidate into one low-entropy field, recompute the
canonical hash, and whichever candidate reproduces the stored `entry_hash` *is*
the original — with cryptographic proof (it hashes to the signed value).

Honest limits (by design — tampering is meant to destroy information):
  - HIGH-entropy fields cannot be recovered: timestamp_unix_ns, the *_sha256
    input/output hashes (and the v0.1/v0.2 *_commitment HMACs), event_id,
    free-text cwd/repo.
  - If more than one field changed, or any high-entropy field changed, the
    search fails and we report "unrecoverable" rather than guess.
  - A reference/backup copy of the chain always yields an exact diff; this
    module is the no-reference best effort.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .schema import ACTORS, EVENT_TYPES, VERSION, canonicalize, sha256_hex

__all__ = ["FieldChange", "LocalizeResult", "localize_entry", "KNOWN_TOOL_NAMES"]

# Known Claude Code tool names — recovering a tampered `tool_name` only works if
# the ORIGINAL value is in this catalog (an unknown original is unrecoverable).
KNOWN_TOOL_NAMES = (
    "Bash", "Read", "Edit", "Write", "Glob", "Grep", "Task", "WebFetch",
    "WebSearch", "NotebookEdit", "TodoWrite", "MultiEdit", "BashOutput",
    "KillShell", "SlashCommand", "ExitPlanMode",
)

# Fields with a small enough candidate space to brute-force. Everything else
# (event_id, timestamp_unix_ns, tool_input_sha256, tool_output_sha256, cwd, repo)
# is high-entropy and cannot be recovered from the hash alone.
_LOW_ENTROPY_FIELDS = ("event_type", "actor", "tool_name", "version", "signer_key_id")


@dataclass(frozen=True)
class FieldChange:
    field: str
    original: Any  # recovered value that reproduces the stored entry_hash (proof)
    observed: Any  # current (tampered) value in the file


@dataclass(frozen=True)
class LocalizeResult:
    recovered: bool
    changes: tuple[FieldChange, ...]
    note: str

    def __bool__(self) -> bool:
        return self.recovered


def _candidates(
    field: str,
    observed: Any,
    header_key_id: Optional[str],
    expected_version: Optional[str],
) -> list[Any]:
    if field == "event_type":
        return [v for v in EVENT_TYPES if v != observed]
    if field == "actor":
        return [v for v in ACTORS if v != observed]
    if field == "tool_name":
        return [v for v in (*KNOWN_TOOL_NAMES, None) if v != observed]
    if field == "version":
        want = expected_version or VERSION
        return [want] if observed != want else []
    if field == "signer_key_id":
        return [header_key_id] if (header_key_id and observed != header_key_id) else []
    return []


def localize_entry(
    record: dict[str, Any],
    stored_entry_hash: str,
    header_key_id: Optional[str] = None,
    expected_version: Optional[str] = None,
) -> LocalizeResult:
    """Recover the original value(s) of a mutated record by hash search.

    `record` is the OBSERVED (tampered) record dict; `stored_entry_hash` is the
    entry_hash stored in the envelope (the hash of the ORIGINAL record)."""
    # If the observed record already hashes to the stored value, nothing was
    # mutated here — the failure is elsewhere (signature, chain link, sequence).
    if sha256_hex(canonicalize(record)) == stored_entry_hash:
        return LocalizeResult(False, (), "entry content matches its stored hash; the break is not a record edit")

    matches: list[FieldChange] = []
    for field in _LOW_ENTROPY_FIELDS:
        observed = record.get(field)
        for cand in _candidates(field, observed, header_key_id, expected_version):
            trial = dict(record)
            trial[field] = cand
            try:
                if sha256_hex(canonicalize(trial)) == stored_entry_hash:
                    matches.append(FieldChange(field, cand, observed))
            except Exception:  # noqa: BLE001 - a non-canonical candidate just isn't the original
                continue

    if len(matches) == 1:
        c = matches[0]
        return LocalizeResult(True, (c,), f"recovered original {c.field} by hash search")
    if len(matches) > 1:
        return LocalizeResult(True, tuple(matches), "multiple single-field edits reproduce the stored hash")
    return LocalizeResult(
        False, (),
        "could not localize: a high-entropy field (timestamp, an input/output hash, event_id) "
        "and/or multiple fields changed — the original cannot be recovered from a tampered copy "
        "(a trusted backup of the chain would still yield an exact diff)",
    )
