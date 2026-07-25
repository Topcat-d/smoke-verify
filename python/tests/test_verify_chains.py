"""Chain verification against the golden signed chains, plus every tamper
class the verifier must catch. Mutations happen on tmp copies only."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from smoke_verify import (
    UnknownVersionError,
    check_anchor,
    diff_chains,
    localize_entry,
    make_anchor,
    verify_log,
    verify_log_any,
)

from .conftest import CHAINS_DIR


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _write(p: Path, lines: list[str]) -> None:
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- valid chains -----------------------------------------------------------

@pytest.mark.parametrize("name", ["valid_basic.jsonl", "valid_unicode.jsonl", "valid_unended.jsonl"])
def test_golden_chain_verifies_pinned(name, trusted_fp, manifest):
    res = verify_log(CHAINS_DIR / name, trusted_spki_sha256=trusted_fp)
    meta = manifest["chains"][name]
    assert res.ok, res.reason
    assert res.count == meta["entries"]
    assert res.ended == meta["ended"]


def test_golden_chain_verifies_unpinned(basic_chain):
    assert verify_log(basic_chain).ok


def test_wrong_pin_fails(basic_chain):
    res = verify_log(basic_chain, trusted_spki_sha256="0" * 64)
    assert not res.ok
    assert "trusted anchor" in res.reason


def test_wrong_key_id_pin_fails(basic_chain):
    res = verify_log(basic_chain, trusted_key_id="not-the-key")
    assert not res.ok


# --- tamper classes ---------------------------------------------------------

def test_field_edit_detected_and_localized(basic_chain, manifest):
    lines = _lines(basic_chain)
    raw = json.loads(lines[2])  # entry index 1 (first pre_tool_use)
    original_tool = raw["record"]["tool_name"]
    raw["record"]["tool_name"] = "Read" if original_tool != "Read" else "Bash"
    lines[2] = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _write(basic_chain, lines)

    res = verify_log(basic_chain)
    assert not res.ok
    assert res.broken_index == 1
    assert "record mutated" in res.reason

    loc = localize_entry(raw["record"], raw["entry_hash"], manifest["signer"]["key_id"])
    assert loc.recovered
    assert any(c.field == "tool_name" and c.original == original_tool for c in loc.changes)


def test_dropped_entry_detected(basic_chain):
    lines = _lines(basic_chain)
    del lines[3]  # drop entry index 2
    _write(basic_chain, lines)
    res = verify_log(basic_chain)
    assert not res.ok
    assert res.broken_index == 2  # sequence gap surfaces at the next entry


def test_reordered_entries_detected(basic_chain):
    lines = _lines(basic_chain)
    lines[2], lines[3] = lines[3], lines[2]
    _write(basic_chain, lines)
    res = verify_log(basic_chain)
    assert not res.ok
    assert res.broken_index == 1


def test_truncated_final_line_fails_closed(basic_chain):
    text = basic_chain.read_text(encoding="utf-8").rstrip("\n")
    basic_chain.write_text(text[: len(text) - 25], encoding="utf-8")  # cut mid-JSON
    res = verify_log(basic_chain)
    assert not res.ok
    assert "malformed/truncated" in res.reason


def test_signature_swap_detected(basic_chain):
    lines = _lines(basic_chain)
    a, b = json.loads(lines[1]), json.loads(lines[2])
    a["signature"], b["signature"] = b["signature"], a["signature"]
    lines[1] = json.dumps(a, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    lines[2] = json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _write(basic_chain, lines)
    res = verify_log(basic_chain)
    assert not res.ok
    assert res.reason == "signature does not verify"


def test_whole_chain_prefix_truncation_is_valid_but_unended(basic_chain):
    """Dropping trailing entries yields a VALID prefix — the documented limit
    that --require-ended / anchoring exist to close."""
    lines = _lines(basic_chain)
    _write(basic_chain, lines[:4])  # header + 3 entries, no session_end
    res = verify_log(basic_chain)
    assert res.ok
    assert not res.ended


# --- anchor closes the rollback gap ----------------------------------------

def test_anchor_catches_rollback(basic_chain):
    anchor = make_anchor(basic_chain)
    assert check_anchor(basic_chain, anchor).ok

    lines = _lines(basic_chain)
    _write(basic_chain, lines[:4])  # roll back to a shorter (still-valid) prefix
    ar = check_anchor(basic_chain, anchor)
    assert not ar.ok
    assert "fewer than the anchored" in ar.reason


# --- diff against a trusted reference ---------------------------------------

def test_diff_identical_and_after_edit(basic_chain, tmp_path):
    ref = tmp_path / "reference.jsonl"
    ref.write_text(basic_chain.read_text(encoding="utf-8"), encoding="utf-8")
    assert diff_chains(ref, basic_chain).identical

    lines = _lines(basic_chain)
    raw = json.loads(lines[2])
    raw["record"]["tool_name"] = "Glob"
    lines[2] = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _write(basic_chain, lines)

    d = diff_chains(ref, basic_chain)
    assert not d.identical
    assert any(x.field == "tool_name" for x in d.entry_changes)


# --- version fail-closed ----------------------------------------------------

def test_unknown_version_refused(basic_chain):
    lines = _lines(basic_chain)
    head = json.loads(lines[0])
    head["version"] = "smoke.attestation.v0.1"
    lines[0] = json.dumps(head, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _write(basic_chain, lines)
    with pytest.raises(UnknownVersionError, match="v0.1"):
        verify_log_any(basic_chain)
