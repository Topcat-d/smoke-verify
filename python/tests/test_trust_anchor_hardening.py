"""Regressions for the 2026-07-25 security review:

1. HIGH — key_id is a producer-chosen LABEL; it must never satisfy the trust
   anchor requirement or earn a "pinned" trust label on its own (a forger sets
   key_id to whatever the victim expects).
2. MEDIUM — a header-only (0-entry) log carries zero signed statements
   (headers are unsigned) and must fail closed, never verify as an empty
   "valid" session.
"""
from __future__ import annotations

import json

from smoke_verify import verify_log
from smoke_verify.cli import main

from .conftest import CHAINS_DIR

CHAIN = CHAINS_DIR / "valid_basic.jsonl"


# --- finding 1: key_id alone is not an anchor --------------------------------

def test_cli_verify_key_id_alone_is_refused(capsys):
    rc = main(["verify", str(CHAIN), "--trusted-key-id", "conformance-test-0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "NOT a trust anchor" in err
    assert "label" in err


def test_cli_verify_all_key_id_alone_is_refused(capsys):
    rc = main(["verify-all", str(CHAINS_DIR), "--trusted-key-id", "conformance-test-0"])
    assert rc == 2


def test_key_id_still_works_as_filter_beside_fingerprint(trusted_fp, capsys):
    rc = main(["verify", str(CHAIN), "--trusted-spki-sha256", trusted_fp,
               "--trusted-key-id", "conformance-test-0", "--quiet"])
    assert rc == 0
    rc = main(["verify", str(CHAIN), "--trusted-spki-sha256", trusted_fp,
               "--trusted-key-id", "not-this-label", "--quiet"])
    assert rc == 1


def test_export_key_id_alone_never_reads_pinned(basic_chain, tmp_path):
    out = tmp_path / "audit.json"
    rc = main(["export", str(basic_chain), "--format", "json", "-o", str(out),
               "--trusted-key-id", "conformance-test-0"])
    assert rc == 0
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["pinned"] is False
    assert summary["trust"] == "log-header (unpinned)"


def test_inspect_key_id_alone_never_reads_valid_pinned(basic_chain, capsys):
    rc = main(["inspect", str(basic_chain), "--trusted-key-id", "conformance-test-0"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "VALID (pinned" not in out
    assert "INTERNALLY CONSISTENT" in out


# --- finding 2: header-only logs fail closed ---------------------------------

def test_header_only_log_fails_closed(tmp_path, trusted_fp):
    header_line = CHAIN.read_text(encoding="utf-8").splitlines()[0]
    p = tmp_path / "empty.jsonl"
    p.write_text(header_line + "\n", encoding="utf-8")

    res = verify_log(p)  # unpinned
    assert not res.ok
    assert "no entries" in res.reason

    res = verify_log(p, trusted_spki_sha256=trusted_fp)  # pinned — still fails
    assert not res.ok

    rc = main(["verify", str(p), "--trusted-spki-sha256", trusted_fp, "--quiet"])
    assert rc == 1
