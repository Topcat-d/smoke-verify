"""CLI behavior: fail-closed trust, tamper demo, export artifacts."""
from __future__ import annotations

import json

from smoke_verify.cli import main

from .conftest import CHAINS_DIR


def test_verify_refuses_without_trust_anchor(capsys):
    rc = main(["verify", str(CHAINS_DIR / "valid_basic.jsonl")])
    assert rc == 2
    assert "refusing to verify without a trust anchor" in capsys.readouterr().err


def test_verify_pinned_ok(trusted_fp, capsys):
    rc = main(["verify", str(CHAINS_DIR / "valid_basic.jsonl"),
               "--trusted-spki-sha256", trusted_fp])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] and out["trust"] == "pinned"


def test_verify_wrong_pin_fails(capsys):
    rc = main(["verify", str(CHAINS_DIR / "valid_basic.jsonl"),
               "--trusted-spki-sha256", "0" * 64])
    assert rc == 1


def test_verify_require_ended_flags_unended(trusted_fp, capsys):
    rc = main(["verify", str(CHAINS_DIR / "valid_unended.jsonl"),
               "--trusted-spki-sha256", trusted_fp, "--require-ended"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert "session_end" in out["reason"]


def test_verify_all_directory(trusted_fp, capsys):
    rc = main(["verify-all", str(CHAINS_DIR), "--trusted-spki-sha256", trusted_fp])
    assert rc == 0
    assert "3/3 valid" in capsys.readouterr().out


def test_inspect_unpinned_never_says_valid(basic_chain, capsys):
    rc = main(["inspect", str(basic_chain)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "INTERNALLY CONSISTENT" in out
    assert "VALID (pinned" not in out


def test_tamper_demo_detects_and_recovers(basic_chain, tmp_path, capsys):
    out_path = tmp_path / "tampered.jsonl"
    rc = main(["tamper", str(basic_chain), "--output", str(out_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "INVALID" in out
    assert "recovered:" in out
    assert out_path.exists()
    # the original is untouched
    assert main(["verify", str(basic_chain), "--trust-log-header", "--quiet"]) == 0


def test_export_md_and_json(basic_chain, tmp_path, capsys):
    md_path = tmp_path / "audit.md"
    rc = main(["export", str(basic_chain), "--format", "md", "--output", str(md_path)])
    assert rc == 0
    assert "INTERNALLY CONSISTENT" in md_path.read_text(encoding="utf-8")

    json_path = tmp_path / "audit.json"
    rc = main(["export", str(basic_chain), "--format", "json", "--output", str(json_path)])
    assert rc == 0
    summary = json.loads(json_path.read_text(encoding="utf-8"))
    assert summary["chain_ok"] and summary["count"] == 6


def test_anchor_roundtrip(basic_chain, tmp_path, capsys):
    anchor_path = tmp_path / "anchor.json"
    rc = main(["anchor", str(basic_chain), "--output", str(anchor_path)])
    assert rc == 0
    rc = main(["verify", str(basic_chain), "--trust-log-header",
               "--anchor", str(anchor_path), "--quiet"])
    assert rc == 0
