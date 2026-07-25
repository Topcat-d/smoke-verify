"""Anchor witness verification: RFC 3161 trusted-time layer + git mirror.

Token fixtures are minted by a synthetic vector TSA (private scalar is public
knowledge, TEST-ONLY) so every path runs offline against committed bytes.
"""
from __future__ import annotations

import base64
import json
import subprocess

import pytest

from smoke_verify.cli import main
from smoke_verify.witness import GitMirrorWitness, verify_anchor_witnesses

from .conftest import CONFORMANCE

ANCHORS = CONFORMANCE / "anchors"
CHAIN = CONFORMANCE / "chains" / "valid_basic.jsonl"


def _load(name: str) -> dict:
    return json.loads((ANCHORS / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def tsa_pin() -> bytes:
    m = json.loads((ANCHORS / "manifest.json").read_text(encoding="utf-8"))
    return base64.b64decode(m["pinned_tsa_spki_b64"])


# --- library-level semantics -------------------------------------------------

def test_valid_witness_verifies_pinned(tsa_pin):
    ok, checks = verify_anchor_witnesses(_load("anchor_witnessed.json"),
                                         pinned_tsa_spki_ders=[tsa_pin])
    assert ok
    statuses = [c.status for c in checks]
    assert statuses == ["verified", "error-recorded"]
    assert checks[0].signature_checked
    assert checks[0].gen_time == "20260712000000Z"


def test_unpinned_witness_is_unverified_and_fails_closed():
    ok, checks = verify_anchor_witnesses(_load("anchor_witnessed.json"))
    assert not ok  # no pin → unverified must NOT silently read as trusted time
    assert checks[0].status == "unverified"

    ok2, _ = verify_anchor_witnesses(_load("anchor_witnessed.json"),
                                     allow_unverified=True)
    assert ok2  # explicit opt-in, mirror of --trust-log-header


def test_corrupt_signature_fails(tsa_pin):
    ok, checks = verify_anchor_witnesses(_load("anchor_witness_badsig.json"),
                                         pinned_tsa_spki_ders=[tsa_pin])
    assert not ok
    assert checks[0].status == "invalid"


def test_wrong_key_fails_under_pin(tsa_pin):
    ok, checks = verify_anchor_witnesses(_load("anchor_witness_wrongkey.json"),
                                         pinned_tsa_spki_ders=[tsa_pin])
    assert not ok
    assert checks[0].status == "invalid"
    assert "pinned" in (checks[0].reason or "")


def test_imprint_mismatch_fails_even_unpinned():
    # A token that timestamps a DIFFERENT hash is invalid regardless of trust
    # in the signer — the binding check needs no key at all.
    ok, checks = verify_anchor_witnesses(_load("anchor_witness_imprint_mismatch.json"),
                                         allow_unverified=True)
    assert not ok
    assert checks[0].status == "invalid"
    assert "messageImprint" in (checks[0].reason or "")


def test_recorded_outage_never_fails(tsa_pin):
    a = _load("anchor_witnessed.json")
    a["witnesses"] = [w for w in a["witnesses"] if w.get("status") == "error"]
    ok, checks = verify_anchor_witnesses(a, pinned_tsa_spki_ders=[tsa_pin])
    assert ok
    assert checks[0].status == "error-recorded"


def test_no_witnesses_is_honest_pass():
    a = _load("anchor_witnessed.json")
    a.pop("witnesses")
    ok, checks = verify_anchor_witnesses(a)
    assert ok and checks == []


def test_unknown_witness_type_skipped_not_failed():
    a = _load("anchor_witnessed.json")
    a["witnesses"] = [{"type": "carrier-pigeon", "status": "ok"}]
    ok, checks = verify_anchor_witnesses(a)
    assert ok
    assert checks[0].status == "skipped"


# --- git mirror witness ------------------------------------------------------

def test_git_mirror_witness_commits(tmp_path):
    repo = tmp_path / "mirror"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@e",
                    "commit", "-q", "--allow-empty", "-m", "init"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@e"], cwd=repo, check=True)

    w = GitMirrorWitness(str(repo)).witness("sess-1", 6, "ab" * 32)
    assert w["status"] == "ok", w
    assert len(w["commit"]) == 40
    logged = (repo / "attestation-anchors.log").read_text(encoding="utf-8")
    assert ("ab" * 32) in logged


def test_git_mirror_failure_is_recorded_not_raised(tmp_path):
    w = GitMirrorWitness(str(tmp_path / "not-a-repo")).witness("s", 1, "cd" * 32)
    assert w["status"] == "error"
    assert "error" in w


# --- CLI ---------------------------------------------------------------------

def test_cli_verify_witnessed_anchor_pinned(tsa_pin, capsys):
    rc = main(["verify", str(CHAIN), "--trust-log-header",
               "--anchor", str(ANCHORS / "anchor_witnessed.json"),
               "--tsa-spki-b64", base64.b64encode(tsa_pin).decode()])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    w = out["anchor"]["witnesses"]
    assert [x["status"] for x in w] == ["verified", "error-recorded"]


def test_cli_verify_witnessed_anchor_unpinned_fails(capsys):
    rc = main(["verify", str(CHAIN), "--trust-log-header",
               "--anchor", str(ANCHORS / "anchor_witnessed.json")])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["anchor"]["witnesses"][0]["status"] == "unverified"

    rc = main(["verify", str(CHAIN), "--trust-log-header",
               "--anchor", str(ANCHORS / "anchor_witnessed.json"),
               "--allow-unverified-witness", "--quiet"])
    assert rc == 0


def test_cli_verify_badsig_witness_fails_pinned(tsa_pin, capsys):
    rc = main(["verify", str(CHAIN), "--trust-log-header",
               "--anchor", str(ANCHORS / "anchor_witness_badsig.json"),
               "--tsa-spki-b64", base64.b64encode(tsa_pin).decode(), "--quiet"])
    assert rc == 1


def test_cli_anchor_git_dir(tmp_path, capsys):
    repo = tmp_path / "mirror"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@e"], cwd=repo, check=True)
    out_path = tmp_path / "anchor.json"
    rc = main(["anchor", str(CHAIN), "--git-dir", str(repo), "-o", str(out_path)])
    assert rc == 0
    a = json.loads(out_path.read_text(encoding="utf-8"))
    assert a["witnesses"][0]["type"] == "git_mirror"
    assert a["witnesses"][0]["status"] == "ok"


def test_cli_anchor_unreachable_tsa_recorded_and_nonzero(tmp_path, capsys):
    out_path = tmp_path / "anchor.json"
    rc = main(["anchor", str(CHAIN),
               "--tsa-url", "http://127.0.0.1:9/unreachable", "-o", str(out_path)])
    assert rc == 1  # witnesses requested, none succeeded
    a = json.loads(out_path.read_text(encoding="utf-8"))
    assert a["witnesses"][0]["status"] == "error"  # recorded loudly, not dropped
