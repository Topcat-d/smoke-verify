"""Golden record vectors: canonical bytes, entry_hash, and signed_digest must
reproduce EXACTLY. Any drift here is a contract break, not a test flake."""
from __future__ import annotations

import json

import pytest

from smoke_verify.schema import AttestationRecordV0, canonicalize, sha256_hex, signed_digest

from .conftest import RECORDS_DIR

VECTORS = sorted(RECORDS_DIR.glob("*.json"))


@pytest.mark.parametrize("path", VECTORS, ids=[p.stem for p in VECTORS])
def test_record_vector_reproduces(path):
    vec = json.loads(path.read_text(encoding="utf-8"))
    record = vec["record"]

    canonical = canonicalize(record)
    assert canonical.decode("utf-8") == vec["canonical_utf8"], "canonical bytes drifted"

    eh = sha256_hex(canonical)
    assert eh == vec["entry_hash"], "entry_hash drifted"

    sd = signed_digest(bytes.fromhex(eh)).hex()
    assert sd == vec["signed_digest"], "signed_digest drifted"


@pytest.mark.parametrize("path", VECTORS, ids=[p.stem for p in VECTORS])
def test_record_vector_parses_strictly(path):
    vec = json.loads(path.read_text(encoding="utf-8"))
    rec = AttestationRecordV0.from_dict(vec["record"])
    assert rec.entry_hash_hex() == vec["entry_hash"]


def test_uint64_max_timestamp_is_exact():
    """The session_end vector pins timestamp_unix_ns = 2^64-1 specifically to
    catch IEEE-754 double rounding in ports."""
    vec = json.loads((RECORDS_DIR / "session_end.json").read_text(encoding="utf-8"))
    assert vec["record"]["timestamp_unix_ns"] == 18446744073709551615
    assert "18446744073709551615" in vec["canonical_utf8"]
