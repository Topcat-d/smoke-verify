from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFORMANCE = REPO_ROOT / "conformance"
RECORDS_DIR = CONFORMANCE / "records"
CHAINS_DIR = CONFORMANCE / "chains"


@pytest.fixture(scope="session")
def manifest() -> dict:
    return json.loads((CHAINS_DIR / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def trusted_fp(manifest) -> str:
    return manifest["signer"]["spki_sha256"]


@pytest.fixture()
def basic_chain(tmp_path) -> Path:
    """A writable copy of the basic golden chain (tests mutate copies, never fixtures)."""
    src = CHAINS_DIR / "valid_basic.jsonl"
    dst = tmp_path / "valid_basic.jsonl"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return dst
