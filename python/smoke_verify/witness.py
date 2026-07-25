"""External anchor witnesses — trusted time for attestation anchors.

The plain anchor token (`make_anchor`) pins a chain head, but a token you
hold yourself proves nothing about WHEN the history existed: the operator
could rewrite the whole log and mint a fresh anchor. A WITNESS closes that
gap by placing the head hash somewhere the operator does not control:

  - `rfc3161` — an RFC 3161 timestamp authority signs SHA-256(ascii(head))
    with its own key at its own clock. Verified offline against a pinned
    TSA key; the token's genTime bounds the entire chain prefix.
  - `git_mirror` — the head is committed to a (second) git repository whose
    history/push times are independent evidence. Structural, not
    cryptographic time — useful as a cheap second channel.

Witness acquisition NEVER raises and never blocks anchoring: an unreachable
TSA is recorded loudly as a `status: "error"` witness (additive evidence,
fail-closed verification). Verification of a PRESENT ok-witness is
fail-closed: forged, mismatched, or unverifiable tokens fail.
"""
from __future__ import annotations

import base64
import secrets
import subprocess
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from .rfc3161 import (
    build_timestamp_request,
    extract_signer_spki_ders,
    message_imprint_digest,
    parse_timestamp_response,
    parse_timestamp_token,
    verify_timestamp_token,
)

__all__ = [
    "TSAClient",
    "GitMirrorWitness",
    "WitnessCheck",
    "verify_anchor_witnesses",
    "WELL_KNOWN_TSA_URLS",
]

# Any RFC 3161 endpoint works; these are common public ones. Live endpoints
# are deployment configuration — tests prove the protocol against committed
# tokens, never against the network.
WELL_KNOWN_TSA_URLS = {
    "digicert": "http://timestamp.digicert.com",
    "sigstore": "https://timestamp.sigstore.dev/api/v1/timestamp",
}


class TSAClient:
    """Minimal RFC 3161 client over HTTP POST (application/timestamp-query).

    request_witness() NEVER raises: any failure is returned as an error
    witness dict so the caller can record it loudly in the anchor.
    """

    def __init__(self, url: str, timeout_s: float = 10.0):
        self.url = url
        self.timeout_s = timeout_s

    def request_witness(self, head_entry_hash: str) -> dict[str, Any]:
        try:
            imprint = message_imprint_digest(head_entry_hash)
            nonce = secrets.randbits(64)
            req_der = build_timestamp_request(imprint, nonce=nonce, cert_req=True)
            request = urllib.request.Request(
                self.url,
                data=req_der,
                headers={"Content-Type": "application/timestamp-query"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout_s) as resp:
                body = resp.read()
            ts_resp = parse_timestamp_response(body)
            if not ts_resp.granted:
                detail = "; ".join(ts_resp.status_strings) or "no status text"
                return self._error(f"TSA refused: status={ts_resp.status} ({detail})")
            if ts_resp.token_der is None:
                return self._error("TSA granted but returned no token")

            token = parse_timestamp_token(ts_resp.token_der)
            if token.imprint_digest != imprint:
                return self._error("TSA token imprint does not match request")
            if token.nonce is not None and token.nonce != nonce:
                return self._error("TSA token nonce does not match request")

            return {
                "type": "rfc3161",
                "url": self.url,
                "status": "ok",
                "gen_time": token.gen_time,
                "token_b64": base64.b64encode(ts_resp.token_der).decode("ascii"),
            }
        except Exception as exc:  # noqa: BLE001 — anchoring must never raise
            return self._error(f"{type(exc).__name__}: {exc}")

    def _error(self, message: str) -> dict[str, Any]:
        return {"type": "rfc3161", "url": self.url, "status": "error",
                "error": message}


class GitMirrorWitness:
    """Append the anchored head to a git repository and commit it.

    The repository's commit history (and its remote's push times) are
    independent evidence of when a chain head existed. witness() never
    raises; failures come back as error witnesses.
    """

    def __init__(self, repo_dir: str, filename: str = "attestation-anchors.log"):
        self.repo_dir = repo_dir
        self.filename = filename

    def witness(self, session_id: str, count: int, head_entry_hash: str) -> dict[str, Any]:
        import os

        try:
            path = os.path.join(self.repo_dir, self.filename)
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{session_id} {count} {head_entry_hash}\n")
            subprocess.run(
                ["git", "add", self.filename],
                cwd=self.repo_dir, check=True, capture_output=True, timeout=30,
            )
            subprocess.run(
                ["git", "commit", "-m",
                 f"attestation-anchor: {session_id} count {count} head {head_entry_hash}"],
                cwd=self.repo_dir, check=True, capture_output=True, timeout=30,
            )
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_dir, check=True, capture_output=True, timeout=30,
            ).stdout.decode("ascii").strip()
            return {"type": "git_mirror", "status": "ok",
                    "repo": self.repo_dir, "file": self.filename,
                    "commit": commit}
        except Exception as exc:  # noqa: BLE001 — anchoring must never raise
            return {"type": "git_mirror", "status": "error",
                    "repo": self.repo_dir, "error": f"{type(exc).__name__}: {exc}"}


@dataclass(frozen=True)
class WitnessCheck:
    """Result of checking ONE witness."""
    type: str
    status: str            # "verified" | "unverified" | "error-recorded" | "invalid" | "skipped"
    gen_time: Optional[str] = None
    reason: Optional[str] = None
    signature_checked: bool = False


def verify_anchor_witnesses(
    anchor: dict[str, Any],
    *,
    pinned_tsa_spki_ders: Sequence[bytes] = (),
    allow_unverified: bool = False,
) -> tuple[bool, list[WitnessCheck]]:
    """Fail-closed check of every witness carried by an anchor.

    Returns (ok, checks). Semantics per witness:

      - status "error" in the anchor: an outage RECORDED at anchoring time.
        Reported as "error-recorded"; never fails verification (the anchor
        is additive evidence and outages are recorded loudly, not hidden).
      - rfc3161 with status "ok": the token MUST parse, MUST bind to this
        anchor's head_entry_hash, and — when pinned TSA keys are supplied —
        MUST signature-verify under one of them. With NO pinned keys the
        token gets structural+imprint checks only and is reported
        "unverified"; that makes the overall result False unless
        `allow_unverified` is set (mirror of --trust-log-header: an
        unverified witness must never silently read as trusted time).
      - git_mirror with status "ok": reported "unverified" (its evidence
        lives in the mirror repo's history, which this offline check cannot
        see). Never fails verification on its own.
      - unknown witness types: "skipped", never a failure (forward compat).

    An anchor with NO witnesses returns (True, []) — the plain anchor
    binding is checked elsewhere (`check_anchor`); absence of witnesses is
    honest, a bad witness is not.
    """
    head = anchor.get("head_entry_hash")
    witnesses = anchor.get("witnesses") or []
    checks: list[WitnessCheck] = []
    ok = True

    for w in witnesses:
        wtype = w.get("type", "?")
        if w.get("status") == "error":
            checks.append(WitnessCheck(wtype, "error-recorded",
                                       reason=w.get("error")))
            continue
        if wtype == "rfc3161":
            token_b64 = w.get("token_b64")
            if not token_b64 or not isinstance(head, str):
                checks.append(WitnessCheck(wtype, "invalid",
                                           reason="ok-witness carries no token"))
                ok = False
                continue
            try:
                token_der = base64.b64decode(token_b64, validate=True)
                imprint = message_imprint_digest(head)
            except Exception as exc:  # noqa: BLE001 — malformed witness fails closed
                checks.append(WitnessCheck(wtype, "invalid", reason=str(exc)))
                ok = False
                continue
            res = verify_timestamp_token(
                token_der, imprint,
                pinned_spki_ders=pinned_tsa_spki_ders,
                require_signature=bool(pinned_tsa_spki_ders),
            )
            if not res["valid"]:
                checks.append(WitnessCheck(wtype, "invalid",
                                           gen_time=res.get("gen_time"),
                                           reason=res.get("reason")))
                ok = False
            elif res["signature_checked"]:
                checks.append(WitnessCheck(wtype, "verified",
                                           gen_time=res.get("gen_time"),
                                           signature_checked=True))
            else:
                checks.append(WitnessCheck(
                    wtype, "unverified", gen_time=res.get("gen_time"),
                    reason="no pinned TSA key — token is structurally sound and "
                           "binds this head, but its signer is UNVERIFIED"))
                if not allow_unverified:
                    ok = False
        elif wtype == "git_mirror":
            checks.append(WitnessCheck(
                wtype, "unverified",
                reason="evidence lives in the mirror repo's commit history; "
                       "check it there (this offline pass cannot)"))
        else:
            checks.append(WitnessCheck(wtype, "skipped",
                                       reason="unknown witness type"))
    return ok, checks


def embedded_tsa_spkis(witness: dict[str, Any]) -> list[bytes]:
    """SPKIs of certificates EMBEDDED in a witness token. Convenience for
    first-contact inspection only — an embedded cert is chosen by whoever
    built the token, so verifying against it proves consistency, NOT that a
    trusted TSA signed. Pin a key out of band for a real claim."""
    token_b64 = witness.get("token_b64")
    if not token_b64:
        return []
    try:
        return extract_signer_spki_ders(base64.b64decode(token_b64, validate=True))
    except Exception:  # noqa: BLE001 — inspection helper, malformed → nothing
        return []
