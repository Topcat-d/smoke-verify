# smoke-verify

**Offline verifier for `smoke.attestation.v0` tamper-evident AI-agent action
logs.** Verifier only — no writer, no signer, no key material.

Every tool call an agent makes becomes a signed, hash-chained record. Given a
log and the signer's public-key fingerprint, this checks offline that **no
committed record was altered, dropped, reordered, or replayed** — without
trusting the party that produced the log, and without any hosted service.

## Install

```bash
pip install smoke-verify
```

Requires Python 3.10+. The wire contract itself is pure stdlib; the only
dependency (`cryptography`) is for ECDSA-P256 signature verification.

## Quickstart

```bash
smoke-verify verify path/to/log.jsonl \
    --trusted-spki-sha256 <expected-signing-key-fingerprint>
smoke-verify inspect path/to/log.jsonl \
    --trusted-spki-sha256 <expected-signing-key-fingerprint>
```

`verify` is **fail-closed**: it refuses to run without a trust anchor unless
you explicitly pass `--trust-log-header` (consistency only, NOT
authenticity), and exits nonzero on any failure.

You can try it right now against a committed golden vector (the test-only
signing key's fingerprint is published in the repo's `conformance/`
manifest):

```bash
git clone https://github.com/Topcat-d/smoke-verify
cd smoke-verify
smoke-verify verify conformance/chains/valid_basic.jsonl \
    --trusted-spki-sha256 f758402958548503ac391ad9859dea4f8f1a2137d3cbee3069bc1f2a5ab23da9
```

which prints:

```json
{
  "ok": true,
  "count": 6,
  "key_id": "conformance-test-0",
  "ended": true,
  "broken_index": null,
  "reason": null,
  "trust": "pinned"
}
```

## Commands

| Command | Purpose |
|---|---|
| `verify` / `verify-all` | verify one log / every log in a directory |
| `inspect` | readable chain summary + timeline |
| `diff` | exact field diff against a trusted reference copy |
| `anchor` | emit a chain-head anchor, optionally witnessed by external TSAs / a git mirror |
| `export` | audit artifact — html for humans, json/md for automation |
| `tamper` | demo: mutate a copy, watch detection + recovery |

## Full documentation

The frozen wire spec, cross-language (Python/TypeScript) golden vectors,
trusted-time anchoring, and everything this tool does and does **not**
prove:

https://github.com/Topcat-d/smoke-verify

## License

Apache-2.0. See [LICENSE](https://github.com/Topcat-d/smoke-verify/blob/main/LICENSE)
and [SECURITY.md](https://github.com/Topcat-d/smoke-verify/blob/main/SECURITY.md).
