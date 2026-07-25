# smoke-verify (Python)

Offline verifier for `smoke.attestation.v0` tamper-evident AI-agent action
logs. Verifier only — no writer, no signer, no key material.

```bash
pip install smoke-verify
smoke-verify verify <log.jsonl> --trusted-spki-sha256 <expected-key-fingerprint>
```

`verify` is fail-closed: it refuses to run without a trust anchor unless you
explicitly pass `--trust-log-header` (consistency only, NOT authenticity),
and exits nonzero on any failure.

Full documentation, the frozen wire spec, and cross-language golden vectors:
https://github.com/Topcat-d/smoke-verify
