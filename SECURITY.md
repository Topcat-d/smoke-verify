# Security Policy

## Reporting a vulnerability

Email **top.dylan.m@gmail.com** with a description and, if possible, a
reproducing input (a crafted log file is usually enough). You should receive
an acknowledgment within 72 hours. Please do not open public issues for
suspected vulnerabilities before contact.

Highest-value reports for a verifier:

- **False VALID**: any input that verifies OK but violates the contract
  (forged signature accepted, mutated record accepted, sequence/link break
  missed, version confusion).
- **Fail-open behavior**: any path where a malformed input is silently
  skipped instead of failing the verification.
- Canonicalization divergence between the Python and TypeScript
  implementations (same bytes, different verdicts).

## Scope notes

- This repository contains **no key material and no signing code**. The
  committed conformance chains are signed by a **test-only** key whose seed is
  published in `conformance/chains/manifest.json` by design — treat anything
  signed by that key as untrusted test data.
- An **unpinned** verification (`--trust-log-header`) proves internal
  consistency only. Reports that an attacker can re-sign a rewritten log
  under their *own* key are the documented trust model, not a vulnerability —
  authenticity requires pinning the expected key fingerprint.
- Log **incompleteness** (events never committed) is a documented
  non-property; see the README truth table.
