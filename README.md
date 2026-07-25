# smoke-verify

**Offline verifier for tamper-evident AI-agent action logs (`smoke.attestation.v0`).**

Every tool call an agent makes becomes a signed, hash-chained record. This
repository holds the *verifier* side: given a log and the signer's public-key
fingerprint, anyone — an auditor, an insurer's claims adjuster, opposing
counsel, a counterparty — can check offline that **no committed record was
altered, dropped, reordered, or replayed**, without trusting the party that
produced the log, and without any hosted service.

> **"Why not just an immutable database?"** An immutable DB proves nobody
> edited *the DB*. It can't prove what your agent actually did, and your
> auditor still has to trust whoever runs the DB. Here the evidence is
> per-record signatures + a hash chain, and the verifier runs on the
> *relying party's* machine. Try it in 10 seconds:
>
> ```
> pip install ./python
> smoke-verify tamper conformance/chains/valid_basic.jsonl
> ```
>
> That mutates a **copy** of a signed log, shows verification fail at the
> exact entry, and — for low-entropy fields — recovers the original value by
> hash search against the signed entry hash.

## What this proves — and what it does NOT

Read this before relying on a green result.

| Claim | Status |
|---|---|
| A committed record was altered after the fact | **CAUGHT** — entry hash + signature break |
| A committed record was dropped, reordered, or replayed | **CAUGHT** — sequence + chain-link break |
| The log was truncated mid-entry (partial line) | **CAUGHT** — fail-closed, never ignored |
| The log was signed by the key *you expected* | **CAUGHT only if you pin** (`--trusted-spki-sha256`) — an unpinned chain is *internally consistent*, not authentic |
| The chain was cut at an entry boundary (rollback to a valid prefix) | **NOT caught by verification alone** — use `--require-ended`, and pin the head with `smoke-verify anchor` published to a place the operator doesn't control |
| An event was suppressed *before* it was ever committed | **NOT caught, by design** — the log truthfully records what was committed, not everything that happened. Closing this requires an enforced collection boundary, not a stronger log format |

The precise claim: **records in the log were not altered after they were
committed, and an independent party can verify that offline without trusting
the producer.** The log being *complete* is a different property with a
different mechanism.

## Quickstart

```bash
pip install ./python
smoke-verify verify conformance/chains/valid_basic.jsonl \
    --trusted-spki-sha256 f758402958548503ac391ad9859dea4f8f1a2137d3cbee3069bc1f2a5ab23da9
smoke-verify inspect conformance/chains/valid_basic.jsonl
smoke-verify export  conformance/chains/valid_basic.jsonl --format html -o audit.html
```

`verify` is **fail-closed**: it refuses to run without a trust anchor unless
you explicitly pass `--trust-log-header` (which proves consistency only), and
it exits nonzero on any failure.

| Command | Purpose |
|---|---|
| `verify` / `verify-all` | verify one log / every log in a directory |
| `inspect` | readable chain summary + timeline |
| `diff` | exact field diff against a trusted reference copy |
| `anchor` | emit/check a chain-head anchor (publish it externally to pin history) |
| `export` | audit artifact — html for humans, json/md for automation |
| `tamper` | demo: mutate a copy, watch detection + recovery |

### TypeScript

`ts/` is a zero-dependency verifier for Node ≥ 22 (native TS). Same accepts,
same rejects, byte-for-byte canonicalization parity with Python — enforced in
CI against the committed golden vectors. `cd ts && npm test`.

## The format

[`spec/attestation-v0.md`](spec/attestation-v0.md) is the frozen v0 wire
contract: RFC 8785 (JCS) canonical JSON, SHA-256 entry hashes, a
domain-separated ECDSA-P256 signature per record, `prev_entry_hash` chaining.
Changing any rule is a new version, never an in-place edit.

`conformance/` holds the golden vectors: record-level fixtures (canonical
bytes, entry hash, signed digest — including a `timestamp_unix_ns = 2⁶⁴−1`
fixture that catches IEEE-754 rounding in ports) and complete signed chains
under a loudly-labeled **test-only** key. Conformance is against these
committed bytes. This release verifies **v0 only** and refuses other versions
loudly; later contract versions ship together with their specs and fixtures
or not at all.

## Where's the writer?

Deliberately not here. Relying parties don't need producer code to check a
chain — that's the point — and shipping a polished writer isn't required for
the evidence to be verifiable. The recorder SDK (framework hooks for Claude
Code / LangChain / OpenAI Agents, remote-signer integration, GPU-backed
signing at fleet scale) is available to design partners.
Contact: top.dylan.m@gmail.com

## License

Apache-2.0. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
