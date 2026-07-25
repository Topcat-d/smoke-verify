# smoke.attestation.v0 — Attestation Wire Contract

**Status**: FROZEN (v0). Changing any rule below is a new version
(`smoke.attestation.v1`), never an in-place edit.

This is the authoritative contract for Smoke's tamper-evident agent
attestation log. The Python reference implementation
(`python/smoke_verify/schema.py`), the committed fixtures
(`conformance/records/`), and the TypeScript port MUST all
agree byte-for-byte with what is written here.

## What it is

An append-only, hash-chained log of agent events (tool calls, session
boundaries). Each event is a **record**; each record's canonical bytes are
hashed to an `entry_hash`; a domain-separated digest of that hash is signed by
Smoke's P-256 engine; the next record links back by `prev_entry_hash`. A
holder of the signer's public key can verify the whole chain offline:
nothing inserted, removed, reordered, or altered, and every event attested by
the key.

Not in v0: encryption, external timestamping, multi-writer chains, revocation,
mid-chain key rotation. See "Out of scope."

## Record — `AttestationRecordV0`

All 14 fields are **always present**. Nullable fields carry JSON `null` when
not applicable. **An absent field is NOT equivalent to a null field** — a
record missing any key is invalid.

| field | type | notes |
|-------|------|-------|
| `version` | const string | always `"smoke.attestation.v0"` |
| `event_id` | string (non-empty) | unique-ish id (uuid or deterministic hash) |
| `session_id` | string (non-empty) | agent run id; one chain per session |
| `sequence` | uint64 | 0-based, monotonic, no gaps within a chain |
| `event_type` | enum | `pre_tool_use` \| `post_tool_use` \| `session_start` \| `session_end` |
| `tool_name` | string \| null | e.g. `"Bash"`; null for session events |
| `tool_input_sha256` | hex32 | SHA-256 of canonical tool input (`SHA256("")` if none) |
| `tool_output_sha256` | hex32 \| null | present on `post_tool_use`; null otherwise |
| `timestamp_unix_ns` | uint64 | signer wall-clock, nanoseconds, self-asserted |
| `actor` | enum | `claude-code` \| `sdk` \| `user` \| `system` |
| `cwd` | string \| null | working directory |
| `repo` | string \| null | repo identifier |
| `prev_entry_hash` | hex32 \| null | previous record's `entry_hash`; `null` only for genesis (sequence 0) |
| `signer_key_id` | string (non-empty) | which signing key attested this record |

`hex32` = exactly 64 lowercase hex characters (a 32-byte value).

## Canonicalization (the signed bytes)

`canonical_record_bytes = JCS(record)` — RFC 8785 JSON Canonicalization
Scheme, restricted to our value set:

- UTF-8 output.
- Object keys sorted (all keys are ASCII, so code-point order == UTF-16 order).
- No insignificant whitespace (`,` and `:` separators only).
- Non-ASCII string **values** emitted as UTF-8, not `\u`-escaped.
- Integers emitted as exact integer literals. **No floats anywhere** (the
  reference rejects them).

### ⚠️ Cross-language integer rule (load-bearing)

`timestamp_unix_ns` (~1.75×10¹⁸) and `sequence` routinely exceed 2⁵³. They are
exact JSON integers. A verifier **MUST** parse and re-serialize them with
arbitrary-precision integers — in JavaScript/TypeScript that means `BigInt`
plus an integer-preserving JSON parser, **never** `JSON.parse` into a
`number` (IEEE-754 double), which would silently round and break the hash.
Python `int` is arbitrary precision, so the reference serializer is exact by
construction. The `session_end` fixture pins `timestamp_unix_ns =
18446744073709551615` (uint64 max) specifically to catch double-rounding.

## Hashing

```
entry_hash    = SHA256( canonical_record_bytes )                       # 32 bytes
signed_digest = SHA256( b"SMOKE-AGENT-ATTESTATION-V0" || 0x00 || entry_hash )
```

The signer signs `signed_digest` (32 bytes) via the existing P-256
`sign_p256(digest)` path. The domain tag + `0x00` separator are mandatory:
they bind a Smoke signature to *this* protocol so an attestation signature
cannot be reinterpreted as a signature over an arbitrary 32-byte value
elsewhere, and vice-versa.

## Chain rule

```
record[i].prev_entry_hash == entry_hash( record[i-1] )      for i > 0
record[0].prev_entry_hash == null                            (genesis)
record[i].sequence        == i
```

Altering any record changes its `entry_hash`, which (a) invalidates that
record's signature and (b) breaks `record[i+1].prev_entry_hash` — so a single
edit is detectable at two places, and dropping / inserting / reordering breaks
the linkage.

## Envelope — `AttestationEnvelopeV0` (one JSONL line per event)

The stored/transported form. Byte fields are lowercase hex. `entry_hash` is
stored for convenience but a verifier MUST recompute it from `record` and
treat a mismatch as tampering.

```json
{
  "record": { "...the 14 fields..." },
  "entry_hash": "<hex32>",
  "signature": {
    "alg": "ECDSA-P256-SHA256",
    "r": "<hex32>",
    "s": "<hex32>",
    "encoding": "raw-rs"
  },
  "public_key": {
    "key_id": "<string, matches record.signer_key_id>",
    "alg": "P-256",
    "spki_sha256": "<hex32 fingerprint of the SubjectPublicKeyInfo DER>"
  }
}
```

`signature.r`/`s` are the raw P-256 signature components (the engine emits
`r || s`; split into 32-byte halves). `public_key.spki_sha256` is the stable
key fingerprint a verifier uses to confirm it is checking against the expected
key.

### Public key distribution / rotation (v0)

- One signing key per chain. The key's SPKI (and its `spki_sha256`) are
  published out-of-band by the signing service; trust in the key is
  established outside this contract.
- If the signing key rotates mid-run, v0 says **start a new chain** under the
  new `signer_key_id`. A signed in-chain rotation record is a v1 concern; the
  per-record `signer_key_id` already reserves room for it.

## Verification (summary)

A chain is valid iff, for every record `i` in order:

1. `sequence == i`.
2. `prev_entry_hash == (i==0 ? null : entry_hash(record[i-1]))`.
3. recomputed `entry_hash` equals the stored `entry_hash`.
4. `ECDSA-P256` verify of `signature` over `signed_digest(entry_hash)` under
   the chain's public key succeeds.
5. `signer_key_id == public_key.key_id`.

**Fail-closed**: any single failure makes the whole chain INVALID, reported
with the first offending index and reason. There is no "partially valid."

**Trust anchor (authenticity vs consistency).** The checks above prove the log
is internally consistent under WHATEVER key its header carries — not that it
was signed by the *expected* key. An attacker who rewrites the log and re-signs
it with their own key produces a self-consistent but untrusted chain. To make
an authenticity claim, the verifier MUST pin the expected key:
`verify_log(path, trusted_spki_sha256=...)` (and/or `trusted_key_id=...`); the
CLI defaults to fail-closed unless a trusted fingerprint is supplied or the
caller explicitly opts into trusting the embedded header.

**Truncation is STRICT.** A malformed or partial final JSONL line (e.g. a
crash mid-write) is a verification FAILURE at that index, never silently
ignored. A separate, explicit `repair_truncated_tail()` helper may later
recover a log to its last complete entry — but recovery is always explicit and
never makes the damaged line appear valid.

## Out of scope (v0)

- No encryption of the log (audit record; sensitive inputs are hashed and
  stored out-of-band, never placed raw in a record).
- No external timestamping authority — `timestamp_unix_ns` is self-asserted.
- No multi-writer / merged chains.
- No revocation list.
- No mid-chain key rotation.

## Fixtures

`conformance/records/*.json` are the cross-language golden vectors.
Each carries `record`, `canonical_utf8`, `entry_hash`, and `signed_digest`.
Both verifier implementations must reproduce all of them exactly. Regenerate
only when intentionally cutting a new contract version.
