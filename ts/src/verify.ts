// smoke.attestation.v0 — chain verifier (TypeScript port). Fail-closed.
//
// Mirrors the Python verifier. Zero deps: ECDSA-P256 verification uses Node's
// built-in crypto. Because signed_digest = SHA256(DOMAIN || 0x00 || entry_hash),
// we verify by letting crypto hash the known message M = DOMAIN||0x00||entry_hash
// with SHA-256 (no prehashed-verify needed) against the raw r||s signature.
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";

import { DOMAIN_TAG, entryHash, parseLossless, sha256 } from "./canonical.ts";

export interface VerifyResult {
  ok: boolean;
  count: number;
  brokenIndex: number | null;
  reason: string | null;
  keyId: string | null;
  ended: boolean;
}

export interface VerifyOpts {
  /** The trust anchor: expected signing key fingerprint (SHA-256 of SPKI DER). */
  trustedSpkiSha256?: string;
  /**
   * SECURITY: a FILTER on the header's key_id LABEL, not a trust anchor —
   * a forger picks their own key_id, so matching it proves nothing about the
   * key. Use only as an additional constraint beside trustedSpkiSha256.
   */
  trustedKeyId?: string;
}

function fail(count: number, idx: number | null, reason: string, keyId: string | null = null): VerifyResult {
  return { ok: false, count, brokenIndex: idx, reason, keyId, ended: false };
}

// The 14 record fields (must be present, no more, no fewer) — mirrors the Python
// verifier's strict from_dict so both verifiers reject the SAME inputs.
const RECORD_FIELDS = [
  "version", "event_id", "session_id", "sequence", "event_type", "tool_name",
  "tool_input_sha256", "tool_output_sha256", "timestamp_unix_ns", "actor", "cwd",
  "repo", "prev_entry_hash", "signer_key_id",
];

/** Structural validation before any crypto: returns an error string or null. */
function envelopeShapeError(env: any): string | null {
  if (env == null || typeof env !== "object") return "envelope is not an object";
  for (const k of ["record", "entry_hash", "signature", "public_key"]) {
    if (!(k in env)) return `missing ${k}`;
  }
  const rec = env.record;
  if (rec == null || typeof rec !== "object") return "record is not an object";
  for (const f of RECORD_FIELDS) if (!(f in rec)) return `record missing ${f}`;
  for (const f of Object.keys(rec)) if (!RECORD_FIELDS.includes(f)) return `record has unknown field ${f}`;
  for (const k of ["alg", "r", "s", "encoding"]) if (!(k in env.signature)) return `signature missing ${k}`;
  for (const k of ["key_id", "alg", "spki_sha256"]) if (!(k in env.public_key)) return `public_key missing ${k}`;
  return null;
}

export function verifyChain(header: any, envelopes: any[], opts: VerifyOpts = {}): VerifyResult {
  if (header == null || header.type !== "smoke-attest-header") return fail(0, null, "not a chain header");
  const keyId: string = header.key_id;

  if (opts.trustedSpkiSha256 != null && header.spki_sha256 !== opts.trustedSpkiSha256) {
    return fail(0, null, "header key is not the trusted anchor (spki_sha256 mismatch)", keyId);
  }
  if (opts.trustedKeyId != null && header.key_id !== opts.trustedKeyId) {
    return fail(0, null, `header key_id ${header.key_id} != trusted key_id ${opts.trustedKeyId}`, keyId);
  }

  let spkiDer: Buffer;
  let pub: ReturnType<typeof createPublicKey>;
  try {
    spkiDer = Buffer.from(header.spki_der_hex, "hex");
    pub = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  } catch (e) {
    return fail(0, null, `header public key unreadable: ${e}`, keyId);
  }
  if (sha256(spkiDer).toString("hex") !== header.spki_sha256) {
    return fail(0, null, "header spki_sha256 does not match spki_der", keyId);
  }

  // A header-only log carries zero signed statements (headers are unsigned),
  // and the writer always emits session_start with the header — a legitimate
  // 0-entry log does not exist. Fail closed.
  if (envelopes.length === 0) {
    return fail(0, null,
      "chain has a header but no entries — an empty log proves nothing and is never a legitimate state (fail-closed)",
      keyId);
  }

  let prev: string | null = null;
  for (let i = 0; i < envelopes.length; i++) {
    const env = envelopes[i];
    const shapeErr = envelopeShapeError(env);
    if (shapeErr) return fail(i, i, `malformed/truncated entry: ${shapeErr}`, keyId);
    const rec = env.record;

    if (rec.sequence !== BigInt(i)) return fail(i, i, `sequence ${rec.sequence} != expected ${i}`, keyId);
    const expectedPrev = i === 0 ? null : prev;
    if ((rec.prev_entry_hash ?? null) !== expectedPrev) {
      return fail(i, i, "prev_entry_hash does not link to previous entry", keyId);
    }

    const ehHex = entryHash(rec).toString("hex");
    if (ehHex !== env.entry_hash) return fail(i, i, "stored entry_hash != recomputed (record mutated)", keyId);

    if (env.public_key.spki_sha256 !== header.spki_sha256) {
      return fail(i, i, "envelope public_key fingerprint != header key", keyId);
    }
    if (env.public_key.key_id !== keyId || rec.signer_key_id !== keyId) {
      return fail(i, i, "key_id mismatch (envelope/record vs header)", keyId);
    }
    // Bind each signed record to the unsigned header's session_id.
    if (rec.session_id !== header.session_id) {
      return fail(i, i, "record session_id != chain header session_id", keyId);
    }

    const eh = Buffer.from(ehHex, "hex");
    const msg = Buffer.concat([DOMAIN_TAG, Buffer.from([0]), eh]); // signed_digest = SHA256(msg)
    let sig: Buffer;
    try {
      sig = Buffer.concat([Buffer.from(env.signature.r, "hex"), Buffer.from(env.signature.s, "hex")]);
    } catch (e) {
      return fail(i, i, `bad signature encoding: ${e}`, keyId);
    }
    const sigOk = cryptoVerify("sha256", msg, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
    if (!sigOk) return fail(i, i, "signature does not verify", keyId);

    prev = ehHex;
  }

  const ended = envelopes.length > 0 && envelopes[envelopes.length - 1].record.event_type === "session_end";
  return { ok: true, count: envelopes.length, brokenIndex: null, reason: null, keyId, ended };
}

export function verifyLog(path: string, opts: VerifyOpts = {}): VerifyResult {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    return fail(0, null, `cannot read log: ${e}`);
  }
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  if (lines.length === 0) return fail(0, null, "empty log (no header)");

  let header: any;
  try {
    header = parseLossless(lines[0]);
  } catch (e) {
    return fail(0, null, `bad chain header: ${e}`);
  }
  const envelopes: any[] = [];
  for (let j = 1; j < lines.length; j++) {
    try {
      envelopes.push(parseLossless(lines[j]));
    } catch (e) {
      return fail(envelopes.length, j - 1, `malformed/truncated entry: ${e}`, header?.key_id ?? null);
    }
  }
  return verifyChain(header, envelopes, opts);
}
