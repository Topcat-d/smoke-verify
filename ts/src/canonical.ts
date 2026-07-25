// smoke.attestation.v0 — canonicalization + hashing (TypeScript port).
//
// Byte-for-byte compatible with the Python reference implementation.
// Zero dependencies — Node built-ins only (node:crypto). Requires Node >= 22
// for JSON.parse source access (lossless big integers).
import { createHash } from "node:crypto";

export const VERSION = "smoke.attestation.v0";
export const DOMAIN_TAG = Buffer.from("SMOKE-AGENT-ATTESTATION-V0");
const U64_MAX = (1n << 64n) - 1n;

export type CanonValue =
  | string
  | bigint
  | number
  | boolean
  | null
  | CanonValue[]
  | { [k: string]: CanonValue };

/**
 * Lossless JSON parse: integer literals become `bigint` via the source-access
 * reviver, so values > 2^53 (e.g. timestamp_unix_ns up to uint64-max) survive
 * EXACTLY. A naive JSON.parse rounds them to IEEE-754 doubles and would change
 * the canonical bytes — which is why this is mandatory for cross-language match.
 */
export function parseLossless(text: string): unknown {
  return JSON.parse(text, function (_key, value, context: { source?: string } | undefined) {
    if (typeof value === "number" && context && typeof context.source === "string") {
      const s = context.source;
      if (/^-?\d+$/.test(s)) return BigInt(s); // integer literal -> exact bigint
    }
    return value;
  });
}

/** RFC 8785 / JCS canonical bytes for our restricted value set. */
export function canonicalize(value: CanonValue): Buffer {
  return Buffer.from(canon(value), "utf8");
}

function canon(v: CanonValue): string {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "bigint") {
    if ((v as bigint) < -(1n << 63n) || (v as bigint) > U64_MAX) {
      throw new Error(`integer out of contract range: ${v}`);
    }
    return (v as bigint).toString();
  }
  if (t === "string") return JSON.stringify(v); // JSON string escaping == RFC8785 for our data
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isInteger(v as number)) throw new Error("floats are forbidden in canonical records");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (t === "object") {
    const o = v as { [k: string]: CanonValue };
    const keys = Object.keys(o).sort(); // ASCII keys: code-unit order == code-point order
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(o[k])).join(",") + "}";
  }
  throw new Error(`non-canonical value type: ${t}`);
}

export function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

export function entryHash(record: CanonValue): Buffer {
  return sha256(canonicalize(record));
}

/** signed_digest = SHA256( DOMAIN_TAG || 0x00 || entry_hash ). */
export function signedDigest(eh: Buffer): Buffer {
  if (eh.length !== 32) throw new Error(`entry_hash must be 32 bytes, got ${eh.length}`);
  return sha256(Buffer.concat([DOMAIN_TAG, Buffer.from([0]), eh]));
}
