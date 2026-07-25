// smoke.attestation.v0 — record shape, validation, payload hashing.
//
// Mirrors the Python reference implementation (smoke_verify/schema.py).
// The record is the object that gets canonicalized
// (src/canonical.ts) into entry_hash; an invalid record MUST never be
// canonicalized or signed, so buildRecord validates and throws (fail-closed).
import { canonicalize, sha256, type CanonValue, VERSION } from "./canonical.ts";

export const SIGNATURE_ALG = "ECDSA-P256-SHA256";
export const HASH_ALG = "SHA-256";
export const HEADER_TYPE = "smoke-attest-header";

export const EVENT_TYPES = ["pre_tool_use", "post_tool_use", "session_start", "session_end"] as const;
export const ACTORS = ["claude-code", "sdk", "user", "system"] as const;
export type EventType = (typeof EVENT_TYPES)[number];
export type Actor = (typeof ACTORS)[number];

const U64_MAX = (1n << 64n) - 1n;
const HEX32 = /^[0-9a-f]{64}$/;

/** Raised for any contract violation (bad field, non-canonical input). */
export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

/** One attestation record — all 14 fields ALWAYS present; nullable as null. */
export interface AttestationRecord {
  version: string;
  event_id: string;
  session_id: string;
  sequence: bigint;
  event_type: EventType;
  tool_name: string | null;
  tool_input_sha256: string;
  tool_output_sha256: string | null;
  timestamp_unix_ns: bigint;
  actor: Actor;
  cwd: string | null;
  repo: string | null;
  prev_entry_hash: string | null;
  signer_key_id: string;
}

/** The 13 caller-supplied fields (everything except the const `version`). */
export interface RecordFields {
  event_id: string;
  session_id: string;
  sequence: bigint;
  event_type: EventType;
  tool_name: string | null;
  tool_input_sha256: string;
  tool_output_sha256: string | null;
  timestamp_unix_ns: bigint;
  actor: Actor;
  cwd: string | null;
  repo: string | null;
  prev_entry_hash: string | null;
  signer_key_id: string;
}

function requireStr(name: string, v: unknown, allowEmpty: boolean): void {
  if (typeof v !== "string") throw new AttestationError(`${name} must be a string`);
  if (!allowEmpty && v === "") throw new AttestationError(`${name} must be non-empty`);
}

function requireStrOrNull(name: string, v: unknown): void {
  if (v !== null && typeof v !== "string") throw new AttestationError(`${name} must be string or null`);
}

function requireU64(name: string, v: unknown): void {
  if (typeof v !== "bigint") throw new AttestationError(`${name} must be a bigint integer`);
  if (v < 0n || v > U64_MAX) throw new AttestationError(`${name} must fit uint64, got ${v}`);
}

function requireHex32(name: string, v: unknown, nullable: boolean): void {
  if (v === null) {
    if (nullable) return;
    throw new AttestationError(`${name} must be a hex32 string, got null`);
  }
  if (typeof v !== "string" || !HEX32.test(v)) {
    throw new AttestationError(`${name} must be 64 lowercase hex chars`);
  }
}

/** Validate a record against the frozen contract. Throws on any violation. */
export function validateRecord(r: AttestationRecord): void {
  if (r.version !== VERSION) throw new AttestationError(`version must be ${VERSION}, got ${r.version}`);
  requireStr("event_id", r.event_id, false);
  requireStr("session_id", r.session_id, false);
  requireStr("signer_key_id", r.signer_key_id, false);
  requireU64("sequence", r.sequence);
  requireU64("timestamp_unix_ns", r.timestamp_unix_ns);
  if (!(EVENT_TYPES as readonly string[]).includes(r.event_type)) {
    throw new AttestationError(`event_type must be one of ${EVENT_TYPES.join(",")}, got ${r.event_type}`);
  }
  if (!(ACTORS as readonly string[]).includes(r.actor)) {
    throw new AttestationError(`actor must be one of ${ACTORS.join(",")}, got ${r.actor}`);
  }
  requireHex32("tool_input_sha256", r.tool_input_sha256, false);
  requireHex32("tool_output_sha256", r.tool_output_sha256, true);
  requireHex32("prev_entry_hash", r.prev_entry_hash, true);
  requireStrOrNull("tool_name", r.tool_name);
  requireStrOrNull("cwd", r.cwd);
  requireStrOrNull("repo", r.repo);
}

/** Build a validated record (version is fixed by the contract). */
export function buildRecord(f: RecordFields): AttestationRecord {
  const r: AttestationRecord = { version: VERSION, ...f };
  validateRecord(r);
  return r;
}

export const EMPTY_SHA256 = sha256(Buffer.alloc(0)).toString("hex");

/**
 * Lowercase-hex SHA-256 for a tool input/output payload. Single rule, matches
 * Python `hash_payload`:
 *   - Buffer       -> SHA-256 of the bytes verbatim
 *   - string       -> SHA-256 of its UTF-8 encoding
 *   - null         -> SHA-256 of the empty string (stable "no input" hex32)
 *   - JSON value   -> SHA-256 of its RFC 8785 canonical JSON bytes
 */
export function hashPayload(value: Buffer | CanonValue | null | undefined): string {
  if (value === null || value === undefined) return EMPTY_SHA256;
  if (Buffer.isBuffer(value)) return sha256(value).toString("hex");
  if (typeof value === "string") return sha256(Buffer.from(value, "utf8")).toString("hex");
  return sha256(canonicalize(value)).toString("hex");
}
