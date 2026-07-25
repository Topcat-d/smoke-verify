// smoke.attestation.v0 — tamper localization (TypeScript port).
//
// Parity with the Python `localize_entry`: recover the original value of a
// mutated LOW-ENTROPY field by hash search. The stored entry_hash is the hash of
// the ORIGINAL record, so the candidate that reproduces it IS the original (with
// cryptographic proof). High-entropy edits (timestamp, *_sha256, event_id) and
// multi-field edits are reported unrecoverable rather than guessed.
import { canonicalize, sha256, VERSION, type CanonValue } from "./canonical.ts";
import { ACTORS, EVENT_TYPES } from "./record.ts";

export const KNOWN_TOOL_NAMES = [
  "Bash", "Read", "Edit", "Write", "Glob", "Grep", "Task", "WebFetch",
  "WebSearch", "NotebookEdit", "TodoWrite", "MultiEdit", "BashOutput",
  "KillShell", "SlashCommand", "ExitPlanMode",
] as const;

const LOW_ENTROPY_FIELDS = ["event_type", "actor", "tool_name", "version", "signer_key_id"] as const;

export interface FieldChange {
  field: string;
  original: unknown; // recovered value that reproduces the stored entry_hash
  observed: unknown; // current (tampered) value
}

export interface LocalizeResult {
  recovered: boolean;
  changes: FieldChange[];
  note: string;
}

function candidates(field: string, observed: unknown, headerKeyId?: string): unknown[] {
  if (field === "event_type") return EVENT_TYPES.filter((v) => v !== observed);
  if (field === "actor") return ACTORS.filter((v) => v !== observed);
  if (field === "tool_name") return [...KNOWN_TOOL_NAMES, null].filter((v) => v !== observed);
  if (field === "version") return observed !== VERSION ? [VERSION] : [];
  if (field === "signer_key_id") return headerKeyId && observed !== headerKeyId ? [headerKeyId] : [];
  return [];
}

function entryHashHex(record: Record<string, unknown>): string {
  return sha256(canonicalize(record as CanonValue)).toString("hex");
}

export function localizeEntry(
  record: Record<string, unknown>,
  storedEntryHash: string,
  headerKeyId?: string,
): LocalizeResult {
  if (entryHashHex(record) === storedEntryHash) {
    return { recovered: false, changes: [], note: "entry content matches its stored hash; the break is not a record edit" };
  }
  const matches: FieldChange[] = [];
  for (const field of LOW_ENTROPY_FIELDS) {
    const observed = record[field];
    for (const cand of candidates(field, observed, headerKeyId)) {
      const trial = { ...record, [field]: cand };
      try {
        if (entryHashHex(trial) === storedEntryHash) matches.push({ field, original: cand, observed });
      } catch {
        /* a non-canonical candidate simply isn't the original */
      }
    }
  }
  if (matches.length === 1) {
    return { recovered: true, changes: matches, note: `recovered original ${matches[0].field} by hash search` };
  }
  if (matches.length > 1) {
    return { recovered: true, changes: matches, note: "multiple single-field edits reproduce the stored hash" };
  }
  return {
    recovered: false,
    changes: [],
    note:
      "could not localize: a high-entropy field (timestamp, an input/output hash, event_id) " +
      "and/or multiple fields changed — the original cannot be recovered from a tampered copy",
  };
}
