// Conformance: the TS verifier must agree with the Python verifier on the
// committed golden vectors — same accepts, same rejects.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { canonicalize, entryHash, parseLossless, sha256, DOMAIN_TAG } from "../src/canonical.ts";
import { verifyLog } from "../src/verify.ts";
import { localizeEntry } from "../src/localize.ts";

const ROOT = path.resolve(import.meta.dirname, "..", "..");
const RECORDS = path.join(ROOT, "conformance", "records");
const CHAINS = path.join(ROOT, "conformance", "chains");
const manifest = JSON.parse(readFileSync(path.join(CHAINS, "manifest.json"), "utf8"));
const TRUSTED_FP: string = manifest.signer.spki_sha256;

// --- golden record vectors: canonical bytes + hashes must reproduce exactly --

for (const f of readdirSync(RECORDS).filter((f) => f.endsWith(".json"))) {
  test(`record vector reproduces: ${f}`, () => {
    const vec = JSON.parse(readFileSync(path.join(RECORDS, f), "utf8"));
    // Parse the record LOSSLESSLY (BigInt) from its canonical bytes — parsing
    // vec.record via JSON.parse would round uint64s through doubles.
    const rec = parseLossless(vec.canonical_utf8);
    const canonical = canonicalize(rec);
    assert.equal(canonical.toString("utf8"), vec.canonical_utf8);
    const eh = sha256(canonical).toString("hex");
    assert.equal(eh, vec.entry_hash);
    const sd = sha256(Buffer.concat([DOMAIN_TAG, Buffer.from([0]), Buffer.from(eh, "hex")])).toString("hex");
    assert.equal(sd, vec.signed_digest);
  });
}

// --- golden chains verify (pinned) ------------------------------------------

for (const name of Object.keys(manifest.chains)) {
  test(`golden chain verifies pinned: ${name}`, () => {
    const res = verifyLog(path.join(CHAINS, name), { trustedSpkiSha256: TRUSTED_FP });
    assert.equal(res.ok, true, res.reason ?? "");
    assert.equal(res.count, manifest.chains[name].entries);
    assert.equal(res.ended, manifest.chains[name].ended);
  });
}

test("wrong pin fails", () => {
  const res = verifyLog(path.join(CHAINS, "valid_basic.jsonl"), { trustedSpkiSha256: "0".repeat(64) });
  assert.equal(res.ok, false);
});

// --- tamper detection + recovery --------------------------------------------

function tamperCopy(mutate: (lines: string[]) => void): string {
  const lines = readFileSync(path.join(CHAINS, "valid_basic.jsonl"), "utf8")
    .split("\n").filter((l) => l.trim() !== "");
  mutate(lines);
  const p = path.join(tmpdir(), `smoke-verify-test-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`);
  writeFileSync(p, lines.join("\n") + "\n");
  return p;
}

test("field edit detected and localized", () => {
  let tamperedRecord: any;
  let storedHash = "";
  const p = tamperCopy((lines) => {
    const env = parseLossless(lines[2]); // entry index 1
    env.record.tool_name = env.record.tool_name === "Read" ? "Bash" : "Read";
    tamperedRecord = env.record;
    storedHash = env.entry_hash;
    // Re-serialize losslessly via canonicalize (record) inside an envelope shell:
    const rec = canonicalize(env.record).toString("utf8");
    lines[2] = `{"entry_hash":${JSON.stringify(env.entry_hash)},"public_key":${JSON.stringify(env.public_key)},"record":${rec},"signature":${JSON.stringify(env.signature)}}`;
  });
  const res = verifyLog(p, { trustedSpkiSha256: TRUSTED_FP });
  assert.equal(res.ok, false);
  assert.equal(res.brokenIndex, 1);
  assert.match(res.reason ?? "", /record mutated/);

  const loc = localizeEntry(tamperedRecord, storedHash, manifest.signer.key_id);
  assert.equal(loc.recovered, true);
  assert.equal(loc.changes[0].field, "tool_name");
});

test("dropped entry detected", () => {
  const p = tamperCopy((lines) => lines.splice(3, 1));
  const res = verifyLog(p, { trustedSpkiSha256: TRUSTED_FP });
  assert.equal(res.ok, false);
});

test("truncated final line fails closed", () => {
  const p = tamperCopy((lines) => {
    lines[lines.length - 1] = lines[lines.length - 1].slice(0, -25);
  });
  const res = verifyLog(p, { trustedSpkiSha256: TRUSTED_FP });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /malformed|truncated/);
});
