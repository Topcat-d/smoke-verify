# AGENTS.md

## Cursor Cloud specific instructions

This repo ships an **offline verifier** for `smoke.attestation.v0` tamper-evident
logs. It is a CLI/library, not a web app — there are no long-running services to
start. Two independent components:

- `python/` — the `smoke-verify` CLI (verify/inspect/diff/anchor/export/tamper).
- `ts/` — a zero-dependency TypeScript verifier (chain verification only).

Standard commands live in `README.md` and `.github/workflows/ci.yml`; the notes
below only cover non-obvious caveats.

### Python (`python/`)
- Install (also done by the startup update script): `pip install ./python[dev]`.
- The `smoke-verify` console script and `pytest` install to `~/.local/bin`. That
  dir is added to PATH via `~/.bashrc`, so new interactive shells find them. If a
  shell can't find `smoke-verify`, run `export PATH="$HOME/.local/bin:$PATH"`.
  Note: `python -m smoke_verify` is NOT supported — use the console script.
- Tests: `pytest python/tests -q`.
- Conformance (verifies the committed golden chains against the pinned key):
  `smoke-verify verify-all conformance/chains --trusted-spki-sha256 f758402958548503ac391ad9859dea4f8f1a2137d3cbee3069bc1f2a5ab23da9`

### TypeScript (`ts/`)
- Zero dependencies — no `npm install` needed. Test with `npm test` (runs
  `node --test test/verify.test.ts`).
- **Gotcha:** the tests rely on Node's native TS type-stripping, which is only
  unflagged in **Node ≥ 22.18**. The default `node` on PATH is `/exec-daemon/node`
  (v22.14.0) and FAILS with `ERR_UNKNOWN_FILE_EXTENSION ".ts"`. Use the nvm node
  (v22.22.2) instead, e.g. run tests with:
  `PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$PATH" npm test` (from `ts/`).

### Lint
- No linter is configured (no ESLint/ruff/flake8). "CI" is: pytest + the CLI
  conformance/tamper commands (Python) and `node --test` (TypeScript).
