"""smoke-verify CLI — offline verification of smoke.attestation.v0 logs.

Commands:
  smoke-verify verify      — verify a log (FAIL-CLOSED on trust by default)
  smoke-verify verify-all  — verify every *.jsonl log in a directory
  smoke-verify inspect     — print a readable chain summary
  smoke-verify diff        — exact field diff vs a trusted reference copy
  smoke-verify anchor      — emit/check a chain-head anchor (append-only proof)
  smoke-verify export      — audit artifact (html for humans, json/md for agents)
  smoke-verify tamper      — DEMO: mutate a copy of a log, watch detection + recovery

Security / fail-closed (nothing fails silently):
  - `verify` defaults to fail-closed: it requires a pinned trust anchor
    (--trusted-spki-sha256 / --trusted-key-id) OR an explicit
    --trust-log-header opt-in, and exits NONZERO on tamper or untrusted key.
  - This tool VERIFIES logs; it cannot create or sign them. There is no key
    material anywhere in this package.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html as _html
import json
import sys
from pathlib import Path
from typing import Any, Optional

from . import chainio
from .schema import AttestationError

# ----------------------------------------------------------------------------
# verify
# ----------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> int:
    # SECURITY: only the SPKI fingerprint is a trust anchor. key_id is a label
    # the log producer chooses freely — a forger sets it to whatever you
    # expect — so it must never satisfy the pin requirement or earn the
    # "pinned" trust label on its own.
    pin = args.trusted_spki_sha256
    if args.trusted_key_id and not pin and not args.trust_log_header:
        sys.stderr.write(
            "smoke-verify: --trusted-key-id alone is NOT a trust anchor — key_id is a "
            "label chosen by whoever wrote the log, so matching it proves nothing about "
            "the signing key. Pin the key itself with --trusted-spki-sha256 <fp> (use "
            "--trusted-key-id only as an extra filter beside it), or pass "
            "--trust-log-header to accept the embedded key (consistency only).\n"
        )
        return 2
    if not pin and not args.trust_log_header:
        sys.stderr.write(
            "smoke-verify: refusing to verify without a trust anchor. "
            "Pass --trusted-spki-sha256 <fp> to prove the log "
            "was signed by the expected key, or --trust-log-header to accept the key embedded "
            "in the log (internal consistency only — NOT authenticity).\n"
        )
        return 2

    try:
        version = chainio.detect_version(args.log)
    except chainio.UnknownVersionError as e:
        sys.stderr.write(f"smoke-verify: {e}\n")
        return 2
    res = chainio.pick_verifier(version)(
        args.log,
        trusted_spki_sha256=args.trusted_spki_sha256,
        trusted_key_id=args.trusted_key_id,
    )
    out = {
        "ok": res.ok,
        "count": res.count,
        "key_id": res.key_id,
        "ended": res.ended,
        "broken_index": res.broken_index,
        "reason": res.reason,
        "trust": "pinned" if pin else "log-header (unpinned)",
    }
    if getattr(args, "explain", False) and not res.ok and res.broken_index is not None:
        from .localize import localize_entry

        lines = [ln for ln in Path(args.log).read_text(encoding="utf-8").splitlines() if ln.strip()]
        raw = json.loads(lines[1 + res.broken_index])
        loc = localize_entry(raw.get("record", {}), raw.get("entry_hash", ""), res.key_id,
                             expected_version=version)
        out["tamper"] = {
            "recovered": loc.recovered,
            "changes": [{"field": c.field, "original": c.original, "observed": c.observed} for c in loc.changes],
            "note": loc.note,
        }
    # Truncation guard: a chain with trailing entries dropped is still a valid
    # PREFIX (ok=True, ended=False). --require-ended fails closed on that.
    truncated = getattr(args, "require_ended", False) and res.ok and not res.ended
    if truncated:
        out["ok"] = False
        out["reason"] = "chain is internally valid but does not end with session_end " \
                        "(--require-ended; possible truncation)"
    anchor_ok = True
    if getattr(args, "anchor", None):
        import base64 as _b64

        from .anchor import check_anchor
        from .witness import verify_anchor_witnesses

        anchor = json.loads(Path(args.anchor).read_text(encoding="utf-8"))
        ar = check_anchor(args.log, anchor)
        anchor_ok = ar.ok
        out["anchor"] = {
            "ok": ar.ok, "reason": ar.reason,
            "anchored_count": ar.anchored_count, "log_count": ar.log_count,
        }
        if not ar.ok:
            out["ok"] = False
            out["reason"] = out["reason"] or ar.reason
        # Witness layer: only meaningful once the anchor itself binds this log.
        if ar.ok and anchor.get("witnesses"):
            pins = [_b64.b64decode(b) for b in (getattr(args, "tsa_spki_b64", None) or [])]
            w_ok, checks = verify_anchor_witnesses(
                anchor, pinned_tsa_spki_ders=pins,
                allow_unverified=getattr(args, "allow_unverified_witness", False),
            )
            out["anchor"]["witnesses"] = [
                {"type": c.type, "status": c.status, "gen_time": c.gen_time,
                 "reason": c.reason} for c in checks
            ]
            if not w_ok:
                anchor_ok = False
                out["ok"] = False
                out["reason"] = out["reason"] or \
                    "anchor witness check failed (see anchor.witnesses)"
    if not getattr(args, "quiet", False):
        print(json.dumps(out, indent=2))
    return 0 if (res.ok and not truncated and anchor_ok) else 1


# ----------------------------------------------------------------------------
# verify-all — verify every session log in a directory (ops at scale)
# ----------------------------------------------------------------------------

def cmd_verify_all(args: argparse.Namespace) -> int:
    pin = args.trusted_spki_sha256  # key_id is a label, never an anchor (see cmd_verify)
    if args.trusted_key_id and not pin and not args.trust_log_header:
        sys.stderr.write(
            "smoke-verify verify-all: --trusted-key-id alone is NOT a trust anchor "
            "(key_id is a producer-chosen label). Pin with --trusted-spki-sha256 <fp>, "
            "or pass --trust-log-header (consistency only).\n"
        )
        return 2
    if not pin and not args.trust_log_header:
        sys.stderr.write(
            "smoke-verify verify-all: refusing to verify without a trust anchor. Pass "
            "--trusted-spki-sha256 <fp>, or --trust-log-header "
            "to accept each log's own key (consistency only — NOT authenticity).\n"
        )
        return 2

    base = Path(args.dir)
    if not base.is_dir():
        sys.stderr.write(f"smoke-verify verify-all: not a directory: {base}\n")
        return 2

    paths = sorted(base.rglob("*.jsonl") if args.recursive else base.glob("*.jsonl"))
    results = []
    for p in paths:
        # A file with an unknown/missing version is a FAIL row, never a crash —
        # one bad file must not abort the sweep over everything else.
        try:
            res = chainio.verify_log_any(
                p, trusted_spki_sha256=args.trusted_spki_sha256, trusted_key_id=args.trusted_key_id)
        except chainio.UnknownVersionError as e:
            results.append({
                "file": str(p), "ok": False, "count": 0,
                "ended": False, "key_id": None, "reason": str(e),
            })
            continue
        ok, reason = res.ok, res.reason
        if args.require_ended and res.ok and not res.ended:
            ok, reason = False, "chain valid but does not end with session_end (--require-ended)"
        results.append({
            "file": str(p), "ok": ok, "count": res.count,
            "ended": res.ended, "key_id": res.key_id, "reason": reason,
        })

    total = len(results)
    valid = sum(1 for r in results if r["ok"])
    failed = total - valid

    if getattr(args, "quiet", False):
        pass  # exit code only
    elif args.json:
        print(json.dumps(
            {"dir": str(base), "total": total, "valid": valid, "failed": failed, "logs": results}, indent=2
        ))
    else:
        for r in results:
            mark = "OK  " if r["ok"] else "FAIL"
            extra = "" if r["ok"] else f"  -- {r['reason']}"
            print(f"{mark}  {r['count']:>4} entries  ended={str(r['ended']):<5}  {r['file']}{extra}")
        print(f"\n{valid}/{total} valid" + (f", {failed} FAILED" if failed else ""))

    if total == 0:
        sys.stderr.write(f"smoke-verify verify-all: no .jsonl logs found in {base}\n")
        return 1
    return 0 if failed == 0 else 1


# ----------------------------------------------------------------------------
# inspect
# ----------------------------------------------------------------------------

def _fmt_ns(ns: int) -> str:
    try:
        return _dt.datetime.fromtimestamp(ns / 1e9, tz=_dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return f"{ns}ns"


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        version, header, envs = chainio.load_chain(args.log)
    except chainio.UnknownVersionError as e:
        raise SystemExit(f"smoke-verify inspect: {e}") from e
    except AttestationError as e:
        raise SystemExit(f"smoke-verify inspect: malformed log: {e}") from e

    # Authenticity requires a pin. Without one, a fully attacker-rewritten log
    # re-signed under the attacker's own key is still "internally consistent" —
    # so an UNPINNED ok result must NEVER be labeled plain "VALID" (a reader
    # would mistake consistency for authenticity).
    # Only a fingerprint pin earns the VALID (pinned) label — key_id is a
    # producer-chosen label and proves nothing about the key (see cmd_verify).
    pin = args.trusted_spki_sha256
    res = chainio.pick_verifier(version)(
        args.log,
        trusted_spki_sha256=args.trusted_spki_sha256,
        trusted_key_id=args.trusted_key_id,
    )

    if not res.ok:
        chain = f"INVALID - {res.reason}"
    elif pin:
        chain = f"VALID (pinned to {str(pin)[:16]}...)"
    else:
        chain = ("INTERNALLY CONSISTENT (UNPINNED - not authenticated; "
                 "pass --trusted-spki-sha256 <fp> to verify authenticity)")

    print(f"version    : {version}")
    print(f"session_id : {header.session_id}")
    print(f"key_id     : {header.key_id}")
    print(f"spki_sha256: {header.spki_sha256}")     # public fingerprint, not secret
    print(f"entries    : {len(envs)}")
    if envs:
        print(f"first ts   : {_fmt_ns(envs[0].record.timestamp_unix_ns)}")
        print(f"last ts    : {_fmt_ns(envs[-1].record.timestamp_unix_ns)}")
    print(f"chain      : {chain}")
    print(f"ended      : {res.ended}")

    n = args.last if args.last and args.last > 0 else len(envs)
    shown = envs[-n:]
    print(f"\nlast {len(shown)} event(s):")
    for e in shown:
        r = e.record
        tool = r.tool_name or "-"
        out = "" if r.tool_output_sha256 is None else f" out={r.tool_output_sha256[:8]}"
        print(f"  #{r.sequence:<5} {r.event_type:<14} {tool:<10} "
              f"in={r.tool_input_sha256[:8]}{out} {_fmt_ns(r.timestamp_unix_ns)}")
    return 0


# ----------------------------------------------------------------------------
# diff — exact field diff against a trusted reference copy
# ----------------------------------------------------------------------------

def cmd_diff(args: argparse.Namespace) -> int:
    from .diff import diff_chains

    d = diff_chains(args.reference, args.log)
    if args.json:
        out = {
            "identical": d.identical,
            "note": d.note,
            "header_changes": [
                {"field": x.field, "reference": x.reference, "target": x.target} for x in d.header_changes
            ],
            "entry_changes": [
                {"sequence": x.sequence, "field": x.field, "reference": x.reference, "target": x.target}
                for x in d.entry_changes
            ],
            "added": list(d.added),
            "removed": list(d.removed),
        }
        print(json.dumps(out, indent=2))
    elif d.identical:
        print(f"identical: {args.log} matches reference {args.reference}")
    else:
        print(f"DIFFERS: {d.note}")
        for x in d.header_changes:
            print(f"  header.{x.field}: {x.reference!r} -> {x.target!r}")
        for x in d.entry_changes:
            print(f"  entry #{x.sequence} {x.field}: {x.reference!r} -> {x.target!r}")
        for s in d.added:
            print(f"  + added entry #{s}")
        for s in d.removed:
            print(f"  - removed entry #{s}")
    return 0 if d.identical else 1


# ----------------------------------------------------------------------------
# anchor — emit an external append-only anchor (publish it at time T)
# ----------------------------------------------------------------------------

def cmd_anchor(args: argparse.Namespace) -> int:
    from .anchor import make_anchor

    try:
        a = make_anchor(args.log)
    except (ValueError, OSError) as e:
        sys.stderr.write(f"smoke-verify anchor: {e}\n")
        return 1

    # External witnesses — trusted time. Acquisition never blocks anchoring:
    # an unreachable witness is RECORDED (status: error), not dropped.
    witnesses = []
    from .witness import WELL_KNOWN_TSA_URLS, GitMirrorWitness, TSAClient

    for url in (args.tsa_url or []):
        url = WELL_KNOWN_TSA_URLS.get(url, url)
        witnesses.append(TSAClient(url).request_witness(a["head_entry_hash"]))
    if args.git_dir:
        witnesses.append(GitMirrorWitness(args.git_dir).witness(
            a["session_id"], a["count"], a["head_entry_hash"]))
    if witnesses:
        a["witnesses"] = witnesses

    text = json.dumps(a, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        wsum = ""
        if witnesses:
            n_ok = sum(1 for w in witnesses if w.get("status") == "ok")
            wsum = f", witnesses: {n_ok}/{len(witnesses)} ok"
        print(f"wrote {args.output} (anchor: {a['count']} entries, "
              f"head {a['head_entry_hash'][:16]}...{wsum})")
    else:
        print(text)
    for w in witnesses:
        if w.get("status") == "error":
            sys.stderr.write(f"smoke-verify anchor: witness {w.get('type')} "
                             f"{w.get('url', w.get('repo', ''))} FAILED (recorded): "
                             f"{w.get('error')}\n")
    # Publishing an anchor that carries zero successful witnesses when
    # witnesses were requested is worth a nonzero exit — the caller asked for
    # trusted time and got none (the anchor file is still written, evidence
    # of the attempt included).
    if witnesses and not any(w.get("status") == "ok" for w in witnesses):
        return 1
    return 0


# ----------------------------------------------------------------------------
# export — one summary, three renderings (html / json / md)
# ----------------------------------------------------------------------------

def _build_summary(
    log_path: str,
    trusted_spki_sha256: Optional[str] = None,
    trusted_key_id: Optional[str] = None,
) -> dict[str, Any]:
    try:
        version, header, envs = chainio.load_chain(log_path)
    except chainio.UnknownVersionError as e:
        raise SystemExit(f"smoke-verify export: {e}") from e
    except AttestationError as e:
        raise SystemExit(f"smoke-verify export: malformed log: {e}") from e
    res = chainio.pick_verifier(version)(
        log_path, trusted_spki_sha256=trusted_spki_sha256, trusted_key_id=trusted_key_id)

    lines = [ln for ln in Path(log_path).read_text(encoding="utf-8").splitlines() if ln.strip()]

    # if an entry was MUTATED, try to recover what changed (low-entropy
    # fields only). Other break kinds (signature, chain link) aren't record edits.
    tamper = None
    if (not res.ok) and res.broken_index is not None and res.reason and "entry_hash" in res.reason:
        from .localize import localize_entry

        raw = json.loads(lines[1 + res.broken_index])
        loc = localize_entry(raw.get("record", {}), raw.get("entry_hash", ""), header.key_id,
                             expected_version=version)
        tamper = {
            "broken_index": res.broken_index,
            "recovered": loc.recovered,
            "changes": [
                {"field": c.field, "original": c.original, "observed": c.observed} for c in loc.changes
            ],
            "note": loc.note,
        }

    events = []
    for e in envs:
        ev: dict[str, Any] = {
            "sequence": e.record.sequence,
            "event_type": e.record.event_type,
            "tool_name": e.record.tool_name,
            "tool_input_sha256": e.record.tool_input_sha256,
            "tool_output_sha256": e.record.tool_output_sha256,
            "timestamp_unix_ns": e.record.timestamp_unix_ns,   # exact int, agent-consumable
            "timestamp_iso": _fmt_ns(e.record.timestamp_unix_ns),
            "cwd": e.record.cwd,
            "entry_hash": e.entry_hash,
        }
        events.append(ev)

    return {
        "version": header.version,
        "session_id": header.session_id,
        "key_id": header.key_id,
        "spki_sha256": header.spki_sha256,          # public fingerprint, not secret
        "count": len(envs),
        "first_ts": events[0]["timestamp_iso"] if events else None,
        "last_ts": events[-1]["timestamp_iso"] if events else None,
        "chain_ok": res.ok,
        "chain_reason": res.reason,
        "broken_index": res.broken_index,
        "ended": res.ended,
        # key_id is a producer-chosen label — only the SPKI fingerprint pins.
        "pinned": bool(trusted_spki_sha256),
        "trust": "pinned" if trusted_spki_sha256 else "log-header (unpinned)",
        "tamper": tamper,
        "events": events,
    }


def _change_strs(s: dict[str, Any]) -> list[str]:
    """Human-readable 'field: original -> observed' lines for a recovered tamper."""
    t = s.get("tamper")
    if not t or not t.get("recovered"):
        return []
    return [f"{c['field']}: {c['original']!r} -> {c['observed']!r}" for c in t["changes"]]


def _export_json(s: dict[str, Any]) -> str:
    return json.dumps(s, indent=2)


def _chain_verdict_md(s: dict[str, Any]) -> str:
    """3-state chain verdict for md/console. An UNPINNED valid chain is only
    INTERNALLY CONSISTENT (it self-verifies under whatever key it carries) — it
    must never read bare 'VALID', which a reader would mistake for authenticity.
    Mirrors cmd_inspect."""
    if not s["chain_ok"]:
        return f"INVALID - {s['chain_reason']} (entry {s['broken_index']})"
    if s.get("pinned"):
        return "VALID (pinned)"
    return "INTERNALLY CONSISTENT (UNPINNED - not authenticated)"


def _export_md(s: dict[str, Any]) -> str:
    status = _chain_verdict_md(s)
    out = [
        f"# Attestation audit — `{s['session_id']}`",
        "",
        f"- **chain**: {status}",
        f"- **trust**: {s['trust']}",
        f"- **key_id**: `{s['key_id']}`",
        f"- **spki_sha256**: `{s['spki_sha256']}`",
        f"- **entries**: {s['count']}  ·  **ended**: {s['ended']}",
        f"- **first**: {s['first_ts']}  ·  **last**: {s['last_ts']}",
    ]
    changes = _change_strs(s)
    if changes:
        out += ["", f"**Tamper detail (entry #{s['tamper']['broken_index']}):**", ""]
        out += [f"- `{c}`" for c in changes]
    elif s.get("tamper") and not s["tamper"]["recovered"]:
        out += ["", f"**Tamper detail (entry #{s['tamper']['broken_index']}):** {s['tamper']['note']}"]
    out += [
        "",
        "| # | event | tool | input | output | timestamp |",
        "|---|-------|------|-------|--------|-----------|",
    ]
    for e in s["events"]:
        tool = e["tool_name"] or "-"
        in_h = e["tool_input_sha256"] or ""
        out_h = e["tool_output_sha256"] or ""
        out.append(
            f"| {e['sequence']} | {e['event_type']} | {tool} "
            f"| `{in_h[:12]}` | `{out_h[:12]}` | {e['timestamp_iso']} |"
        )
    return "\n".join(out) + "\n"


def _export_html(s: dict[str, Any]) -> str:
    esc = _html.escape
    ok = s["chain_ok"]
    pinned = s.get("pinned")
    # 3-state banner: green only when authenticated (pinned), amber for an
    # unpinned-but-consistent chain (consistency != authenticity), red on tamper.
    if not ok:
        banner_bg = "#b00020"
        banner_txt = "CHAIN INVALID / TAMPERED"
        detail = f" &mdash; {esc(str(s['chain_reason']))} (entry {s['broken_index']})"
    elif pinned:
        banner_bg = "#0f7b3f"
        banner_txt = "CHAIN VALID (pinned)"
        detail = ""
    else:
        banner_bg = "#9a6700"
        banner_txt = "CHAIN CONSISTENT (UNPINNED - NOT AUTHENTICATED)"
        detail = ""

    # human-readable "what changed" box under the banner.
    tamper_html = ""
    t = s.get("tamper")
    if t and t.get("recovered"):
        diffs = "".join(
            f"<div class=diffrow><span class=field>{esc(c['field'])}</span>"
            f"<span class=orig>{esc(repr(c['original']))}</span>"
            f"<span class=arrow>&rarr;</span>"
            f"<span class=obs>{esc(repr(c['observed']))}</span></div>"
            for c in t["changes"]
        )
        tamper_html = (
            f'<div class="tamper"><div class=tamper-h>Entry #{t["broken_index"]} modified '
            f'&mdash; recovered original by hash search</div>{diffs}</div>'
        )
    elif t:
        tamper_html = f'<div class="tamper"><div class=tamper-h>Entry #{t["broken_index"]} modified</div>' \
                      f'<div class=tnote>{esc(t["note"])}</div></div>'

    rows = []
    for e in s["events"]:
        tool = esc(e["tool_name"] or "-")
        in_h = e["tool_input_sha256"] or ""
        out_h = e["tool_output_sha256"] or ""
        rows.append(
            f"<tr><td>{e['sequence']}</td><td>{esc(e['event_type'])}</td><td>{tool}</td>"
            f"<td class=h>{esc(in_h[:16])}</td><td class=h>{esc(out_h[:16])}</td>"
            f"<td>{esc(e['timestamp_iso'])}</td></tr>"
        )
    rows_html = "\n".join(rows)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Smoke attestation — {esc(s['session_id'])}</title>
<style>
  body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
  .banner{{background:{banner_bg};color:#fff;padding:.9rem 1.2rem;border-radius:8px;font-weight:700;font-size:1.05rem}}
  .meta{{margin:1.2rem 0;display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}}
  .meta b{{color:#555;font-weight:600}}
  code,.h{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}}
  table{{border-collapse:collapse;width:100%;margin-top:1rem;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
  th,td{{text-align:left;padding:.45rem .7rem;border-bottom:1px solid #eee}}
  th{{background:#f3f3f3;font-weight:600}}
  .tamper{{margin-top:1rem;background:#fff4f4;border:1px solid #f0c0c0;border-left:4px solid #b00020;border-radius:6px;padding:.8rem 1rem}}
  .tamper-h{{font-weight:700;color:#b00020;margin-bottom:.5rem}}
  .diffrow{{display:flex;gap:.6rem;align-items:center;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;padding:.15rem 0}}
  .field{{min-width:9rem;color:#555;font-weight:600}}
  .orig{{color:#0f7b3f}}.obs{{color:#b00020;text-decoration:line-through}}.arrow{{color:#999}}
  .tnote{{color:#7a3a3a;font-size:.9em}}
  .foot{{margin-top:1.4rem;color:#888;font-size:.8rem}}
</style></head><body>
<div class="banner">{banner_txt}{detail}</div>
{tamper_html}
<div class="meta">
  <b>session</b><span class=h>{esc(s['session_id'])}</span>
  <b>trust</b><span>{esc(s['trust'])}</span>
  <b>key_id</b><span class=h>{esc(s['key_id'])}</span>
  <b>spki_sha256</b><span class=h>{esc(s['spki_sha256'])}</span>
  <b>entries</b><span>{s['count']} (ended: {s['ended']})</span>
  <b>span</b><span>{esc(str(s['first_ts']))} &rarr; {esc(str(s['last_ts']))}</span>
</div>
<table><thead><tr><th>#</th><th>event</th><th>tool</th><th>input&nbsp;sha256</th><th>output&nbsp;sha256</th><th>timestamp</th></tr></thead>
<tbody>
{rows_html}
</tbody></table>
<div class="foot">smoke.attestation.{esc(str(s['version']))} &middot; tool inputs are hashed, not stored &middot; self-contained, no server required</div>
</body></html>
"""


def cmd_export(args: argparse.Namespace) -> int:
    summary = _build_summary(args.log, args.trusted_spki_sha256, args.trusted_key_id)
    if args.format == "json":
        text = _export_json(summary)
    elif args.format == "md":
        text = _export_md(summary)
    else:
        text = _export_html(summary)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        if not summary["chain_ok"]:
            chain = "INVALID"
        elif summary["pinned"]:
            chain = "valid (pinned)"
        else:
            chain = "consistent (unpinned)"
        print(f"wrote {args.output} ({args.format}, chain={chain})")
    else:
        # Write UTF-8 to stdout regardless of the console codec (a unicode
        # tool_name/cwd would otherwise crash on a cp1252 Windows console).
        # Fall back to text write when stdout has no binary buffer (pytest capsys).
        data = text.encode("utf-8")
        buf = getattr(sys.stdout, "buffer", None)
        if buf is not None:
            buf.write(data)
            buf.flush()
        else:
            sys.stdout.write(text)
    # Surface tamper as a nonzero exit so `export` is scriptable in CI too.
    return 0 if summary["chain_ok"] else 1


# ----------------------------------------------------------------------------
# tamper — the 10-second demo. Mutate a COPY of a log, watch the verifier
# catch it and (for low-entropy fields) recover the original by hash search.
# ----------------------------------------------------------------------------

def cmd_tamper(args: argparse.Namespace) -> int:
    from .localize import KNOWN_TOOL_NAMES, localize_entry

    src = Path(args.log)
    try:
        version, header, envs = chainio.load_chain(src)
    except (chainio.UnknownVersionError, AttestationError) as e:
        sys.stderr.write(f"smoke-verify tamper: {e}\n")
        return 2
    if not envs:
        sys.stderr.write("smoke-verify tamper: log has no entries to tamper with\n")
        return 2

    # Baseline: the untouched log must be internally consistent, or the demo
    # proves nothing.
    base = chainio.pick_verifier(version)(src)
    if not base.ok:
        sys.stderr.write(f"smoke-verify tamper: log already fails verification: {base.reason}\n")
        return 2

    # Pick the entry: first tool event, else entry 0.
    idx = args.entry
    if idx is None:
        idx = next((i for i, e in enumerate(envs)
                    if e.record.event_type in ("pre_tool_use", "post_tool_use")), 0)
    if not (0 <= idx < len(envs)):
        sys.stderr.write(f"smoke-verify tamper: entry {idx} out of range (0..{len(envs)-1})\n")
        return 2

    lines = [ln for ln in src.read_text(encoding="utf-8").splitlines() if ln.strip()]
    raw = json.loads(lines[1 + idx])
    rec = raw["record"]

    field = args.field
    observed = rec.get(field)
    if field == "tool_name":
        new_val = next((t for t in KNOWN_TOOL_NAMES if t != observed), "Bash")
    elif field == "event_type":
        new_val = "post_tool_use" if observed != "post_tool_use" else "pre_tool_use"
    elif field == "actor":
        new_val = "user" if observed != "user" else "system"
    else:
        sys.stderr.write(f"smoke-verify tamper: unsupported --field {field!r}\n")
        return 2
    rec[field] = new_val

    # json.dumps here is display-layer; the verifier recanonicalizes the record
    # itself, so this file only needs to be valid JSON lines.
    lines[1 + idx] = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    out_path = Path(args.output) if args.output else src.with_suffix(".tampered.jsonl")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"original : {src} -- verifies OK ({base.count} entries)")
    print(f"tampered : {out_path} -- entry #{idx} {field}: {observed!r} -> {new_val!r}")
    print()

    res = chainio.pick_verifier(version)(out_path)
    if res.ok:
        # This must be impossible; if it happens the verifier is broken.
        print("!! TAMPER NOT DETECTED — this is a verifier bug, please report it")
        return 1
    print(f"verify   : INVALID at entry #{res.broken_index} -- {res.reason}")

    loc = localize_entry(rec, raw.get("entry_hash", ""), header.key_id, expected_version=version)
    if loc.recovered:
        for c in loc.changes:
            print(f"recovered: {c.field} was {c.original!r} (edit changed it to {c.observed!r}) -- "
                  "proven by hash search against the signed entry_hash")
    else:
        print(f"recovery : {loc.note}")
    print()
    print("The edit broke the entry's own hash AND the next entry's chain link.")
    print("Without the signing key, no edit to a committed record can go unnoticed.")
    return 0


# ----------------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smoke-verify",
        description="Offline verifier for smoke.attestation.v0 tamper-evident agent action logs",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pv = sub.add_parser("verify", help="verify a log (fail-closed on trust)")
    pv.add_argument("log")
    pv.add_argument("--trusted-spki-sha256", default=None,
                    help="the trust anchor: expected signing key fingerprint (SHA-256 of SPKI DER)")
    pv.add_argument("--trusted-key-id", default=None,
                    help="EXTRA filter on the header's key_id label; NOT a trust anchor by "
                         "itself (labels are producer-chosen) — requires --trusted-spki-sha256 "
                         "or --trust-log-header")
    pv.add_argument("--trust-log-header", action="store_true",
                    help="accept the key embedded in the log (consistency only, NOT authenticity)")
    pv.add_argument("--explain", action="store_true",
                    help="on a mutated entry, recover which low-entropy field changed")
    pv.add_argument("--require-ended", action="store_true",
                    help="fail (exit 1) if the chain does not end with session_end (truncation guard)")
    pv.add_argument("--anchor", default=None,
                    help="path to a previously-published anchor; fail if history diverges from it")
    pv.add_argument("--tsa-spki-b64", action="append", default=None, metavar="B64",
                    help="pinned TSA public key (base64 SPKI DER) for anchor witness "
                         "verification; repeatable. Without a pin, rfc3161 witnesses "
                         "are checked structurally but reported UNVERIFIED and fail "
                         "the run unless --allow-unverified-witness")
    pv.add_argument("--allow-unverified-witness", action="store_true",
                    help="accept structurally-sound rfc3161 witnesses without a pinned "
                         "TSA key (consistency only — NOT trusted time)")
    pv.add_argument("--quiet", "-q", action="store_true",
                    help="exit code only, no stdout (0 ok / 1 fail / 2 no trust anchor) — for CI")
    pv.set_defaults(func=cmd_verify)

    pva = sub.add_parser("verify-all", help="verify every *.jsonl log in a directory (exit 1 if any fail)")
    pva.add_argument("dir")
    pva.add_argument("--trusted-spki-sha256", default=None,
                     help="the trust anchor: expected signing key fingerprint (SHA-256 of SPKI DER)")
    pva.add_argument("--trusted-key-id", default=None,
                     help="EXTRA filter on the key_id label; NOT a trust anchor by itself")
    pva.add_argument("--trust-log-header", action="store_true",
                     help="accept each log's own key (consistency only, NOT authenticity)")
    pva.add_argument("--require-ended", action="store_true",
                     help="also fail logs that do not end with session_end")
    pva.add_argument("--recursive", action="store_true", help="recurse into subdirectories")
    pva.add_argument("--json", action="store_true")
    pva.add_argument("--quiet", "-q", action="store_true", help="exit code only, no stdout — for CI")
    pva.set_defaults(func=cmd_verify_all)

    pn = sub.add_parser("inspect", help="print a readable chain summary")
    pn.add_argument("log")
    pn.add_argument("--last", type=int, default=20)
    pn.add_argument("--trusted-spki-sha256", default=None,
                    help="pin the expected key; without it the chain status reads INTERNALLY CONSISTENT, not VALID")
    pn.add_argument("--trusted-key-id", default=None)
    pn.set_defaults(func=cmd_inspect)

    pd = sub.add_parser("diff", help="exact field diff of a log against a trusted reference copy")
    pd.add_argument("log")
    pd.add_argument("--reference", required=True, help="path to a trusted/known-good copy of the chain")
    pd.add_argument("--json", action="store_true")
    pd.set_defaults(func=cmd_diff)

    pan = sub.add_parser("anchor", help="emit a chain-head anchor to publish externally (append-only proof)")
    pan.add_argument("log")
    pan.add_argument("--output", "-o", default=None, help="write the anchor JSON to a file (default: stdout)")
    pan.add_argument("--tsa-url", action="append", default=None, metavar="URL",
                     help="RFC 3161 TSA endpoint to witness the chain head (repeatable; "
                          "shortcuts: digicert, sigstore). Outages are recorded, never hidden")
    pan.add_argument("--git-dir", default=None, metavar="PATH",
                     help="git repository to append+commit the head into (git_mirror witness)")
    pan.set_defaults(func=cmd_anchor)

    pe = sub.add_parser("export", help="export an audit artifact (html for humans, json/md for agents)")
    pe.add_argument("log")
    pe.add_argument("--format", choices=["html", "json", "md"], default="html")
    pe.add_argument("--output", "-o", default=None, help="output path (default: stdout)")
    pe.add_argument("--trusted-spki-sha256", default=None,
                    help="pin the expected key so the exported chain status reflects authenticity")
    pe.add_argument("--trusted-key-id", default=None)
    pe.set_defaults(func=cmd_export)

    pt = sub.add_parser("tamper", help="DEMO: mutate a COPY of a log, watch detection + recovery")
    pt.add_argument("log", help="a valid log to copy and tamper (the original is never touched)")
    pt.add_argument("--entry", type=int, default=None, help="entry index to mutate (default: first tool event)")
    pt.add_argument("--field", choices=["tool_name", "event_type", "actor"], default="tool_name")
    pt.add_argument("--output", "-o", default=None, help="tampered copy path (default: <log>.tampered.jsonl)")
    pt.set_defaults(func=cmd_tamper)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
