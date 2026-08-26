"""L6 — the analyst-facing investigation report.

    source source_env.sh
    $SENTINEL_PYTHON L6/report.py <sha256> --out report.html
    $SENTINEL_PYTHON L6/report.py <sha256> --pdf report.pdf

One self-contained HTML file per sample: no external CSS, no fonts, no scripts
from anywhere. It opens on an air-gapped analyst workstation and prints to PDF
through the browser, which is why there is no hard dependency on a PDF engine.

**The report's job is to make a verdict checkable, not to assert it.** Every
number on the page is traceable: each scoring contribution names the signal and
the evidence ``id`` behind it, and each finding shows the rule, the file and
the matched string. A reader who disagrees can find the exact line that
produced the disagreement.

**Uncertainty is displayed, not buried.** Confidence sits next to the score
rather than being folded into it, coverage gaps are listed by name, and an
`unsupported` scoring stamp is rendered as a banner across the top rather than
a footnote — because at ``n_benign = 4`` the score is, by measurement, not
usable, and a report that hid that would be worse than no report.
"""

from __future__ import annotations

import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402
from L6.export import Bundleable, gather, spine_exists  # noqa: E402

BAND_COLOR = {
    "Critical": "#b3261e", "High": "#c25a00", "Medium": "#8a6d00",
    "Low": "#2c6e49", "Informational": "#40566b",
}
SEV_COLOR = {
    "critical": "#b3261e", "high": "#c25a00", "medium": "#8a6d00",
    "low": "#40566b", "info": "#64748b",
}

CSS = """
*{box-sizing:border-box}
body{margin:0;padding:2rem;font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
     color:#17212b;background:#f6f7f9;max-width:1100px;margin-inline:auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:2rem 0 .6rem;padding-bottom:.3rem;border-bottom:1px solid #dfe3e8}
.sub{color:#5b6b7c;margin:0 0 1.5rem;font-size:.9rem}
.card{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:1.1rem 1.25rem;margin-bottom:1rem}
.banner{background:#fff4e5;border:1px solid #e0a458;border-left-width:5px;border-radius:8px;
        padding:.85rem 1rem;margin-bottom:1.25rem}
.banner strong{color:#8a4b00}
.verdict{display:flex;gap:1.5rem;align-items:center;flex-wrap:wrap}
.score{font-size:2.6rem;font-weight:700;line-height:1;letter-spacing:-.02em}
.band{font-size:.72rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
      color:#fff;padding:.28rem .6rem;border-radius:999px;display:inline-block}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.3rem 1.1rem;font-size:.88rem}
.kv dt{color:#5b6b7c}
.kv dd{margin:0;font-variant-numeric:tabular-nums}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{text-align:left;padding:.4rem .55rem;border-bottom:1px solid #eceff2;vertical-align:top}
th{color:#5b6b7c;font-weight:600;font-size:.76rem;text-transform:uppercase;letter-spacing:.05em}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.82em}
details{border:1px solid #e4e8ec;border-radius:8px;margin-bottom:.5rem;background:#fff}
details>summary{cursor:pointer;padding:.55rem .8rem;font-weight:600;font-size:.88rem;
                display:flex;gap:.6rem;align-items:center}
details>div{padding:0 .8rem .8rem}
.sev{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
     color:#fff;padding:.14rem .45rem;border-radius:4px}
.pill{background:#eef1f4;color:#41525f;border-radius:999px;padding:.13rem .5rem;
      font-size:.75rem;margin-right:.3rem;display:inline-block}
.gap{color:#8a4b00}
.muted{color:#7a8894}
.pos{color:#b3261e}.neg{color:#2c6e49}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #dfe3e8;
       color:#7a8894;font-size:.78rem}
@media print{body{background:#fff;padding:0;max-width:none}
  .card,details{break-inside:avoid}details{border:none}details>summary{padding-left:0}
  details[open]>div{padding-left:0}}
"""


def _e(v: Any) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _score_artifact(sha: str) -> dict[str, Any]:
    p = REPO_ROOT / "L5" / "artifacts" / sha / "score.json"
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _verdict_card(b: Bundleable, l5: dict[str, Any]) -> str:
    band = b.band or "Not scored"
    color = BAND_COLOR.get(band, "#40566b")
    score = b.score if b.score is not None else "—"
    conf = f"{b.confidence:.2f}" if b.confidence is not None else "—"
    conf_band = _e(l5.get("confidence_band", ""))

    rows = [("Package", b.package or "—"), ("Application", b.label)]
    if b.impersonates:
        rows.append(("Impersonates", b.impersonates))
    rows += [
        ("SHA-256", b.sha256),
        ("Confidence", f"{conf} ({conf_band})" if conf_band else conf),
        ("Binding constraint", l5.get("binding_reason", "—")),
    ]
    kv = "".join(f"<dt>{_e(k)}</dt><dd class='mono'>{_e(v)}</dd>" for k, v in rows)

    return f"""<div class="card"><div class="verdict">
  <div>
    <div class="score" style="color:{color}">{_e(score)}<span style="font-size:1rem;
      color:#94a3b1;font-weight:400"> / 100</span></div>
    <span class="band" style="background:{color}">{_e(band)}</span>
  </div>
  <dl class="kv" style="flex:1;min-width:340px">{kv}</dl>
</div></div>"""


def _contributions_table(l5: dict[str, Any]) -> str:
    contribs = [c for c in l5.get("contributions", []) if c.get("status") == "priced"]
    if not contribs:
        return "<p class='muted'>No signal carried a usable weight.</p>"
    contribs.sort(key=lambda c: -abs(c.get("weight_applied", 0)))
    rows = []
    for c in contribs:
        w = c.get("weight_applied", 0)
        cls = "pos" if w > 0 else "neg"
        ids = ", ".join(c.get("evidence_ids") or []) or "—"
        disc = c.get("discount", 1.0)
        rows.append(
            f"<tr><td class='num {cls}'>{w:+.2f}</td>"
            f"<td class='mono'>{_e(c.get('source'))}</td>"
            f"<td class='mono'>{_e(ids)}</td>"
            f"<td class='muted'>{_e(c.get('family') or '—')}</td>"
            f"<td class='num muted'>{'' if disc == 1.0 else f'×{disc:.2f}'}</td></tr>")
    skipped = [c for c in l5.get("contributions", []) if c.get("status") != "priced"]
    note = ""
    if skipped:
        by = {}
        for c in skipped:
            by[c["status"]] = by.get(c["status"], 0) + 1
        note = ("<p class='muted' style='margin-top:.6rem'>Priced at zero: "
                + ", ".join(f"{n} {k}" for k, n in sorted(by.items())) + ".</p>")
    return (f"<table><thead><tr><th>Points</th><th>Signal</th><th>Evidence</th>"
            f"<th>Family</th><th>Discount</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>{note}")


def _gates_section(l5: dict[str, Any]) -> str:
    gates = l5.get("gates", [])
    if not gates:
        return ""
    out = []
    for g in gates:
        state = g.get("state", "?")
        mark = {"fired": "⬤ fired", "not_fired": "○ not fired",
                "indeterminate": "◐ indeterminate", "disabled": "○ disabled"}.get(state, state)
        legs = "".join(
            f"<tr><td>{_e(l.get('leg'))}</td>"
            f"<td>{_e({True: 'yes', False: 'no', None: 'unknown'}.get(l.get('satisfied')))}</td>"
            f"<td class='mono'>{_e(', '.join(l.get('evidence_ids') or []) or '—')}</td>"
            f"<td class='muted'>{_e(l.get('note') or '')}</td></tr>"
            for l in g.get("legs", []))
        body = (f"<table><thead><tr><th>Leg</th><th>Satisfied</th><th>Evidence</th>"
                f"<th>Note</th></tr></thead><tbody>{legs}</tbody></table>"
                if legs else f"<p class='muted'>{_e(g.get('note') or 'not evaluated')}</p>")
        out.append(
            f"<details><summary><span class='mono'>{_e(g.get('gate_id'))}</span>"
            f"<span class='muted'>{_e(mark)}</span>"
            f"<span class='muted' style='margin-left:auto'>floor {_e(g.get('floor'))}</span>"
            f"</summary><div>{body}</div></details>")
    return "".join(out)


def _findings_section(b: Bundleable) -> str:
    if not b.findings:
        return "<p class='muted'>No findings.</p>"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(b.findings, key=lambda f: order.get(f.get("severity", "low"), 9))
    out = []
    for f in findings:
        sev = f.get("severity", "low")
        detail = f.get("detail") or {}
        rows = []
        for key in ("yara_rule", "spine_key", "scopes", "match_count", "location_count"):
            if key in detail:
                v = detail[key]
                rows.append(f"<tr><td class='muted'>{_e(key)}</td>"
                            f"<td class='mono'>{_e(v if not isinstance(v, list) else ', '.join(map(str, v)))}</td></tr>")
        samples = detail.get("samples") or []
        for s in samples[:6]:
            rows.append(f"<tr><td class='muted'>match</td><td class='mono'>"
                        f"{_e(s.get('snippet'))} <span class='muted'>@ {_e(s.get('location'))}</span></td></tr>")
        locs = detail.get("locations") or []
        if locs:
            rows.append(f"<tr><td class='muted'>locations</td><td class='mono'>"
                        + "<br>".join(_e(l) for l in locs[:8]) + "</td></tr>")
        tech = "".join(f"<span class='pill'>{_e(t)}</span>"
                       for t in f.get("mitre_techniques") or [])
        out.append(
            f"<details><summary>"
            f"<span class='sev' style='background:{SEV_COLOR.get(sev, '#64748b')}'>{_e(sev)}</span>"
            f"<span class='mono'>{_e(f.get('id'))}</span>"
            f"<span>{_e(f.get('category'))}</span>"
            f"<span class='muted' style='margin-left:auto'>{_e(f.get('engine'))}</span>"
            f"</summary><div><p>{_e(f.get('evidence'))}</p>"
            f"<p class='muted mono'>{_e(f.get('location'))}</p>{tech}"
            + (f"<table>{''.join(rows)}</table>" if rows else "")
            + "</div></details>")
    return "".join(out)


def _iocs_section(b: Bundleable) -> str:
    if not b.iocs:
        return ("<p class='muted'>No indicators were extracted from this sample. "
                "This is reported rather than padded — an indicator list a bank "
                "cannot act on is worse than none.</p>")
    rows = "".join(
        f"<tr><td>{_e(i.get('type'))}</td><td class='mono'>{_e(i.get('value'))}</td>"
        f"<td class='num'>{_e(i.get('count'))}</td>"
        f"<td class='mono muted'>{_e((i.get('locations') or ['—'])[0])}</td></tr>"
        for i in b.iocs)
    return (f"<table><thead><tr><th>Type</th><th>Indicator</th><th>Count</th>"
            f"<th>First location</th></tr></thead><tbody>{rows}</tbody></table>")


BAND_TAG_COLOR = {
    "grounded": "#2c6e49", "plausible": "#8a6d00",
    "hunch": "#c25a00", "refuted": "#94a3b1",
}


def _l4_artifact(sha: str) -> dict[str, Any]:
    p = REPO_ROOT / "L4" / "artifacts" / sha / "deobfuscation.json"
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _l4_section(sha: str, l5: dict[str, Any]) -> str:
    """AI-Assisted Code Analysis — L4's agentic verdicts.

    Per `decisions/plan_l4_agentic_verdicts.md`, these scores rank classes for
    a human reader's attention and are not asserted as evidence on their own —
    but per the 2026-08-26 policy change, a *qualifying* reading (RAG-grounded,
    or a best class score >= the configured floor) now DOES contribute a
    bounded, positive-only delta to the L5 score (`L5/score.py::apply_l4`).
    The banner below states plainly whether that happened for *this* sample,
    rather than a blanket "never contributes" claim that stopped being true.
    Every kept claim shown here already survived mechanical re-derivation
    (`L4/verify.py`); dropped claims and the verifier's counter-argument are
    shown too, so a reader sees what did *not* survive as plainly as what did.
    """
    l4 = _l4_artifact(sha)
    explanations = l4.get("explanations") or []
    if not explanations:
        return "<p class='muted'>L4 did not run, or produced nothing verifiable, for this sample.</p>"

    ai_delta = l5.get("ai_delta") or 0
    if ai_delta:
        banner = (f"<p class='muted' style='margin:0 0 .8rem'><strong style='color:#2c6e49'>"
                  f"+{_e(ai_delta)} points contributed to the score above</strong> — this "
                  f"sample's best class reading qualified (RAG-grounded, or scored at/above "
                  f"the AI floor). Capped, positive-only, and cannot reach Critical alone. "
                  f"Every claim shown already survived mechanical re-derivation against this "
                  f"sample's own bytes.</p>")
    else:
        banner = (
            "<p class='muted' style='margin:0 0 .8rem'>Report-only for this sample — no "
            "class reading was RAG-grounded or scored high enough to clear the AI "
            "contribution floor, so nothing here was added to the score above or fed any "
            "gate. Every claim shown already survived mechanical re-derivation against this "
            "sample's own bytes.</p>")

    ranked = sorted(explanations, key=lambda e: (e.get("score") or {}).get("score", -1),
                     reverse=True)
    cards = []
    for e in ranked:
        score = e.get("score") or {}
        band = score.get("band", "unscored")
        color = BAND_TAG_COLOR.get(band, "#5b6b7c")
        verifier = e.get("verifier") or {}
        trail = e.get("reasoning_trail") or []
        dropped = e.get("dropped_claims") or []

        trail_html = ("".join(f"<li>{_e(s)}</li>" for s in trail)
                      or "<li class='muted'>no reasoning trail</li>")
        dropped_html = ("".join(
            f"<li class='muted'>✗ {_e(d.get('kind'))}: {_e(str(d.get('claim'))[:90])} "
            f"({_e(d.get('reason'))})</li>" for d in dropped)
            if dropped else "")

        cards.append(f"""<details><summary>
  <span class="band" style="background:{color}">{_e(band)} · {_e(score.get('score', '—'))}/10</span>
  <span class="mono">{_e(e.get('location'))}</span>
</summary><div>
  <p class="muted" style="margin:.4rem 0">{_e(score.get('rationale', ''))}</p>
  {f"<p style='margin:.4rem 0'><strong>Verifier:</strong> {_e(verifier.get('status'))} "
    f"({_e(verifier.get('confidence'))}) — {_e(verifier.get('counter_argument', ''))}</p>"
    if verifier else ''}
  <p style="margin:.6rem 0 .2rem"><strong>Reasoning trail</strong></p>
  <ul style="margin:.2rem 0">{trail_html}</ul>
  {f"<p style='margin:.6rem 0 .2rem'><strong>Dropped claims</strong></p><ul style='margin:.2rem 0'>{dropped_html}</ul>" if dropped else ''}
</div></details>""")

    return banner + "".join(cards)


def _coverage_section(doc: dict[str, Any]) -> str:
    layers = doc.get("layers", {})
    rows = "".join(
        f"<tr><td class='mono'>{_e(name)}</td><td>{_e(blk.get('status'))}</td>"
        f"<td class='muted mono'>{_e(', '.join(f'{k}={v}' for k, v in list((blk.get('coverage') or {}).items())[:5]))}</td></tr>"
        for name, blk in layers.items())
    gaps = doc.get("analysis_gaps") or []
    gap_html = ("".join(f"<span class='pill gap'>{_e(g)}</span>" for g in gaps)
                if gaps else "<span class='muted'>none</span>")
    return (f"<table><thead><tr><th>Layer</th><th>Status</th><th>Coverage</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            f"<p style='margin-top:.7rem'><strong>Declared gaps:</strong> {gap_html}</p>")


def render(doc: dict[str, Any]) -> str:
    b = gather(doc)
    l5 = _score_artifact(b.sha256)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    banner = ""
    if b.unsupported or l5.get("unsupported"):
        banner = ("<div class='banner'><strong>This score is not usable as "
                  "evidence.</strong> Its weights were computed against a benign "
                  "corpus too small to support them, so the interval around every "
                  "false-positive rate is wide enough to include values that would "
                  "make the score meaningless. The findings below are real; the "
                  "number is provisional.</div>")

    l5_section = (
        f"<h2>How the score was reached</h2>{_contributions_table(l5)}"
        f"<h3 style='font-size:.9rem;margin:1.2rem 0 .5rem;color:#5b6b7c'>"
        f"Smoking-gun gates</h3>{_gates_section(l5)}"
        if l5 else
        "<h2>How the score was reached</h2><p class='muted'>L5 has not scored "
        "this sample.</p>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APK Sentinel — {_e(b.label)}</title><style>{CSS}</style></head><body>
<h1>APK Sentinel investigation report</h1>
<p class="sub">{_e(b.label)} · generated {_e(generated)}</p>
{banner}
{_verdict_card(b, l5)}
{l5_section}
<h2>Findings ({len(b.findings)})</h2>
{_findings_section(b)}
<h2>Indicators ({len(b.iocs)})</h2>
{_iocs_section(b)}
<h2>AI-assisted code analysis (L4)</h2>
{_l4_section(b.sha256, l5)}
<h2>Analysis coverage</h2>
{_coverage_section(doc)}
<footer>
Generated by APK Sentinel. The score, findings and indicators above derive from
deterministic analysis layers: scoring weights are computed from measured
rule-firing rates, indicators are extracted from the sample's own bytes, and
technique mappings come from the findings themselves. The AI-assisted code
analysis section is model-generated; every checkable claim in it was
mechanically re-derived and discarded if wrong. Per policy, it contributes a
capped, positive-only amount to the score above only when a class reading is
RAG-grounded or scores at/above the AI floor (see that section for whether it
did so here) — it never feeds a gate, and an unqualifying reading contributes
nothing.
<br>Schema {_e(doc.get('schema_version'))} ·
policy {_e(l5.get('policy_version', '—'))} ·
weights {_e(l5.get('weights_version', '—'))} ·
ruleset {_e(l5.get('ruleset_version', '—'))}
</footer></body></html>"""


def to_pdf(html_text: str, out: Path) -> bool:
    """Best-effort PDF. Returns False when no engine is available.

    Not a hard dependency: the HTML prints correctly from any browser, and
    requiring a rendering engine to read a report would be a worse trade than
    telling the user to press Ctrl-P.
    """
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:  # noqa: BLE001
        return False
    HTML(string=html_text).write_pdf(str(out))
    return True


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sha256")
    ap.add_argument("--out", default=None, help="write HTML here")
    ap.add_argument("--pdf", default=None, help="also try to write a PDF")
    args = ap.parse_args(argv)

    if not spine_exists(args.sha256):
        print(f"no spine for {args.sha256}", file=sys.stderr)
        return 1
    doc = spine.load_spine(args.sha256)
    text = render(doc)

    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    elif not args.pdf:
        print(text)

    if args.pdf:
        if to_pdf(text, Path(args.pdf)):
            print(f"wrote {args.pdf}")
        else:
            print("weasyprint not installed — open the HTML and print to PDF",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
