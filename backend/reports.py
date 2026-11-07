"""Board-ready HTML report. Self-contained, printable, no JavaScript."""
from __future__ import annotations

import html
import sqlite3

from . import audit, service
from .db import get_setting


def _m(v) -> str:
    if v is None or v == "":
        return "-"
    v = float(v)
    if v >= 1_000_000:
        return f"${v / 1_000_000:.2f}M"
    if v >= 1_000:
        return f"${v / 1_000:.0f}k"
    return f"${v:,.0f}"


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


BAND_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}


def board_report_html(conn: sqlite3.Connection) -> str:
    d = service.dashboard(conn)
    org = get_setting(conn, "org_name", "Example Co")
    risks = service.list_risks(conn)
    open_risks = [r for r in risks if r["status"] != "Closed"]
    appetite = service.appetite_map(conn)
    statement = get_setting(conn, "appetite_statement", "")

    def chip(band: str) -> str:
        return f'<span class="chip" style="background:{BAND_COLORS.get(band, "#999")}">{_e(band)}</span>'

    heat = d["heatmap"]["residual"]
    heat_rows = ""
    for L in range(5, 0, -1):
        cells = ""
        for I in range(1, 6):
            s = L * I
            band = next(b for b in service.scoring.BANDS if b["min"] <= s <= b["max"])
            ids = heat[L - 1][I - 1]
            cells += f'<td style="background:{band["color"]}22;border-left:4px solid {band["color"]}"><b>{len(ids) or ""}</b><br><small>{_e(", ".join(ids))}</small></td>'
        heat_rows += f"<tr><th>L{L}</th>{cells}</tr>"

    rows = ""
    for r in open_risks:
        ale = r["fair"]["residual"]["ale_p90"] if r["fair"] else None
        rows += (f"<tr><td>{_e(r['id'])}</td><td><b>{_e(r['title'])}</b><br><small>{_e(r['business_impact'][:160])}</small></td>"
                 f"<td>{_e(r['category'])}</td><td>{_e(r['owner'])}</td><td>{r['inherent_score']} {chip(r['inherent_band'])}</td>"
                 f"<td>{r['residual_score']} {chip(r['residual_band'])}</td><td>{_m(ale)}</td>"
                 f"<td>{'<b style=color:#c62828>OUTSIDE</b>' if r['appetite']['breach'] else 'inside'}</td>"
                 f"<td>{r['treatments_summary']['open']} open / {r['treatments_summary']['overdue']} late</td><td>{_e(r['status'])}</td></tr>")

    treat_rows = "".join(
        f"<tr><td>{_e(t['risk_id'])}</td><td>{_e(t['title'])}</td><td>{_e(t['owner'])}</td><td>{_e(t['due_date'])}</td><td>{t['progress']}%</td></tr>"
        for t in d["overdue_treatments"])
    app_rows = "".join(
        f"<tr><td>{_e(a['category'])}</td><td>{a['max_residual_score']}</td><td>{_m(a['max_ale'])}</td><td>{_e(a.get('statement') or '')}</td></tr>"
        for a in appetite.values())
    headlines = "".join(f'<li class="{h["tone"]}">{_e(h["text"])}</li>' for h in d["headlines"])
    p = d["portfolio"]
    portfolio = "" if not p else (
        f"<p>Across the {p['risks_quantified']} of {p['risks_total']} open risks that have been quantified, the expected annual loss after controls is "
        f"<b>{_m(p['residual']['ale_mean'])}</b> (median {_m(p['residual']['ale_median'])}). In a bad year (1-in-10) losses reach "
        f"<b>{_m(p['residual']['ale_p90'])}</b>; 1-in-20 reaches {_m(p['residual']['ale_p95'])}. Without current controls the expected loss would be "
        f"{_m(p['inherent']['ale_mean'])}, so the control estate is worth roughly {_m(p['inherent']['ale_mean'] - p['residual']['ale_mean'])} a year.</p>")
    tiers = d["counts"]["evidence_tiers"]
    verify = audit.verify(conn)

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Risk Report - {_e(org)}</title>
<style>
body{{font-family:Georgia,serif;max-width:1100px;margin:30px auto;color:#1a1a1a;line-height:1.45;padding:0 16px}}
h1{{margin-bottom:0}} h2{{border-bottom:2px solid #333;padding-bottom:4px;margin-top:36px}}
table{{border-collapse:collapse;width:100%;font-family:Helvetica,Arial,sans-serif;font-size:13px}}
th,td{{border:1px solid #ccc;padding:6px 8px;vertical-align:top;text-align:left}} th{{background:#f0f0f0}}
.chip{{color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-family:Helvetica,Arial,sans-serif}}
ul.head li{{margin:6px 0;padding-left:8px;border-left:5px solid #999}} li.bad{{border-color:#c62828!important}} li.warn{{border-color:#ef6c00!important}} li.good{{border-color:#2e7d32!important}}
.meta{{color:#555;font-family:Helvetica,Arial,sans-serif;font-size:12px}} .heat td{{height:48px;width:18%;text-align:center}}
@media print{{h2{{page-break-after:avoid}} table{{page-break-inside:auto}}}}
</style></head><body>
<h1>{_e(org)} - Risk Report</h1>
<div class="meta">Generated {_e(d['generated_at'])} by NextGen Risk Register. Scores are deterministic; re-running this report on the same data gives the same numbers.</div>
<h2>1. What the board needs to know</h2>
<ul class="head">{headlines}</ul>
{portfolio}
<h2>2. Risk appetite</h2>
<p>{_e(statement) or 'No appetite statement recorded.'}</p>
<table><tr><th>Category</th><th>Max residual score (of 25)</th><th>Max annual loss (P90)</th><th>Statement</th></tr>{app_rows}</table>
<h2>3. Residual heat map (after controls, evidence-weighted)</h2>
<table class="heat"><tr><th></th><th>I1 Negligible</th><th>I2 Minor</th><th>I3 Moderate</th><th>I4 Major</th><th>I5 Severe</th></tr>{heat_rows}</table>
<h2>4. Open risks ({len(open_risks)})</h2>
<table><tr><th>ID</th><th>Risk</th><th>Category</th><th>Owner</th><th>Inherent</th><th>Residual</th><th>P90 annual loss</th><th>Appetite</th><th>Treatments</th><th>Status</th></tr>{rows}</table>
<h2>5. Overdue treatment actions ({len(d['overdue_treatments'])})</h2>
<table><tr><th>Risk</th><th>Action</th><th>Owner</th><th>Due</th><th>Progress</th></tr>{treat_rows or '<tr><td colspan=5>None</td></tr>'}</table>
<h2>6. Control assurance</h2>
<p>{d['counts']['controls']} controls in the library. Evidence quality: {tiers[1]} self-declared, {tiers[2]} scanner-observed, {tiers[3]} SIEM-verified.
Self-declared controls receive only half credit in residual scoring, which is why "we have a policy for that" does not move the heat map.</p>
<h2>7. Integrity</h2>
<p>Audit trail: {_e(verify['message']) if verify else 'n/a'} ({verify['entries'] if verify else 0} entries, chain head {_e((verify or {}).get('head', '')[:16])}...).</p>
</body></html>"""
