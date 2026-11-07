"""Domain service: everything between the SQL rows and the HTTP layer.

All risk maths is delegated to `scoring`; this module assembles rows, links,
and derived fields into the shape the UI and reports consume.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from . import scoring
from .audit import now_iso
from .db import row_to_dict

RISK_JSON = ("attack_techniques", "framework_refs", "tags")
CONTROL_JSON = ("framework_refs",)
RISK_STATUSES = ["Identified", "Assessed", "Treating", "Monitoring", "Accepted", "Closed"]
TREATMENT_STATUSES = ["Planned", "In Progress", "Done", "Cancelled"]
STRATEGIES = ["Mitigate", "Accept", "Transfer", "Avoid"]

_SIM_CACHE: dict[tuple, dict] = {}


def _today() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------- controls

def get_control(conn: sqlite3.Connection, cid: str) -> dict | None:
    return row_to_dict(conn.execute("SELECT * FROM controls WHERE id=?", (cid,)).fetchone(), CONTROL_JSON)


def list_controls(conn: sqlite3.Connection) -> list[dict]:
    rows = [row_to_dict(r, CONTROL_JSON) for r in conn.execute("SELECT * FROM controls ORDER BY id").fetchall()]
    links = conn.execute("SELECT control_id, COUNT(*) AS n FROM risk_controls GROUP BY control_id").fetchall()
    counts = {r["control_id"]: r["n"] for r in links}
    for c in rows:
        c["credit"] = scoring.control_credit(c)
        c["evidence_tier_name"] = scoring.EVIDENCE_TIERS[int(c["evidence_tier"])]["name"]
        c["linked_risks"] = counts.get(c["id"], 0)
    return rows


def controls_for_risk(conn: sqlite3.Connection, risk_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT c.* FROM controls c JOIN risk_controls rc ON rc.control_id=c.id WHERE rc.risk_id=? ORDER BY c.id", (risk_id,)
    ).fetchall()
    out = []
    for r in rows:
        c = row_to_dict(r, CONTROL_JSON)
        c["credit"] = scoring.control_credit(c)
        c["evidence_tier_name"] = scoring.EVIDENCE_TIERS[int(c["evidence_tier"])]["name"]
        out.append(c)
    return out


# ---------------------------------------------------------------- appetite

def appetite_map(conn: sqlite3.Connection) -> dict[str, dict]:
    return {r["category"]: dict(r) for r in conn.execute("SELECT * FROM appetite").fetchall()}


# ---------------------------------------------------------------- risks

def get_risk_row(conn: sqlite3.Connection, rid: str) -> dict | None:
    return row_to_dict(conn.execute("SELECT * FROM risks WHERE id=?", (rid,)).fetchone(), RISK_JSON)


def _simulate_cached(key: tuple, **kw) -> dict:
    if key not in _SIM_CACHE:
        if len(_SIM_CACHE) > 500:
            _SIM_CACHE.clear()
        _SIM_CACHE[key] = scoring.simulate(**kw)
    return _SIM_CACHE[key]


def enrich_risk(conn: sqlite3.Connection, r: dict, *, appetite: dict[str, dict] | None = None, deep: bool = False) -> dict:
    """Attach every derived field the UI needs. Pure given the DB state."""
    appetite = appetite if appetite is not None else appetite_map(conn)
    controls = controls_for_risk(conn, r["id"])
    sug = scoring.suggested_residual(r["inherent_likelihood"], r["inherent_impact"], controls)

    if r.get("residual_override") and r.get("residual_likelihood") and r.get("residual_impact"):
        res_l, res_i = int(r["residual_likelihood"]), int(r["residual_impact"])
    else:
        res_l, res_i = sug["likelihood"], sug["impact"]

    inh_score = scoring.score(r["inherent_likelihood"], r["inherent_impact"])
    res_score = scoring.score(res_l, res_i)
    r.update({
        "inherent_score": inh_score, "inherent_band": scoring.band_for(inh_score)["name"],
        "residual_likelihood": res_l, "residual_impact": res_i,
        "residual_score": res_score, "residual_band": scoring.band_for(res_score)["name"],
        "suggested_residual": {"likelihood": sug["likelihood"], "impact": sug["impact"],
                                "likelihood_reduction": sug["likelihood_reduction"], "impact_reduction": sug["impact_reduction"],
                                "likelihood_scale": sug["likelihood_scale"], "impact_scale": sug["impact_scale"]},
        "control_count": len(controls),
        "control_credits": sug["credits"],
        "weakest_evidence_tier": min((int(c["evidence_tier"]) for c in controls), default=None),
    })

    # Quantitative
    r["has_fair"] = scoring.has_fair_inputs(r)
    if r["has_fair"]:
        lef = (r["lef_min"], r["lef_likely"], r["lef_max"])
        lm = (r["lm_min"], r["lm_likely"], r["lm_max"])
        inh = _simulate_cached((r["id"], "inh", lef, lm), lef=lef, lm=lm, seed_key=r["id"])
        ls, ms = sug["likelihood_scale"], sug["impact_scale"]
        res = _simulate_cached((r["id"], "res", lef, lm, ls, ms), lef=lef, lm=lm, seed_key=r["id"], lef_scale=ls, lm_scale=ms)
        strip = lambda d: {k: v for k, v in d.items() if k not in ("raw",)}  # noqa: E731
        r["fair"] = {"inherent": strip(inh), "residual": strip(res)}
        if deep:
            r["fair"]["_raw_residual"] = res["raw"]
            r["fair"]["_raw_inherent"] = inh["raw"]
        res_p90 = res["ale_p90"]
    else:
        r["fair"] = None
        res_p90 = None

    r["appetite"] = scoring.appetite_check(res_score, res_p90, appetite.get(r["category"]))

    # Review cadence
    base = _parse(r.get("last_reviewed_at")) or _parse(r["created_at"]) or _today()
    nxt = base + timedelta(days=int(r.get("review_frequency_days") or 90))
    r["next_review_at"] = nxt.date().isoformat()
    r["review_overdue"] = nxt < _today() and r["status"] != "Closed"
    r["days_to_review"] = (nxt - _today()).days

    # Treatments / KRIs / acceptance summaries
    t = conn.execute("SELECT status, due_date, progress FROM treatments WHERE risk_id=?", (r["id"],)).fetchall()
    today = _today().date().isoformat()
    r["treatments_summary"] = {
        "total": len(t),
        "open": sum(1 for x in t if x["status"] in ("Planned", "In Progress")),
        "overdue": sum(1 for x in t if x["status"] in ("Planned", "In Progress") and x["due_date"] and x["due_date"] < today),
        "avg_progress": round(sum(x["progress"] for x in t) / len(t)) if t else 0,
    }
    k = conn.execute("SELECT * FROM kris WHERE risk_id=?", (r["id"],)).fetchall()
    r["kri_status"] = worst_kri_status([dict(x) for x in k])
    acc = conn.execute("SELECT * FROM acceptances WHERE risk_id=? AND status='Active' ORDER BY created_at DESC LIMIT 1", (r["id"],)).fetchone()
    r["active_acceptance"] = dict(acc) if acc else None
    if acc and acc["expires_at"] < today:
        r["active_acceptance"]["expired"] = True
    r["attack_technique_names"] = r.get("attack_techniques") or []
    return r


def list_risks(conn: sqlite3.Connection, *, status: str | None = None, category: str | None = None,
               band: str | None = None, q: str | None = None, owner: str | None = None) -> list[dict]:
    sql, params = "SELECT * FROM risks WHERE 1=1", []
    if status:
        sql += " AND status=?"; params.append(status)
    if category:
        sql += " AND category=?"; params.append(category)
    if owner:
        sql += " AND owner=?"; params.append(owner)
    if q:
        sql += " AND (title LIKE ? OR description LIKE ? OR business_impact LIKE ? OR id LIKE ? OR tags LIKE ?)"
        params += [f"%{q}%"] * 5
    sql += " ORDER BY id"
    appetite = appetite_map(conn)
    out = [enrich_risk(conn, row_to_dict(r, RISK_JSON), appetite=appetite) for r in conn.execute(sql, params).fetchall()]
    if band:
        out = [r for r in out if r["residual_band"] == band]
    out.sort(key=lambda r: (-r["residual_score"], -(r["fair"]["residual"]["ale_p90"] if r["fair"] else 0), r["id"]))
    return out


def risk_detail(conn: sqlite3.Connection, rid: str) -> dict | None:
    r = get_risk_row(conn, rid)
    if not r:
        return None
    enrich_risk(conn, r)
    r["controls"] = controls_for_risk(conn, rid)
    r["treatments"] = [dict(x) for x in conn.execute("SELECT * FROM treatments WHERE risk_id=? ORDER BY due_date", (rid,)).fetchall()]
    r["kris"] = list_kris(conn, rid)
    r["acceptances"] = [dict(x) for x in conn.execute("SELECT * FROM acceptances WHERE risk_id=? ORDER BY created_at DESC", (rid,)).fetchall()]
    r["evidence"] = [dict(x) for x in conn.execute("SELECT * FROM evidence WHERE entity_type='risk' AND entity_id=? ORDER BY uploaded_at DESC", (rid,)).fetchall()]
    r["history"] = [audit_row(x) for x in conn.execute(
        "SELECT * FROM audit_log WHERE entity_id=? OR (entity_type IN ('treatment','kri','acceptance','evidence') AND detail LIKE ?) ORDER BY seq DESC LIMIT 100",
        (rid, f'%"risk_id": "{rid}"%')).fetchall()]
    return r


def audit_row(x: sqlite3.Row) -> dict:
    d = dict(x)
    try:
        d["detail"] = json.loads(d["detail"])
    except json.JSONDecodeError:
        pass
    return d


# ---------------------------------------------------------------- KRIs

def kri_status(k: dict) -> str:
    v = k.get("current_value")
    if v is None:
        return "No data"
    if k["direction"] == "above_is_bad":
        if v >= k["critical"]:
            return "Critical"
        if v >= k["warning"]:
            return "Warning"
        return "OK"
    if v <= k["critical"]:
        return "Critical"
    if v <= k["warning"]:
        return "Warning"
    return "OK"


def worst_kri_status(kris: list[dict]) -> str | None:
    if not kris:
        return None
    order = {"Critical": 3, "Warning": 2, "OK": 1, "No data": 0}
    return max((kri_status(k) for k in kris), key=lambda s: order[s])


def list_kris(conn: sqlite3.Connection, risk_id: str | None = None) -> list[dict]:
    sql, params = "SELECT * FROM kris", ()
    if risk_id:
        sql += " WHERE risk_id=?"; params = (risk_id,)
    out = []
    for row in conn.execute(sql + " ORDER BY id", params).fetchall():
        k = dict(row)
        k["status"] = kri_status(k)
        k["readings"] = [dict(x) for x in conn.execute("SELECT ts, value FROM kri_readings WHERE kri_id=? ORDER BY ts DESC LIMIT 24", (k["id"],)).fetchall()][::-1]
        out.append(k)
    return out


# ---------------------------------------------------------------- dashboard

def dashboard(conn: sqlite3.Connection) -> dict:
    risks = [r for r in list_risks(conn)]
    appetite = appetite_map(conn)
    open_risks = [r for r in risks if r["status"] != "Closed"]
    today = _today().date().isoformat()

    heat_res = [[[] for _ in range(5)] for _ in range(5)]
    heat_inh = [[[] for _ in range(5)] for _ in range(5)]
    for r in open_risks:
        heat_res[r["residual_likelihood"] - 1][r["residual_impact"] - 1].append(r["id"])
        heat_inh[r["inherent_likelihood"] - 1][r["inherent_impact"] - 1].append(r["id"])

    bands = {b["name"]: 0 for b in scoring.BANDS}
    for r in open_risks:
        bands[r["residual_band"]] += 1
    by_status = {s: sum(1 for r in risks if r["status"] == s) for s in RISK_STATUSES}
    by_category = {}
    for r in open_risks:
        by_category.setdefault(r["category"], {"count": 0, "max_score": 0, "breaches": 0})
        c = by_category[r["category"]]
        c["count"] += 1
        c["max_score"] = max(c["max_score"], r["residual_score"])
        c["breaches"] += 1 if r["appetite"]["breach"] else 0

    treatments = [dict(x) for x in conn.execute("SELECT t.*, r.title AS risk_title FROM treatments t JOIN risks r ON r.id=t.risk_id").fetchall()]
    overdue_treatments = [t for t in treatments if t["status"] in ("Planned", "In Progress") and t["due_date"] and t["due_date"] < today]
    done = sum(1 for t in treatments if t["status"] == "Done")

    kris = list_kris(conn)
    kri_alerts = [k for k in kris if k["status"] in ("Warning", "Critical")]
    controls = list_controls(conn)
    tiers = {1: 0, 2: 0, 3: 0}
    for c in controls:
        tiers[int(c["evidence_tier"])] += 1

    # Portfolio Monte Carlo: sum per-simulation losses across independent risks
    quant = [r for r in open_risks if r["has_fair"]]
    portfolio = None
    if quant:
        n = None
        sums_res: list[float] = []
        sums_inh: list[float] = []
        for r in quant:
            full = enrich_risk(conn, get_risk_row(conn, r["id"]), appetite=appetite, deep=True)
            rr, ri = full["fair"]["_raw_residual"], full["fair"]["_raw_inherent"]
            if n is None:
                n = len(rr); sums_res = [0.0] * n; sums_inh = [0.0] * n
            for i in range(n):
                sums_res[i] += rr[i]; sums_inh[i] += ri[i]
        portfolio = {"residual": _summarise(sums_res), "inherent": _summarise(sums_inh), "risks_quantified": len(quant), "risks_total": len(open_risks)}

    acc_expiring = [dict(x) for x in conn.execute(
        "SELECT a.*, r.title AS risk_title FROM acceptances a JOIN risks r ON r.id=a.risk_id WHERE a.status='Active' ORDER BY a.expires_at").fetchall()]
    for a in acc_expiring:
        a["expired"] = a["expires_at"] < today

    breaches = [r for r in open_risks if r["appetite"]["breach"]]
    overdue_reviews = [r for r in open_risks if r["review_overdue"]]
    return {
        "generated_at": now_iso(),
        "headlines": _headlines(open_risks, breaches, overdue_reviews, overdue_treatments, kri_alerts, portfolio, acc_expiring),
        "counts": {"risks": len(risks), "open": len(open_risks), "bands": bands, "status": by_status, "by_category": by_category,
                   "breaches": len(breaches), "overdue_reviews": len(overdue_reviews), "overdue_treatments": len(overdue_treatments),
                   "treatments_total": len(treatments), "treatments_done": done, "kri_alerts": len(kri_alerts),
                   "controls": len(controls), "evidence_tiers": tiers},
        "heatmap": {"residual": heat_res, "inherent": heat_inh},
        "top_risks": [_slim(r) for r in open_risks[:8]],
        "breaches": [_slim(r) for r in breaches],
        "overdue_reviews": [_slim(r) for r in overdue_reviews],
        "overdue_treatments": overdue_treatments,
        "kri_alerts": kri_alerts,
        "acceptances": acc_expiring,
        "portfolio": portfolio,
    }


def _summarise(samples: list[float]) -> dict:
    s = sorted(samples)
    n = len(s)
    pct = lambda p: s[min(n - 1, int(p * n))] if n else 0.0  # noqa: E731
    curve = [{"loss": round(pct(i / 20), 2), "probability_exceeding": round(1 - i / 20, 3)} for i in range(21)]
    return {"ale_mean": round(sum(s) / n, 2) if n else 0, "ale_median": round(pct(0.5), 2), "ale_p90": round(pct(0.9), 2),
            "ale_p95": round(pct(0.95), 2), "ale_max": round(s[-1], 2) if n else 0, "exceedance_curve": curve}


def _slim(r: dict) -> dict:
    keys = ("id", "title", "category", "owner", "status", "inherent_score", "inherent_band", "residual_score", "residual_band",
            "residual_likelihood", "residual_impact", "appetite", "review_overdue", "next_review_at", "treatments_summary", "kri_status",
            "control_count", "weakest_evidence_tier", "business_impact")
    d = {k: r.get(k) for k in keys}
    d["ale_p90"] = r["fair"]["residual"]["ale_p90"] if r.get("fair") else None
    d["ale_mean"] = r["fair"]["residual"]["ale_mean"] if r.get("fair") else None
    return d


def _headlines(open_risks, breaches, overdue_reviews, overdue_treatments, kri_alerts, portfolio, acceptances) -> list[dict]:
    """Deterministic plain-English sentences for the executive view. No LLM involved."""
    h = []
    crit = [r for r in open_risks if r["residual_band"] == "Critical"]
    high = [r for r in open_risks if r["residual_band"] == "High"]
    if breaches:
        worst = breaches[0]
        h.append({"tone": "bad", "text": f"{len(breaches)} risk{'s' if len(breaches) != 1 else ''} sit outside the risk appetite the board set. The worst is \"{worst['title']}\"."})
    else:
        h.append({"tone": "good", "text": "Every open risk is inside the agreed risk appetite."})
    if crit or high:
        h.append({"tone": "warn", "text": f"{len(crit)} critical and {len(high)} high residual risks remain after counting the controls we actually have evidence for."})
    if portfolio:
        p = portfolio["residual"]
        h.append({"tone": "info", "text": f"Expected annual loss across quantified risks is about {_money(p['ale_mean'])}; one bad year in ten could cost {_money(p['ale_p90'])} or more."})
    if overdue_treatments:
        h.append({"tone": "warn", "text": f"{len(overdue_treatments)} treatment action{'s are' if len(overdue_treatments) != 1 else ' is'} past due."})
    if overdue_reviews:
        h.append({"tone": "warn", "text": f"{len(overdue_reviews)} risk{'s have' if len(overdue_reviews) != 1 else ' has'} not been reviewed on schedule, so the scores may be stale."})
    if kri_alerts:
        h.append({"tone": "warn", "text": f"{len(kri_alerts)} key risk indicator{'s are' if len(kri_alerts) != 1 else ' is'} past the warning line."})
    expired = [a for a in acceptances if a["expired"]]
    if expired:
        h.append({"tone": "bad", "text": f"{len(expired)} risk acceptance{'s have' if len(expired) != 1 else ' has'} expired and need{'s' if len(expired) == 1 else ''} a fresh decision."})
    return h


def _money(v: float) -> str:
    if v >= 1_000_000:
        return f"${v / 1_000_000:.1f}M"
    if v >= 1_000:
        return f"${v / 1_000:.0f}k"
    return f"${v:,.0f}"


# ---------------------------------------------------------------- import/export

EXPORT_COLUMNS = [
    "id", "title", "category", "owner", "status", "description", "business_impact", "asset", "threat_source", "vulnerability",
    "inherent_likelihood", "inherent_impact", "inherent_score", "inherent_band", "residual_likelihood", "residual_impact", "residual_score", "residual_band",
    "ale_mean", "ale_p90", "appetite_breach", "control_count", "weakest_evidence_tier", "next_review_at", "review_overdue",
    "treatments_open", "treatments_overdue", "kri_status", "attack_techniques", "framework_refs", "tags", "cvss", "created_at", "updated_at",
]


def export_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    out = []
    for r in list_risks(conn):
        out.append({
            **{k: r.get(k) for k in EXPORT_COLUMNS if k in r},
            "ale_mean": r["fair"]["residual"]["ale_mean"] if r["fair"] else "",
            "ale_p90": r["fair"]["residual"]["ale_p90"] if r["fair"] else "",
            "appetite_breach": "yes" if r["appetite"]["breach"] else "no",
            "treatments_open": r["treatments_summary"]["open"],
            "treatments_overdue": r["treatments_summary"]["overdue"],
            "attack_techniques": "; ".join(r["attack_techniques"]),
            "framework_refs": "; ".join(f"{a}:{b}" for a, b in r["framework_refs"]),
            "tags": "; ".join(r["tags"]),
        })
    return out
