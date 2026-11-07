"""HTTP API for the NextGen Risk Register (FastAPI)."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import audit, scoring, service
from .db import EVIDENCE_DIR, get_setting, init_db, next_id, row_to_dict, session, set_setting
from .frameworks import ATTACK_TECHNIQUES, RISK_CATEGORIES, framework_catalog
from .reports import board_report_html
from .scenarios import get_scenario, scenario_catalog

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(title="NextGen Risk Register", version="1.0.0",
              description="Risk register that speaks plain English to the business and MITRE / FAIR / ISO to engineers.")


init_db()


# ------------------------------------------------------------------ identity / RBAC

ROLES = ["Executive", "Risk Analyst", "Security Engineer", "Auditor"]
PERMISSIONS = {
    "risk:write": {"Risk Analyst", "Security Engineer"},
    "risk:delete": {"Risk Analyst"},
    "control:write": {"Risk Analyst", "Security Engineer"},
    "treatment:write": {"Risk Analyst", "Security Engineer"},
    "kri:write": {"Risk Analyst", "Security Engineer"},
    "evidence:write": {"Risk Analyst", "Security Engineer"},
    "accept": {"Executive", "Risk Analyst"},
    "settings:write": {"Risk Analyst"},
    "import": {"Risk Analyst"},
}


@dataclass
class Actor:
    id: str
    name: str
    role: str

    def can(self, perm: str) -> bool:
        return self.role in PERMISSIONS.get(perm, set())


def get_actor(x_actor: Optional[str] = Header(default=None)) -> Actor:
    with session() as conn:
        row = None
        if x_actor:
            row = conn.execute("SELECT * FROM users WHERE id=?", (x_actor,)).fetchone()
        if row is None:
            row = conn.execute("SELECT * FROM users WHERE role='Risk Analyst' ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return Actor(id="system", name="System", role="Risk Analyst")
        return Actor(id=row["id"], name=row["name"], role=row["role"])


def require(actor: Actor, perm: str) -> None:
    if not actor.can(perm):
        raise HTTPException(status_code=403, detail=f"Role '{actor.role}' cannot perform '{perm}'. This is logged.")


def _log(conn: sqlite3.Connection, actor: Actor, entity_type: str, entity_id: str, action: str, detail: dict | None = None) -> None:
    audit.record(conn, actor=actor.name, role=actor.role, entity_type=entity_type, entity_id=entity_id, action=action, detail=detail)


# ------------------------------------------------------------------ schemas

class RiskIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    business_impact: str = ""
    category: str
    asset: str = ""
    threat_source: str = ""
    vulnerability: str = ""
    owner: str = ""
    status: str = "Identified"
    inherent_likelihood: int = Field(ge=1, le=5)
    inherent_impact: int = Field(ge=1, le=5)
    residual_likelihood: Optional[int] = Field(default=None, ge=1, le=5)
    residual_impact: Optional[int] = Field(default=None, ge=1, le=5)
    residual_override: bool = False
    lef_min: Optional[float] = Field(default=None, ge=0)
    lef_likely: Optional[float] = Field(default=None, ge=0)
    lef_max: Optional[float] = Field(default=None, ge=0)
    lm_min: Optional[float] = Field(default=None, ge=0)
    lm_likely: Optional[float] = Field(default=None, ge=0)
    lm_max: Optional[float] = Field(default=None, ge=0)
    cvss: Optional[float] = Field(default=None, ge=0, le=10)
    attack_techniques: list[str] = []
    framework_refs: list[list[str]] = []
    tags: list[str] = []
    scenario_key: Optional[str] = None
    review_frequency_days: int = Field(default=90, ge=7, le=730)
    control_ids: list[str] = []


class ControlIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: str = ""
    control_type: str = "Preventive"
    implementation_status: str = "Not Implemented"
    effectiveness: int = Field(default=50, ge=0, le=100)
    evidence_tier: int = Field(default=1, ge=1, le=3)
    evidence_source: str = ""
    owner: str = ""
    last_tested_at: Optional[str] = None
    framework_refs: list[list[str]] = []


class TreatmentIn(BaseModel):
    risk_id: str
    strategy: str = "Mitigate"
    title: str = Field(min_length=3)
    description: str = ""
    owner: str = ""
    due_date: Optional[str] = None
    status: str = "Planned"
    progress: int = Field(default=0, ge=0, le=100)
    cost: Optional[float] = None


class KriIn(BaseModel):
    risk_id: str
    name: str
    unit: str = ""
    direction: str = "above_is_bad"
    warning: float
    critical: float
    current_value: Optional[float] = None
    source: str = ""


class KriReadingIn(BaseModel):
    value: float
    ts: Optional[str] = None


class AcceptanceIn(BaseModel):
    rationale: str = Field(min_length=10)
    expires_at: str


class AppetiteIn(BaseModel):
    category: str
    max_residual_score: int = Field(ge=1, le=25)
    max_ale: float = Field(ge=0)
    statement: str = ""


class SettingsIn(BaseModel):
    org_name: Optional[str] = None
    currency: Optional[str] = None
    appetite_statement: Optional[str] = None


class SimulateIn(BaseModel):
    lef_min: float = Field(ge=0)
    lef_likely: float = Field(ge=0)
    lef_max: float = Field(ge=0)
    lm_min: float = Field(ge=0)
    lm_likely: float = Field(ge=0)
    lm_max: float = Field(ge=0)
    likelihood_reduction: float = Field(default=0, ge=0, le=1)
    impact_reduction: float = Field(default=0, ge=0, le=1)
    seed_key: str = "preview"


class TranslateIn(BaseModel):
    annual_probability: Optional[float] = Field(default=None, ge=0, le=1)
    events_per_year: Optional[float] = Field(default=None, ge=0)
    loss_dollars: Optional[float] = Field(default=None, ge=0)


class ReviewIn(BaseModel):
    note: str = ""


# ------------------------------------------------------------------ meta

@app.get("/api/meta")
def meta():
    with session() as conn:
        users = [dict(u) for u in conn.execute("SELECT * FROM users ORDER BY id").fetchall()]
        all_settings = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM settings").fetchall()}
        settings = {k: v for k, v in all_settings.items() if not k.startswith("control_key:")}
        control_keys = {k.split(":", 1)[1]: v for k, v in all_settings.items() if k.startswith("control_key:")}
        appetite = list(service.appetite_map(conn).values())
    return {
        "control_keys": control_keys,
        "likelihood_scale": scoring.LIKELIHOOD_SCALE,
        "impact_scale": scoring.IMPACT_SCALE,
        "bands": scoring.BANDS,
        "evidence_tiers": [{"tier": k, **v} for k, v in scoring.EVIDENCE_TIERS.items()],
        "control_types": list(scoring.CONTROL_TYPES),
        "implementation_statuses": list(scoring.IMPLEMENTATION_FACTOR.keys()),
        "risk_statuses": service.RISK_STATUSES,
        "treatment_statuses": service.TREATMENT_STATUSES,
        "strategies": service.STRATEGIES,
        "categories": RISK_CATEGORIES,
        "frameworks": framework_catalog(),
        "attack_techniques": [{"id": k, "name": v} for k, v in ATTACK_TECHNIQUES.items()],
        "scenarios": scenario_catalog(),
        "users": users,
        "roles": ROLES,
        "permissions": {k: sorted(v) for k, v in PERMISSIONS.items()},
        "settings": settings,
        "appetite": appetite,
    }


@app.get("/api/whoami")
def whoami(actor: Actor = Depends(get_actor)):
    return {"id": actor.id, "name": actor.name, "role": actor.role, "permissions": sorted(p for p in PERMISSIONS if actor.can(p))}


@app.put("/api/settings")
def update_settings(body: SettingsIn, actor: Actor = Depends(get_actor)):
    require(actor, "settings:write")
    with session() as conn:
        changed = {}
        for k, v in body.model_dump(exclude_none=True).items():
            old = get_setting(conn, k)
            if old != v:
                set_setting(conn, k, v)
                changed[k] = {"from": old, "to": v}
        if changed:
            _log(conn, actor, "settings", "global", "update", changed)
        return {r["key"]: r["value"] for r in conn.execute("SELECT * FROM settings").fetchall()}


@app.put("/api/appetite")
def update_appetite(items: list[AppetiteIn], actor: Actor = Depends(get_actor)):
    require(actor, "settings:write")
    with session() as conn:
        before = service.appetite_map(conn)
        for a in items:
            conn.execute(
                "INSERT INTO appetite(category,max_residual_score,max_ale,statement) VALUES(?,?,?,?) "
                "ON CONFLICT(category) DO UPDATE SET max_residual_score=excluded.max_residual_score, max_ale=excluded.max_ale, statement=excluded.statement",
                (a.category, a.max_residual_score, a.max_ale, a.statement))
        after = service.appetite_map(conn)
        d = {k: audit.diff(before.get(k), after.get(k)) for k in after if audit.diff(before.get(k), after.get(k))}
        if d:
            _log(conn, actor, "appetite", "global", "update", d)
        return list(after.values())


# ------------------------------------------------------------------ scoring helpers

@app.post("/api/simulate")
def simulate(body: SimulateIn):
    lef = (body.lef_min, body.lef_likely, body.lef_max)
    lm = (body.lm_min, body.lm_likely, body.lm_max)
    inh = scoring.simulate(lef=lef, lm=lm, seed_key=body.seed_key, n=3000)
    res = scoring.simulate(lef=lef, lm=lm, seed_key=body.seed_key, n=3000,
                           lef_scale=1 - scoring.LIKELIHOOD_DAMPING * body.likelihood_reduction,
                           lm_scale=1 - scoring.IMPACT_DAMPING * body.impact_reduction)
    strip = lambda d: {k: v for k, v in d.items() if k != "raw"}  # noqa: E731
    return {"inherent": strip(inh), "residual": strip(res),
            "suggested_likelihood": scoring.likelihood_level_from_lef(body.lef_likely),
            "suggested_impact": scoring.impact_level_from_dollars(body.lm_likely)}


@app.post("/api/translate")
def translate(body: TranslateIn):
    """Impact translator: numbers <-> plain-English levels."""
    out: dict[str, Any] = {}
    if body.annual_probability is not None:
        lvl = scoring.likelihood_level_from_probability(body.annual_probability)
        out["likelihood"] = scoring.LIKELIHOOD_SCALE[lvl - 1]
    if body.events_per_year is not None:
        lvl = scoring.likelihood_level_from_lef(body.events_per_year)
        out["likelihood"] = scoring.LIKELIHOOD_SCALE[lvl - 1]
    if body.loss_dollars is not None:
        lvl = scoring.impact_level_from_dollars(body.loss_dollars)
        out["impact"] = scoring.IMPACT_SCALE[lvl - 1]
    return out


@app.get("/api/fair-defaults")
def fair_defaults(likelihood: int = Query(ge=1, le=5), impact: int = Query(ge=1, le=5)):
    return scoring.default_fair_from_qualitative(likelihood, impact)


# ------------------------------------------------------------------ risks

def _risk_values(body: RiskIn) -> dict:
    d = body.model_dump(exclude={"control_ids"})
    d["attack_techniques"] = json.dumps(d["attack_techniques"])
    d["framework_refs"] = json.dumps(d["framework_refs"])
    d["tags"] = json.dumps(d["tags"])
    d["residual_override"] = 1 if d["residual_override"] else 0
    return d


def _validate_risk(body: RiskIn) -> None:
    if body.category not in RISK_CATEGORIES:
        raise HTTPException(400, f"Unknown category '{body.category}'")
    if body.status not in service.RISK_STATUSES:
        raise HTTPException(400, f"Unknown status '{body.status}'")
    fair = [body.lef_min, body.lef_likely, body.lef_max, body.lm_min, body.lm_likely, body.lm_max]
    if any(v is not None for v in fair) and not all(v is not None for v in fair):
        raise HTTPException(400, "Provide all six FAIR inputs (frequency min/likely/max and magnitude min/likely/max) or none")
    if all(v is not None for v in fair):
        if not (body.lef_min <= body.lef_likely <= body.lef_max) or not (body.lm_min <= body.lm_likely <= body.lm_max):
            raise HTTPException(400, "FAIR inputs must satisfy min <= likely <= max")
    for t in body.attack_techniques:
        if t not in ATTACK_TECHNIQUES:
            raise HTTPException(400, f"Unknown ATT&CK / ATLAS technique '{t}'")


@app.get("/api/risks")
def risks(status: Optional[str] = None, category: Optional[str] = None, band: Optional[str] = None,
          q: Optional[str] = None, owner: Optional[str] = None):
    with session() as conn:
        return service.list_risks(conn, status=status, category=category, band=band, q=q, owner=owner)


@app.post("/api/risks", status_code=201)
def create_risk(body: RiskIn, actor: Actor = Depends(get_actor)):
    require(actor, "risk:write")
    _validate_risk(body)
    with session() as conn:
        rid = next_id(conn, "risks", "RISK")
        now = audit.now_iso()
        vals = _risk_values(body)
        cols = list(vals.keys()) + ["id", "created_by", "created_at", "updated_at"]
        conn.execute(f"INSERT INTO risks({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                     [*vals.values(), rid, actor.name, now, now])
        for cid in body.control_ids:
            if conn.execute("SELECT 1 FROM controls WHERE id=?", (cid,)).fetchone():
                conn.execute("INSERT OR IGNORE INTO risk_controls(risk_id,control_id) VALUES(?,?)", (rid, cid))
        _log(conn, actor, "risk", rid, "create", {"title": body.title, "category": body.category,
                                                 "inherent": f"L{body.inherent_likelihood} x I{body.inherent_impact}", "controls": body.control_ids})
        return service.risk_detail(conn, rid)


@app.post("/api/risks/from-scenario/{key}", status_code=201)
def create_from_scenario(key: str, actor: Actor = Depends(get_actor)):
    require(actor, "risk:write")
    sc = get_scenario(key)
    if not sc:
        raise HTTPException(404, "Unknown scenario")
    with session() as conn:
        ctl_ids = [r["id"] for r in conn.execute("SELECT id FROM controls").fetchall()]
        key_to_id = {get_setting(conn, f"control_key:{cid}"): cid for cid in ctl_ids}
        body = RiskIn(title=sc["title"], description=sc["description"], business_impact=sc["business_impact"], category=sc["category"],
                      asset=sc["asset"], threat_source=sc["threat_source"], vulnerability=sc["vulnerability"],
                      inherent_likelihood=sc["likelihood"], inherent_impact=sc["impact"], **sc["fair"],
                      attack_techniques=sc["attack_techniques"], framework_refs=sc["framework_refs"], tags=sc["tags"], scenario_key=key,
                      control_ids=[key_to_id[k] for k in sc["controls"] if k in key_to_id])
    return create_risk(body, actor)


@app.get("/api/risks/{rid}")
def risk(rid: str):
    with session() as conn:
        r = service.risk_detail(conn, rid)
        if not r:
            raise HTTPException(404, "Risk not found")
        return r


@app.put("/api/risks/{rid}")
def update_risk(rid: str, body: RiskIn, actor: Actor = Depends(get_actor)):
    require(actor, "risk:write")
    _validate_risk(body)
    with session() as conn:
        before = service.get_risk_row(conn, rid)
        if not before:
            raise HTTPException(404, "Risk not found")
        vals = _risk_values(body)
        vals["updated_at"] = audit.now_iso()
        sets = ", ".join(f"{k}=?" for k in vals)
        conn.execute(f"UPDATE risks SET {sets} WHERE id=?", [*vals.values(), rid])
        old_ctl = {r["control_id"] for r in conn.execute("SELECT control_id FROM risk_controls WHERE risk_id=?", (rid,))}
        new_ctl = set(body.control_ids)
        for cid in old_ctl - new_ctl:
            conn.execute("DELETE FROM risk_controls WHERE risk_id=? AND control_id=?", (rid, cid))
        for cid in new_ctl - old_ctl:
            if conn.execute("SELECT 1 FROM controls WHERE id=?", (cid,)).fetchone():
                conn.execute("INSERT OR IGNORE INTO risk_controls(risk_id,control_id) VALUES(?,?)", (rid, cid))
        after = service.get_risk_row(conn, rid)
        d = audit.diff(before, after)
        if old_ctl != new_ctl:
            d["controls"] = {"from": sorted(old_ctl), "to": sorted(new_ctl)}
        _log(conn, actor, "risk", rid, "update", d)
        return service.risk_detail(conn, rid)


@app.delete("/api/risks/{rid}")
def delete_risk(rid: str, actor: Actor = Depends(get_actor)):
    require(actor, "risk:delete")
    with session() as conn:
        before = service.get_risk_row(conn, rid)
        if not before:
            raise HTTPException(404, "Risk not found")
        conn.execute("DELETE FROM risks WHERE id=?", (rid,))
        _log(conn, actor, "risk", rid, "delete", {"title": before["title"]})
        return {"deleted": rid}


@app.post("/api/risks/{rid}/review")
def review_risk(rid: str, body: ReviewIn, actor: Actor = Depends(get_actor)):
    require(actor, "risk:write")
    with session() as conn:
        if not service.get_risk_row(conn, rid):
            raise HTTPException(404, "Risk not found")
        now = audit.now_iso()
        conn.execute("UPDATE risks SET last_reviewed_at=?, updated_at=? WHERE id=?", (now, now, rid))
        _log(conn, actor, "risk", rid, "review", {"note": body.note})
        return service.risk_detail(conn, rid)


@app.post("/api/risks/{rid}/controls/{cid}")
def link_control(rid: str, cid: str, actor: Actor = Depends(get_actor)):
    require(actor, "risk:write")
    with session() as conn:
        if not service.get_risk_row(conn, rid) or not service.get_control(conn, cid):
            raise HTTPException(404, "Risk or control not found")
        conn.execute("INSERT OR IGNORE INTO risk_controls(risk_id,control_id) VALUES(?,?)", (rid, cid))
        _log(conn, actor, "risk", rid, "link_control", {"control_id": cid})
        return service.risk_detail(conn, rid)


@app.delete("/api/risks/{rid}/controls/{cid}")
def unlink_control(rid: str, cid: str, actor: Actor = Depends(get_actor)):
    require(actor, "risk:write")
    with session() as conn:
        conn.execute("DELETE FROM risk_controls WHERE risk_id=? AND control_id=?", (rid, cid))
        _log(conn, actor, "risk", rid, "unlink_control", {"control_id": cid})
        return service.risk_detail(conn, rid)


@app.post("/api/risks/{rid}/accept", status_code=201)
def accept_risk(rid: str, body: AcceptanceIn, actor: Actor = Depends(get_actor)):
    require(actor, "accept")
    with session() as conn:
        r = service.get_risk_row(conn, rid)
        if not r:
            raise HTTPException(404, "Risk not found")
        try:
            exp = datetime.fromisoformat(body.expires_at)
        except ValueError:
            raise HTTPException(400, "expires_at must be YYYY-MM-DD")
        if exp.date() <= datetime.now(timezone.utc).date():
            raise HTTPException(400, "Acceptance must expire in the future: open-ended acceptances are how risks get forgotten")
        if (exp.date() - datetime.now(timezone.utc).date()).days > 365:
            raise HTTPException(400, "Acceptances are limited to 12 months; re-approve annually")
        conn.execute("UPDATE acceptances SET status='Superseded' WHERE risk_id=? AND status='Active'", (rid,))
        aid = next_id(conn, "acceptances", "ACC")
        now = audit.now_iso()
        conn.execute("INSERT INTO acceptances(id,risk_id,accepted_by,role,rationale,expires_at,status,created_at) VALUES(?,?,?,?,?,?,'Active',?)",
                     (aid, rid, actor.name, actor.role, body.rationale, body.expires_at, now))
        conn.execute("UPDATE risks SET status='Accepted', updated_at=? WHERE id=?", (now, rid))
        _log(conn, actor, "acceptance", aid, "create", {"risk_id": rid, "expires_at": body.expires_at, "rationale": body.rationale})
        return service.risk_detail(conn, rid)


# ------------------------------------------------------------------ controls

@app.get("/api/controls")
def controls():
    with session() as conn:
        return service.list_controls(conn)


def _control_validate(body: ControlIn) -> None:
    if body.control_type not in scoring.CONTROL_TYPES:
        raise HTTPException(400, "control_type must be Preventive, Detective or Corrective")
    if body.implementation_status not in scoring.IMPLEMENTATION_FACTOR:
        raise HTTPException(400, "Bad implementation_status")
    if body.evidence_tier > 1 and not body.evidence_source.strip():
        raise HTTPException(400, "Evidence tier 2 or 3 requires naming the evidence source (scanner, SIEM search, report)")


@app.post("/api/controls", status_code=201)
def create_control(body: ControlIn, actor: Actor = Depends(get_actor)):
    require(actor, "control:write")
    _control_validate(body)
    with session() as conn:
        cid = next_id(conn, "controls", "CTL")
        now = audit.now_iso()
        d = body.model_dump()
        d["framework_refs"] = json.dumps(d["framework_refs"])
        cols = list(d.keys()) + ["id", "created_at", "updated_at"]
        conn.execute(f"INSERT INTO controls({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [*d.values(), cid, now, now])
        _log(conn, actor, "control", cid, "create", {"name": body.name, "evidence_tier": body.evidence_tier})
        return service.get_control(conn, cid)


@app.put("/api/controls/{cid}")
def update_control(cid: str, body: ControlIn, actor: Actor = Depends(get_actor)):
    require(actor, "control:write")
    _control_validate(body)
    with session() as conn:
        before = service.get_control(conn, cid)
        if not before:
            raise HTTPException(404, "Control not found")
        d = body.model_dump()
        d["framework_refs"] = json.dumps(d["framework_refs"])
        d["updated_at"] = audit.now_iso()
        conn.execute(f"UPDATE controls SET {', '.join(f'{k}=?' for k in d)} WHERE id=?", [*d.values(), cid])
        after = service.get_control(conn, cid)
        _log(conn, actor, "control", cid, "update", audit.diff(before, after))
        service._SIM_CACHE.clear()
        return after


@app.delete("/api/controls/{cid}")
def delete_control(cid: str, actor: Actor = Depends(get_actor)):
    require(actor, "control:write")
    with session() as conn:
        before = service.get_control(conn, cid)
        if not before:
            raise HTTPException(404, "Control not found")
        conn.execute("DELETE FROM controls WHERE id=?", (cid,))
        _log(conn, actor, "control", cid, "delete", {"name": before["name"]})
        return {"deleted": cid}


# ------------------------------------------------------------------ treatments

@app.get("/api/treatments")
def treatments(risk_id: Optional[str] = None):
    with session() as conn:
        sql = "SELECT t.*, r.title AS risk_title FROM treatments t JOIN risks r ON r.id=t.risk_id"
        params: tuple = ()
        if risk_id:
            sql += " WHERE t.risk_id=?"; params = (risk_id,)
        return [dict(x) for x in conn.execute(sql + " ORDER BY t.due_date", params).fetchall()]


def _treatment_validate(body: TreatmentIn) -> None:
    if body.strategy not in service.STRATEGIES:
        raise HTTPException(400, "strategy must be Mitigate, Accept, Transfer or Avoid")
    if body.status not in service.TREATMENT_STATUSES:
        raise HTTPException(400, "Bad treatment status")


@app.post("/api/treatments", status_code=201)
def create_treatment(body: TreatmentIn, actor: Actor = Depends(get_actor)):
    require(actor, "treatment:write")
    _treatment_validate(body)
    with session() as conn:
        if not service.get_risk_row(conn, body.risk_id):
            raise HTTPException(404, "Risk not found")
        tid = next_id(conn, "treatments", "TRT")
        now = audit.now_iso()
        d = body.model_dump()
        d["completed_at"] = now if body.status == "Done" else None
        cols = list(d.keys()) + ["id", "created_at", "updated_at"]
        conn.execute(f"INSERT INTO treatments({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [*d.values(), tid, now, now])
        _log(conn, actor, "treatment", tid, "create", {"risk_id": body.risk_id, "title": body.title, "strategy": body.strategy, "due_date": body.due_date})
        return dict(conn.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone())


@app.put("/api/treatments/{tid}")
def update_treatment(tid: str, body: TreatmentIn, actor: Actor = Depends(get_actor)):
    require(actor, "treatment:write")
    _treatment_validate(body)
    with session() as conn:
        before = conn.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone()
        if not before:
            raise HTTPException(404, "Treatment not found")
        before = dict(before)
        d = body.model_dump()
        d["updated_at"] = audit.now_iso()
        if body.status == "Done":
            d["completed_at"] = before["completed_at"] or d["updated_at"]
            d["progress"] = 100
        else:
            d["completed_at"] = None
        conn.execute(f"UPDATE treatments SET {', '.join(f'{k}=?' for k in d)} WHERE id=?", [*d.values(), tid])
        after = dict(conn.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone())
        _log(conn, actor, "treatment", tid, "update", {"risk_id": body.risk_id, **audit.diff(before, after)})
        return after


@app.delete("/api/treatments/{tid}")
def delete_treatment(tid: str, actor: Actor = Depends(get_actor)):
    require(actor, "treatment:write")
    with session() as conn:
        before = conn.execute("SELECT * FROM treatments WHERE id=?", (tid,)).fetchone()
        if not before:
            raise HTTPException(404, "Treatment not found")
        conn.execute("DELETE FROM treatments WHERE id=?", (tid,))
        _log(conn, actor, "treatment", tid, "delete", {"risk_id": before["risk_id"], "title": before["title"]})
        return {"deleted": tid}


# ------------------------------------------------------------------ KRIs

@app.get("/api/kris")
def kris(risk_id: Optional[str] = None):
    with session() as conn:
        return service.list_kris(conn, risk_id)


@app.post("/api/kris", status_code=201)
def create_kri(body: KriIn, actor: Actor = Depends(get_actor)):
    require(actor, "kri:write")
    if body.direction not in ("above_is_bad", "below_is_bad"):
        raise HTTPException(400, "direction must be above_is_bad or below_is_bad")
    with session() as conn:
        if not service.get_risk_row(conn, body.risk_id):
            raise HTTPException(404, "Risk not found")
        kid = next_id(conn, "kris", "KRI")
        now = audit.now_iso()
        d = body.model_dump()
        conn.execute(f"INSERT INTO kris({','.join(d)},id,updated_at) VALUES({','.join('?' * len(d))},?,?)", [*d.values(), kid, now])
        if body.current_value is not None:
            conn.execute("INSERT INTO kri_readings(kri_id,ts,value) VALUES(?,?,?)", (kid, now, body.current_value))
        _log(conn, actor, "kri", kid, "create", {"risk_id": body.risk_id, "name": body.name, "warning": body.warning, "critical": body.critical})
        return service.list_kris(conn, body.risk_id)


@app.put("/api/kris/{kid}")
def update_kri(kid: str, body: KriIn, actor: Actor = Depends(get_actor)):
    require(actor, "kri:write")
    with session() as conn:
        before = conn.execute("SELECT * FROM kris WHERE id=?", (kid,)).fetchone()
        if not before:
            raise HTTPException(404, "KRI not found")
        before = dict(before)
        d = body.model_dump()
        d["updated_at"] = audit.now_iso()
        conn.execute(f"UPDATE kris SET {', '.join(f'{k}=?' for k in d)} WHERE id=?", [*d.values(), kid])
        after = dict(conn.execute("SELECT * FROM kris WHERE id=?", (kid,)).fetchone())
        _log(conn, actor, "kri", kid, "update", {"risk_id": body.risk_id, **audit.diff(before, after)})
        return service.list_kris(conn, body.risk_id)


@app.post("/api/kris/{kid}/readings", status_code=201)
def add_reading(kid: str, body: KriReadingIn, actor: Actor = Depends(get_actor)):
    require(actor, "kri:write")
    with session() as conn:
        k = conn.execute("SELECT * FROM kris WHERE id=?", (kid,)).fetchone()
        if not k:
            raise HTTPException(404, "KRI not found")
        ts = body.ts or audit.now_iso()
        conn.execute("INSERT INTO kri_readings(kri_id,ts,value) VALUES(?,?,?)", (kid, ts, body.value))
        conn.execute("UPDATE kris SET current_value=?, updated_at=? WHERE id=?", (body.value, ts, kid))
        status = service.kri_status({**dict(k), "current_value": body.value})
        _log(conn, actor, "kri", kid, "reading", {"risk_id": k["risk_id"], "value": body.value, "status": status})
        return service.list_kris(conn, k["risk_id"])


@app.delete("/api/kris/{kid}")
def delete_kri(kid: str, actor: Actor = Depends(get_actor)):
    require(actor, "kri:write")
    with session() as conn:
        k = conn.execute("SELECT * FROM kris WHERE id=?", (kid,)).fetchone()
        if not k:
            raise HTTPException(404, "KRI not found")
        conn.execute("DELETE FROM kris WHERE id=?", (kid,))
        _log(conn, actor, "kri", kid, "delete", {"risk_id": k["risk_id"], "name": k["name"]})
        return {"deleted": kid}


# ------------------------------------------------------------------ evidence

MAX_EVIDENCE_BYTES = 10 * 1024 * 1024


@app.post("/api/evidence", status_code=201)
async def upload_evidence(entity_type: str = Form(...), entity_id: str = Form(...), tier: int = Form(1), note: str = Form(""),
                          file: UploadFile = File(...), actor: Actor = Depends(get_actor)):
    require(actor, "evidence:write")
    if entity_type not in ("risk", "control", "treatment"):
        raise HTTPException(400, "entity_type must be risk, control or treatment")
    data = await file.read()
    if len(data) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, "Evidence files are limited to 10 MB")
    if not data:
        raise HTTPException(400, "Empty file")
    with session() as conn:
        table = {"risk": "risks", "control": "controls", "treatment": "treatments"}[entity_type]
        if not conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (entity_id,)).fetchone():
            raise HTTPException(404, f"{entity_type} {entity_id} not found")
        eid = next_id(conn, "evidence", "EVD")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", file.filename or "evidence.bin")[:120]
        stored = f"{eid}_{safe}"
        (EVIDENCE_DIR / stored).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        now = audit.now_iso()
        conn.execute("INSERT INTO evidence(id,entity_type,entity_id,filename,sha256,size,stored_name,tier,note,uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (eid, entity_type, entity_id, safe, digest, len(data), stored, max(1, min(3, tier)), note, actor.name, now))
        _log(conn, actor, "evidence", eid, "upload", {"risk_id": entity_id if entity_type == "risk" else None, "entity_type": entity_type,
                                                     "entity_id": entity_id, "filename": safe, "sha256": digest, "size": len(data)})
        return dict(conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone())


@app.get("/api/evidence")
def list_evidence(entity_type: Optional[str] = None, entity_id: Optional[str] = None):
    with session() as conn:
        sql, params = "SELECT * FROM evidence WHERE 1=1", []
        if entity_type:
            sql += " AND entity_type=?"; params.append(entity_type)
        if entity_id:
            sql += " AND entity_id=?"; params.append(entity_id)
        return [dict(x) for x in conn.execute(sql + " ORDER BY uploaded_at DESC", params).fetchall()]


@app.get("/api/evidence/{eid}/download")
def download_evidence(eid: str):
    with session() as conn:
        e = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not e:
        raise HTTPException(404, "Evidence not found")
    path = EVIDENCE_DIR / e["stored_name"]
    if not path.exists():
        raise HTTPException(410, "Evidence file missing on disk")
    return FileResponse(path, filename=e["filename"], media_type="application/octet-stream")


# ------------------------------------------------------------------ audit

@app.get("/api/audit")
def audit_log(entity_type: Optional[str] = None, entity_id: Optional[str] = None, limit: int = Query(default=200, le=2000)):
    with session() as conn:
        sql, params = "SELECT * FROM audit_log WHERE 1=1", []
        if entity_type:
            sql += " AND entity_type=?"; params.append(entity_type)
        if entity_id:
            sql += " AND entity_id=?"; params.append(entity_id)
        sql += " ORDER BY seq DESC LIMIT ?"; params.append(limit)
        return [service.audit_row(x) for x in conn.execute(sql, params).fetchall()]


@app.get("/api/audit/verify")
def audit_verify():
    with session() as conn:
        return audit.verify(conn)


# ------------------------------------------------------------------ dashboard & reports

@app.get("/api/dashboard")
def dashboard():
    with session() as conn:
        return service.dashboard(conn)


@app.get("/api/reports/board", response_class=HTMLResponse)
def board_report():
    with session() as conn:
        return board_report_html(conn)


@app.get("/api/export/csv")
def export_csv():
    with session() as conn:
        rows = service.export_rows(conn)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=service.EXPORT_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=risk-register.csv"})


@app.get("/api/export/json")
def export_json():
    with session() as conn:
        payload = {
            "exported_at": audit.now_iso(),
            "settings": {r["key"]: r["value"] for r in conn.execute("SELECT * FROM settings").fetchall() if not r["key"].startswith("control_key:")},
            "appetite": list(service.appetite_map(conn).values()),
            "risks": [service.risk_detail(conn, r["id"]) for r in conn.execute("SELECT id FROM risks ORDER BY id").fetchall()],
            "controls": service.list_controls(conn),
            "audit_verification": audit.verify(conn),
        }
    return JSONResponse(payload, headers={"Content-Disposition": "attachment; filename=risk-register.json"})


IMPORT_COLUMNS = ["title", "description", "business_impact", "category", "owner", "status", "asset", "threat_source", "vulnerability",
                  "inherent_likelihood", "inherent_impact", "tags", "review_frequency_days"]


@app.get("/api/import/template", response_class=PlainTextResponse)
def import_template():
    sample = ["Example: laptop with customer data lost", "A staff laptop without disk encryption is lost or stolen", "Customer data could be exposed",
              "Cyber Security", "IT Security", "Identified", "Staff laptops", "Opportunistic thief", "No full-disk encryption", "3", "3", "endpoint; privacy", "90"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(IMPORT_COLUMNS)
    w.writerow(sample)
    return PlainTextResponse(buf.getvalue(), headers={"Content-Disposition": "attachment; filename=risk-import-template.csv"})


@app.post("/api/import/csv")
async def import_csv(file: UploadFile = File(...), actor: Actor = Depends(get_actor)):
    """Bring an existing spreadsheet register across. Rows that fail validation are reported, not silently dropped."""
    require(actor, "import")
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    created, errors = [], []
    with session() as conn:
        for i, row in enumerate(reader, start=2):
            try:
                cat = (row.get("category") or "").strip()
                if cat not in RISK_CATEGORIES:
                    cat = _nearest_category(cat)
                body = RiskIn(
                    title=(row.get("title") or "").strip(), description=(row.get("description") or "").strip(),
                    business_impact=(row.get("business_impact") or "").strip(), category=cat, owner=(row.get("owner") or "").strip(),
                    status=(row.get("status") or "Identified").strip() or "Identified", asset=(row.get("asset") or "").strip(),
                    threat_source=(row.get("threat_source") or "").strip(), vulnerability=(row.get("vulnerability") or "").strip(),
                    inherent_likelihood=int(float(row.get("inherent_likelihood") or 3)), inherent_impact=int(float(row.get("inherent_impact") or 3)),
                    tags=[t.strip() for t in (row.get("tags") or "").split(";") if t.strip()],
                    review_frequency_days=int(float(row.get("review_frequency_days") or 90)),
                )
                _validate_risk(body)
                rid = next_id(conn, "risks", "RISK")
                now = audit.now_iso()
                vals = _risk_values(body)
                cols = list(vals.keys()) + ["id", "created_by", "created_at", "updated_at"]
                conn.execute(f"INSERT INTO risks({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [*vals.values(), rid, actor.name, now, now])
                _log(conn, actor, "risk", rid, "import", {"title": body.title, "source_row": i, "file": file.filename})
                created.append(rid)
            except Exception as exc:  # noqa: BLE001 - report every bad row
                errors.append({"row": i, "error": str(exc)[:300]})
    return {"created": created, "errors": errors}


def _nearest_category(text: str) -> str:
    t = text.lower()
    rules = [("ai", "AI / Model"), ("model", "AI / Model"), ("cloud", "Cloud & Infrastructure"), ("vendor", "Third Party"), ("third", "Third Party"),
             ("supplier", "Third Party"), ("privacy", "Data Privacy"), ("gdpr", "Data Privacy"), ("compliance", "Compliance & Legal"),
             ("legal", "Compliance & Legal"), ("regulat", "Compliance & Legal"), ("insider", "People & Insider"), ("people", "People & Insider"),
             ("hr", "People & Insider"), ("financ", "Financial"), ("fraud", "Financial"), ("operation", "Operational"), ("availab", "Operational")]
    for needle, cat in rules:
        if needle in t:
            return cat
    return "Cyber Security"


# ------------------------------------------------------------------ frontend

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
