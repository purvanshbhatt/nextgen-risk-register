"""Hash-chained, append-only audit log.

Each entry's hash covers the previous entry's hash, so any edit or deletion in
the middle of the log breaks verification from that point on. Think of it as a
lightweight blockchain without the consensus theatre.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _digest(prev_hash: str, ts: str, actor: str, role: str, entity_type: str, entity_id: str, action: str, detail: str) -> str:
    payload = "|".join([prev_hash, ts, actor, role, entity_type, entity_id, action, detail])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record(conn: sqlite3.Connection, *, actor: str, role: str, entity_type: str, entity_id: str, action: str, detail: dict | None = None) -> dict:
    last = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev_hash = last["hash"] if last else GENESIS
    ts = now_iso()
    detail_json = json.dumps(detail or {}, sort_keys=True, default=str)
    h = _digest(prev_hash, ts, actor, role, entity_type, entity_id, action, detail_json)
    conn.execute(
        "INSERT INTO audit_log(ts,actor,role,entity_type,entity_id,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
        (ts, actor, role, entity_type, entity_id, action, detail_json, prev_hash, h),
    )
    return {"ts": ts, "actor": actor, "action": action, "hash": h}


def verify(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
    prev = GENESIS
    for r in rows:
        expected = _digest(prev, r["ts"], r["actor"], r["role"], r["entity_type"], r["entity_id"], r["action"], r["detail"])
        if r["prev_hash"] != prev or r["hash"] != expected:
            return {"ok": False, "entries": len(rows), "broken_at_seq": r["seq"], "message": f"Chain broken at entry {r['seq']}: record was altered or removed"}
        prev = r["hash"]
    return {"ok": True, "entries": len(rows), "head": prev, "message": "Audit chain intact"}


def diff(before: dict | None, after: dict | None, ignore: tuple[str, ...] = ("updated_at",)) -> dict:
    """Field-level diff so the audit log shows what changed, not a JSON blob."""
    before = before or {}
    after = after or {}
    out = {}
    for k in sorted(set(before) | set(after)):
        if k in ignore:
            continue
        if before.get(k) != after.get(k):
            out[k] = {"from": before.get(k), "to": after.get(k)}
    return out
