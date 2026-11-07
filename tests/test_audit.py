"""Hash-chain integrity tests for the audit log."""
import sqlite3

from backend import audit
from backend.db import SCHEMA


def _mem():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def test_chain_verifies_after_many_records():
    conn = _mem()
    for i in range(5):
        audit.record(conn, actor="a", role="Risk Analyst", entity_type="risk", entity_id=f"RISK-{i}", action="create", detail={"i": i})
    v = audit.verify(conn)
    assert v["ok"] and v["entries"] == 5 and len(v["head"]) == 64


def test_first_entry_links_to_genesis():
    conn = _mem()
    audit.record(conn, actor="a", role="r", entity_type="t", entity_id="x", action="a")
    row = conn.execute("SELECT * FROM audit_log").fetchone()
    assert row["prev_hash"] == audit.GENESIS


def test_tampering_breaks_chain_at_that_entry():
    conn = _mem()
    for i in range(4):
        audit.record(conn, actor="a", role="r", entity_type="t", entity_id=str(i), action="a", detail={"v": i})
    conn.execute("UPDATE audit_log SET detail='{\"v\": 99}' WHERE seq=2")
    v = audit.verify(conn)
    assert not v["ok"]
    assert v["broken_at_seq"] == 2


def test_deleting_an_entry_breaks_chain():
    conn = _mem()
    for i in range(4):
        audit.record(conn, actor="a", role="r", entity_type="t", entity_id=str(i), action="a")
    conn.execute("DELETE FROM audit_log WHERE seq=3")
    v = audit.verify(conn)
    assert not v["ok"] and v["broken_at_seq"] == 4


def test_diff_reports_only_changed_fields():
    d = audit.diff({"a": 1, "b": 2, "updated_at": "x"}, {"a": 1, "b": 3, "updated_at": "y"})
    assert d == {"b": {"from": 2, "to": 3}}
