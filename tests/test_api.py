"""End-to-end API tests against the seeded demo dataset."""
import hashlib
import io

import pytest
from datetime import date, timedelta

ANALYST = {"X-Actor": "u-ciso"}
ENGINEER = {"X-Actor": "u-eng"}
EXEC = {"X-Actor": "u-ceo"}
AUDITOR = {"X-Actor": "u-audit"}


def _risk_payload(**over):
    body = {"title": "Test risk created by pytest", "description": "d", "business_impact": "b", "category": "Cyber Security",
            "owner": "QA", "inherent_likelihood": 4, "inherent_impact": 4}
    body.update(over)
    return body


def test_meta(client):
    m = client.get("/api/meta").json()
    assert len(m["likelihood_scale"]) == 5 and len(m["impact_scale"]) == 5
    assert [t["tier"] for t in m["evidence_tiers"]] == [1, 2, 3]
    assert {f["key"] for f in m["frameworks"]} >= {"NIST_CSF_2", "ISO_27001_2022", "SOC2_TSC", "NIST_AI_RMF", "OWASP_LLM_2025"}
    assert len(m["scenarios"]) >= 10
    assert {u["id"] for u in m["users"]} == {"u-ceo", "u-ciso", "u-eng", "u-audit"}
    assert m["settings"]["org_name"] == "Lumen Analytics"


def test_whoami_defaults_and_roles(client):
    assert client.get("/api/whoami").json()["role"] == "Risk Analyst"
    w = client.get("/api/whoami", headers=AUDITOR).json()
    assert w["role"] == "Auditor" and w["permissions"] == []


def test_risks_sorted_by_residual_desc(client):
    risks = client.get("/api/risks").json()
    assert len(risks) >= 12
    scores = [r["residual_score"] for r in risks]
    assert scores == sorted(scores, reverse=True)
    r = risks[0]
    for k in ("inherent_band", "residual_band", "appetite", "fair", "next_review_at", "treatments_summary", "suggested_residual"):
        assert k in r
    assert r["fair"]["residual"]["ale_p90"] >= r["fair"]["residual"]["ale_median"]


def test_risk_filters(client):
    assert all(r["category"] == "AI / Model" for r in client.get("/api/risks", params={"category": "AI / Model"}).json())
    assert all(r["residual_band"] == "Medium" for r in client.get("/api/risks", params={"band": "Medium"}).json())
    assert any("Ransomware" in r["title"] for r in client.get("/api/risks", params={"q": "ransom"}).json())


def test_create_risk_rbac(client):
    r = client.post("/api/risks", json=_risk_payload(), headers=ENGINEER)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"].startswith("RISK-") and body["inherent_score"] == 16 and body["residual_score"] == 16
    assert body["history"][0]["action"] == "create"

    denied = client.post("/api/risks", json=_risk_payload(), headers=AUDITOR)
    assert denied.status_code == 403


def test_create_risk_validation(client):
    bad_cat = client.post("/api/risks", json=_risk_payload(category="Nope"), headers=ANALYST)
    assert bad_cat.status_code == 400
    partial = client.post("/api/risks", json=_risk_payload(lef_min=1, lef_likely=2), headers=ANALYST)
    assert partial.status_code == 400 and "six FAIR" in partial.json()["detail"]
    unordered = client.post("/api/risks", json=_risk_payload(lef_min=3, lef_likely=2, lef_max=4, lm_min=1, lm_likely=2, lm_max=3), headers=ANALYST)
    assert unordered.status_code == 400
    bad_tech = client.post("/api/risks", json=_risk_payload(attack_techniques=["T9999"]), headers=ANALYST)
    assert bad_tech.status_code == 400
    out_of_range = client.post("/api/risks", json=_risk_payload(inherent_likelihood=6), headers=ANALYST)
    assert out_of_range.status_code == 422


def test_create_from_scenario_links_controls(client):
    r = client.post("/api/risks/from-scenario/ransomware", headers=ANALYST)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["scenario_key"] == "ransomware"
    assert body["has_fair"] and body["control_count"] == 5
    assert body["residual_score"] < body["inherent_score"]
    assert body["attack_techniques"] == ["T1566", "T1078", "T1486"]
    assert client.post("/api/risks/from-scenario/does-not-exist", headers=ANALYST).status_code == 404


def test_update_with_controls_changes_residual(client):
    created = client.post("/api/risks", json=_risk_payload(inherent_likelihood=5, inherent_impact=5), headers=ANALYST).json()
    rid = created["id"]
    assert created["residual_score"] == 25
    controls = client.get("/api/controls").json()
    strong = [c["id"] for c in controls if c["control_type"] == "Preventive" and c["implementation_status"] == "Implemented"][:2]
    upd = client.put(f"/api/risks/{rid}", json=_risk_payload(inherent_likelihood=5, inherent_impact=5, control_ids=strong), headers=ANALYST)
    assert upd.status_code == 200, upd.text
    body = upd.json()
    assert body["control_count"] == 2
    assert body["residual_likelihood"] < 5 and body["residual_impact"] == 5  # preventive controls move likelihood only
    assert body["suggested_residual"]["likelihood_reduction"] > 0
    # Manual override wins when flagged
    ov = client.put(f"/api/risks/{rid}", json=_risk_payload(inherent_likelihood=5, inherent_impact=5, control_ids=strong,
                                                           residual_override=True, residual_likelihood=4, residual_impact=4), headers=ANALYST).json()
    assert (ov["residual_likelihood"], ov["residual_impact"]) == (4, 4)
    # History records the control change
    actions = [h["action"] for h in ov["history"]]
    assert "update" in actions and "create" in actions


def test_link_and_unlink_control(client):
    rid = client.post("/api/risks", json=_risk_payload(), headers=ANALYST).json()["id"]
    cid = client.get("/api/controls").json()[0]["id"]
    assert client.post(f"/api/risks/{rid}/controls/{cid}", headers=ENGINEER).json()["control_count"] == 1
    assert client.delete(f"/api/risks/{rid}/controls/{cid}", headers=ENGINEER).json()["control_count"] == 0
    assert client.post(f"/api/risks/{rid}/controls/CTL-9999", headers=ENGINEER).status_code == 404


def test_review_updates_cadence(client):
    rid = client.post("/api/risks", json=_risk_payload(review_frequency_days=30), headers=ANALYST).json()["id"]
    r = client.post(f"/api/risks/{rid}/review", json={"note": "checked"}, headers=ANALYST).json()
    assert r["last_reviewed_at"] and not r["review_overdue"]
    reviewed_on = date.fromisoformat(r["last_reviewed_at"][:10])  # server stamps in UTC; do not compare with local today()
    assert r["next_review_at"] == (reviewed_on + timedelta(days=30)).isoformat()


def test_accept_risk_rules(client):
    rid = client.post("/api/risks", json=_risk_payload(), headers=ANALYST).json()["id"]
    future = (date.today() + timedelta(days=90)).isoformat()
    past = (date.today() - timedelta(days=1)).isoformat()
    too_far = (date.today() + timedelta(days=400)).isoformat()
    rationale = "Residual exposure is within appetite and mitigation cost exceeds benefit."
    assert client.post(f"/api/risks/{rid}/accept", json={"rationale": rationale, "expires_at": past}, headers=EXEC).status_code == 400
    assert client.post(f"/api/risks/{rid}/accept", json={"rationale": rationale, "expires_at": too_far}, headers=EXEC).status_code == 400
    assert client.post(f"/api/risks/{rid}/accept", json={"rationale": rationale, "expires_at": future}, headers=ENGINEER).status_code == 403
    ok = client.post(f"/api/risks/{rid}/accept", json={"rationale": rationale, "expires_at": future}, headers=EXEC)
    assert ok.status_code == 201, ok.text
    body = ok.json()
    assert body["status"] == "Accepted"
    assert body["active_acceptance"]["accepted_by"] == "Dana Whitfield" and body["active_acceptance"]["role"] == "Executive"
    # A second acceptance supersedes the first
    client.post(f"/api/risks/{rid}/accept", json={"rationale": rationale, "expires_at": future}, headers=ANALYST)
    statuses = [a["status"] for a in client.get(f"/api/risks/{rid}").json()["acceptances"]]
    assert statuses.count("Active") == 1 and "Superseded" in statuses


def test_treatment_lifecycle(client):
    rid = client.post("/api/risks", json=_risk_payload(), headers=ANALYST).json()["id"]
    due = (date.today() - timedelta(days=3)).isoformat()
    t = client.post("/api/treatments", json={"risk_id": rid, "strategy": "Mitigate", "title": "Patch the thing", "owner": "QA", "due_date": due}, headers=ENGINEER)
    assert t.status_code == 201, t.text
    tid = t.json()["id"]
    summary = client.get(f"/api/risks/{rid}").json()["treatments_summary"]
    assert summary == {"total": 1, "open": 1, "overdue": 1, "avg_progress": 0}
    done = client.put(f"/api/treatments/{tid}", json={"risk_id": rid, "strategy": "Mitigate", "title": "Patch the thing", "owner": "QA",
                                                     "due_date": due, "status": "Done", "progress": 10}, headers=ENGINEER).json()
    assert done["status"] == "Done" and done["progress"] == 100 and done["completed_at"]
    assert client.get(f"/api/risks/{rid}").json()["treatments_summary"]["overdue"] == 0
    assert client.post("/api/treatments", json={"risk_id": rid, "strategy": "Ignore", "title": "nope"}, headers=ENGINEER).status_code == 400
    assert client.delete(f"/api/treatments/{tid}", headers=ENGINEER).json() == {"deleted": tid}


def test_kri_and_readings(client):
    rid = client.post("/api/risks", json=_risk_payload(), headers=ANALYST).json()["id"]
    k = client.post("/api/kris", json={"risk_id": rid, "name": "Open criticals", "unit": "count", "direction": "above_is_bad",
                                       "warning": 3, "critical": 6, "current_value": 1}, headers=ENGINEER)
    assert k.status_code == 201, k.text
    kri = k.json()[0]
    assert kri["status"] == "OK" and len(kri["readings"]) == 1
    kid = kri["id"]
    after = client.post(f"/api/kris/{kid}/readings", json={"value": 7}, headers=ENGINEER).json()[0]
    assert after["status"] == "Critical" and after["current_value"] == 7 and len(after["readings"]) == 2
    assert client.get(f"/api/risks/{rid}").json()["kri_status"] == "Critical"
    assert client.post("/api/kris", json={"risk_id": rid, "name": "x", "direction": "sideways", "warning": 1, "critical": 2}, headers=ENGINEER).status_code == 400
    assert client.post(f"/api/kris/{kid}/readings", json={"value": 1}, headers=AUDITOR).status_code == 403


def test_evidence_upload_and_download(client):
    rid = client.get("/api/risks").json()[0]["id"]
    content = b"scanner output: 0 public buckets\n"
    r = client.post("/api/evidence", data={"entity_type": "risk", "entity_id": rid, "tier": "2", "note": "Wiz export"},
                    files={"file": ("wiz-export.txt", io.BytesIO(content), "text/plain")}, headers=ENGINEER)
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["sha256"] == hashlib.sha256(content).hexdigest() and ev["size"] == len(content) and ev["tier"] == 2
    dl = client.get(f"/api/evidence/{ev['id']}/download")
    assert dl.status_code == 200 and dl.content == content
    assert any(e["id"] == ev["id"] for e in client.get(f"/api/risks/{rid}").json()["evidence"])
    assert client.post("/api/evidence", data={"entity_type": "risk", "entity_id": rid},
                       files={"file": ("x.txt", io.BytesIO(b""), "text/plain")}, headers=ENGINEER).status_code == 400
    assert client.post("/api/evidence", data={"entity_type": "risk", "entity_id": "RISK-9999"},
                       files={"file": ("x.txt", io.BytesIO(b"a"), "text/plain")}, headers=ENGINEER).status_code == 404
    assert client.post("/api/evidence", data={"entity_type": "risk", "entity_id": rid},
                       files={"file": ("x.txt", io.BytesIO(b"a"), "text/plain")}, headers=AUDITOR).status_code == 403


def test_controls_crud_and_evidence_rule(client):
    c = client.post("/api/controls", json={"name": "Test control", "control_type": "Preventive", "implementation_status": "Implemented",
                                           "effectiveness": 70, "evidence_tier": 3}, headers=ENGINEER)
    assert c.status_code == 400 and "evidence source" in c.json()["detail"]
    c = client.post("/api/controls", json={"name": "Test control", "control_type": "Preventive", "implementation_status": "Implemented",
                                           "effectiveness": 70, "evidence_tier": 3, "evidence_source": "Splunk search"}, headers=ENGINEER)
    assert c.status_code == 201, c.text
    cid = c.json()["id"]
    upd = client.put(f"/api/controls/{cid}", json={"name": "Test control", "control_type": "Detective", "implementation_status": "Partial",
                                                   "effectiveness": 70, "evidence_tier": 1}, headers=ENGINEER).json()
    assert upd["control_type"] == "Detective"
    assert client.delete(f"/api/controls/{cid}", headers=ENGINEER).json() == {"deleted": cid}
    assert client.get("/api/controls").json()[0]["credit"] > 0


def test_audit_log_and_verify(client):
    v = client.get("/api/audit/verify").json()
    assert v["ok"] and v["entries"] > 20
    log = client.get("/api/audit", params={"entity_type": "risk", "limit": 5}).json()
    assert len(log) == 5 and all(e["entity_type"] == "risk" for e in log)
    assert isinstance(log[0]["detail"], dict)


def test_dashboard_shape(client):
    d = client.get("/api/dashboard").json()
    assert d["headlines"] and all({"tone", "text"} <= set(h) for h in d["headlines"])
    assert len(d["heatmap"]["residual"]) == 5 and all(len(row) == 5 for row in d["heatmap"]["residual"])
    assert d["portfolio"]["risks_quantified"] >= 12
    assert d["portfolio"]["residual"]["ale_mean"] < d["portfolio"]["inherent"]["ale_mean"]
    assert len(d["portfolio"]["residual"]["exceedance_curve"]) == 21
    assert set(d["counts"]["bands"]) == {"Low", "Medium", "High", "Critical"}
    assert d["counts"]["evidence_tiers"] == {"1": 7, "2": 9, "3": 4} or sum(d["counts"]["evidence_tiers"].values()) == d["counts"]["controls"]
    assert d["top_risks"] and "ale_p90" in d["top_risks"][0]


def test_export_csv_and_json(client):
    csv_resp = client.get("/api/export/csv")
    assert csv_resp.status_code == 200
    header = csv_resp.text.splitlines()[0].split(",")
    assert header[:4] == ["id", "title", "category", "owner"] and "residual_band" in header and "ale_p90" in header
    j = client.get("/api/export/json").json()
    assert j["audit_verification"]["ok"] and len(j["risks"]) >= 12 and "control_key:CTL-0001" not in j["settings"]


def test_import_csv_from_template(client):
    template = client.get("/api/import/template").text
    assert template.splitlines()[0].startswith("title,description")
    r = client.post("/api/import/csv", files={"file": ("legacy.csv", io.BytesIO(template.encode()), "text/csv")}, headers=ANALYST)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["created"]) == 1 and body["errors"] == []
    imported = client.get(f"/api/risks/{body['created'][0]}").json()
    assert imported["title"].startswith("Example") and imported["tags"] == ["endpoint", "privacy"]
    # Bad rows are reported, not dropped silently
    bad = "title,category,inherent_likelihood,inherent_impact\nok row,Vendor stuff,3,3\n,Cyber Security,3,3\n"
    r = client.post("/api/import/csv", files={"file": ("bad.csv", io.BytesIO(bad.encode()), "text/csv")}, headers=ANALYST).json()
    assert len(r["created"]) == 1 and len(r["errors"]) == 1 and r["errors"][0]["row"] == 3
    assert client.get(f"/api/risks/{r['created'][0]}").json()["category"] == "Third Party"
    assert client.post("/api/import/csv", files={"file": ("x.csv", io.BytesIO(b"title\n"), "text/csv")}, headers=ENGINEER).status_code == 403


def test_board_report_html(client):
    r = client.get("/api/reports/board")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "Lumen Analytics" in r.text and "Residual heat map" in r.text and "Open risks" in r.text


def test_board_report_includes_audit_integrity(client):
    r = client.get("/api/reports/board")
    assert "Audit chain intact" in r.text


def test_simulate_and_translate_helpers(client):
    s = client.post("/api/simulate", json={"lef_min": 0.1, "lef_likely": 0.5, "lef_max": 1, "lm_min": 1e4, "lm_likely": 1e5, "lm_max": 1e6,
                                           "likelihood_reduction": 0.5, "impact_reduction": 0.5}).json()
    assert s["residual"]["ale_mean"] < s["inherent"]["ale_mean"]
    assert s["suggested_likelihood"] == 3 and s["suggested_impact"] == 3
    t = client.post("/api/translate", json={"loss_dollars": 2_000_000, "events_per_year": 0.02}).json()
    assert t["impact"]["label"] == "Major" and t["likelihood"]["label"] == "Rare"
    d = client.get("/api/fair-defaults", params={"likelihood": 3, "impact": 4}).json()
    assert d["lef_min"] <= d["lef_likely"] <= d["lef_max"]


def test_settings_and_appetite_updates(client):
    assert client.put("/api/settings", json={"org_name": "X"}, headers=ENGINEER).status_code == 403
    s = client.put("/api/settings", json={"org_name": "Lumen Analytics"}, headers=ANALYST).json()
    assert s["org_name"] == "Lumen Analytics"
    a = client.put("/api/appetite", json=[{"category": "Operational", "max_residual_score": 15, "max_ale": 1e6, "statement": "relaxed"}], headers=ANALYST).json()
    assert next(x for x in a if x["category"] == "Operational")["max_residual_score"] == 15


def test_delete_risk_requires_analyst(client):
    rid = client.post("/api/risks", json=_risk_payload(), headers=ANALYST).json()["id"]
    assert client.delete(f"/api/risks/{rid}", headers=ENGINEER).status_code == 403
    assert client.delete(f"/api/risks/{rid}", headers=ANALYST).json() == {"deleted": rid}
    assert client.get(f"/api/risks/{rid}").status_code == 404
    assert client.get("/api/audit/verify").json()["ok"]
