"""Demo data for an AI-first cloud SaaS company ("Lumen Analytics").

Run `python run.py --reseed` to wipe and rebuild. Everything here goes through
the same code paths as the UI so the audit chain is real.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from . import audit
from .db import DB_PATH, init_db, next_id, session, set_setting
from .frameworks import RISK_CATEGORIES
from .scenarios import SCENARIOS, SEED_CONTROLS

USERS = [
    ("u-ceo", "Dana Whitfield", "Executive", "Chief Executive Officer"),
    ("u-ciso", "Priya Raman", "Risk Analyst", "Head of Security & GRC"),
    ("u-eng", "Marcus Chen", "Security Engineer", "Staff Security Engineer"),
    ("u-audit", "Elena Novak", "Auditor", "External Auditor (SOC 2)"),
]

APPETITE = {
    "Cyber Security": (9, 1_500_000, "We tolerate moderate cyber risk but will not accept any risk that could stop the product for more than 24 hours."),
    "AI / Model": (9, 1_000_000, "AI features must not expose one customer's data to another or take actions without a human approval path."),
    "Cloud & Infrastructure": (9, 1_000_000, "No customer data exposed to the public internet, ever."),
    "Third Party": (12, 1_500_000, "Vendors handling customer data must be tiered and assessed annually."),
    "Data Privacy": (6, 1_000_000, "Privacy regulation breaches are outside appetite regardless of financial size."),
    "Compliance & Legal": (6, 1_000_000, "We will not knowingly operate outside regulatory requirements."),
    "Operational": (12, 500_000, "Service degradation is tolerable; data loss is not."),
    "People & Insider": (9, 750_000, "Insider risk is managed through least privilege, not surveillance."),
    "Financial": (9, 750_000, "Fraud losses above $750k in a year trigger a board review."),
}

SEED_SCENARIOS = ["ransomware", "prompt_injection", "excessive_agency", "data_poisoning", "cloud_misconfig", "secrets_leak",
                  "supply_chain", "subprocessor_breach", "insider_exfil", "bec_phishing", "ddos_inference", "gdpr_ai_processing"]


def _days(n: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=n)).date().isoformat()


def _ts(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).replace(microsecond=0).isoformat()


def is_empty() -> bool:
    with session() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM risks").fetchone()["n"] == 0


def reset() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    for suffix in ("-wal", "-shm"):
        p = DB_PATH.with_name(DB_PATH.name + suffix)
        if p.exists():
            p.unlink()
    init_db()


def seed() -> None:
    init_db()
    with session() as conn:
        analyst = {"actor": "Priya Raman", "role": "Risk Analyst"}
        eng = {"actor": "Marcus Chen", "role": "Security Engineer"}

        for uid, name, role, title in USERS:
            conn.execute("INSERT OR REPLACE INTO users(id,name,role,title) VALUES(?,?,?,?)", (uid, name, role, title))
        set_setting(conn, "org_name", "Lumen Analytics")
        set_setting(conn, "currency", "USD")
        set_setting(conn, "appetite_statement",
                    "Lumen Analytics accepts the risks inherent in building AI products quickly, but not risks that expose customer data, "
                    "mislead customers through model behaviour, or threaten the SOC 2 attestation our enterprise revenue depends on.")
        for cat in RISK_CATEGORIES:
            s, ale, text = APPETITE[cat]
            conn.execute("INSERT OR REPLACE INTO appetite(category,max_residual_score,max_ale,statement) VALUES(?,?,?,?)", (cat, s, ale, text))
        audit.record(conn, **analyst, entity_type="settings", entity_id="global", action="seed", detail={"org": "Lumen Analytics"})

        # Controls
        key_to_id: dict[str, str] = {}
        for c in SEED_CONTROLS:
            cid = next_id(conn, "controls", "CTL")
            now = _ts(120)
            conn.execute(
                "INSERT INTO controls(id,name,description,control_type,implementation_status,effectiveness,evidence_tier,evidence_source,owner,last_tested_at,framework_refs,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, c["name"], c["description"], c["control_type"], c["implementation_status"], c["effectiveness"], c["evidence_tier"],
                 c["evidence_source"], c["owner"], _ts(45) if c["evidence_tier"] > 1 else None, __import__("json").dumps(c["framework_refs"]), now, now))
            key_to_id[c["key"]] = cid
            set_setting(conn, f"control_key:{cid}", c["key"])
            audit.record(conn, **eng, entity_type="control", entity_id=cid, action="create", detail={"name": c["name"], "evidence_tier": c["evidence_tier"]})

        # Risks
        status_plan = {"ransomware": "Treating", "prompt_injection": "Treating", "excessive_agency": "Assessed", "data_poisoning": "Identified",
                       "cloud_misconfig": "Monitoring", "secrets_leak": "Monitoring", "supply_chain": "Treating", "subprocessor_breach": "Assessed",
                       "insider_exfil": "Assessed", "bec_phishing": "Accepted", "ddos_inference": "Monitoring", "gdpr_ai_processing": "Treating"}
        review_plan = {"ransomware": 20, "prompt_injection": 10, "excessive_agency": 40, "data_poisoning": 130, "cloud_misconfig": 30,
                       "secrets_leak": 15, "supply_chain": 100, "subprocessor_breach": 95, "insider_exfil": 50, "bec_phishing": 25,
                       "ddos_inference": 60, "gdpr_ai_processing": 12}
        owners = {"Cyber Security": "Priya Raman", "AI / Model": "Marcus Chen", "Cloud & Infrastructure": "Marcus Chen", "Third Party": "Priya Raman",
                  "Data Privacy": "Priya Raman", "Operational": "Marcus Chen", "People & Insider": "Priya Raman", "Financial": "Dana Whitfield",
                  "Compliance & Legal": "Priya Raman"}
        risk_ids: dict[str, str] = {}
        for key in SEED_SCENARIOS:
            sc = next(s for s in SCENARIOS if s["key"] == key)
            rid = next_id(conn, "risks", "RISK")
            created = _ts(180)
            reviewed = _ts(review_plan[key])
            j = __import__("json")
            conn.execute(
                "INSERT INTO risks(id,title,description,business_impact,category,asset,threat_source,vulnerability,owner,status,inherent_likelihood,inherent_impact,"
                "lef_min,lef_likely,lef_max,lm_min,lm_likely,lm_max,attack_techniques,framework_refs,tags,scenario_key,review_frequency_days,last_reviewed_at,created_by,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, sc["title"], sc["description"], sc["business_impact"], sc["category"], sc["asset"], sc["threat_source"], sc["vulnerability"],
                 owners[sc["category"]], status_plan[key], sc["likelihood"], sc["impact"],
                 sc["fair"]["lef_min"], sc["fair"]["lef_likely"], sc["fair"]["lef_max"], sc["fair"]["lm_min"], sc["fair"]["lm_likely"], sc["fair"]["lm_max"],
                 j.dumps(sc["attack_techniques"]), j.dumps(sc["framework_refs"]), j.dumps(sc["tags"]), key, 90, reviewed, "Priya Raman", created, reviewed))
            for ck in sc["controls"]:
                conn.execute("INSERT OR IGNORE INTO risk_controls(risk_id,control_id) VALUES(?,?)", (rid, key_to_id[ck]))
            risk_ids[key] = rid
            audit.record(conn, **analyst, entity_type="risk", entity_id=rid, action="create",
                         detail={"title": sc["title"], "inherent": f"L{sc['likelihood']} x I{sc['impact']}", "controls": [key_to_id[c] for c in sc["controls"]]})
            audit.record(conn, **analyst, entity_type="risk", entity_id=rid, action="review", detail={"note": "Quarterly review"})

        # Treatments
        treatments = [
            ("ransomware", "Mitigate", "Move backups to isolated account with object lock and run restore test", "Marcus Chen", -12, "In Progress", 60, 18_000),
            ("ransomware", "Mitigate", "Network segmentation between production and corporate", "Marcus Chen", 45, "Planned", 0, 40_000),
            ("prompt_injection", "Mitigate", "Red-team the assistant with prompt-injection corpus; fix top findings", "Marcus Chen", 20, "In Progress", 35, 25_000),
            ("prompt_injection", "Mitigate", "Enforce JSON schema validation on all tool calls from the model", "Marcus Chen", -5, "In Progress", 80, 8_000),
            ("supply_chain", "Mitigate", "Sign and verify container images and model artifacts (Sigstore)", "Marcus Chen", 60, "Planned", 0, 15_000),
            ("gdpr_ai_processing", "Mitigate", "Complete DPIAs for remaining 3 AI systems", "Priya Raman", 30, "In Progress", 40, 12_000),
            ("gdpr_ai_processing", "Mitigate", "Propagate deletion requests to vector store", "Marcus Chen", -20, "Planned", 0, 10_000),
            ("cloud_misconfig", "Mitigate", "Block public ACLs at AWS Organizations level (SCP)", "Marcus Chen", -60, "Done", 100, 2_000),
            ("secrets_leak", "Mitigate", "Roll out gitleaks pre-commit to all repos", "Marcus Chen", -40, "Done", 100, 1_000),
            ("subprocessor_breach", "Transfer", "Require cyber insurance and 24h breach notification in all tier-1 vendor DPAs", "Priya Raman", 90, "Planned", 0, 5_000),
            ("excessive_agency", "Mitigate", "Introduce human approval step for agent actions touching billing", "Marcus Chen", 25, "In Progress", 50, 6_000),
            ("ddos_inference", "Mitigate", "Per-tenant token budgets on inference API", "Marcus Chen", -90, "Done", 100, 4_000),
        ]
        for key, strat, title, owner, due, status, prog, cost in treatments:
            tid = next_id(conn, "treatments", "TRT")
            now = _ts(90)
            conn.execute(
                "INSERT INTO treatments(id,risk_id,strategy,title,owner,due_date,status,progress,cost,completed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (tid, risk_ids[key], strat, title, owner, _days(due), status, prog, cost, _ts(abs(due)) if status == "Done" else None, now, now))
            audit.record(conn, **analyst, entity_type="treatment", entity_id=tid, action="create", detail={"risk_id": risk_ids[key], "title": title, "strategy": strat, "due_date": _days(due)})

        # KRIs
        kris = [
            ("ransomware", "Endpoints without EDR agent", "%", "above_is_bad", 2, 5, [4.1, 3.2, 2.6, 1.8, 1.1], "Falcon coverage report"),
            ("ransomware", "Days since last successful restore test", "days", "above_is_bad", 90, 180, [60, 90, 120, 150, 184], "Backup runbook"),
            ("prompt_injection", "Guardrail bypasses detected per week", "count", "above_is_bad", 5, 15, [2, 4, 7, 6, 9], "Splunk llm_jailbreak"),
            ("cloud_misconfig", "Public-exposure findings open > 24h", "count", "above_is_bad", 1, 3, [3, 2, 1, 0, 0], "Wiz"),
            ("secrets_leak", "Secrets detected in commits per month", "count", "above_is_bad", 3, 8, [9, 6, 4, 2, 1], "gitleaks CI"),
            ("bec_phishing", "Phishing simulation click rate", "%", "above_is_bad", 8, 15, [14, 12, 10, 9, 9.5], "KnowBe4"),
            ("ddos_inference", "Inference API p99 latency during peak", "ms", "above_is_bad", 1500, 3000, [900, 1100, 1300, 1200, 1250], "Datadog"),
            ("supply_chain", "Critical CVEs in production dependencies", "count", "above_is_bad", 2, 5, [6, 5, 4, 3, 3], "Snyk"),
            ("gdpr_ai_processing", "AI systems with completed DPIA", "%", "below_is_bad", 80, 50, [20, 20, 40, 40, 40], "Privacy register"),
        ]
        for key, name, unit, direction, warn, crit, series, source in kris:
            kid = next_id(conn, "kris", "KRI")
            conn.execute("INSERT INTO kris(id,risk_id,name,unit,direction,warning,critical,current_value,source,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (kid, risk_ids[key], name, unit, direction, warn, crit, series[-1], source, _ts(2)))
            for i, v in enumerate(series):
                conn.execute("INSERT INTO kri_readings(kri_id,ts,value) VALUES(?,?,?)", (kid, _ts((len(series) - 1 - i) * 30 + 2), v))
            audit.record(conn, **eng, entity_type="kri", entity_id=kid, action="create", detail={"risk_id": risk_ids[key], "name": name})

        # Acceptance (BEC risk accepted by CEO with expiry; one expired acceptance as a trap for the dashboard)
        aid = next_id(conn, "acceptances", "ACC")
        conn.execute("INSERT INTO acceptances(id,risk_id,accepted_by,role,rationale,expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
                     (aid, risk_ids["bec_phishing"], "Dana Whitfield", "Executive",
                      "Finance now verifies every bank-detail change by phone. Residual exposure is below the $250k appetite and the cost of further tooling outweighs the benefit this year.",
                      _days(150), "Active", _ts(30)))
        audit.record(conn, actor="Dana Whitfield", role="Executive", entity_type="acceptance", entity_id=aid, action="create",
                     detail={"risk_id": risk_ids["bec_phishing"], "expires_at": _days(150)})
        aid2 = next_id(conn, "acceptances", "ACC")
        conn.execute("INSERT INTO acceptances(id,risk_id,accepted_by,role,rationale,expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
                     (aid2, risk_ids["insider_exfil"], "Dana Whitfield", "Executive",
                      "Accepted pending DLP rollout budget approval.", _days(-10), "Active", _ts(200)))
        audit.record(conn, actor="Dana Whitfield", role="Executive", entity_type="acceptance", entity_id=aid2, action="create",
                     detail={"risk_id": risk_ids["insider_exfil"], "expires_at": _days(-10)})


if __name__ == "__main__":
    reset()
    seed()
    print(f"Seeded {DB_PATH}")
