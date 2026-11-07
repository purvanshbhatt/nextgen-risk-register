# Gaps in Typical Risk Registers, and What This Project Does About Them

Most organisations run risk on a spreadsheet. Larger ones buy a GRC platform and end up with a prettier spreadsheet. This document lists the concrete failures seen in both, why each one matters, how the NextGen Risk Register addresses it, and, honestly, what it still does not do.

---

### 1. Residual risk is typed, not derived

**Gap.** The "residual" column is a number someone chose. Nothing links it to the controls that supposedly reduce the risk, so adding or removing a control changes nothing and the column drifts into fiction.

**Why it matters.** Residual risk is the number the board acts on. If it is unsupported, every downstream decision (appetite, acceptance, budget) is unsupported.

**Here.** Residual likelihood and impact are computed from the linked controls' credit (effectiveness × implementation × evidence tier), with overlap-aware stacking and damping. Unlink a control and the residual moves. A manual override exists but is flagged and audited.

**Still missing.** Effectiveness itself is a human estimate. There is no control-testing workflow that updates it automatically.

---

### 2. "We have a control" and "the control works" are scored the same

**Gap.** A policy document and a SIEM detection rule both appear as a tick in the controls column.

**Why it matters.** Auditors (SOC 2, ISO 27001) credit evidence of operation, not assertions. A register that credits assertions overstates posture precisely where it is weakest.

**Here.** Three evidence tiers (Self-Declared 50 %, Scanner-Observed 80 %, SIEM-Verified 100 %) discount control credit. Tiers above 1 require a named evidence source. The dashboard and board report show the tier mix.

**Still missing.** Tiers are declared by a human. Nothing ingests scanner or SIEM data to set or revoke a tier automatically.

---

### 3. No financial view

**Gap.** A 5×5 heat map cannot answer "how much should we spend on this" or "is $200k of insurance worth it".

**Why it matters.** Budget decisions are made in money. A register that cannot express risk in money is excluded from the conversation where risk is actually traded off.

**Here.** Any risk can carry FAIR-style frequency and magnitude ranges. A seeded Monte Carlo produces mean, median, P90, P95 annual loss and a loss-exceedance curve; the dashboard aggregates per-simulation across the portfolio. The textbook ARO × SLE figure is shown alongside for people who expect it.

**Still missing.** No secondary-loss modelling, no decomposition of frequency into threat-event frequency and vulnerability, no cost-benefit comparison of treatment options.

---

### 4. Two numbers that disagree

**Gap.** Where a quantitative figure exists at all, it lives in a separate workbook and contradicts the matrix.

**Here.** Qualitative and quantitative views are driven by the same control credits: the residual simulation scales frequency and magnitude by the same factors that move the matrix. The impact translator converts dollars and frequencies into scale levels so the wizard never lets the two drift at entry time.

---

### 5. The business cannot use it

**Gap.** Fields like "threat source", "vulnerability", "CVSS" and "control objective" are meaningless to the people who own most risks. They either guess or stop contributing.

**Why it matters.** Risk ownership that does not sit with the business is theatre. If only the security team edits the register, it is a security to-do list.

**Here.** A persona switcher. The Business persona gets a four-screen wizard in plain English with word cards ("Coin-flip odds of happening within a year"), scenario templates with business-language impact statements, and no technical fields. The Security Engineer persona sees ATT&CK / ATLAS techniques, CVSS, framework citations and evidence detail on the same risk.

**Still missing.** No per-owner notifications or sign-off workflow for the business owner's quarterly attestation.

---

### 6. No risk appetite, or an appetite nobody checks

**Gap.** The board signs an appetite statement; the register has no field for it.

**Here.** Appetite is set per category as a maximum residual score and a maximum P90 annual loss. Every risk is checked against both and the dashboard's first headline is the number of risks outside appetite.

**Still missing.** Appetite is per category, not per business unit or product line.

---

### 7. Treatments with no deadline

**Gap.** "Mitigation: implement MFA" sits in a cell for three years.

**Here.** Treatments have strategy, owner, due date, status, progress and cost. Overdue actions are counted on the risk, the dashboard and the board report. Marking Done stamps a completion timestamp.

**Still missing.** No integration with Jira / ServiceNow, so engineers must update the register separately.

---

### 8. Nothing tells you when a risk is getting worse

**Gap.** The register is a point-in-time assessment. Between reviews it is blind.

**Here.** Key Risk Indicators with warning and critical thresholds, direction, source and reading history. KRI status rolls up to the risk and the dashboard.

**Still missing.** Readings are posted through the API or UI; there is no scheduled collector or SIEM webhook yet.

---

### 9. Risk acceptance as a permanent exit

**Gap.** "Accepted" is a status a risk enters and never leaves. Who accepted it, on what basis and until when is lost.

**Here.** Acceptance requires an authorised role, a rationale and an expiry no more than 12 months away. Expired acceptances are flagged on the dashboard until renewed or replaced. Previous acceptances are kept as Superseded.

---

### 10. No audit trail, or one that can be edited

**Gap.** Spreadsheet version history is coarse and editable; GRC-tool audit logs are often plain tables an admin can clean up.

**Here.** Every mutation appends a hash-chained entry (SHA-256 over the previous hash and the entry). A verify endpoint recomputes the chain; editing or deleting any row is detected and the first bad entry is named. The board report prints the chain head.

**Still missing.** The chain protects integrity, not availability: an attacker with file access could still delete the whole database. External anchoring (publishing the head hash elsewhere) is not implemented.

---

### 11. Stale scores presented as current

**Gap.** A risk assessed in 2023 looks identical to one assessed last week.

**Here.** Each risk has a review frequency; overdue reviews are shown on the risk, the list, the dashboard and in a headline ("scores may be stale").

---

### 12. Everyone can edit everything

**Gap.** Shared spreadsheets have no roles. GRC tools have roles but they are rarely configured.

**Here.** Four roles with explicit permissions enforced server-side. Auditors cannot change anything; executives can accept but not edit; only analysts can delete, import or change appetite. Denied calls are logged.

**Still missing.** Identity is a header. Real authentication (SSO) is on the roadmap.

---

### 13. Starting from a blank page

**Gap.** New registers start empty and inconsistently worded; AI-specific risks are usually absent entirely.

**Here.** A scenario library of fourteen risks for an AI and cloud SaaS company, each with a plain-English impact statement, FAIR defaults, ATT&CK / ATLAS techniques, OWASP LLM Top 10, NIST AI RMF, NIST CSF 2.0, ISO 27001:2022, SOC 2, CIS v8 and GDPR references, and suggested controls. One click creates the risk with controls linked.

**Still missing.** Libraries for financial services (PCI DSS, SOX, FFIEC) and healthcare (HIPAA, TPRM) are not included.

---

### 14. Migration is a rewrite

**Gap.** Moving off the spreadsheet means re-keying.

**Here.** CSV import with a downloadable template, tolerant category matching, and per-row error reporting. CSV and JSON export of the full enriched register.

---

### 15. Reports are rebuilt by hand before every board meeting

**Gap.** Someone spends a day turning the spreadsheet into slides.

**Here.** A self-contained, printable board report: headlines in sentences, appetite table, residual heat map with risk IDs, open risks with P90 loss, overdue actions, evidence-tier mix and audit integrity. Generated on demand from live data; same data, same report.

**Still missing.** No trend charts over time (the register stores current state and the audit log, not periodic snapshots).

---

## Summary

| Gap                                   | Addressed | Remaining limitation                        |
|---------------------------------------|:---------:|---------------------------------------------|
| Residual typed, not derived           | yes       | effectiveness still a human estimate        |
| Assertions credited like evidence     | yes       | tiers set by hand, no telemetry ingestion   |
| No financial view                     | yes       | FAIR-style, not full FAIR decomposition     |
| Qualitative and quantitative disagree | yes       |                                             |
| Unusable by the business              | yes       | no attestation workflow                     |
| No appetite checks                    | yes       | per category only                           |
| Treatments without deadlines          | yes       | no ticketing integration                    |
| No early warning                      | yes       | no automatic collectors                     |
| Permanent acceptance                  | yes       |                                             |
| Editable or absent audit trail        | yes       | no external anchoring                       |
| Stale scores                          | yes       |                                             |
| No roles                              | yes       | header identity, no SSO                     |
| Blank page start                      | yes       | AI / cloud SaaS library only                |
| Migration is a rewrite                | yes       |                                             |
| Hand-built board reports              | yes       | no trend history                            |
