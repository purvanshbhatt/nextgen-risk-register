# Interview Guide

How to demo the NextGen Risk Register in five minutes, and how to answer what comes next.

---

## The five-minute demo

Start the app (`python run.py`) and open <http://127.0.0.1:8000>. The demo tenant is Lumen Analytics, an AI and cloud SaaS company. Use the persona switcher in the header.

**0:00 — Executive persona, Dashboard.**
Read the headlines aloud. They are sentences, not charts: "12 risks sit outside the risk appetite the board set", "one bad year in ten could cost $8.3M or more", "1 risk acceptance has expired". Point at the residual heat map and the loss-exceedance curve. Say: *every number on this screen is deterministic; the same data produces the same screen for the auditor.*

**1:00 — Business persona, New Risk.**
Click New Risk, pick the "Prompt injection" scenario. Walk the four screens: Describe (plain-English title and "what happens to the business"), How likely and how bad (word cards, no numbers), Put a number on it (optional; the FAIR defaults appear from the qualitative choice, the live simulation updates as you drag). Notice the Technical details step is hidden for this persona. Create the risk. Say: *the business owner never sees CVSS or ATT&CK, yet the risk they create is already mapped to OWASP LLM01 and MITRE ATLAS AML.T0051 behind the scenes.*

**2:30 — Security Engineer persona, Controls.**
Open the controls library. Point at the evidence tier column: EDR is SIEM-Verified, backups are Self-Declared and Partial. Open the ransomware risk, Scoring tab: show the suggested residual and the credit each control earned. Change the backups control to Implemented with a scanner-observed restore report and watch residual impact drop. Say: *"we have a policy" earns half credit; a SIEM search earns full credit. That is how the register aligns with what a SOC 2 auditor would actually credit.*

**4:00 — Auditor persona, Audit trail.**
Show the log of everything you just did, with field-level diffs. Click Verify: "Audit chain intact, N entries". Explain the SHA-256 chain in one sentence. Open Reports and generate the board report. Say: *this is the pack I would hand the audit committee, and it prints the chain head so they can check it is the same data.*

**5:00 — Close.**
"Spreadsheet registers fail on five things: residual is typed, controls are assertions, there is no money, the business cannot use it, and nobody can prove what changed. This fixes all five, and the methodology is written down and unit-tested."

---

## Likely questions and strong answers

**Why FAIR? Isn't a heat map enough?**
A heat map prioritises; it cannot budget. When the CFO asks whether $150k of EDR coverage is worth it, I need expected annual loss before and after. I implemented a FAIR-style model (PERT-distributed loss-event frequency and loss magnitude, Poisson event counts, Monte Carlo) rather than a full FAIR decomposition because the inputs are elicitable from a risk owner in one screen. The matrix stays, because boards read matrices, and both views are driven by the same control credits so they cannot disagree.

**Why evidence tiers on controls?**
Because an auditor does not credit assertions. SOC 2 Type II asks for evidence of operation over a period; ISO 27001 Annex A audits ask "show me". I took the Profile-Declared / Platform-Observed / SIEM-Verified progression from a governance architecture whitepaper I worked on and turned it into a multiplier on control credit: 0.5, 0.8, 1.0. It also creates the right incentive: wiring a scanner export or a SIEM search into the register visibly lowers residual risk.

**Why does the register insist on being deterministic? Why no AI in the scoring?**
Reproducibility is an audit requirement. If an auditor cannot regenerate the P90 I reported, it is an opinion. LLMs are non-deterministic and opaque, so they stay out of the system of record. They are fine for drafting narrative; the whitepaper I based this on calls that the dual-engine separation. Here the Monte Carlo is seeded from the risk ID, so re-running it yields the identical samples.

**How is residual risk derived?**
Each control earns a credit: effectiveness × implementation factor × evidence-tier factor. Preventive controls reduce likelihood; detective and corrective controls reduce impact, because detection shortens dwell time rather than stopping the event. Credits stack overlap-aware: the strongest control counts fully, each further control covers half of what remains, since controls on the same risk are never independent. Then damping: likelihood can move at most 60 %, impact at most 40 %, so perfect controls on a 5×5 risk land at 2×3, never 1×1. The worked example in METHODOLOGY.md walks the ransomware risk from 15 to 6 by hand and a unit test pins it.

**How would you connect this to a SIEM?**
Two integrations. First, KRIs: a Splunk or Sentinel saved search posts its result to `POST /api/kris/{id}/readings` on a schedule, so the "guardrail bypasses per week" indicator is live rather than typed. Second, control evidence: a scheduled job checks that the detection rule exists and has fired in the last 30 days, then sets the control's evidence tier to 3 with the search name as the source, and drops it back to 1 if the rule disappears. The data model already has the fields; what is missing is the collector.

**What would you do for SOC 2 evidence?**
Map each control to the TSC criteria (the control library already carries CC6.1, CC7.2 and so on), attach the evidence file with its SHA-256 through the evidence endpoint, and export the JSON for the auditor's workpapers. The audit chain gives them change history over the period; the board report gives them management review evidence (CC4.1, CC3.2). Next step would be period-locked snapshots so a Type II window is frozen.

**How does the business owner choose a likelihood without guessing?**
Word cards with a concrete description ("coin-flip odds within a year"), and an impact translator: if they know "roughly $2M if it happens", the register maps that to Major. The FAIR defaults step takes their qualitative choice and proposes frequency and magnitude ranges they can adjust, so the quantitative view starts from something sensible rather than a blank.

**What frameworks did you map and why those?**
NIST CSF 2.0 and ISO 27001:2022 because they are the common language of security programmes; SOC 2 because it is what SaaS customers ask for; NIST AI RMF and OWASP Top 10 for LLM Applications 2025 because the scenarios are for an AI product; MITRE ATT&CK and ATLAS so an engineer can jump from a risk to detection and mitigation guidance; CIS v8 for prioritised controls; GDPR for the privacy risks.

**What are the weaknesses?**
Identity is a header, not SSO. Control effectiveness is still a human number. The FAIR model is not a full FAIR decomposition. The evidence tiers are labels until a collector sets them. Single tenant. I listed these in the README because a register that hides its own limitations is the thing I am arguing against.

**How would you roll this out?**
Import the existing spreadsheet through the CSV template, run both for one quarter, use the staleness and overdue flags to show what the spreadsheet was hiding, then retire it. Train business owners on the four-screen wizard only; they never need the engineer view.

---

## STAR talking points

**Situation.** Organisations keep risk in spreadsheets where residual risk is typed by hand, controls are assertions, there is no financial view, and the audit trail is whatever the version history kept.

**Task.** Build a register that a non-technical risk owner can use, that a security engineer trusts, that an auditor can verify, and that a board can act on in money terms.

**Action.** Designed a deterministic scoring engine combining a 5×5 matrix with a FAIR-style Monte Carlo model; introduced evidence-weighted control credit so residual risk is derived, not typed; implemented per-category appetite checks on both score and P90 loss, time-boxed acceptance, KRIs, treatment tracking and a SHA-256 hash-chained audit log; mapped an AI and cloud SaaS scenario library to NIST CSF 2.0, ISO 27001:2022, SOC 2, NIST AI RMF, OWASP LLM Top 10, CIS v8, GDPR, MITRE ATT&CK and ATLAS; wrote the methodology down and pinned it with unit tests.

**Result.** A working register with a persona-aware interface, a printable board report, CSV migration, a test suite covering the engine and the API, and documented limitations and roadmap.

### Vocabulary to use naturally

- ISO/IEC 27005: risk identification, analysis, evaluation, treatment; risk owner; risk acceptance criteria; residual risk.
- NIST RMF (SP 800-37) and SP 800-30: likelihood, impact, risk response (accept, avoid, mitigate, share/transfer), continuous monitoring, authorisation.
- FAIR: loss-event frequency, loss magnitude, annualised loss expectancy, loss-exceedance curve, calibrated estimates.
- NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover; GV.RM (risk management strategy) is where appetite lives.
- SOC 2: Trust Services Criteria, Type I versus Type II, evidence of operating effectiveness.
- ISO 27001: Statement of Applicability, Annex A controls, management review.
