# Scoring Methodology

This document describes exactly how the NextGen Risk Register turns inputs into scores. Every formula below is implemented in `backend/scoring.py`; the test `tests/test_scoring.py::test_ransomware_worked_example_matches_methodology_doc` fails if the code and this document drift apart.

Guiding rule: **the scoring path is deterministic**. Given the same risk, controls and appetite, the register produces the same numbers every time. No language model, no wall clock and no unseeded randomness participate in a score. This mirrors the dual-engine separation argued in the ResilAI / AIRS governance whitepaper: narrative text may be generated, the system of record may not.

---

## 1. Qualitative scales

Both scales are written plain-English first so a non-technical owner can pick a level without a glossary. The numeric bands are what the impact translator uses to map dollars and frequencies onto the scale.

### Likelihood (per year)

| Level | Label          | Plain English                                                  | Annual probability of at least one event |
|------:|----------------|----------------------------------------------------------------|------------------------------------------|
| 1     | Rare           | Would surprise us if it happened in the next 10 years          | < 10 %                                   |
| 2     | Unlikely       | Could happen, but probably not this year                       | 10 – 30 %                                |
| 3     | Possible       | Coin-flip odds of happening within a year                      | 30 – 60 %                                |
| 4     | Likely         | More likely than not to happen this year                       | 60 – 90 %                                |
| 5     | Almost certain | We expect this to happen this year, maybe more than once       | > 90 %                                   |

### Impact (per event)

| Level | Label      | Plain English                                                              | Financial band   |
|------:|------------|----------------------------------------------------------------------------|------------------|
| 1     | Negligible | Annoying. Fixed in a day, nobody outside the team notices                  | < $10k           |
| 2     | Minor      | A bad week. Some customers notice, no regulator involved                   | $10k – $100k     |
| 3     | Moderate   | A bad quarter. Customer churn, possible regulator notification             | $100k – $1M      |
| 4     | Major      | A bad year. Breach notifications, fines, board involvement                 | $1M – $10M       |
| 5     | Severe     | Threatens the company's survival or licence to operate                     | > $10M           |

### Score and bands

```
score = likelihood × impact            (each clamped to 1..5, so score ∈ 1..25)
```

| Band     | Score range |
|----------|-------------|
| Low      | 1 – 4       |
| Medium   | 5 – 9       |
| High     | 10 – 16     |
| Critical | 17 – 25     |

### Impact translator

- Dollars → impact level: the band whose range contains the amount (`impact_level_from_dollars`).
- Annual probability → likelihood level: the band whose range contains the probability (`likelihood_level_from_probability`).
- Events per year (loss-event frequency, LEF) → likelihood level: convert to the probability of at least one event under a Poisson assumption, then look up the band:

```
P(at least one event) = 1 − e^(−LEF)
```

So LEF = 0.05 → 4.9 % → Rare; LEF = 0.5 → 39 % → Possible; LEF = 3 → 95 % → Almost certain.

---

## 2. Control credit

A control contributes a *credit* in the range 0..1, the share of a risk axis it removes if it were the only control:

```
credit = effectiveness / 100 × implementation_factor × evidence_tier_credit
```

| Implementation status | Factor |
|-----------------------|-------:|
| Not Implemented       | 0.0    |
| Partial               | 0.5    |
| Implemented           | 1.0    |

| Evidence tier | Name             | Credit | Meaning                                                                 |
|--------------:|------------------|-------:|-------------------------------------------------------------------------|
| 1             | Self-Declared    | 0.5    | Someone says the control exists. Nothing has checked it.                |
| 2             | Scanner-Observed | 0.8    | A tool (scanner, CSPM, dependency audit) has observed the control.      |
| 3             | SIEM-Verified    | 1.0    | Continuous telemetry proves the control is operating effectively.       |

The tiers are adapted from the Profile-Declared / Platform-Observed / SIEM-Verified progression in the ResilAI / AIRS whitepaper. The API refuses tier 2 or 3 unless an evidence source is named.

Effectiveness remains a human input (0–100). The tier discount is the mechanism that stops an unverified "95 % effective" claim from dominating the residual score.

---

## 3. Stacking controls

Controls on the same risk overlap (MFA and phishing training both fight the same phishing email), so the independent-layers formula `1 − Π(1 − cᵢ)` overstates layered defence. The register uses an overlap-aware rule:

```
sort credits descending: c₁ ≥ c₂ ≥ c₃ …
remaining = (1 − c₁) × (1 − c₂/2) × (1 − c₃/2) × …
combined_reduction = 1 − remaining
```

The strongest control counts in full; each further control covers only half of what is left. Order of entry does not matter because credits are sorted first. The result is always below 1 unless the strongest control has a credit of exactly 1.

Controls are split by type:

- **Preventive** controls reduce **likelihood**.
- **Detective** and **Corrective** controls reduce **impact**. A detective control shortens the window between compromise and containment, which is an impact lever, not a likelihood lever.

---

## 4. Residual score

Controls can move an axis, but never all the way. Two damping constants cap how much:

```
LIKELIHOOD_DAMPING = 0.6
IMPACT_DAMPING     = 0.4

likelihood_scale = 1 − 0.6 × likelihood_reduction
impact_scale     = 1 − 0.4 × impact_reduction

residual_likelihood = max(1, round_half_up(inherent_likelihood × likelihood_scale))
residual_impact     = max(1, round_half_up(inherent_impact     × impact_scale))
residual_score      = residual_likelihood × residual_impact
```

Likelihood is easier to engineer down than impact: once ransomware detonates, the loss is still large. With perfect, fully verified controls on both axes a 5 × 5 risk lands at 2 × 3 = 6 (Medium), never at 1 × 1.

An analyst may set `residual_override = true` and type residual levels directly. The suggested residual is still computed and shown beside the override, and the override is recorded in the audit trail.

### Worked example: the seeded ransomware risk

Inherent: likelihood 3 (Possible), impact 5 (Severe), score 15 (High). Linked controls from `backend/scenarios.py`:

| Control                          | Type       | Effectiveness | Implementation   | Tier | Credit                       |
|----------------------------------|------------|--------------:|------------------|-----:|------------------------------|
| Phishing-resistant MFA           | Preventive | 85            | Implemented (1.0)| 2 (0.8) | 0.85 × 1.0 × 0.8 = **0.68**  |
| Security awareness training      | Preventive | 40            | Implemented (1.0)| 2 (0.8) | 0.40 × 1.0 × 0.8 = **0.32**  |
| EDR with 24×7 monitoring         | Detective  | 80            | Implemented (1.0)| 3 (1.0) | 0.80 × 1.0 × 1.0 = **0.80**  |
| Incident response plan           | Corrective | 70            | Implemented (1.0)| 1 (0.5) | 0.70 × 1.0 × 0.5 = **0.35**  |
| Immutable backups                | Corrective | 90            | Partial (0.5)    | 1 (0.5) | 0.90 × 0.5 × 0.5 = **0.225** |

Likelihood side (preventive): credits 0.68, 0.32.

```
remaining = (1 − 0.68) × (1 − 0.32/2) = 0.32 × 0.84 = 0.2688
likelihood_reduction = 0.7312
likelihood_scale = 1 − 0.6 × 0.7312 = 0.5613
residual_likelihood = round_half_up(3 × 0.5613 = 1.68) = 2
```

Impact side (detective + corrective): credits 0.80, 0.35, 0.225.

```
remaining = (1 − 0.80) × (1 − 0.35/2) × (1 − 0.225/2) = 0.20 × 0.825 × 0.8875 = 0.1464
impact_reduction = 0.8536
impact_scale = 1 − 0.4 × 0.8536 = 0.6586
residual_impact = round_half_up(5 × 0.6586 = 3.29) = 3
```

Residual: 2 × 3 = **6 (Medium)**, down from 15 (High). Note what the evidence tiers did: the backups control, on paper 90 % effective, contributed only 0.225 because it is partially implemented and self-declared. Record a restore test as scanner-observed evidence and complete the rollout, and its credit rises to 0.72.

---

## 5. Quantitative model (FAIR-style)

Any risk may carry six numbers: loss-event frequency per year (`lef_min`, `lef_likely`, `lef_max`) and loss magnitude per event in currency units (`lm_min`, `lm_likely`, `lm_max`). The API insists on all six or none, and on `min ≤ likely ≤ max`.

### Distributions

Each triple is sampled from a **PERT** distribution, a Beta distribution rescaled to [min, max] with the mode at *likely* (shape parameter λ = 4):

```
α = 1 + 4 × (likely − min) / (max − min)
β = 1 + 4 × (max − likely) / (max − min)
sample = min + Beta(α, β) × (max − min)
```

If `max ≤ min` the sample is simply `min`.

### Simulation

For each of *n* simulated years (default 5 000 per stored risk, 3 000 for the live wizard preview):

1. Draw a frequency `λ` from the LEF PERT.
2. Draw the number of events this year from **Poisson(λ)** (Knuth's algorithm; a normal approximation is used above λ = 30).
3. For each event draw a loss from the LM PERT and sum them.

The result is a list of annual losses. Reported statistics:

| Field                 | Meaning                                                       |
|-----------------------|---------------------------------------------------------------|
| `ale_mean`            | Expected annual loss (the FAIR "ALE")                         |
| `ale_median`          | 50th percentile                                               |
| `ale_p90`, `ale_p95`  | A bad year in ten, a bad year in twenty                       |
| `ale_max`             | Worst simulated year                                          |
| `probability_of_loss` | Share of simulated years with any loss at all                 |
| `sle_likely`, `aro_likely`, `ale_simple` | Textbook figures: SLE = likely magnitude, ARO = likely frequency, ALE_simple = ARO × SLE, for people who want the classic number next to the simulated one |
| `exceedance_curve`    | 21 points `(loss, probability_exceeding)` for the loss-exceedance chart |

Percentiles are taken by index on the sorted sample (`index = int(p × n)`, capped at `n − 1`).

### Determinism

The random generator is `random.Random(seed)` with the seed derived from SHA-256 of a key, which is the risk ID for stored risks. Re-running the simulation for the same risk yields byte-identical samples, so an auditor can reproduce every P90 in a report.

### Inherent versus residual

The inherent simulation uses the raw inputs. The residual simulation multiplies the LEF triple by `likelihood_scale` and the LM triple by `impact_scale` from Section 4, so the quantitative and qualitative views are driven by the same control credits and agree with each other.

For the ransomware example (LEF 0.05 / 0.2 / 0.5, LM $500k / $3M / $15M): ALE_simple = 0.2 × $3M = $600k inherent. The seeded demo's residual simulation (seed `RISK-0001`, n = 5 000) reports a mean of about $356k and a P90 of about $1.25M.

### Portfolio exposure

The dashboard sums annual losses **per simulated year** across all quantified open risks, then takes statistics of the sums. Summing per-risk P90s would overstate exposure (it assumes every risk has its bad year at once); summing means would hide the tail. Risks are treated as independent.

### Defaults for the business persona

When a user has chosen qualitative levels but has no numbers, `default_fair_from_qualitative` offers a starting point:

- LEF min/max are the likelihood band's probability bounds converted with `LEF = −ln(1 − p)` (upper bound capped at p = 0.99); the mode is their midpoint.
- LM min is the impact band's lower dollar bound (at least $1 000), LM max the upper bound, and the mode the band midpoint (a quarter of the upper bound for the lowest band).

---

## 6. Risk appetite

Appetite is set per category with two thresholds:

```
breach if residual_score > max_residual_score
     or (residual P90 annual loss is known and > max_ale)
```

Either condition is enough. The reasons are returned as sentences and shown on the risk, the dashboard headlines and the board report. Categories without an appetite entry are never reported as breaching.

---

## 7. Review cadence

```
next_review_at = (last_reviewed_at or created_at) + review_frequency_days
review_overdue = next_review_at < now and status ≠ Closed
```

Frequency defaults to 90 days and is bounded to 7–730 days. Recording a review stamps `last_reviewed_at` and writes a `review` audit entry with the note.

---

## 8. Risk acceptance

- Only the Executive and Risk Analyst roles may accept.
- A rationale of at least 10 characters is required.
- `expires_at` must be a future date no more than 365 days away. Open-ended acceptances are how risks get forgotten.
- A new acceptance marks any previous active acceptance as *Superseded* and sets the risk status to *Accepted*.
- The dashboard lists active acceptances and flags any whose expiry has passed.

---

## 9. Treatments and KRIs

- Treatment strategies: Mitigate, Accept, Transfer, Avoid. Statuses: Planned, In Progress, Done, Cancelled. Marking a treatment Done forces progress to 100 and records `completed_at`. A treatment is overdue when it is Planned or In Progress and its due date is before today.
- A KRI has `warning` and `critical` thresholds and a `direction` (`above_is_bad` or `below_is_bad`). Status is Critical, Warning, OK or No data; a risk reports the worst status of its KRIs. Every new reading is kept in history and becomes the current value.

---

## 10. Audit chain

Every mutation appends one row to `audit_log`:

```
hash = SHA-256( prev_hash | ts | actor | role | entity_type | entity_id | action | detail_json )
```

Fields are joined with `|`; `detail_json` is the change detail serialised with sorted keys; the first row's `prev_hash` is 64 zero characters. `GET /api/audit/verify` walks the table in sequence order and recomputes every hash. Editing any field of any row, or deleting a row, breaks verification from that row onward and the response names the first bad sequence number. Updates store a field-level diff (`from` / `to`) rather than whole-object snapshots, so the history reads as a change log.

---

## 11. Why these choices

- **A matrix and a distribution, not one or the other.** NIST SP 800-30 Rev. 1 and ISO 31000 both accept qualitative scales, and boards are used to heat maps. FAIR (The Open Group, O-RT / O-RA) is the de-facto standard for putting money on cyber risk. Offering both from the same inputs lets each audience use the view it trusts while keeping them consistent.
- **PERT rather than triangular or normal.** PERT is the FAIR community's conventional choice for expert-elicited min / likely / max ranges: it weights the mode more than a triangle does and never produces values outside the range.
- **Poisson event counts.** Treating loss events as a Poisson process is the standard assumption behind "frequency per year" and gives a principled bridge to "probability of at least one event", which is what the qualitative likelihood scale describes.
- **Evidence tiers.** SOC 2 Type II and ISO 27001 auditors do not accept assertions; they ask for evidence of operation. Weighting control credit by evidence quality makes the register's residual numbers align with what an auditor would credit, and creates an incentive to wire scanners and SIEM searches into the register.
- **Overlap-aware stacking and damping.** Independent-layer maths lets five mediocre controls drive a risk to Low, which experienced practitioners recognise as wrong. The chosen rule is simple to explain to a board ("the best control counts fully, the rest count half") and is conservative.
- **Preventive to likelihood, detective and corrective to impact.** This follows the ISO 27001 / NIST CSF 2.0 control-type vocabulary (Protect reduces likelihood; Detect, Respond and Recover reduce impact).
- **Deterministic engine.** Reproducibility is an audit requirement, not a nicety. A score an auditor cannot regenerate is an opinion.
- **Scenario references.** Techniques come from MITRE ATT&CK (Enterprise) and MITRE ATLAS for AI-specific tactics; AI risks also cite the OWASP Top 10 for LLM Applications (2025) and NIST AI RMF 1.0 so an engineer can jump from the register to the relevant mitigation guidance.

### References

- The Open Group, *Risk Taxonomy (O-RT) Standard* and *Risk Analysis (O-RA) Standard* (FAIR).
- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments*.
- NIST SP 800-37 Rev. 2, *Risk Management Framework*.
- ISO 31000:2018, *Risk management — Guidelines*; ISO/IEC 27005:2022, *Guidance on managing information security risks*.
- NIST Cybersecurity Framework 2.0 (2024).
- ISO/IEC 27001:2022, Annex A.
- AICPA, *Trust Services Criteria* (SOC 2).
- NIST AI RMF 1.0 (2023).
- OWASP Top 10 for LLM Applications 2025.
- MITRE ATT&CK (Enterprise) and MITRE ATLAS.
- ResilAI / AIRS, *Deterministic Governance Inference & Validation Architecture for Continuous Compliance Intelligence* (2026), for the dual-engine principle and evidence tiers.
