"""Deterministic risk scoring engine.

Design rules (see docs/METHODOLOGY.md):
  * Every function is pure: same inputs -> same outputs. No LLM, no clock.
  * Qualitative 5x5 matrix and FAIR-style quantitative model run side by side.
  * Control credit is discounted by *evidence tier* so a control somebody
    merely claims to have never earns the same credit as one a SIEM proves.
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass
from typing import Iterable, Sequence

# --------------------------------------------------------------------------
# Qualitative scales (plain English first, numbers second)
# --------------------------------------------------------------------------

LIKELIHOOD_SCALE = [
    {"level": 1, "label": "Rare", "plain": "Would surprise us if it happened in the next 10 years", "annual_probability": "< 10%"},
    {"level": 2, "label": "Unlikely", "plain": "Could happen, but probably not this year", "annual_probability": "10 - 30%"},
    {"level": 3, "label": "Possible", "plain": "Coin-flip odds of happening within a year", "annual_probability": "30 - 60%"},
    {"level": 4, "label": "Likely", "plain": "More likely than not to happen this year", "annual_probability": "60 - 90%"},
    {"level": 5, "label": "Almost certain", "plain": "We expect this to happen this year, maybe more than once", "annual_probability": "> 90%"},
]

IMPACT_SCALE = [
    {"level": 1, "label": "Negligible", "plain": "Annoying. Fixed in a day, nobody outside the team notices", "financial": "< $10k"},
    {"level": 2, "label": "Minor", "plain": "A bad week. Some customers notice, no regulator involved", "financial": "$10k - $100k"},
    {"level": 3, "label": "Moderate", "plain": "A bad quarter. Customer churn, possible regulator notification", "financial": "$100k - $1M"},
    {"level": 4, "label": "Major", "plain": "A bad year. Breach notifications, fines, board involvement", "financial": "$1M - $10M"},
    {"level": 5, "label": "Severe", "plain": "Threatens the company's survival or licence to operate", "financial": "> $10M"},
]

# Midpoints used to translate a qualitative impact level into a dollar figure
# when the user has not supplied FAIR inputs (and the reverse).
IMPACT_DOLLAR_BANDS = [(1, 0, 10_000), (2, 10_000, 100_000), (3, 100_000, 1_000_000), (4, 1_000_000, 10_000_000), (5, 10_000_000, 100_000_000)]
LIKELIHOOD_PROB_BANDS = [(1, 0.0, 0.10), (2, 0.10, 0.30), (3, 0.30, 0.60), (4, 0.60, 0.90), (5, 0.90, 10.0)]

BANDS = [
    {"name": "Low", "min": 1, "max": 4, "color": "#2e7d32"},
    {"name": "Medium", "min": 5, "max": 9, "color": "#f9a825"},
    {"name": "High", "min": 10, "max": 16, "color": "#ef6c00"},
    {"name": "Critical", "min": 17, "max": 25, "color": "#c62828"},
]

IMPLEMENTATION_FACTOR = {"Not Implemented": 0.0, "Partial": 0.5, "Implemented": 1.0}

# Evidence tiers adapted from the ResilAI / AIRS governance whitepaper:
# Tier 1 = Self-Declared, Tier 2 = Scanner-Observed, Tier 3 = SIEM-Verified.
EVIDENCE_TIERS = {
    1: {"name": "Self-Declared", "credit": 0.5, "plain": "Someone says the control exists. Nothing has checked it."},
    2: {"name": "Scanner-Observed", "credit": 0.8, "plain": "A tool (scanner, CSPM, dependency audit) has observed the control in place."},
    3: {"name": "SIEM-Verified", "credit": 1.0, "plain": "Continuous telemetry proves the control is operating effectively."},
}

CONTROL_TYPES = ("Preventive", "Detective", "Corrective")


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def score(likelihood: int, impact: int) -> int:
    return int(clamp(likelihood, 1, 5)) * int(clamp(impact, 1, 5))


def band_for(s: int) -> dict:
    for b in BANDS:
        if b["min"] <= s <= b["max"]:
            return b
    return BANDS[0]


def impact_level_from_dollars(amount: float) -> int:
    for level, lo, hi in IMPACT_DOLLAR_BANDS:
        if lo <= amount < hi:
            return level
    return 5


def likelihood_level_from_probability(p: float) -> int:
    for level, lo, hi in LIKELIHOOD_PROB_BANDS:
        if lo <= p < hi:
            return level
    return 5


def likelihood_level_from_lef(lef_per_year: float) -> int:
    """Convert loss-event frequency (events / year) to annual probability of >=1 event."""
    p = 1 - math.exp(-max(lef_per_year, 0.0))
    return likelihood_level_from_probability(p)


# --------------------------------------------------------------------------
# Control credit
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlCredit:
    control_id: str
    control_type: str
    credit: float  # 0..1 share of the risk this single control removes


def control_credit(control: dict) -> float:
    eff = clamp(float(control.get("effectiveness", 0)) / 100.0, 0.0, 1.0)
    impl = IMPLEMENTATION_FACTOR.get(control.get("implementation_status", "Not Implemented"), 0.0)
    tier = EVIDENCE_TIERS.get(int(control.get("evidence_tier", 1)), EVIDENCE_TIERS[1])["credit"]
    return round(eff * impl * tier, 4)


def combined_reduction(credits: Iterable[float]) -> float:
    """Overlap-aware stacking of control credits.

    Controls on the same risk are never independent (MFA and awareness
    training both fight phishing), so the naive 1 - prod(1 - c) formula
    overstates layered defence. The strongest control counts in full; each
    additional control only covers half of what remains.
    """
    remaining = 1.0
    for i, c in enumerate(sorted((clamp(x, 0.0, 1.0) for x in credits), reverse=True)):
        share = c if i == 0 else c * 0.5
        remaining *= (1.0 - share)
    return round(1.0 - remaining, 4)


# How far controls can move each axis. Likelihood is easier to engineer down
# than impact: once ransomware detonates, the loss is still large.
LIKELIHOOD_DAMPING = 0.6
IMPACT_DAMPING = 0.4


def reductions_for_controls(controls: Sequence[dict]) -> dict:
    """Preventive controls cut likelihood; detective + corrective cut impact.

    A detective control that is paired with response capability shortens the
    window between compromise and containment, which is an impact lever, not a
    likelihood lever. That is why detective sits on the impact side.
    """
    lik = [control_credit(c) for c in controls if c.get("control_type") == "Preventive"]
    imp = [control_credit(c) for c in controls if c.get("control_type") in ("Detective", "Corrective")]
    lr, ir = combined_reduction(lik), combined_reduction(imp)
    return {
        "likelihood_reduction": lr,
        "impact_reduction": ir,
        "likelihood_scale": round(1 - LIKELIHOOD_DAMPING * lr, 4),
        "impact_scale": round(1 - IMPACT_DAMPING * ir, 4),
        "credits": [
            {"control_id": c["id"], "control_type": c.get("control_type"), "credit": control_credit(c),
             "evidence_tier": int(c.get("evidence_tier", 1))}
            for c in controls
        ],
    }


def _round_half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


def suggested_residual(inherent_likelihood: int, inherent_impact: int, controls: Sequence[dict]) -> dict:
    r = reductions_for_controls(controls)
    lik = max(1, _round_half_up(inherent_likelihood * r["likelihood_scale"]))
    imp = max(1, _round_half_up(inherent_impact * r["impact_scale"]))
    return {"likelihood": lik, "impact": imp, **r}


# --------------------------------------------------------------------------
# FAIR-style quantification (PERT + Monte Carlo)
# --------------------------------------------------------------------------

def _pert_sample(rng: random.Random, lo: float, mode: float, hi: float, lam: float = 4.0) -> float:
    if hi <= lo:
        return lo
    mode = clamp(mode, lo, hi)
    a = 1 + lam * (mode - lo) / (hi - lo)
    b = 1 + lam * (hi - mode) / (hi - lo)
    return lo + rng.betavariate(a, b) * (hi - lo)


def _seed_for(key: str) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest()[:12], 16)


def simulate(lef: tuple[float, float, float], lm: tuple[float, float, float], *, n: int = 5000,
             seed_key: str = "default", lef_scale: float = 1.0, lm_scale: float = 1.0) -> dict:
    """Monte Carlo annualised loss.

    lef = (min, likely, max) loss events per year
    lm  = (min, likely, max) loss magnitude per event, currency units
    The RNG is seeded from `seed_key` so the same risk always yields the same
    numbers (auditors can re-run and match).
    """
    rng = random.Random(_seed_for(seed_key))
    losses: list[float] = []
    lef_t = tuple(max(0.0, x * lef_scale) for x in lef)
    lm_t = tuple(max(0.0, x * lm_scale) for x in lm)
    for _ in range(n):
        freq = _pert_sample(rng, *lef_t)
        # Number of events this year ~ Poisson(freq)
        events = _poisson(rng, freq)
        total = 0.0
        for _ in range(events):
            total += _pert_sample(rng, *lm_t)
        losses.append(total)
    raw = list(losses)
    losses.sort()

    def pct(p: float) -> float:
        if not losses:
            return 0.0
        idx = min(len(losses) - 1, int(p * len(losses)))
        return losses[idx]

    mean = sum(losses) / len(losses) if losses else 0.0
    prob_any = sum(1 for x in losses if x > 0) / len(losses) if losses else 0.0
    curve = []
    for i in range(0, 21):
        q = i / 20
        curve.append({"loss": round(pct(q), 2), "probability_exceeding": round(1 - q, 3)})
    return {
        "samples": n,
        "ale_mean": round(mean, 2),
        "ale_median": round(pct(0.5), 2),
        "ale_p90": round(pct(0.9), 2),
        "ale_p95": round(pct(0.95), 2),
        "ale_max": round(losses[-1], 2) if losses else 0.0,
        "probability_of_loss": round(prob_any, 3),
        "sle_likely": round(lm_t[1], 2),
        "aro_likely": round(lef_t[1], 4),
        "ale_simple": round(lef_t[1] * lm_t[1], 2),  # classic ARO x SLE for people who want the textbook number
        "exceedance_curve": curve,
        "raw": raw,
    }


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:  # normal approximation for large rates
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    L = math.exp(-lam)
    k, p = 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


def has_fair_inputs(r: dict) -> bool:
    keys = ("lef_min", "lef_likely", "lef_max", "lm_min", "lm_likely", "lm_max")
    return all(r.get(k) is not None for k in keys)


def default_fair_from_qualitative(likelihood: int, impact: int) -> dict:
    """Give the business-persona user a starting point for the quantitative step."""
    _, plo, phi = LIKELIHOOD_PROB_BANDS[likelihood - 1]
    phi = min(phi, 0.99)
    _, dlo, dhi = IMPACT_DOLLAR_BANDS[impact - 1]
    # Convert probability of >=1 event to an event rate: lef = -ln(1-p)
    lef_lo = -math.log(1 - plo) if plo < 1 else 1.0
    lef_hi = -math.log(1 - phi)
    lef_mode = (lef_lo + lef_hi) / 2
    return {
        "lef_min": round(lef_lo, 3), "lef_likely": round(lef_mode, 3), "lef_max": round(lef_hi, 3),
        "lm_min": float(max(dlo, 1000)), "lm_likely": float((dlo + dhi) / 2 if dlo else dhi / 4), "lm_max": float(dhi),
    }


# --------------------------------------------------------------------------
# Appetite
# --------------------------------------------------------------------------

def appetite_check(residual_score: int, residual_ale_p90: float | None, appetite: dict | None) -> dict:
    if not appetite:
        return {"defined": False, "breach": False, "reasons": []}
    reasons = []
    if residual_score > appetite["max_residual_score"]:
        reasons.append(f"Residual score {residual_score} exceeds tolerance {appetite['max_residual_score']}")
    if residual_ale_p90 is not None and appetite.get("max_ale") and residual_ale_p90 > appetite["max_ale"]:
        reasons.append(f"90th percentile annual loss exceeds tolerance of {appetite['max_ale']:,.0f}")
    return {"defined": True, "breach": bool(reasons), "reasons": reasons,
            "max_residual_score": appetite["max_residual_score"], "max_ale": appetite["max_ale"]}
