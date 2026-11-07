"""Unit tests for the deterministic scoring engine."""
import pytest

from backend import scoring


def _ctl(ctype="Preventive", eff=80, impl="Implemented", tier=2, cid="CTL-X"):
    return {"id": cid, "control_type": ctype, "effectiveness": eff, "implementation_status": impl, "evidence_tier": tier}


# ----------------------------------------------------------------- qualitative

@pytest.mark.parametrize("s,band", [(1, "Low"), (4, "Low"), (5, "Medium"), (9, "Medium"), (10, "High"), (16, "High"), (17, "Critical"), (25, "Critical")])
def test_band_boundaries(s, band):
    assert scoring.band_for(s)["name"] == band


def test_score_clamps_to_scale():
    assert scoring.score(5, 5) == 25
    assert scoring.score(0, 9) == 5  # clamped to 1 x 5
    assert scoring.score(3, 4) == 12


@pytest.mark.parametrize("dollars,level", [(0, 1), (9_999, 1), (10_000, 2), (99_999, 2), (100_000, 3), (1_000_000, 4), (10_000_000, 5), (1e12, 5)])
def test_impact_level_from_dollars(dollars, level):
    assert scoring.impact_level_from_dollars(dollars) == level


@pytest.mark.parametrize("p,level", [(0.0, 1), (0.09, 1), (0.1, 2), (0.3, 3), (0.6, 4), (0.9, 5), (1.0, 5)])
def test_likelihood_level_from_probability(p, level):
    assert scoring.likelihood_level_from_probability(p) == level


def test_likelihood_level_from_lef_uses_poisson_probability():
    # P(>=1 event) = 1 - e^-lef. lef=0.05 -> 4.9% (Rare); lef=0.5 -> 39% (Possible); lef=3 -> 95% (Almost certain)
    assert scoring.likelihood_level_from_lef(0.05) == 1
    assert scoring.likelihood_level_from_lef(0.5) == 3
    assert scoring.likelihood_level_from_lef(3) == 5


# ----------------------------------------------------------------- control credit

def test_control_credit_multiplies_effectiveness_implementation_and_tier():
    assert scoring.control_credit(_ctl(eff=100, impl="Implemented", tier=3)) == 1.0
    assert scoring.control_credit(_ctl(eff=100, impl="Implemented", tier=2)) == 0.8
    assert scoring.control_credit(_ctl(eff=100, impl="Implemented", tier=1)) == 0.5
    assert scoring.control_credit(_ctl(eff=100, impl="Partial", tier=3)) == 0.5
    assert scoring.control_credit(_ctl(eff=100, impl="Not Implemented", tier=3)) == 0.0
    assert scoring.control_credit(_ctl(eff=50, impl="Implemented", tier=2)) == pytest.approx(0.4)


def test_control_credit_unknown_tier_falls_back_to_self_declared():
    assert scoring.control_credit(_ctl(eff=100, impl="Implemented", tier=9)) == 0.5


def test_combined_reduction_overlap_rule():
    # Strongest control counts in full; second covers half of what remains.
    assert scoring.combined_reduction([]) == 0.0
    assert scoring.combined_reduction([0.6]) == 0.6
    # remaining = (1-0.6) * (1 - 0.4*0.5) = 0.4 * 0.8 = 0.32 -> reduction 0.68
    assert scoring.combined_reduction([0.4, 0.6]) == pytest.approx(0.68)
    # order must not matter
    assert scoring.combined_reduction([0.6, 0.4]) == scoring.combined_reduction([0.4, 0.6])
    # naive independent stacking would give 0.76; overlap rule stays below it
    assert scoring.combined_reduction([0.4, 0.6]) < 1 - (0.4 * 0.6)


def test_combined_reduction_never_reaches_one():
    assert scoring.combined_reduction([1.0, 1.0, 1.0]) <= 1.0
    assert scoring.combined_reduction([0.9, 0.9, 0.9, 0.9]) < 1.0


def test_reductions_split_by_control_type():
    r = scoring.reductions_for_controls([_ctl("Preventive", 100, tier=3), _ctl("Detective", 100, tier=3, cid="D"), _ctl("Corrective", 100, tier=3, cid="C")])
    assert r["likelihood_reduction"] == 1.0
    # detective + corrective: remaining = 0 * ... = 0 -> 1.0
    assert r["impact_reduction"] == 1.0
    assert r["likelihood_scale"] == pytest.approx(1 - scoring.LIKELIHOOD_DAMPING)
    assert r["impact_scale"] == pytest.approx(1 - scoring.IMPACT_DAMPING)


def test_suggested_residual_damping_and_floor():
    # Perfect controls on both axes: 5 * 0.4 = 2.0 -> 2 ; 5 * 0.6 = 3.0 -> 3
    res = scoring.suggested_residual(5, 5, [_ctl("Preventive", 100, tier=3), _ctl("Corrective", 100, tier=3, cid="C")])
    assert res["likelihood"] == 2
    assert res["impact"] == 3
    # Never below 1 even at inherent 1
    res = scoring.suggested_residual(1, 1, [_ctl("Preventive", 100, tier=3), _ctl("Corrective", 100, tier=3, cid="C")])
    assert res["likelihood"] == 1 and res["impact"] == 1
    # No controls: residual equals inherent
    res = scoring.suggested_residual(4, 3, [])
    assert (res["likelihood"], res["impact"]) == (4, 3)


def test_ransomware_worked_example_matches_methodology_doc():
    """Hand-computed figures in docs/METHODOLOGY.md must stay in sync with the code."""
    controls = [
        _ctl("Preventive", 85, "Implemented", 2, "mfa"),
        _ctl("Detective", 80, "Implemented", 3, "edr"),
        _ctl("Corrective", 90, "Partial", 1, "backups"),
        _ctl("Corrective", 70, "Implemented", 1, "ir_plan"),
        _ctl("Preventive", 40, "Implemented", 2, "awareness"),
    ]
    res = scoring.suggested_residual(3, 5, controls)
    assert res["likelihood_reduction"] == pytest.approx(0.7312, abs=1e-4)
    assert res["impact_reduction"] == pytest.approx(0.8536, abs=1e-4)
    assert res["likelihood_scale"] == pytest.approx(0.5613, abs=1e-4)
    assert res["impact_scale"] == pytest.approx(0.6586, abs=1e-4)
    assert (res["likelihood"], res["impact"]) == (2, 3)


# ----------------------------------------------------------------- FAIR

LEF = (0.1, 0.5, 1.5)
LM = (50_000, 500_000, 5_000_000)


def test_simulate_is_deterministic_for_same_seed():
    a = scoring.simulate(LEF, LM, n=2000, seed_key="RISK-0001")
    b = scoring.simulate(LEF, LM, n=2000, seed_key="RISK-0001")
    assert a["ale_mean"] == b["ale_mean"]
    assert a["ale_p90"] == b["ale_p90"]
    assert a["raw"] == b["raw"]


def test_simulate_differs_for_different_seed():
    a = scoring.simulate(LEF, LM, n=2000, seed_key="RISK-0001")
    b = scoring.simulate(LEF, LM, n=2000, seed_key="RISK-0002")
    assert a["ale_mean"] != b["ale_mean"]


def test_simulate_scaling_lowers_losses():
    base = scoring.simulate(LEF, LM, n=3000, seed_key="k")
    less_freq = scoring.simulate(LEF, LM, n=3000, seed_key="k", lef_scale=0.5)
    less_mag = scoring.simulate(LEF, LM, n=3000, seed_key="k", lm_scale=0.5)
    assert less_freq["ale_mean"] < base["ale_mean"]
    assert less_mag["ale_mean"] < base["ale_mean"]
    assert less_mag["ale_mean"] == pytest.approx(base["ale_mean"] * 0.5, rel=1e-6)


def test_simulate_output_shape_and_percentile_order():
    s = scoring.simulate(LEF, LM, n=1000, seed_key="shape")
    assert s["samples"] == 1000
    assert 0 <= s["ale_median"] <= s["ale_p90"] <= s["ale_p95"] <= s["ale_max"]
    assert len(s["exceedance_curve"]) == 21
    assert s["exceedance_curve"][0]["probability_exceeding"] == 1.0
    assert s["exceedance_curve"][-1]["probability_exceeding"] == 0.0
    assert s["ale_simple"] == pytest.approx(0.5 * 500_000)
    assert 0 < s["probability_of_loss"] <= 1


def test_simulate_zero_frequency_means_zero_loss():
    s = scoring.simulate((0, 0, 0), LM, n=500, seed_key="z")
    assert s["ale_mean"] == 0 and s["probability_of_loss"] == 0


def test_default_fair_from_qualitative_is_ordered():
    for L in range(1, 6):
        for I in range(1, 6):
            d = scoring.default_fair_from_qualitative(L, I)
            assert d["lef_min"] <= d["lef_likely"] <= d["lef_max"]
            assert d["lm_min"] <= d["lm_likely"] <= d["lm_max"]
            assert d["lm_min"] > 0


def test_has_fair_inputs():
    assert not scoring.has_fair_inputs({"lef_min": 1})
    assert scoring.has_fair_inputs({"lef_min": 0, "lef_likely": 1, "lef_max": 2, "lm_min": 1, "lm_likely": 2, "lm_max": 3})


# ----------------------------------------------------------------- appetite

def test_appetite_check():
    assert scoring.appetite_check(10, None, None) == {"defined": False, "breach": False, "reasons": []}
    app = {"max_residual_score": 9, "max_ale": 100_000}
    ok = scoring.appetite_check(9, 50_000, app)
    assert ok["defined"] and not ok["breach"]
    by_score = scoring.appetite_check(10, 50_000, app)
    assert by_score["breach"] and len(by_score["reasons"]) == 1
    by_ale = scoring.appetite_check(4, 150_000, app)
    assert by_ale["breach"] and "90th percentile" in by_ale["reasons"][0]
    both = scoring.appetite_check(12, 150_000, app)
    assert len(both["reasons"]) == 2
