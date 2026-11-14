"""Orchestrator — deterministic ranking + hard budget ceiling."""

from __future__ import annotations

from redteam.contracts import AttackBudget, CampaignDirective
from redteam.orchestrator import Orchestrator, priority


def test_priority_is_deterministic_weighted():
    # fm: a non-reproducible target-selection can't be audited or defended
    m = {"coverage_gap": 1.0, "open_finding_pressure": 0.0, "regression_risk": 0.0, "resilience_downtrend": 0.0}
    assert priority(m) == 0.4  # w1 only
    assert priority(m) == priority(dict(m))  # stable


def test_rank_orders_by_score_then_name():
    # fm: nondeterministic tie-breaking would make the campaign order unstable
    rm = {
        "unauth_surface": {"coverage_gap": 1.0},
        "cross_patient_exfil": {"regression_risk": 1.0},  # 0.2
        "persona_privilege": {"coverage_gap": 1.0},        # 0.4, ties unauth -> name breaks tie
    }
    ranked = Orchestrator().rank(rm)
    assert ranked[0][0] in ("persona_privilege", "unauth_surface")
    assert ranked[-1][0] == "cross_patient_exfil"  # lowest score last


def test_next_directive_targets_top_and_picks_endpoint():
    # fm: the directive not routing unauth attacks to /ready (no token) breaks the live path
    rm = {"unauth_surface": {"coverage_gap": 1.0}, "cross_patient_exfil": {"coverage_gap": 0.1}}
    d = Orchestrator(env="prod").next_directive(rm)
    assert isinstance(d, CampaignDirective)
    assert d.target_category == "unauth_surface"
    assert d.target_endpoint == "/ready" and d.target_descriptor.token_mode == "unauth"


def test_budget_ceiling_is_hard():
    # fm: an AI orchestrator talking itself past the spend ceiling
    o = Orchestrator(budget=AttackBudget(max_attempts=3, max_tokens=100, max_cost_usd=1.0))
    assert o.within_budget(attempts_spent=2) is True
    assert o.within_budget(attempts_spent=3) is False  # ceiling reached, stop


def test_read_model_from_store():
    # fm: the orchestrator can't see coverage gaps / regressions -> attacks randomly
    rm = Orchestrator.read_model_from(
        store_summary={"by_status": {"open": 2, "regressed": 1}},
        resilience={"unauth_surface": 0.9},
        case_counts={"unauth_surface": 1},
        target_n=3,
    )
    assert rm["unauth_surface"]["coverage_gap"] > 0     # only 1 of 3 cases
    assert rm["unauth_surface"]["regression_risk"] > 0  # a regression exists
