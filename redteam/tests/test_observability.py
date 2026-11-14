"""RedTeam observability substrate — counters the Orchestrator reads; never fatal."""

from __future__ import annotations

from redteam import observability as obs


def setup_function(_):
    obs.reset()


def test_counters_and_success_rate():
    # fm: the orchestrator can't see per-category attempts / success rate
    obs.record_attempt(category="unauth_surface", endpoint="/ready")
    obs.record_attempt(category="unauth_surface", endpoint="/ready")
    obs.record_verdict(category="unauth_surface", verdict="fail")
    obs.record_verdict(category="cross_patient_exfil", verdict="success")
    s = obs.summary()
    assert s["attempts_by_category"]["unauth_surface"] == 2
    assert s["verdicts"]["success"] == 1 and s["verdicts"]["fail"] == 1
    assert s["attack_success_rate"] == 0.5


def test_findings_by_severity_and_status():
    # fm: finding status/severity not surfaced -> can't answer 'open vs resolved'
    obs.record_finding(category="cross_patient_exfil", severity="critical", status="pending_review")
    s = obs.summary()
    assert s["findings_by_severity"]["critical"] == 1
    assert s["findings_by_status"]["pending_review"] == 1


def test_never_fatal():
    # fm: an observability call must never crash a red-team run
    obs.record_attempt(category="x", endpoint="y", extra="ignored")  # unexpected kwargs tolerated
    assert isinstance(obs.summary(), dict)
