"""ExploitStore — versioned regression memory + reappearance detection."""

from __future__ import annotations

from redteam.contracts import ConfirmedExploit, DeterministicEvidence
from redteam.store import ExploitStore

EV = DeterministicEvidence(phi_leaked=True, scope_widened=False, uncited_survived=False)


def _exploit(seed="seed-1", category="prompt_injection_indirect", severity="high"):
    return ConfirmedExploit(attempt_id="a1", category=category, severity=severity,
                            deterministic_evidence=EV, reproduction_seed=seed)


def test_add_is_idempotent_and_queryable():
    # fm: duplicate findings inflating the store / an open finding not queryable
    s = ExploitStore()
    id1 = s.add(_exploit(), "seeded", "sha-A")
    id2 = s.add(_exploit(), "seeded", "sha-A")  # same (category, seed)
    assert id1 == id2
    assert len(s.findings(status="open")) == 1


def test_reappearance_flips_fixed_to_regressed():
    # fm: a previously-fixed vuln silently coming back (the classic regression)
    s = ExploitStore()
    s.add(_exploit(), "seeded", "sha-A")
    s.mark_fixed("prompt_injection_indirect", "seed-1", "sha-B")
    assert s.findings(status="fixed")
    new = s.verify("prompt_injection_indirect", "seed-1", "success", "sha-C")
    assert new == "regressed"
    assert len(s.regressions()) == 1


def test_fixed_stays_fixed_when_defense_holds():
    # fm: a green regression run wrongly reopening a genuinely-fixed finding
    s = ExploitStore()
    s.add(_exploit(), "seeded", "sha-A")
    s.mark_fixed("prompt_injection_indirect", "seed-1", "sha-B")
    assert s.verify("prompt_injection_indirect", "seed-1", "fail", "sha-C") == "fixed"


def test_summary_counts():
    # fm: observability can't report finding status/severity distribution
    s = ExploitStore()
    s.add(_exploit(seed="s1", severity="critical"), "seeded", "sha-A")
    s.add(_exploit(seed="s2", severity="high"), "mutation_discovered", "sha-A")
    summ = s.summary()
    assert summ["total"] == 2
    assert summ["by_severity"]["critical"] == 1 and summ["by_status"]["open"] == 2
