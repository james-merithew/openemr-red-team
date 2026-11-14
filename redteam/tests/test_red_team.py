"""RedTeamAgent — generate + mutate + dispatch, budget-bounded, over the Target seam."""

from __future__ import annotations

from redteam.contracts import AttackBudget, CampaignDirective, TargetDescriptor
from redteam.generators.local import LocalDeterministicAttacks
from redteam.red_team import RedTeamAgent
from redteam.target_base import Target


class FakeTarget:
    version = "faketgt"

    def __init__(self):
        self.calls = 0

    def chat(self, pid, message, history=None):
        self.calls += 1
        return 200, {"briefing": [], "notes": "refused", "quarantined_count": 1}

    def ingest(self, pid, doc_type, filename, content, mime):
        return 200, {"status": "needs_review"}

    def ready(self):
        return 200, {"ready": True}

    def metrics(self, token=None):
        return 200, {"red_team": {}}


def _directive(category="cross_patient_exfil", endpoint="/chat", strategy="none", max_attempts=3):
    return CampaignDirective(
        target_category=category, target_endpoint=endpoint,
        attack_budget=AttackBudget(max_attempts=max_attempts, max_tokens=1000, max_cost_usd=1.0),
        mutation_strategy=strategy,
        target_descriptor=TargetDescriptor(env="local", token_mode="minted"),
    )


def test_fake_target_conforms():
    # fm: a target that drifts from the Target seam would break dispatch
    assert isinstance(FakeTarget(), Target)


def test_run_respects_budget_and_populates_attempts():
    # fm: the agent ignoring the budget, or emitting malformed attempts
    agent = RedTeamAgent(LocalDeterministicAttacks(), FakeTarget())
    attempts = agent.run(_directive(max_attempts=3))
    assert 1 <= len(attempts) <= 3
    for a in attempts:
        assert a.category == "cross_patient_exfil"
        assert a.request_transcript and a.response_transcript
        assert a.endpoint == "/chat" and a.target_version == "faketgt"


def test_mutation_lineage_recorded():
    # fm: mutation not actually applied -> no lineage, no mutation-family regression
    agent = RedTeamAgent(LocalDeterministicAttacks(), FakeTarget())
    attempts = agent.run(_directive(strategy="roleplay_frame", max_attempts=4))
    assert any(a.mutation_lineage == ["roleplay_frame"] for a in attempts)


def test_endpoint_dispatch_ready():
    # fm: unauth-surface attacks must hit /ready (no token), not /chat
    agent = RedTeamAgent(LocalDeterministicAttacks(), FakeTarget())
    attempts = agent.run(_directive(category="unauth_surface", endpoint="/ready", max_attempts=2))
    assert all(a.endpoint == "/ready" for a in attempts)
