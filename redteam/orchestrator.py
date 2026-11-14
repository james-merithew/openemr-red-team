"""Orchestrator — the campaign brain (deterministic ranking + hard budget ceiling).

Reads the observability/store read-model and decides what the Red Team targets next
via a **deterministic** priority score — a reproducible, auditable ranking, not an LLM
guess (an AI orchestrator must never be able to talk itself past the spend ceiling):

    priority(category) = w1·coverage_gap + w2·open_finding_pressure
                       + w3·regression_risk + w4·resilience_downtrend

AI is used (later, optionally) only to propose the *mutation strategy* within the
chosen category; the category choice and the budget are deterministic. The budget is a
hard ceiling: campaigns stop when attempts/tokens/cost are spent, not when the model
gives up.
"""

from __future__ import annotations

from typing import Optional

from redteam.contracts import AttackBudget, AttackCategory, CampaignDirective, TargetDescriptor

# Default target endpoint per category (unauth needs no token; indirect enters via ingest).
_ENDPOINT: dict[str, str] = {
    "unauth_surface": "/ready",
    "prompt_injection_indirect": "/ingest",
}

_WEIGHTS = {"coverage_gap": 0.4, "open_finding_pressure": 0.3, "regression_risk": 0.2, "resilience_downtrend": 0.1}


def priority(metrics: dict) -> float:
    """Deterministic weighted score over a category's read-model metrics."""
    return round(sum(_WEIGHTS[k] * float(metrics.get(k, 0.0)) for k in _WEIGHTS), 6)


class Orchestrator:
    def __init__(self, budget: Optional[AttackBudget] = None, env: str = "local"):
        self.budget = budget or AttackBudget(max_attempts=6, max_tokens=8000, max_cost_usd=1.0)
        self.env = env

    def rank(self, read_model: dict[str, dict]) -> list[tuple[str, float]]:
        """Rank categories by descending priority; ties broken by name for determinism."""
        scored = [(cat, priority(m)) for cat, m in read_model.items()]
        return sorted(scored, key=lambda t: (-t[1], t[0]))

    def next_directive(self, read_model: dict[str, dict]) -> Optional[CampaignDirective]:
        ranked = self.rank(read_model)
        if not ranked:
            return None
        category: AttackCategory = ranked[0][0]  # type: ignore[assignment]
        endpoint = _ENDPOINT.get(category, "/chat")
        token_mode = "unauth" if endpoint == "/ready" else "minted"
        return CampaignDirective(
            target_category=category,
            target_endpoint=endpoint,
            attack_budget=self.budget,
            mutation_strategy="paraphrase",
            target_descriptor=TargetDescriptor(env=self.env, token_mode=token_mode),
            rationale=f"highest priority={ranked[0][1]} among {[c for c, _ in ranked]}",
        )

    def within_budget(self, attempts_spent: int, tokens_spent: int = 0, cost_spent: float = 0.0) -> bool:
        """Deterministic budget ceiling — an AI can never push past this."""
        return (attempts_spent < self.budget.max_attempts
                and tokens_spent < self.budget.max_tokens
                and cost_spent < self.budget.max_cost_usd)

    @staticmethod
    def read_model_from(store_summary: dict, resilience: dict, case_counts: dict, target_n: int = 3) -> dict[str, dict]:
        """Build a read-model from the store + last run: coverage gaps, open findings, regressions."""
        cats = set(case_counts) | set(resilience) | {"unauth_surface"}
        rm: dict[str, dict] = {}
        by_status = store_summary.get("by_status", {})
        for cat in cats:
            n = case_counts.get(cat, 0)
            rm[cat] = {
                "coverage_gap": max(0.0, (target_n - n) / target_n),
                "open_finding_pressure": min(1.0, by_status.get("open", 0) / 5.0),
                "regression_risk": min(1.0, by_status.get("regressed", 0) / 3.0),
                "resilience_downtrend": max(0.0, 1.0 - float(resilience.get(cat, 1.0))),
            }
        return rm
