"""RedTeamAgent — generate + mutate + dispatch attacks against the target.

Fully untrusted by design: it produces hostile content and dispatches it through the
``Target`` Protocol, emitting one ``AttackAttempt`` per exchange. It respects the
Orchestrator's budget (``max_attempts``), logs enum-only via ``observability``, and
carries all free-text (attack/response) on the payload, never to a logger.
"""

from __future__ import annotations

import json
import uuid
from typing import Optional

from redteam import observability
from redteam.contracts import AttackAttempt, CampaignDirective
from redteam.generators.base import AttackGenerator
from redteam.target_base import Target


class RedTeamAgent:
    def __init__(self, generator: AttackGenerator, target: Target, correlation_id: Optional[str] = None):
        self.generator = generator
        self.target = target
        self.correlation_id = correlation_id or uuid.uuid4().hex

    def _dispatch(self, endpoint: str, attack: str, pid: int) -> tuple[int, dict]:
        if endpoint.startswith("/ingest"):
            return self.target.ingest(pid, "intake_form", "attack.txt", attack.encode(), "text/plain")
        if endpoint.startswith("/ready"):
            return self.target.ready()
        if endpoint.startswith("/metrics"):
            return self.target.metrics()
        return self.target.chat(pid, attack)  # default: /chat

    def run(self, directive: CampaignDirective, pid: int = 101) -> list[AttackAttempt]:
        budget = directive.attack_budget.max_attempts
        category = directive.target_category
        endpoint = directive.target_endpoint
        strategy = directive.mutation_strategy

        seeds = list(directive.seed_refs)
        base = self.generator.generate(category, seeds, budget)

        # Build the working set: base attacks, optionally expanded by mutation, capped at budget.
        work: list[tuple[str, list[str]]] = []  # (attack_text, lineage)
        for atk in base:
            work.append((atk, []))
            if strategy != "none":
                for mut in self.generator.mutate(atk, strategy, 2):
                    work.append((mut, [strategy]))
        work = work[:budget]

        conversation_id = uuid.uuid4().hex
        attempts: list[AttackAttempt] = []
        for seq, (attack, lineage) in enumerate(work):
            status, body = self._dispatch(endpoint, attack, pid)
            attempts.append(AttackAttempt(
                conversation_id=conversation_id,
                turn_seq=seq,
                category=category,
                mutation_lineage=lineage,
                request_transcript=attack,
                response_transcript=json.dumps(body),
                endpoint=endpoint,
                target_version=getattr(self.target, "version", "unknown"),
                correlation_id=self.correlation_id,
            ))
            observability.record_attempt(category=category, endpoint=endpoint)
        return attempts
