"""The AttackGenerator seam — a typed Protocol so the generator is swappable.

Mirrors the ``copilot/app/rag/providers.py`` provider pattern: a
``@runtime_checkable`` Protocol plus a ``select_generator(settings)`` auto/keyless
ladder (in ``redteam.generators.__init__``). This is the deliberate answer to the
"frontier models refuse offensive workflows" concern — the concrete default is a
Claude generator, but a local/OSS uncensored model drops in without touching any
call site, and a keyless/hermetic env selects the deterministic local generator so
tests and the gate never need an API key.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from redteam.contracts import AttackCategory, MutationStrategy


@runtime_checkable
class AttackGenerator(Protocol):
    """Generates and mutates attack prompts. Output is untrusted by design.

    Implementations MUST degrade to a deterministic canned set on provider outage
    rather than raise — a refusing or unavailable generator yields *fewer* attacks,
    never a crashed run and never a false finding (the Judge veto is the guarantee).
    """

    name: str

    def generate(self, category: AttackCategory, seeds: list[str], n: int) -> list[str]:
        """Return up to ``n`` fresh attack prompts for ``category``, informed by ``seeds``."""
        ...

    def mutate(self, attack: str, strategy: MutationStrategy, n: int) -> list[str]:
        """Return up to ``n`` mutated variants of ``attack`` under ``strategy``."""
        ...
