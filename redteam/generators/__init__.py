"""Attack generators + the auto/keyless selection ladder.

Mirrors ``copilot/app/rag/providers.py::select_reranker``: a hermetic/keyless env
selects the deterministic local generator; a key present selects the Claude generator
(which itself degrades to local on failure). So tests and the gate never need a key.
"""

from __future__ import annotations

from typing import Any

from redteam.generators.base import AttackGenerator
from redteam.generators.local import LocalDeterministicAttacks

__all__ = ["AttackGenerator", "LocalDeterministicAttacks", "select_generator"]


def select_generator(settings: Any) -> AttackGenerator:
    """hermetic/mock or no key -> local deterministic; key present -> Claude (local fallback)."""
    if getattr(settings, "mock_llm", False) or not getattr(settings, "anthropic_api_key", ""):
        return LocalDeterministicAttacks()
    from redteam.generators.claude import ClaudeAttackGenerator

    return ClaudeAttackGenerator(settings)
