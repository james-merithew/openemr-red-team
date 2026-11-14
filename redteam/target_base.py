"""The Target seam — a typed Protocol for the system under test.

The Red Team dispatches attacks through this interface, so it never imports a
concrete client and can be tested against a fake. Lane 1's ``TargetClient``
implements it (modes: hermetic stub / local dev-mode HTTP / prod HTTP); the runner
wires the concrete client to the agents. Every method returns ``(status_code, body)``
where ``body`` is the parsed JSON (an ``AgentResponse``-shaped dict for ``chat``).
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class Target(Protocol):
    """The Clinical Co-Pilot under test (read-only; attacked, never mutated)."""

    version: str  # git_sha of the target under test, or "hermetic"/"unknown"

    def chat(
        self, pid: int, message: str, history: Optional[list[dict]] = None
    ) -> tuple[int, dict]:
        """POST /chat — returns (status, AgentResponse-shaped body)."""
        ...

    def ingest(
        self, pid: int, doc_type: str, filename: str, content: bytes, mime: str
    ) -> tuple[int, dict]:
        """POST /ingest (multipart) — returns (status, IngestResult-shaped body)."""
        ...

    def ready(self) -> tuple[int, dict]:
        """GET /ready (no auth) — returns (status, readiness body)."""
        ...

    def metrics(self, token: Optional[str] = None) -> tuple[int, dict]:
        """GET /metrics/summary — returns (status, counters body)."""
        ...
