"""PHI-safe observability substrate for the adversarial platform.

Self-contained, thread-safe, never-fatal counters — the data substrate the Orchestrator
reads to decide what to attack next, and the human-facing summary. Kept in ``redteam/``
(not bolted onto the co-pilot's ``MetricsSummary``) so the shipped golden gate stays
untouched. Records enum/count only — attack/finding free text NEVER reaches a recorder
(it rides the message payload). Wiring this summary into the co-pilot ``/dashboard`` is
an additive follow-up.

Answers the observability requirement: per-category attempt counts, verdict pass/fail
rates, findings by severity/status, and (via the store's ``target_version``) resilience
across system versions.
"""

from __future__ import annotations

import threading
from typing import Any


class RedTeamMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._attempts: dict[str, int] = {}
            self._verdicts: dict[str, int] = {}
            self._findings_sev: dict[str, int] = {}
            self._findings_status: dict[str, int] = {}

    def record_attempt(self, category: str, endpoint: str) -> None:
        with self._lock:
            self._attempts[category] = self._attempts.get(category, 0) + 1

    def record_verdict(self, category: str, verdict: str, consistent: bool = True) -> None:
        with self._lock:
            self._verdicts[verdict] = self._verdicts.get(verdict, 0) + 1

    def record_finding(self, category: str, severity: str, status: str = "open") -> None:
        with self._lock:
            self._findings_sev[severity] = self._findings_sev.get(severity, 0) + 1
            self._findings_status[status] = self._findings_status.get(status, 0) + 1

    def summary(self) -> dict:
        with self._lock:
            total_v = sum(self._verdicts.values())
            success = self._verdicts.get("success", 0)
            return {
                "attempts_by_category": dict(self._attempts),
                "verdicts": dict(self._verdicts),
                "attack_success_rate": round(success / total_v, 4) if total_v else 0.0,
                "findings_by_severity": dict(self._findings_sev),
                "findings_by_status": dict(self._findings_status),
            }


_METRICS = RedTeamMetrics()


def record_attempt(*, category: str, endpoint: str, **_: Any) -> None:
    try:
        _METRICS.record_attempt(category, endpoint)
    except Exception:  # noqa: BLE001 - observability is never fatal
        pass


def record_verdict(*, category: str, verdict: str, consistent: bool = True, **_: Any) -> None:
    try:
        _METRICS.record_verdict(category, verdict, consistent)
    except Exception:  # noqa: BLE001
        pass


def record_finding(*, category: str, severity: str, status: str = "open", **_: Any) -> None:
    try:
        _METRICS.record_finding(category, severity, status)
    except Exception:  # noqa: BLE001
        pass


def summary() -> dict:
    return _METRICS.summary()


def reset() -> None:
    _METRICS.reset()
