"""ExploitStore — the versioned, queryable regression memory.

A confirmed exploit is stored keyed by ``(category, reproduction_seed)`` with the
target version it was found on and a provenance label (``seeded`` vs
``mutation_discovered``). On every re-verification the store detects the classic
regression: an exploit marked ``fixed`` that verdicts ``success`` again flips to
``regressed`` and names the version that lost the protection. This is what makes a
"pass" mean *the vulnerability is fixed*, not *the attack string stopped working*.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Optional

from redteam.contracts import ConfirmedExploit

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS exploit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    reproduction_seed TEXT NOT NULL,
    severity TEXT NOT NULL,
    provenance TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen_sha TEXT NOT NULL,
    fixed_in_sha TEXT,
    last_verified_sha TEXT,
    last_verified_verdict TEXT,
    last_verified_ts REAL,
    schema_version INTEGER NOT NULL,
    UNIQUE(category, reproduction_seed)
);
"""


class ExploitStore:
    def __init__(self, path: str = ":memory:", now=None):
        # check_same_thread=False: the console shares one store across FastAPI worker
        # threads (campaign thread writes; request threads read). Access is low-volume and
        # sqlite serializes at the module level, so a single shared connection is safe here.
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(_DDL)
        self.conn.commit()
        self._now = now or time.time

    def add(self, exploit: ConfirmedExploit, provenance: str, first_seen_sha: str) -> int:
        """Idempotent by (category, reproduction_seed). Returns the row id."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO exploit "
            "(category, reproduction_seed, severity, provenance, status, first_seen_sha, schema_version) "
            "VALUES (?,?,?,?,'open',?,?)",
            (exploit.category, exploit.reproduction_seed, exploit.severity, provenance,
             first_seen_sha, SCHEMA_VERSION),
        )
        self.conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        row = self.conn.execute(
            "SELECT id FROM exploit WHERE category=? AND reproduction_seed=?",
            (exploit.category, exploit.reproduction_seed),
        ).fetchone()
        return row["id"]

    def mark_fixed(self, category: str, reproduction_seed: str, fixed_in_sha: str) -> None:
        self.conn.execute(
            "UPDATE exploit SET status='fixed', fixed_in_sha=? WHERE category=? AND reproduction_seed=?",
            (fixed_in_sha, category, reproduction_seed),
        )
        self.conn.commit()

    def verify(self, category: str, reproduction_seed: str, verdict: str, target_version: str) -> str:
        """Record a re-verification. A 'fixed' exploit that succeeds again REGRESSES. Returns new status."""
        row = self.conn.execute(
            "SELECT status FROM exploit WHERE category=? AND reproduction_seed=?",
            (category, reproduction_seed),
        ).fetchone()
        if row is None:
            return "unknown"
        status = row["status"]
        if status == "fixed" and verdict == "success":
            status = "regressed"  # reappearance alarm — the fix at fixed_in_sha lost its protection
        elif status in ("open", "regressed") and verdict != "success":
            status = "open"  # still tracked; a single non-success doesn't declare it fixed
        self.conn.execute(
            "UPDATE exploit SET status=?, last_verified_sha=?, last_verified_verdict=?, last_verified_ts=? "
            "WHERE category=? AND reproduction_seed=?",
            (status, target_version, verdict, self._now(), category, reproduction_seed),
        )
        self.conn.commit()
        return status

    def findings(self, status: Optional[str] = None, category: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM exploit"
        clauses, args = [], []
        if status:
            clauses.append("status=?")
            args.append(status)
        if category:
            clauses.append("category=?")
            args.append(category)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def regressions(self) -> list[dict]:
        return self.findings(status="regressed")

    def summary(self) -> dict:
        rows = self.findings()
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for r in rows:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
        return {"total": len(rows), "by_status": by_status, "by_severity": by_severity}

    def close(self) -> None:
        self.conn.close()


# The already-remediated finding the live loop must keep watching: the unauthenticated
# /ready information-disclosure (RT-005). Seeding it as ``fixed`` is what lets the loop show
# the fix HOLDING run after run — and flip it to ``regressed`` if the leak ever returns.
READY_FINDING_CATEGORY = "unauth_surface"
# Stable seed for the GET /ready probe: sha256("unauth_surface|/ready|GET /ready")[:16].
# Must match redteam.judge._stable_seed for that attempt, or the fixed marker won't line up.
READY_FINDING_SEED = "94c9db08ea414bd7"


def seed_fixed_findings(store: "ExploitStore", fixed_sha: str) -> None:
    """Record the remediated unauthenticated /ready info-disclosure finding as ``fixed``.

    Idempotent: safe to call on every startup. Records the finding (so the store has a row
    to re-verify) and marks it ``fixed`` at ``fixed_sha``. The next live ``store.verify()``
    then either confirms the fix holds (stays ``fixed``) or raises the regression alarm
    (``fixed -> regressed``) if the leak comes back.
    """
    from redteam.contracts import ConfirmedExploit, DeterministicEvidence

    exploit = ConfirmedExploit(
        attempt_id="seed-ready-info-disclosure",
        category=READY_FINDING_CATEGORY,
        severity="medium",
        deterministic_evidence=DeterministicEvidence(
            phi_leaked=False, scope_widened=False, uncited_survived=False
        ),
        reproduction_seed=READY_FINDING_SEED,
    )
    store.add(exploit, provenance="seeded", first_seen_sha=fixed_sha)
    store.mark_fixed(
        category=READY_FINDING_CATEGORY,
        reproduction_seed=READY_FINDING_SEED,
        fixed_in_sha=fixed_sha,
    )
