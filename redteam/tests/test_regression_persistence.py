"""The regression loop actually CLOSES across runs.

These guard the two bugs that made it structurally broken and amnesiac:
  1. the reproduction seed was ``attempt_id`` (a fresh uuid every run), so the store's
     UNIQUE(category, seed) key never matched the same exploit twice and
     ``fixed -> regressed`` could never fire;
  2. the live loop never seeded the already-fixed finding, so there was nothing to
     re-verify and no alarm could ever ring.
"""

from __future__ import annotations

from redteam.contracts import (
    AttackAttempt,
    ConfirmedExploit,
    DeterministicEvidence,
)
from redteam.judge import _stable_seed
from redteam.store import (
    READY_FINDING_CATEGORY,
    READY_FINDING_SEED,
    ExploitStore,
    seed_fixed_findings,
)

EV = DeterministicEvidence(phi_leaked=False, scope_widened=False, uncited_survived=False)


def _attempt(attempt_id: str) -> AttackAttempt:
    # Same attack surface; only the volatile attempt_id differs run-to-run.
    return AttackAttempt(
        attempt_id=attempt_id,
        category="unauth_surface",
        request_transcript="GET /ready",
        response_transcript="{}",
        endpoint="/ready",
        target_version="v1",
    )


def test_stable_seed_is_identical_across_runs_but_varies_by_attack():
    # fm: seed derived from attempt_id -> never matches the same exploit across runs.
    a1 = _attempt("uuid-aaaa")
    a2 = _attempt("uuid-bbbb")  # different fresh uuid, SAME attack
    assert a1.attempt_id != a2.attempt_id
    assert _stable_seed(a1) == _stable_seed(a2)  # stable across runs
    # And a MUTATED attack string yields a NEW seed (correctly a distinct finding).
    mutated = _attempt("uuid-cccc")
    mutated = mutated.model_copy(update={"request_transcript": "GET /ready?verbose=1"})
    assert _stable_seed(mutated) != _stable_seed(a1)
    # The published /ready seed constant matches what the judge computes for the probe.
    assert _stable_seed(a1) == READY_FINDING_SEED


def test_loop_closes_fixed_then_success_flips_to_regressed():
    # fm: a previously-fixed vuln silently reappearing goes undetected.
    s = ExploitStore(":memory:")
    seed = _stable_seed(_attempt("uuid-run-1"))
    ex = ConfirmedExploit(
        attempt_id="uuid-run-1", category="unauth_surface", severity="medium",
        deterministic_evidence=EV, reproduction_seed=seed,
    )
    s.add(ex, "seeded", "sha-A")
    s.mark_fixed("unauth_surface", seed, "sha-B")
    assert s.findings(status="fixed")

    # A LATER run (fresh attempt_id) recomputes the SAME stable seed and re-verifies.
    later_seed = _stable_seed(_attempt("uuid-run-2"))
    assert later_seed == seed  # the whole point: same attack -> same key
    new_status = s.verify("unauth_surface", later_seed, "success", "v2")
    assert new_status == "regressed"
    rows = s.findings(category="unauth_surface")
    assert len(rows) == 1 and rows[0]["status"] == "regressed"
    assert len(s.regressions()) == 1


def test_seed_fixed_findings_records_ready_as_fixed_and_is_idempotent():
    # fm: the live loop has nothing to re-verify, so the fix can never be shown holding.
    s = ExploitStore(":memory:")
    seed_fixed_findings(s, "deployed")
    seed_fixed_findings(s, "deployed")  # idempotent — no duplicate row
    rows = s.findings(category=READY_FINDING_CATEGORY)
    assert len(rows) == 1
    assert rows[0]["status"] == "fixed"
    assert rows[0]["reproduction_seed"] == READY_FINDING_SEED

    # Fix holds when the probe fails; regresses the moment it succeeds again.
    assert s.verify(READY_FINDING_CATEGORY, READY_FINDING_SEED, "fail", "v2") == "fixed"
    assert s.verify(READY_FINDING_CATEGORY, READY_FINDING_SEED, "success", "v3") == "regressed"
