"""Adversarial runner — hermetic end-to-end over the real seed cases + leak capture."""

from __future__ import annotations

from redteam.cases import load_cases
from redteam.runner import run_suite
from redteam.store import ExploitStore
from redteam.target import TargetClient


def test_hermetic_suite_runs_end_to_end():
    # fm: the harness can't actually drive the case suite through judge+store
    cases = load_cases()
    assert len(cases) >= 3  # >=3 categories required
    store = ExploitStore()
    out = run_suite(TargetClient(mode="hermetic"), cases, store=store)
    assert out["n_cases"] == len(cases)
    assert all(r["verdict"] in ("success", "fail", "partial") for r in out["results"])
    assert "by_category" in out["summary"] and isinstance(out["summary"]["findings"], int)


def test_loop_catches_and_records_injected_leak():
    # fm: THE point of the platform — a real leak must be judged 'success' and stored
    leaky = TargetClient(
        mode="hermetic",
        response_fn=lambda pid, msg: {
            "briefing": [{"text": "patient SSN 8675309", "source_refs": []}],  # uncited + PHI sentinel
            "notes": "", "quarantined_count": 0,
        },
    )
    # pick a /chat case that asserts the invariants this leak violates
    cases = [c for c in load_cases() if c.input.surface == "/chat"
             and set(c.expected.evaluated_invariants()) & {"no_uncited_claim_surfaced", "no_phi_in_logs"}]
    assert cases, "need a /chat case asserting uncited/phi invariants"
    store = ExploitStore()
    out = run_suite(leaky, cases[:1], store=store)
    assert out["results"][0]["verdict"] == "success"
    assert out["results"][0]["severity"] in ("critical", "high")
    assert store.summary()["total"] == 1  # the finding was recorded for regression


def test_hermetic_stub_is_defended_by_construction():
    # fm: the stub target should DEFEND (so a clean hermetic run has ~no findings)
    cases = [c for c in load_cases() if c.input.surface == "/chat"]
    out = run_suite(TargetClient(mode="hermetic"), cases)
    assert out["summary"]["findings"] == 0  # a benign stub yields no false findings
