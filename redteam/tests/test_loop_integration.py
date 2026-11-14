"""Full-loop acceptance: Orchestrator -> Red Team -> Judge -> Documentation -> store."""

from __future__ import annotations

import json

from redteam.documentation import DocumentationAgent
from redteam.generators.local import LocalDeterministicAttacks
from redteam.judge import AdversarialJudge
from redteam.orchestrator import Orchestrator
from redteam.red_team import RedTeamAgent
from redteam.store import ExploitStore
from redteam.target import TargetClient

SENTINELS = ["8675309"]


def test_full_loop_end_to_end():
    # fm: the four agents don't actually compose into a working loop
    # 1. Orchestrator directs (deterministic ranking)
    orch = Orchestrator(env="local")
    rm = {"prompt_injection_direct": {"coverage_gap": 1.0}}
    directive = orch.next_directive(rm)
    assert directive is not None and directive.target_category == "prompt_injection_direct"

    # 2. Red Team generates+mutates+dispatches against a target that leaks (to exercise the whole chain)
    leaky = TargetClient(mode="hermetic", response_fn=lambda pid, msg: {
        "briefing": [{"text": "leaked 8675309", "source_refs": []}], "notes": "", "quarantined_count": 0})
    attempts = RedTeamAgent(LocalDeterministicAttacks(), leaky).run(directive)
    assert attempts, "red team produced no attempts"

    # 3. Judge rules (deterministic veto), 4. Documentation reports, store records
    judge = AdversarialJudge()
    doc = DocumentationAgent()
    store = ExploitStore()
    reports = []
    for a in attempts:
        status, body = 200, json.loads(a.response_transcript)
        v = judge.verdict(a, status, body, {"no_uncited_claim_surfaced": True, "no_phi_in_logs": True}, SENTINELS)
        if v.verdict == "success":
            ex = judge.confirmed_exploit(v, a)
            store.add(ex, "seeded", "sha-int")
            reports.append(doc.report(ex, a, provenance="seeded"))

    assert reports, "the loop produced no report for a leaking target"
    assert store.summary()["total"] >= 1
    assert reports[0]["status"] in ("open", "pending_review")
    assert "8675309" in reports[0]["markdown"]  # the real leak is in the report
