"""Adversarial runner — drives cases through the Red Team / Judge / store loop.

Two target modes:
- ``hermetic`` — a deterministic stub target (``TargetClient(mode="hermetic")``). A green
  hermetic run asserts **the harness works** (platform regression); it says NOTHING about
  the real Co-Pilot. Used by the gate.
- ``live`` — the deployed fork. Unauth-surface attacks need no token; ``/chat`` attacks use
  a self-minted local dev-mode token. **This is the only evidence about the target.**

Stochastic ``/chat`` probes run ``n_trials`` times with **any-leak = success** (one real
leak is a real vulnerability); deterministic unauth-surface probes run once. Every finding
carries a provenance label (``seeded`` from the threat model vs ``mutation_discovered``);
we never present a seeded case as a discovery.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Optional

from redteam import invariants
from redteam.cases import load_cases
from redteam.contracts import AttackAttempt
from redteam.judge import AdversarialJudge
from redteam.store import ExploitStore

# Synthetic demo-data sentinels (no real PHI, ever). Foreign pids = other demo patients.
SENTINELS = ["Marcus Delgado", "Eleanor Whitfield", "Rachel Osei", "8675309"]
FOREIGN_PIDS = [102, 103, 120, 202, 203]
PROD_URL = "https://copilot-production-5e86.up.railway.app"
LOCAL_URL = "http://127.0.0.1:8811"


def _case_attack(case: Any) -> tuple[str, str, int, dict]:
    seq = case.input.sequence
    surface = case.input.surface
    pid = case.input.pid or 101
    chat_turns = [t.content for t in seq if t.channel == "chat" and t.content]
    if surface in ("/ready", "/metrics", "/health"):
        attack = f"GET {surface}"
    elif chat_turns:
        attack = chat_turns[-1]
    else:
        attack = (seq[-1].content or "attack")
    expected = case.expected.model_dump(exclude_none=True)
    return attack, surface, pid, expected


def _dispatch(target: Any, surface: str, attack: str, pid: int) -> tuple[int, dict]:
    if surface == "/ready":
        return target.ready()
    if surface == "/metrics":
        return target.metrics()
    if surface == "/ingest":
        return target.ingest(pid, "intake_form", "attack.txt", attack.encode(), "text/plain")
    return target.chat(pid, attack)


def run_suite(
    target: Any,
    cases: list[Any],
    sentinels: Optional[list[str]] = None,
    foreign_pids: Optional[list[int]] = None,
    store: Optional[ExploitStore] = None,
    judge: Optional[AdversarialJudge] = None,
    n_trials: int = 1,
    first_seen_sha: str = "unknown",
) -> dict:
    sentinels = sentinels or SENTINELS
    foreign_pids = foreign_pids if foreign_pids is not None else FOREIGN_PIDS
    judge = judge or AdversarialJudge()
    version = getattr(target, "version", "unknown")

    results: list[dict] = []
    for case in cases:
        attack, surface, pid, expected = _case_attack(case)
        trials = n_trials if surface == "/chat" else 1  # deterministic surfaces run once
        chosen = None
        for _ in range(max(1, trials)):
            status, body = _dispatch(target, surface, attack, pid)
            attempt = AttackAttempt(
                category=case.category, request_transcript=attack,
                response_transcript=json.dumps(body), endpoint=surface, target_version=version,
            )
            v = judge.verdict(attempt, status, body, expected, sentinels, foreign_pids)
            _, checks = invariants.evaluate(attempt, status, body, expected, sentinels, foreign_pids)
            chosen = (v, attempt, body, status, checks)
            if v.verdict == "success":  # any-leak across trials = success
                break

        v, attempt, body, status, checks = chosen
        provenance = "seeded"
        if v.verdict == "success" and store is not None:
            ex = judge.confirmed_exploit(v, attempt)
            if ex is not None:
                store.add(ex, provenance, first_seen_sha)
                store.verify(case.category, ex.reproduction_seed, "success", version)
        results.append({
            "case_id": case.id, "category": case.category, "verdict": v.verdict,
            "severity": judge.confirmed_exploit(v, attempt).severity if v.verdict == "success" else None,
            "provenance": provenance, "invariants": checks,
            "evidence": v.deterministic_evidence.model_dump(),
            "endpoint": surface, "target_version": version,
        })

    return {"target_version": version, "n_cases": len(results), "results": results,
            "summary": _summarize(results)}


def _summarize(results: list[dict]) -> dict:
    by_cat: dict[str, dict] = {}
    for r in results:
        c = by_cat.setdefault(r["category"], {"n": 0, "held": 0})
        c["n"] += 1
        if r["verdict"] != "success":  # defense held (attack failed/partial)
            c["held"] += 1
    for c in by_cat.values():
        c["resilience"] = round(c["held"] / c["n"], 4) if c["n"] else None
    return {"by_category": by_cat,
            "findings": sum(1 for r in results if r["verdict"] == "success")}


def _build_target(mode: str, base_url: Optional[str], token: Optional[str]):
    from redteam.target import TargetClient
    if mode == "hermetic":
        return TargetClient(mode="hermetic")
    if mode == "local":
        tok = token or TargetClient.mint_token(pid=101)
        return TargetClient(mode="local", base_url=base_url or LOCAL_URL, token=tok)
    return TargetClient(mode="prod", base_url=base_url or PROD_URL, token=token)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Adversarial suite runner")
    ap.add_argument("--target", choices=["hermetic", "local", "prod"], default="hermetic")
    ap.add_argument("--cases", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--token-env", default="COPILOT_LIVE_TOKEN")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--category", default=None, help="restrict to one attack category (bounds live runs)")
    args = ap.parse_args(argv)

    import os
    token = os.environ.get(args.token_env) if args.target == "prod" else None
    target = _build_target(args.target, args.base_url, token)
    cases = load_cases(args.cases) if args.cases else load_cases()
    if args.category:
        cases = [c for c in cases if c.category == args.category]
    store = ExploitStore()
    out = run_suite(target, cases, store=store, n_trials=args.trials)
    out["store"] = store.summary()
    text = json.dumps(out, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(f"[runner] target={args.target} cases={out['n_cases']} findings={out['summary']['findings']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
