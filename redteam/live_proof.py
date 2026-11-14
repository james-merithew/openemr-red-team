"""Bounded live proof — attack the DEPLOYED fork's unauthenticated surface, judge,
document, store.

This is the only evidence about the real target (a green hermetic gate only proves the
harness works). It is deliberately bounded: unauth-surface cases only (no token, no
rate-limit hammering), against our OWN fork on SYNTHETIC demo data. Findings are judged
deterministically, stored as regression cases, and written to a markdown report with
honest provenance (``seeded`` = from our threat model; never presented as a novel 0-day).

Usage:
    python -m redteam.live_proof [--base-url URL] [--category unauth_surface] [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Optional

from redteam import invariants, runner
from redteam.cases import load_cases
from redteam.contracts import AttackAttempt
from redteam.documentation import DocumentationAgent
from redteam.judge import AdversarialJudge
from redteam.store import ExploitStore


def run(base_url: Optional[str] = None, category: str = "unauth_surface", token: Optional[str] = None) -> dict:
    target = runner._build_target("prod", base_url or runner.PROD_URL, token)
    cases = [c for c in load_cases() if c.category == category]
    judge, doc, store = AdversarialJudge(), DocumentationAgent(), ExploitStore()
    findings, results = [], []

    for case in cases:
        attack, surface, pid, expected = runner._case_attack(case)
        status, body = runner._dispatch(target, surface, attack, pid)
        attempt = AttackAttempt(category=case.category, request_transcript=attack,
                                response_transcript=json.dumps(body), endpoint=surface,
                                target_version=target.version)
        v = judge.verdict(attempt, status, body, expected, runner.SENTINELS, runner.FOREIGN_PIDS)
        _, checks = invariants.evaluate(attempt, status, body, expected, runner.SENTINELS, runner.FOREIGN_PIDS)
        row = {"case_id": case.id, "category": case.category, "verdict": v.verdict,
               "status_code": status, "invariants": checks, "provenance": "seeded"}
        if v.verdict == "success":
            ex = judge.confirmed_exploit(v, attempt)
            store.add(ex, "seeded", target.version)
            rep = doc.report(ex, attempt, provenance="seeded")
            row["severity"] = rep["severity"]
            findings.append(rep)
        results.append(row)

    return {"target": base_url or runner.PROD_URL, "target_version": target.version,
            "n_cases": len(results), "results": results, "findings": findings,
            "store": store.summary()}


def _markdown(out: dict) -> str:
    lines = [
        "# Live proof — adversarial run against the deployed Co-Pilot",
        "",
        f"- **Target:** {out['target']}  \n- **Cases run:** {out['n_cases']}  "
        f"\n- **Confirmed findings:** {len(out['findings'])}",
        "",
        "> This is REAL evidence about the deployed target (synthetic demo data, our own fork). "
        "A green hermetic gate only proves the harness works — this run is the target evidence. "
        "Findings are labeled by provenance; none is presented as a novel 0-day.",
        "",
        "## Per-case result",
        "",
        "| case | category | status | verdict | invariants held |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in out["results"]:
        held = all(r["invariants"].values())
        lines.append(f"| {r['case_id']} | {r['category']} | {r['status_code']} | {r['verdict']} | {held} |")
    for rep in out["findings"]:
        lines += ["", "---", "", rep["markdown"]]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Bounded live proof against the deployed fork")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--category", default="unauth_surface")
    ap.add_argument("--token-env", default="COPILOT_LIVE_TOKEN")
    ap.add_argument("--out", default="defense/week3/live_proof.md")
    args = ap.parse_args(argv)
    import os
    out = run(args.base_url, args.category, os.environ.get(args.token_env))
    md = _markdown(out)
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(md, encoding="utf-8")
    print(f"[live-proof] target={out['target']} cases={out['n_cases']} findings={len(out['findings'])} -> {args.out}")
    for rep in out["findings"]:
        print(f"  FINDING {rep['report_id'][:8]} {rep['severity']} {rep['status']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
