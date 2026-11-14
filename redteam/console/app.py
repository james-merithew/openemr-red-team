"""Red Team Console — continuous adversarial evaluation of the deployed Clinical Co-Pilot.

On startup and every REDTEAM_CAMPAIGN_INTERVAL_S seconds this service runs a BOUNDED
campaign and caches the result:
  - the full HERMETIC suite (all attack categories) against a deterministic stub — proves
    the harness works and gives the OWASP coverage matrix;
  - a LIVE unauthenticated-surface probe against the deployed target (no token needed) —
    the real, current status of the target's attack surface.

It then serves a public, read-only dashboard (no login) at `/`, plus `/health`, `/ready`,
and `/api/summary` (JSON). It is deliberately bounded: one category live, on a long
interval, wrapped so a target outage degrades gracefully instead of crashing the console.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from html import escape

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from redteam import live_proof, owasp, runner
from redteam.cases import load_cases
from redteam.contracts import AttackAttempt
from redteam.judge import AdversarialJudge
from redteam.store import READY_FINDING_SEED, ExploitStore, seed_fixed_findings
from redteam.target import TargetClient

log = logging.getLogger("redteam.console")

TARGET_URL = os.environ.get("REDTEAM_TARGET_URL", runner.PROD_URL)
INTERVAL_S = int(os.environ.get("REDTEAM_CAMPAIGN_INTERVAL_S", "1800"))
LIVE_CATEGORY = "unauth_surface"  # the only category safely runnable against prod without a token
FIXED_SHA = os.environ.get("REDTEAM_FIXED_SHA", "deployed")

# PERSISTENT regression memory — spans campaigns so the fix -> verify loop actually closes.
# Default :memory: keeps a local run self-contained; set REDTEAM_STORE to a file to persist.
STORE = ExploitStore(path=os.environ.get("REDTEAM_STORE", ":memory:"))
if not STORE.findings():  # first boot: seed the already-remediated /ready finding as 'fixed'
    seed_fixed_findings(STORE, FIXED_SHA)

STATE: dict = {
    "ts": None, "target": TARGET_URL, "hermetic": None,
    "live": None, "live_err": None, "coverage": None, "n_cases": 0,
    "cycle": 0, "judge_ok": None,
}

# A KNOWN-LEAK /ready body: an unauthenticated readiness probe that discloses the full
# internal integration map. A working detector MUST flag this — it is the fixture the
# judge canary feeds itself each cycle to prove it can still SEE a leak.
_JUDGE_LEAK_BODY: dict = {
    "ready": True, "status": "ready",
    "checks": {
        "database": True, "llm": True, "observability": True, "vector_index": True,
        "reranker": True, "openemr_api": True, "ingest_db": True, "document_storage": True,
    },
}


def judge_canary() -> bool:
    """Test-the-tester: prove the deterministic judge still CATCHES a known /ready leak.

    Mirrors exactly how ``run_suite`` judges the unauth_surface case (same case ``expected``,
    same sentinels/foreign pids), but feeds a KNOWN-LEAK ``/ready`` body — the full internal
    integration map. A working detector MUST return a ``success`` verdict (the attack worked);
    if it does not, the invariant is blind and we render JUDGE BLIND. This is the anti-
    "marking its own homework" signal: the console proves its own detector still bites.
    """
    try:
        uas = next(c for c in load_cases() if c.category == "unauth_surface")
        _attack, _surface, _pid, expected = runner._case_attack(uas)
        attempt = AttackAttempt(
            category="unauth_surface", request_transcript="GET /ready",
            response_transcript=json.dumps(_JUDGE_LEAK_BODY), endpoint="/ready",
            target_version="canary",
        )
        v = AdversarialJudge().verdict(
            attempt, 200, _JUDGE_LEAK_BODY, expected, runner.SENTINELS, runner.FOREIGN_PIDS
        )
        return v.verdict == "success"  # a real leak MUST be caught; if not, the detector is blind
    except Exception:  # noqa: BLE001 — a broken canary means "can't prove it", never "safe"
        return False


def run_campaign() -> dict:
    """One bounded campaign (blocking; run via a worker thread)."""
    cases = load_cases()
    hermetic = runner.run_suite(TargetClient(mode="hermetic"), cases)
    live = None
    live_err = None
    try:
        # Pass the persistent store so store.verify() runs each cycle — this is what keeps
        # the fix HOLDING and flips to 'regressed' if the /ready leak ever returns.
        live = live_proof.run(base_url=TARGET_URL, category=LIVE_CATEGORY, store=STORE)
    except Exception as exc:  # noqa: BLE001 — a target outage must not crash the console
        live_err = f"{type(exc).__name__}: {exc}"
    return {
        "hermetic": hermetic,
        "live": live,
        "live_err": live_err,
        "coverage": owasp.coverage_matrix(cases),
        "n_cases": len(cases),
        # Test-the-tester: does the deterministic judge still catch a planted /ready leak?
        "judge_ok": judge_canary(),
        # Liveness cycle counter — proves "every N min" is real, not cron-theater.
        "cycle": STATE.get("cycle", 0) + 1,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


async def _campaign_loop() -> None:
    while True:
        try:
            res = await asyncio.to_thread(run_campaign)
            STATE.update(res)
        except Exception as exc:  # noqa: BLE001
            log.warning("campaign_failed error=%s", type(exc).__name__)
            STATE["live_err"] = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(INTERVAL_S)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_campaign_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(
    title="Red Team Console",
    version="1.0.0",
    docs_url=None, redoc_url=None, openapi_url=None,  # the console practices what it audits
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict:
    return {"status": "alive"}


@app.get("/ready")
def ready() -> JSONResponse:
    ok = STATE["ts"] is not None
    return JSONResponse(
        status_code=200,
        content={"ready": ok, "target": TARGET_URL, "last_run": STATE["ts"],
                 "status": "ready" if ok else "warming_up"},
    )


@app.get("/api/summary")
def api_summary() -> JSONResponse:
    return JSONResponse(_public_summary())


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(_render(STATE))


# --------------------------------------------------------------------------------------


def _public_summary() -> dict:
    h = STATE.get("hermetic") or {}
    live = STATE.get("live") or {}
    return {
        "target": TARGET_URL,
        "last_run": STATE["ts"],
        "hermetic_summary": h.get("summary"),
        "live_findings": len(live.get("findings", [])) if live else None,
        "live_error": STATE.get("live_err"),
        "coverage": STATE.get("coverage"),
        "n_cases": STATE.get("n_cases"),
        "cycle": STATE.get("cycle"),
        "judge_ok": STATE.get("judge_ok"),
        # Persistent regression memory — the fix -> verify loop across campaigns.
        "regression_store": STORE.summary(),
        "regressions": STORE.regressions(),
    }


def _pill(ok: bool, good: str, bad: str) -> str:
    color = "#1a7f37" if ok else "#cf222e"
    label = good if ok else bad
    return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;font-size:13px">{escape(label)}</span>'


def _hero_html() -> str:
    """The headline 'find -> fix -> verify' story for the /ready info-disclosure finding.

    RED (invariant tripped: the leaked internal component map) -> the fix -> GREEN (the
    finding is now 'fixed', findings 1 -> 0) -> a regressions row that turns red the moment
    a previously-fixed exploit reappears. Driven entirely by the persistent ExploitStore.
    """
    ready = next(
        (r for r in STORE.findings(category="unauth_surface")
         if r.get("reproduction_seed") == READY_FINDING_SEED),
        None,
    )
    status = (ready or {}).get("status", "unseeded")
    fixed = status == "fixed"
    regressed = status == "regressed"
    last_verdict = (ready or {}).get("last_verified_verdict")
    last_sha = (ready or {}).get("last_verified_sha")

    regressions = STORE.regressions()
    has_reg = bool(regressions)

    leaked = "openemr_api, ingest_db, reranker, vector_index, document_storage"

    # GREEN unless the store says the fix regressed.
    if regressed:
        verify_pill = _pill(False, "", "REGRESSED — leak is back")
        verify_line = (
            f"Re-verification verdict <code>{escape(str(last_verdict))}</code> at "
            f"<code>{escape(str(last_sha))}</code> — the fix at <code>{escape(FIXED_SHA)}</code> "
            "lost its protection. Findings 0 &rarr; 1."
        )
    elif fixed:
        verify_pill = _pill(True, "VERIFIED — fix holding", "")
        vtxt = f" (last live verdict <code>{escape(str(last_verdict))}</code>)" if last_verdict else ""
        verify_line = (
            f"Findings <b>1 &rarr; 0</b>, status <code>fixed</code> at "
            f"<code>{escape(FIXED_SHA)}</code>{vtxt}. Every campaign re-runs the probe; "
            "if the internal map reappears this flips to <code>regressed</code> automatically."
        )
    else:
        verify_pill = _pill(False, "", "not yet seeded")
        verify_line = "The /ready finding is not seeded in the regression store."

    reg_pill = _pill(not has_reg, "no regressions", f"{len(regressions)} regression(s)")
    reg_detail = ""
    if has_reg:
        reg_detail = "".join(
            f"<li><code>{escape(str(r.get('category','')))}</code> "
            f"seed <code>{escape(str(r.get('reproduction_seed',''))[:12])}</code> "
            f"— last verdict <code>{escape(str(r.get('last_verified_verdict','')))}</code></li>"
            for r in regressions
        )
        reg_detail = f"<ul>{reg_detail}</ul>"

    border = "#cf222e" if (has_reg or regressed) else "#1a7f37"
    summ = STORE.summary()
    return f"""
    <div style="border:2px solid {border};border-radius:10px;padding:14px 18px;margin:1rem 0;background:#8881">
      <h2 style="border:0;margin-top:0">🎯 Find &rarr; Fix &rarr; Verify — unauthenticated <code>/ready</code> disclosure (RT-005)</h2>
      <p style="margin:.4rem 0">{_pill(False, "", "RED — invariant tripped")}
        &nbsp; An unauthenticated <code>GET /ready</code> leaked the internal integration map:
        <code>{escape(leaked)}</code> — recon for the PHI-bearing stores behind the sidecar.</p>
      <p style="margin:.4rem 0">{_pill(True, "FIX", "")}
        &nbsp; Restrict <code>/ready</code>: return a bare readiness status to unauthenticated
        callers; never the internal component inventory.</p>
      <p style="margin:.4rem 0">{verify_pill} &nbsp; {verify_line}</p>
      <p style="margin:.4rem 0">{reg_pill}
        &nbsp; Regression memory: {summ.get('total',0)} tracked finding(s),
        by status {escape(str(summ.get('by_status',{})))}.</p>
      {reg_detail}
    </div>
    """


def _heartbeat_html(state: dict) -> str:
    """Liveness panel — make 'every N min' credible, not cron-theater.

    Shows the last-run timestamp, the cadence, a cycle counter that ticks each campaign,
    how many attacks fired this cycle, and the judge-integrity canary pill (the anti-
    'marking its own homework' signal).
    """
    ts = state.get("ts") or "warming up"
    cycle = state.get("cycle", 0)
    n = state.get("n_cases", 0)
    judge_ok = state.get("judge_ok")
    if judge_ok is None:
        judge_pill = _pill(False, "", "judge canary pending")
    else:
        judge_pill = _pill(bool(judge_ok), "judge live: catches a planted leak", "JUDGE BLIND — detector is blind")
    return f"""
    <div style="display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;
                border:1px solid #8884;border-radius:8px;padding:10px 14px;margin:1rem 0;
                font-size:14px;background:#8881">
      <span>💓 <b>liveness</b></span>
      <span>last run <code>{escape(str(ts))}</code></span>
      <span>next run in ~{INTERVAL_S // 60} min</span>
      <span>cycle <code>#{escape(str(cycle))}</code></span>
      <span><b>{escape(str(n))}</b> attacks fired this cycle</span>
      <span>{judge_pill}</span>
    </div>"""


def _verdict_details(state: dict) -> str:
    """Inspectable verdicts — an expandable per-case view of the DETERMINISTIC check over
    the payload, so a skeptic sees the mechanical invariants and raw signal, not just the
    conclusion. Prefers the LIVE results (real target); falls back to the hermetic suite.
    """
    live = state.get("live") or {}
    live_results = live.get("results") if isinstance(live, dict) else None
    if live_results:
        results, source = live_results, "live target"
    else:
        results = (state.get("hermetic") or {}).get("results") or []
        source = "hermetic suite"
    if not results:
        return ""

    # Map case_id -> the attack string actually sent (reconstructed from the case), since the
    # stored result rows keep the verdict/invariants but not the raw request text.
    attacks: dict[str, str] = {}
    try:
        for c in load_cases():
            a, _s, _p, _e = runner._case_attack(c)
            attacks[c.id] = a
    except Exception:  # noqa: BLE001 — the inspector must render even if case reload fails
        attacks = {}

    blocks = []
    for r in results:
        cid = str(r.get("case_id", ""))
        cat = str(r.get("category", ""))
        verdict = str(r.get("verdict", ""))
        attack = attacks.get(cid, "(attack text unavailable)")
        inv = r.get("invariants") or {}

        # Response snippet: the signal the deterministic check ran over (status + computed
        # safety facts). This is what the invariant map is computed FROM.
        bits = []
        if r.get("status_code") is not None:
            bits.append(f"HTTP {r.get('status_code')}")
        if r.get("evidence"):
            bits.append(json.dumps(r.get("evidence")))
        snippet = " · ".join(bits) or "(no response signal captured)"

        inv_rows = "".join(
            f"<tr><td><code>{escape(str(k))}</code></td>"
            f"<td>{_pill(bool(val), 'held', 'VIOLATED')}</td></tr>"
            for k, val in inv.items()
        ) or "<tr><td colspan=\"2\"><i>no invariants asserted</i></td></tr>"

        held = verdict != "success"
        summary_pill = _pill(held, f"defense held ({verdict})", f"ATTACK SUCCEEDED ({verdict})")
        blocks.append(f"""
        <details style="margin:.35rem 0;border:1px solid #8883;border-radius:6px;padding:6px 10px">
          <summary style="cursor:pointer"><code>{escape(cid)}</code> · {escape(cat)} &nbsp; {summary_pill}</summary>
          <p style="margin:.4rem 0"><b>attack request:</b> <code>{escape(attack)}</code></p>
          <p style="margin:.4rem 0"><b>response snippet:</b> <code>{escape(snippet[:280])}</code></p>
          <p style="margin:.4rem 0"><b>invariants — the mechanical checks:</b></p>
          <table><tr><th>invariant</th><th>result</th></tr>{inv_rows}</table>
          <p style="margin:.4rem 0"><b>verdict:</b> <code>{escape(verdict)}</code>
             &nbsp;(defense {"held" if held else "FAILED — attack worked"})</p>
        </details>""")

    return (
        f"<p class=\"sub\">Deterministic verdict inspector — {source}, {len(results)} case(s). "
        "Expand any case to see the mechanical invariant check computed over the payload, "
        "not just the conclusion.</p>" + "".join(blocks)
    )


def _render(state: dict) -> str:
    ts = state.get("ts")
    if not ts:
        return _page(_heartbeat_html(state) + _hero_html()
                     + "<p>Warming up — the first campaign is running. Refresh in a few seconds.</p>")

    live = state.get("live") or {}
    live_findings = live.get("findings", []) if live else []
    live_err = state.get("live_err")
    herm = state.get("hermetic") or {}
    summ = herm.get("summary") or {}
    by_cat = summ.get("by_category") or {}
    cov = state.get("coverage") or {}

    # --- live target panel ---
    if live_err:
        live_html = f"<p>{_pill(False, '', 'target unreachable')} <code>{escape(live_err)}</code></p>"
    else:
        n = live.get("n_cases", 0)
        f = len(live_findings)
        live_html = (
            f"<p>{_pill(f == 0, 'defenses holding', f'{f} open finding(s)')} "
            f"&nbsp; {n} unauthenticated-surface case(s) run against the live target.</p>"
        )
        if live_findings:
            rows = "".join(
                f"<tr><td>{escape(str(x.get('severity','')))}</td>"
                f"<td>{escape(str(x.get('report_id',''))[:8])}</td>"
                f"<td>{escape(str(x.get('status','')))}</td></tr>"
                for x in live_findings
            )
            live_html += f"<table><tr><th>severity</th><th>id</th><th>status</th></tr>{rows}</table>"

    # --- hermetic resilience per category ---
    cat_rows = "".join(
        f"<tr><td>{escape(cat)}</td><td>{c.get('held',0)}/{c.get('n',0)}</td>"
        f"<td>{(c.get('resilience') if c.get('resilience') is not None else 0):.0%}</td></tr>"
        for cat, c in sorted(by_cat.items())
    )
    herm_html = (
        f"<p>{_pill(summ.get('findings', 0) == 0, 'all categories held', 'a category failed')} "
        f"&nbsp; hermetic suite, {state.get('n_cases',0)} cases across {len(by_cat)} categories.</p>"
        f"<table><tr><th>category</th><th>held</th><th>resilience</th></tr>{cat_rows}</table>"
    )

    # --- OWASP coverage ---
    web = ", ".join(sorted(cov.get("web", {}).keys())) if isinstance(cov.get("web"), dict) else escape(str(cov.get("web", "")))
    llm = ", ".join(sorted(cov.get("llm", {}).keys())) if isinstance(cov.get("llm"), dict) else escape(str(cov.get("llm", "")))
    cov_html = f"<p><b>OWASP Web:</b> {escape(web)}<br><b>OWASP LLM:</b> {escape(llm)}</p>"

    body = f"""
    <p class="sub">Continuous adversarial evaluation of the deployed Clinical Co-Pilot.
    Target: <code>{escape(TARGET_URL)}</code> · last campaign: <b>{escape(ts)}</b> · re-runs every {INTERVAL_S // 60} min.</p>

    {_heartbeat_html(state)}

    {_hero_html()}

    <h2>Live target — unauthenticated attack surface</h2>
    {live_html}

    <h2>Harness — hermetic suite resilience</h2>
    {herm_html}

    <h2>Inspectable verdicts — the deterministic check, per case</h2>
    {_verdict_details(state)}

    <h2>OWASP coverage</h2>
    {cov_html}

    <p class="foot">The Judge's authority is a deterministic invariant, not an LLM vote.
    Confirmed exploits become versioned regression cases. Findings carry honest provenance —
    seeded from the threat model, never sold as novel 0-days. This console runs bounded
    campaigns (one category live, no token) and degrades gracefully if the target is down.</p>
    """
    return _page(body)


def _page(body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Red Team Console — Clinical Co-Pilot</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         max-width: 820px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1 {{ margin-bottom: 0; font-size: 1.6rem; }}
  h2 {{ margin-top: 1.8rem; font-size: 1.15rem; border-bottom: 1px solid #8884; padding-bottom: 4px; }}
  .sub {{ color: #6a737d; margin-top: .3rem; }}
  .foot {{ color: #6a737d; font-size: .9rem; margin-top: 2rem; }}
  table {{ border-collapse: collapse; margin: .5rem 0; width: 100%; }}
  th, td {{ text-align: left; padding: 4px 10px; border-bottom: 1px solid #8883; font-size: 14px; }}
  code {{ background: #8882; padding: 1px 5px; border-radius: 4px; font-size: 13px; }}
</style></head>
<body>
  <h1>🛡️ Red Team Console</h1>
  {body}
</body></html>"""
