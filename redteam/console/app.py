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
import logging
import os
import time
from contextlib import asynccontextmanager
from html import escape

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from redteam import live_proof, owasp, runner
from redteam.cases import load_cases
from redteam.target import TargetClient

log = logging.getLogger("redteam.console")

TARGET_URL = os.environ.get("REDTEAM_TARGET_URL", runner.PROD_URL)
INTERVAL_S = int(os.environ.get("REDTEAM_CAMPAIGN_INTERVAL_S", "1800"))
LIVE_CATEGORY = "unauth_surface"  # the only category safely runnable against prod without a token

STATE: dict = {
    "ts": None, "target": TARGET_URL, "hermetic": None,
    "live": None, "live_err": None, "coverage": None, "n_cases": 0,
}


def run_campaign() -> dict:
    """One bounded campaign (blocking; run via a worker thread)."""
    cases = load_cases()
    hermetic = runner.run_suite(TargetClient(mode="hermetic"), cases)
    live = None
    live_err = None
    try:
        live = live_proof.run(base_url=TARGET_URL, category=LIVE_CATEGORY)
    except Exception as exc:  # noqa: BLE001 — a target outage must not crash the console
        live_err = f"{type(exc).__name__}: {exc}"
    return {
        "hermetic": hermetic,
        "live": live,
        "live_err": live_err,
        "coverage": owasp.coverage_matrix(cases),
        "n_cases": len(cases),
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
    }


def _pill(ok: bool, good: str, bad: str) -> str:
    color = "#1a7f37" if ok else "#cf222e"
    label = good if ok else bad
    return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;font-size:13px">{escape(label)}</span>'


def _render(state: dict) -> str:
    ts = state.get("ts")
    if not ts:
        return _page("<p>Warming up — the first campaign is running. Refresh in a few seconds.</p>")

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

    <h2>Live target — unauthenticated attack surface</h2>
    {live_html}

    <h2>Harness — hermetic suite resilience</h2>
    {herm_html}

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
