"""Materialize full-schema vulnerability reports from LIVE probes of the deployed target.

Produces the submission's vulnerability reports (>=3 distinct) by running the real
DocumentationAgent over confirmed findings discovered against the deployed Co-Pilot —
unauthenticated information-disclosure surfaces. Every report is reproducible: the exact
request + the real observed response are embedded, and re-running this script re-probes
the live target. `/metrics/summary` is included as a CONTROL (it returns 401 — a defense
that HELD), so the set demonstrates true findings AND a correctly-rejected probe, the way
a real triage set distinguishes signal from false positives.

Honest provenance: these are `seeded` unauth-surface probes from our own threat model
against our own fork on synthetic data — never presented as novel 0-days.

Run:  python -m redteam.materialize_live_reports [--base-url URL] [--out-dir DIR]
"""

from __future__ import annotations

import argparse
from pathlib import Path

import httpx

from redteam import runner
from redteam.contracts import AttackAttempt, ConfirmedExploit, DeterministicEvidence
from redteam.documentation import DocumentationAgent

_TIMEOUT = 20.0

# (endpoint, severity, what it discloses, disclosed-item extractor) for the probes we
# expect to be information-disclosure findings on an unauthenticated caller.
_PROBES = [
    ("/ready", "medium", "the full internal integration map (every backing subsystem)"),
    ("/openapi.json", "low", "the complete API route + schema inventory"),
    ("/docs", "low", "an interactive Swagger UI enumerating every endpoint"),
    ("/dashboard", "medium", "the observability dashboard"),
]
_CONTROL = "/metrics/summary"  # expected 401 — a defense that HELD (documented as a control)


def _disclosed_items(endpoint: str, body: str) -> list[str]:
    """A few concrete tokens the response disclosed — the deterministic evidence of the
    leak (kept short + structural, never PHI)."""
    import json as _json

    try:
        obj = _json.loads(body)
    except Exception:  # noqa: BLE001
        return [endpoint.strip("/")]
    if endpoint == "/ready" and isinstance(obj.get("checks"), dict):
        return sorted(obj["checks"].keys())
    if endpoint == "/openapi.json" and isinstance(obj.get("paths"), dict):
        return sorted(obj["paths"].keys())[:12]
    return [endpoint.strip("/")]


def run(base_url: str, out_dir: Path) -> dict:
    doc = DocumentationAgent()
    version = "deployed"
    try:
        r = httpx.get(f"{base_url}/health", timeout=_TIMEOUT)
        version = str(r.json().get("version") or "deployed") if r.headers.get("content-type", "").startswith("application/json") else "deployed"
    except Exception:  # noqa: BLE001
        pass

    out_dir.mkdir(parents=True, exist_ok=True)
    reports: list[dict] = []
    index_rows: list[str] = []

    for endpoint, severity, discloses in _PROBES:
        try:
            resp = httpx.get(f"{base_url}{endpoint}", timeout=_TIMEOUT, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            index_rows.append(f"| `{endpoint}` | probe error | — | {type(exc).__name__} |")
            continue
        if resp.status_code != 200:
            index_rows.append(f"| `{endpoint}` | HTTP {resp.status_code} | defense held | not a finding |")
            continue

        body = resp.text[:800]
        items = _disclosed_items(endpoint, body)
        attempt = AttackAttempt(
            category="unauth_surface",
            request_transcript=f"GET {endpoint}   (no Authorization header)",
            response_transcript=f"HTTP 200\n{body}",
            endpoint=endpoint,
            target_version=version,
        )
        exploit = ConfirmedExploit(
            attempt_id=attempt.attempt_id,
            category="unauth_surface",
            severity=severity,
            deterministic_evidence=DeterministicEvidence(
                phi_leaked=False, scope_widened=False, uncited_survived=False,
                sentinels_hit=items,
            ),
            reproduction_seed=f"unauth:{endpoint}",
        )
        rep = doc.report(exploit, attempt, provenance="seeded")
        # Prepend a one-line disclosure summary so the report reads standalone.
        rep["markdown"] = rep["markdown"].replace(
            "## Reproduction",
            f"> **Disclosed to an unauthenticated caller:** {discloses} — {', '.join(items)}.\n\n## Reproduction",
            1,
        )
        slug = endpoint.strip("/").replace("/", "_").replace(".", "_") or "root"
        path = out_dir / f"unauth_{slug}.md"
        path.write_text(rep["markdown"], encoding="utf-8")
        reports.append(rep)
        index_rows.append(
            f"| [`{endpoint}`]({path.name}) | HTTP 200 | **{severity}** finding | {rep['report_id'][:8]} |"
        )

    # the control probe (expected to be rejected)
    try:
        cr = httpx.get(f"{base_url}{_CONTROL}", timeout=_TIMEOUT)
        held = cr.status_code in (401, 403)
        index_rows.append(
            f"| `{_CONTROL}` | HTTP {cr.status_code} | {'defense held (control)' if held else 'UNEXPECTED 200'} | not a finding |"
        )
    except Exception:  # noqa: BLE001
        pass

    index = (
        "# Vulnerability reports — live unauthenticated-surface probes\n\n"
        f"Target: `{base_url}` · generated by `redteam/materialize_live_reports.py` (reproducible: re-run to re-probe).\n\n"
        "> Real evidence about the deployed fork (synthetic demo data, our own system). "
        "`seeded` provenance — from our threat model, never presented as novel 0-days.\n\n"
        f"**{len(reports)} confirmed findings** materialized as full reports below, plus a rejected control.\n\n"
        "| endpoint | status | outcome | report id |\n| --- | --- | --- | --- |\n"
        + "\n".join(index_rows) + "\n"
    )
    (out_dir / "README.md").write_text(index, encoding="utf-8")
    return {"n_reports": len(reports), "out_dir": str(out_dir)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Materialize full vuln reports from live probes")
    ap.add_argument("--base-url", default=runner.PROD_URL)
    ap.add_argument("--out-dir", default="defense/week3/reports")
    args = ap.parse_args(argv)
    res = run(args.base_url, Path(args.out_dir))
    print(f"[reports] wrote {res['n_reports']} full-schema report(s) to {res['out_dir']}")
    return 0 if res["n_reports"] >= 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
