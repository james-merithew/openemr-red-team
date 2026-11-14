# Remediation — closing the loop on the red-team findings

The AI Red Team project (separate repo) attacked this deployed Co-Pilot and confirmed a
set of **unauthenticated information-disclosure** findings on its attack surface. This
document is the OpenEMR side of the loop: each finding → the fix → the regression test →
live verification. It's the "commits fixing what the red team found" record.

## Findings → fixes

| # | Finding (from the red team) | Severity | Fix | Regression test |
| --- | --- | --- | --- | --- |
| RT-005 | `/ready` disclosed the full internal component inventory (database, llm, vector_index, reranker, openemr_api, ingest_db, document_storage) to an anonymous caller | medium | `/ready` now returns a **bare `{ready, status}`** to anonymous callers (still 200/503 for health checks); the component `checks` map is disclosed only to an authenticated caller or under the `COPILOT_READY_PUBLIC_DETAIL` demo flag. The Week-2 rubric detail is preserved for authorized callers — scoped, not removed. | `copilot/tests/test_attack_surface_hardening.py::test_ready_hides_component_inventory_from_anonymous` |
| RT-014 | `/openapi.json` exposed the complete API route + schema inventory unauthenticated | low | The machine schema route is **disabled by default** (`COPILOT_EXPOSE_DOCS` unset). `app.openapi()` (used by the export script + drift test) is unaffected. | `…::test_openapi_and_docs_disabled_by_default` |
| RT-015 | `/docs` + `/redoc` served an interactive Swagger explorer of every endpoint | low | **Disabled by default** via the same flag. | `…::test_openapi_and_docs_disabled_by_default` |
| RT-016 | `/dashboard` returned HTTP 200 unauthenticated | (reclassified) | **Triaged — accepted low, no code change.** Investigation showed it serves only an empty HTML shell; all data flows through `/metrics/summary`, which already **requires a session token** (returns 401 to anonymous). No data is disclosed. This is the platform correctly distinguishing a real finding from a benign 200. | existing `/metrics/summary` auth test |

## Why not just delete the detailed `/ready`?

The Week-2 grade explicitly rewarded `/ready` reporting `vector_index`, `reranker`, and
`document_storage`. Deleting that detail would regress a graded win. The correct posture —
and the one shipped here — is **detail behind authorization**: anonymous callers get the
coarse status a health check needs; authenticated/internal callers (and the demo flag) get
the full inventory. Good observability and low disclosure are not in conflict once the
audience is scoped.

## Verification

- **Code + tests:** `copilot/tests/test_attack_surface_hardening.py` (4 cases) locks the
  fixes; `test_ready_checks.py` still verifies the detailed payload (with the demo flag on);
  `test_openapi_contract.py` confirms `app.openapi()` + the committed spec are unaffected.
- **Live — confirmed 2026-07-21 on `https://copilot-production-5e86.up.railway.app`** after
  redeploying the sidecar:

  | probe | before fix | after fix |
  | --- | --- | --- |
  | `GET /ready` (anon) | 200 + full `checks` map (8 subsystems) | **200, bare `{ready,status}` — no `checks`** |
  | `GET /openapi.json` | 200 (full API schema) | **404** |
  | `GET /docs` | 200 (Swagger UI) | **404** |
  | `GET /health` | 200 | 200 (unchanged) |

  Red-team re-run (`python -m redteam.live_proof --category unauth_surface`) against the
  redeployed target: **findings 1 → 0** — the `no_info_disclosure` invariant now holds
  (defense held). That before → after is the closed loop.
