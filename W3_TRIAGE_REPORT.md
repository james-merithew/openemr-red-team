# W3_TRIAGE_REPORT.md — Adversarial Scan + Triage over the Clinical Co-Pilot

> **Status: SIMULATED SCAN + TRIAGE (v1, 2026-07-20).** This is a worked triage over 13 findings drawn from the Co-Pilot's *real* attack surface (`copilot/`) — a deliberate mix of genuine issues and the plausible false positives a naive scanner raises — to show that the Week-3 Documentation agent produces output an engineer can actually act on. Every finding is validated against the shipped code and the Co-Pilot's deterministic spine; nothing here is a live-exploited breach.
>
> **Companion documents:** [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`ARCHITECTURE.md`](./ARCHITECTURE.md) · [`W3_ATO_PACKET.md`](./W3_ATO_PACKET.md) · [`W2_ARCHITECTURE.md`](./W2_ARCHITECTURE.md)

---

## 1. Scan metadata

| Field | Value |
| --- | --- |
| **Target** | Clinical Co-Pilot FastAPI sidecar — `copilot/app/`, read-only agent tier |
| **Scan date** | 2026-07-20 |
| **Tooling** | Platform self-run (multi-agent red-team) + OWASP ZAP (DAST) + Semgrep (SAST) + `bandit` (Python SAST) + `pip-audit` (dependency CVEs) — the deterministic sensors described in [`W3_BUILD_VS_CONFIGURE.md`](./W3_BUILD_VS_CONFIGURE.md) |
| **Validation basis** | Findings re-checked against source (`file:line`) and the deterministic spine: Authorization Gateway, verifier, critic, read-only DB tier |
| **Live posture check** | `/dev/token` returns 404 on the production host (`auth_dev_mode=false`), VERIFIED live |

### Severity summary

| Severity | Count |
| --- | --- |
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 3 |
| ⚪ FALSE POSITIVE | 5 |
| **Total** | **13** |

### Disposition legend

| Disposition | Meaning |
| --- | --- |
| **Validate** | Reproduce and confirm the pathway before spending remediation effort |
| **Remediate** | A code/config change is warranted; ship a fix |
| **Defer** | Real but low-priority; backlog with an owner and a compensating control |
| **Document** | No code change; record the evidence and the standing mitigation so the finding does not resurface |

Each finding maps to an OWASP category (Web Top-10 or LLM Top-10) to align with the threat model.

---

## 2. Findings

### RT-001 — `/dev/token` mints an any-`pid` token with no auth

| | |
| --- | --- |
| **Severity** | 🔴 CRITICAL |
| **Surface** | Auth / token minting — `GET /dev/token` |
| **OWASP** | A07:2021 Identification & Authentication Failures |
| **Evidence** | `copilot/app/main.py:540` defines `GET /dev/token`, minting a session token for an arbitrary `pid` with no caller authentication. It is gated by `auth_dev_mode` (`copilot/app/config.py:108`) and returns **404 in production** (dev-mode off, VERIFIED live). But `auth_dev_mode` is **TRUE in the committed local `.env`**, and the fixed dev signing key `"dev-local-signing-key-not-for-prod"` (`copilot/app/config.py:111-114`) becomes usable if the DB-resident key is absent. |
| **Validation** | **Confirmed** — dev-mode exposure and a prod-enablement footgun (a mis-set flag on a prod host would open unauthenticated any-patient token minting). |
| **Disposition** | **Remediate + Document** |
| **Control** | Add a startup assertion/alert that refuses to boot (or loudly alarms) if `auth_dev_mode` is true on a production host; CI assertion that `.env.example` keeps the flag `false`; accept-in-dev rationale documented. Residual risk in dev is bounded to seeded demo data. |

### RT-002 — Indirect prompt injection via ingested document free-text

| | |
| --- | --- |
| **Severity** | 🔴 CRITICAL |
| **Surface** | LLM answerer context — document ingestion → intake facts |
| **OWASP** | LLM01:2025 Prompt Injection |
| **Evidence** | Uploaded document free-text flows into `copilot.intake_fact` (`chief_concern` / `family_history`) and is later surfaced **verbatim** into the answerer's context, unsanitized. Ingestion persists free text (`W2_ARCHITECTURE.md` §4.2); the only current defenses are a system-prompt instruction (`copilot/app/prompts.py:22`), verbatim persistence, and numeric grounding. |
| **Validation** | **Confirmed** — the injection pathway is real, but blast radius is bounded (see control). |
| **Disposition** | **Validate + Remediate** |
| **Control** | Delimit/quarantine intake free-text as *untrusted* in the prompt (explicit fenced boundary + "treat as data, not instructions"); add a regression eval case. **Residual:** an injection can influence answer *phrasing* but cannot cross patient scope (no-`pid` tools + `enforce_patient`), cannot write (read-only tier), and cannot launder guideline text into patient facts (verifier partition rule, `W2_ARCHITECTURE.md` §6.3). |

### RT-003 — Rate limiter is proxy-spoofable and in-memory

| | |
| --- | --- |
| **Severity** | 🟠 HIGH |
| **Surface** | Rate limiting — `rate_limit` dependency |
| **OWASP** | A04:2021 Insecure Design |
| **Evidence** | `copilot/app/main.py:76-85` keys the limiter on `request.client.host` in a per-process `defaultdict(deque)`. Behind Railway's edge, all clients can collapse into one bucket (or spoof a forwarded value); the state resets on restart and is **not shared across replicas**. |
| **Validation** | **Confirmed.** |
| **Disposition** | **Remediate + Defer + Document** |
| **Control** | Move to a shared store (Redis) or push limiting to the edge; heavy fix deferred behind a backlog item; interim behavior documented. Short-term compensation: session-token scoping already limits who can reach authenticated routes. |

### RT-004 — Rate limit not applied to several routes

| | |
| --- | --- |
| **Severity** | 🟠 HIGH |
| **Surface** | Rate limiting — route coverage |
| **OWASP** | A04:2021 Insecure Design |
| **Evidence** | `/health`, `/ready`, `/`, `/dashboard`, and `/dev/token` do not declare `Depends(rate_limit)` (`copilot/app/main.py`), so those routes are unthrottled. |
| **Validation** | **Confirmed.** |
| **Disposition** | **Remediate + Document** |
| **Control** | Add throttling to `/dev/token` and `/dashboard`; document `/health` and `/ready` as **intentionally unthrottled** so orchestrator/uptime probes are never rate-limited out. |

### RT-005 — `/ready` information disclosure

| | |
| --- | --- |
| **Severity** | 🟠 HIGH |
| **Surface** | Readiness probe — `GET /ready` |
| **OWASP** | A05:2021 Security Misconfiguration |
| **Evidence** | `copilot/app/main.py:217-253` returns per-dependency check names — `database`, `llm`, `observability`, `vector_index`, `reranker`, `openemr_api`, `ingest_db`, `document_storage` — **unauthenticated**. This reveals which integrations are configured (it exposes **no secret values**). |
| **Validation** | **Confirmed** — a reconnaissance aid, not a direct leak. |
| **Disposition** | **Remediate (preferred) or Document** |
| **Control** | Return a bare `ready/not-ready` status unauthenticated and gate the per-dependency detail behind auth; alternatively document as low-sensitivity given no secret values are exposed and `/ready` must stay probe-reachable. |

### RT-006 — `/metrics/summary` readable by any valid token, no patient binding

| | |
| --- | --- |
| **Severity** | 🟡 MEDIUM |
| **Surface** | Metrics — `GET /metrics/summary` |
| **OWASP** | A01:2021 Broken Access Control |
| **Evidence** | `copilot/app/main.py:515-523` guards the route with `Depends(require_session_token)` only; it accepts a day- or patient-scoped token and performs **no `enforce_patient`** binding. The payload is in-process counters and rates, **PHI-free by design**. |
| **Validation** | **Confirmed** — low impact (no PHI crosses the boundary). |
| **Disposition** | **Document / Defer** |
| **Control** | Accept as aggregate non-PHI telemetry, or add a lightweight scope check if operator-only visibility is later required. |

### RT-007 — Fixed, logged dev signing key when `auth_dev_mode` is on

| | |
| --- | --- |
| **Severity** | 🟡 MEDIUM |
| **Surface** | Token signing — dev fallback |
| **OWASP** | A02:2021 Cryptographic Failures |
| **Evidence** | The dev signing-key fallback in `copilot/app/session_token.py` uses the constant from `copilot/app/config.py:111-114` when `auth_dev_mode` is on and the DB key table is absent. |
| **Validation** | **Confirmed** — dev-only. |
| **Disposition** | **Document** |
| **Control** | Production uses the DB-resident `copilot_signing_key` (`W2_ARCHITECTURE.md` §3.1); the fixed constant is inert whenever the flag is false. Recorded so a future reader does not mistake the constant for a prod secret. |

### RT-008 — Unbounded growth of the in-memory rate-limit map

| | |
| --- | --- |
| **Severity** | 🟡 MEDIUM |
| **Surface** | Rate limiting — memory management |
| **OWASP** | A04:2021 Insecure Design |
| **Evidence** | The per-IP `defaultdict(deque)` (`copilot/app/main.py:73`) never evicts drained entries. A stream of many distinct source IPs grows the map without bound → memory-exhaustion DoS. |
| **Validation** | **Confirmed** — minor. |
| **Disposition** | **Remediate / Defer** |
| **Control** | Evict empty deques after the window drains (or migrate to the shared store from RT-003, which resolves both). Low priority. |

---

## 3. False-positive cluster (the pedagogical point)

A naive autonomous scanner flags each of these confidently. Each is **actually mitigated** by the Co-Pilot's deterministic spine. Filing them as open findings would waste engineering time — so the triage step disposes of them with evidence.

### RT-009 — "SQL injection in the labs LIKE clause"

| | |
| --- | --- |
| **Severity** | ⚪ FALSE POSITIVE |
| **Surface** | Data tier — labs query |
| **OWASP** | A03:2021 Injection |
| **Scanner claim** | A `LIKE` clause on a lab-name filter is user-controlled and therefore SQL-injectable. |
| **Reality** | The `LIKE` uses a **bound `:nm` parameter**, and `db.query` **rejects any non-`SELECT`/`WITH` statement** and binds every parameter (`copilot/app/db.py:53-68`). No string interpolation reaches the driver. |
| **Validation** | **False Positive.** |
| **Disposition** | **Document** with the `db.py:53-68` evidence. |

### RT-010 — "A no-`pid` tool lets the agent read across patients"

| | |
| --- | --- |
| **Severity** | ⚪ FALSE POSITIVE |
| **Surface** | Tool contracts / authorization |
| **OWASP** | LLM06:2025 Excessive Agency / A01:2021 Broken Access Control |
| **Scanner claim** | Read tools take no `pid` argument, so the model can request any patient. |
| **Reality** | The **absent `pid` IS the guard**. `pid` is injected **server-side** into `ToolContext` (`copilot/app/tools/__init__.py`) — the model never supplies it — and every read passes **two-layer authz**: `enforce_patient` (`copilot/app/main.py:176`) plus `authorize` (`copilot/app/authz.py:58`). |
| **Validation** | **False Positive.** |
| **Disposition** | **Document.** |

### RT-011 — "The LLM can write to the database"

| | |
| --- | --- |
| **Severity** | ⚪ FALSE POSITIVE |
| **Surface** | Data tier — write path |
| **OWASP** | LLM06:2025 Excessive Agency |
| **Scanner claim** | The agent has a DB connection, therefore it can mutate records. |
| **Reality** | The agent tier is **read-only** via the `copilot_ro` identity; `db.query` **rejects writes**. Ingestion runs under a **separate, INSERT-only `copilot_ingest`** identity invoked **only by an explicit endpoint — never as a model tool** (CLAUDE.md invariant 3; `W2_ARCHITECTURE.md` §3). |
| **Validation** | **False Positive.** |
| **Disposition** | **Document.** |

### RT-012 — "VLM hallucination persists fabricated lab values"

| | |
| --- | --- |
| **Severity** | ⚪ FALSE POSITIVE (mitigated) |
| **Surface** | Ingestion — vision extraction |
| **OWASP** | LLM09:2025 Misinformation |
| **Scanner claim** | The vision model can hallucinate a lab value that then lands in the chart as fact. |
| **Reality** | Extraction passes **deterministic text-layer quote verification**; unverified fields are **never persisted** (`COPILOT_INGEST_ALLOW_UNVERIFIED=false`; `W2_ARCHITECTURE.md` §4.3). A hallucinated number with no matching text-layer quote is dropped, not stored. |
| **Validation** | **False Positive (mitigated).** |
| **Disposition** | **Document.** |

### RT-013 — "Guideline text laundered into patient facts"

| | |
| --- | --- |
| **Severity** | ⚪ FALSE POSITIVE |
| **Surface** | Verifier — claim partitioning |
| **OWASP** | LLM09:2025 Misinformation |
| **Scanner claim** | RAG guideline text could be surfaced as if it were this patient's chart data. |
| **Reality** | The **verifier partition rule** ensures a claim with **zero patient-record handles can never enter the briefing** (`W2_ARCHITECTURE.md` §6.3). Guideline evidence renders under its own separate header and cannot be attributed to a patient PK. |
| **Validation** | **False Positive.** |
| **Disposition** | **Document.** |

---

## 4. Triage philosophy

The false-positive cluster (RT-009 through RT-013) is the point of this document. An autonomous Documentation agent that files *confident* false positives is worse than no scanner at all: it burns the engineering time it was supposed to save and trains reviewers to ignore its output. What makes the agent's output trustworthy is not the scan — any tool can raise alarms — it is the **validation step**, which checks each finding against the Co-Pilot's **deterministic spine**: the Authorization Gateway (server-injected `pid` + two-layer authz), the verifier (source-attribution and partition rules), the critic, and the read-only DB tier. That spine is evidence a naive scanner cannot see and a disciplined triage cannot ignore. The genuine findings (RT-001 through RT-008) survive that scrutiny and carry concrete dispositions and compensating controls; the noise is disposed of *with citations*, so it does not resurface on the next scan. Separating real risk from scanner noise — with `file:line` evidence on both sides of the line — is the deliverable.
