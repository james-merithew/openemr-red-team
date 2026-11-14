# W3 — Adversarial Platform Cost Analysis (per test-run scale)

> Scope: the cost of running **the adversarial evaluation platform** at 100 / 1K / 10K /
> 100K **test runs**. This is deliberately separate from
> [`copilot/COST_ANALYSIS.md`](copilot/COST_ANALYSIS.md), which scales the *target*
> product by physicians. Actual dev spend is below; projections follow.

## The load-bearing insight (why this is not cost-per-token × n)

The platform is **deterministic-heavy by design**, and that is the whole cost story:

- **The Judge's authority is a computed invariant, not an LLM vote** (`redteam/invariants.py`,
  `redteam/judge.py`). Evaluating whether an attack succeeded costs **$0** — it is a
  predicate over the response, not a model call.
- **The regression harness is a replay.** A confirmed exploit is stored as a
  deterministic seed (`redteam/store.py`, `UNIQUE(category, reproduction_seed)`); re-running
  it on a new target version re-issues the *same* request and re-checks the *same*
  invariant. **Regression runs use no generation tokens at all.**
- **The gate is deterministic** (`redteam/gate.py`): severity floors + OWASP coverage +
  manifest. $0.
- LLM cost attaches to exactly one place: **generating *novel* attacks** (the Red Team
  generator). Everything downstream — dispatch, judging, storage, regression, gating — is
  deterministic.

So the cost curve is set by *how many NEW attacks you generate*, not how many test runs you
execute. A test **run** is mostly regression replay (deterministic, $0) plus a bounded
budget of new generation. Cost scales **sub-linearly** with runs, and the Orchestrator's
`AttackBudget` (`contracts.py`, `max_attempts`/`max_tokens`/`max_cost_usd`) is a hard
ceiling per campaign — an AI orchestrator can never talk itself past spend.

## Actual dev spend to date

- **Platform build + live proofs:** a few dollars. The build used the **deterministic +
  seeded generators** (`generators/local.py`) and the **stub judge** for the gate, so the
  65-case golden gate, the adversarial gate, and CI are **$0 to run** (hermetic, keyless).
- **Live runs against the deployed target** (`redteam/live_proof.py`,
  `redteam/materialize_live_reports.py`): the confirmed findings are **unauthenticated
  info-disclosure probes** — HTTP GETs, deterministic judge → **~$0 in LLM cost** per run.
- The frontier generator (Sonnet 5) was used sparingly during design; the platform does
  **not** require it to run — a refusing/absent generator yields *fewer* attacks, never
  false findings (the deterministic Judge is the quality guarantee).

## Projected cost + the architectural change forced at each scale

Cost per NEW attack ≈ generation tokens (Red Team) only — judging/regression/gate are free.
Assume ~2–4K tokens per generated attack; regression replays are $0.

| Scale (test runs) | Dominant cost | Est. LLM $ / full run | Architectural change forced |
| --- | --- | --- | --- |
| **100** | one-time generation; mostly seeds | **< $1** | None. Seeded + deterministic generators (`generators/local.py`) cover the floor; frontier generator optional for novel variants. |
| **1K** | mutation families per category | **~$2–8** | **Dedup + cache at the store.** `UNIQUE(category, reproduction_seed)` + `INSERT OR IGNORE` already skip re-generating known attacks; cache mutation families so a variant is generated once and replayed thereafter. |
| **10K** | novel-attack generation volume | **~$15–60** | **Swap the generator to a local/OSS uncensored model** behind the existing `AttackGenerator` Protocol (`generators/base.py`) — offensive-capable, no per-token API cost, no refusal tax. Concurrency caps + sampling keep wall-clock bounded. |
| **100K** | continuous discovery + full regression sweeps | **~$100–400** (discovery only) | **Deterministic-only regression tier + self-hosted generator.** Regression sweeps run with **zero** LLM (replay + invariants). Reserve a frontier model *only* for a small novel-discovery sample; queue attack work items with rate-limit backoff (`AgentError{retryable}` → Orchestrator backs off); shard by category. Per-run cost **falls** as the deterministic tier dominates. |

Numbers are LLM spend for a *full* run at that scale; infra (the sidecar target, sqlite
store, CI runner) stays a rounding error — the store is embedded, the gate is seconds.

## The forced-changes summary

Seeds + deterministic judge (100) → store dedup + mutation cache (1K) → **local/OSS
generator swap** behind the Protocol (10K) → **deterministic-only regression tier + queue +
self-hosted discovery** (100K). The through-line: **push work onto the deterministic layers
that cost nothing**, and spend tokens only on genuinely novel attack generation, hard-capped
by the Orchestrator budget. That is why per-test-run cost *drops* as scale rises rather than
growing linearly — the opposite of a naive cost-per-token × n model.

## Rate limits, backoff, model constraints

- LLM provider 429 / target flap → typed `AgentError{error_type, retryable}`
  (`contracts/error.v1.json`); the Orchestrator backs off + retries when `retryable`,
  halts/redirects when not (budget spent).
- Frontier-model refusal of offensive prompts is a **known constraint**, handled by the
  generator Protocol seam (deterministic + local/OSS fallback) — see
  [`docs/DECISIONS.md`](docs/DECISIONS.md) (2026-07-20, generator Protocol) and
  [`ARCHITECTURE.md`](ARCHITECTURE.md) §12.
