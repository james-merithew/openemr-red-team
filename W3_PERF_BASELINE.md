# W3 — Performance Baseline & Load Test

Baseline CPU/latency/throughput/memory for the **adversarial platform itself** under a
representative run (100 attack cases + full regression suite), plus a 100-consecutive-case
load test, the bottleneck, and the architectural change that addresses it.

> Scope note: these numbers profile the **platform's own overhead** on the **hermetic**
> (in-process, no-network, no-LLM) target — the path the deterministic gate exercises. That
> is deliberate: it isolates the harness cost from the target's cost. The live-target section
> below states, honestly, where the real-world cost actually lives.

## Methodology

- Machine: developer workstation, Python 3.12, Windows.
- Load: the 8 authored attack cases (`evals/adversarial/cases/`) replicated round-robin to
  **100 cases**, each driven through the full Red Team → Judge → deterministic-invariant →
  `ExploitStore` loop via `redteam.runner.run_suite` against
  `redteam.runner._build_target("hermetic", …)`.
- Procedure: 1 warm-up run discarded; **3 measured runs**; medians reported. Per-case latency
  from `time.perf_counter`; peak heap from `tracemalloc`.
- Reproduce: `python -m redteam.runner --target hermetic --out results.json` (single suite),
  or the 100-case replication harness described above.

## Baseline (100 cases + full regression loop, hermetic)

| Metric | Value |
| --- | --- |
| Wall-clock, 100 cases (median of 3) | **0.029 s** |
| Throughput | **~3,400 cases / sec** |
| Per-case latency p50 | **0.25 ms** |
| Per-case latency p95 | **0.59 ms** |
| Peak incremental Python heap | **< 1 MB** |
| CPU | single-threaded, CPU-bound on invariant evaluation; no measurable I/O wait (in-process target) |

Interpretation: the platform's own orchestration + judging + storage overhead is
**negligible** (sub-millisecond per case). A full regression sweep of the current suite
completes in tens of milliseconds, comfortably inside any CI time budget.

## Load / stress test — 100 consecutive cases

Running 100 cases back-to-back (same harness, single process, shared `ExploitStore`) held
steady across all 3 runs (`0.027 / 0.029 / 0.037 s`) with **no latency creep, no memory
growth**, and no sqlite contention — the store's `INSERT OR IGNORE` on
`UNIQUE(category, reproduction_seed)` keeps repeated cases idempotent rather than accumulating
rows. The platform does not degrade under a sustained 100-case burst on the hermetic path.

## Bottleneck analysis

On the hermetic path the dominant cost is CPU spent in `redteam.invariants.evaluate` — and it
is already trivial. **The real bottleneck appears only against the live target**, where each
case is dominated by:

1. **Network round-trip** to the deployed Co-Pilot (`TargetClient.chat()` / `.ready()` — one
   HTTPS request/response per case), and
2. for `/chat` cases, the **target Co-Pilot's own model latency**, plus
3. for escalated cases, the **optional Opus judge lens** (`judge.py`, gated behind
   `COPILOT_JUDGE=="live"`), which adds one LLM call.

So end-to-end live throughput is **network- and LLM-bound, not harness-bound**. The single
biggest lever is the serial, one-request-at-a-time dispatch in `runner.run_suite`.

## Architectural change that addresses it

1. **Concurrent case dispatch.** Replace the serial per-case loop with a bounded async / thread
   pool (e.g. 8–16 in-flight requests). Because cases are independent and the judge is
   deterministic, this is embarrassingly parallel; expected near-linear speedup up to the
   target's own rate limits. The platform already treats the target as an untrusted remote
   service, so this is a dispatch change only.
2. **Deterministic-only regression tier.** For routine regression sweeps, skip the LLM judge
   lens entirely (the deterministic invariant is the sole authority anyway) — removes the LLM
   call from the hot path and makes regression cost network-only.
3. **Campaign batching + queue.** For large sweeps, enqueue cases and drain with the pool above;
   the `Orchestrator.within_budget()` ceiling already bounds spend so a backed-up queue aborts
   rather than runs away. Queue-depth monitoring is the natural next observability signal.

These map directly to the scale tiers in [`W3_COST_ANALYSIS.md`](W3_COST_ANALYSIS.md): the
deterministic-only tier is what keeps cost sub-linear at 10K–100K runs.
