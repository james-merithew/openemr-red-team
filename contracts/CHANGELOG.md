# contracts/ — inter-agent message schema changelog

Versioned JSON Schema (draft 2020-12) for every message that passes between the
four adversarial-platform agents. **These are the source of truth for inter-agent
communication** (`CLAUDE.md` invariant 5). A contract test (planned:
`contracts/test_contracts.py`) verifies **both** the producing and the consuming
agent conform to the published schema; a **breaking change requires a version bump**
(new `*.vN.json` file), mirroring the `openapi.json` byte-drift discipline
(`copilot/scripts/export_openapi.py` + `copilot/tests/test_openapi_contract.py`).

See [`ARCHITECTURE.md`](../ARCHITECTURE.md) §6 for the field-level rationale and the
producer→consumer map.

## The message contracts

| File | Producer → Consumer | Purpose |
| --- | --- | --- |
| `campaign_directive.v1.json` | Orchestrator → Red Team | Directs the next campaign under a budget |
| `attack_attempt.v1.json` | Red Team → Judge | One record per attack turn |
| `confirmed_exploit.v1.json` | Judge → Documentation | Emitted only on a `success` verdict |
| `verdict.v1.json` | Judge → Regression harness | Emitted for every attempt (success/fail/partial) |

## The error contract

Every agent emits a typed `error.v1.json` (`AgentError`) INSTEAD of its success message
when a known failure condition trips. One versioned envelope discriminates all five
required failure modes via `error_type`; `retryable` tells the Orchestrator whether to
back off + retry or halt/redirect.

| `error_type` | Raised by (`agent`) | Meaning | `retryable` |
| --- | --- | --- | --- |
| `target_unreachable` | `red_team` | the deployed target did not answer | usually true |
| `budget_exceeded` | `orchestrator` / `red_team` | the attack budget ceiling was hit | false |
| `judge_timeout` | `judge` | no verdict within the time budget | true |
| `no_findings` | `orchestrator` | a campaign window closed with nothing new | false |
| `regression_detected` | `regression` | a previously-fixed exploit reappeared | false |

Every message carries `schema_version`, `correlation_id`, and `ts` (the `Handoff`
envelope discipline, `copilot/app/contracts.py:361`). Enum fields
(`category`/`severity`/`verdict`/`mutation_strategy`/`env`) are log-safe; free-text
fields (`request_transcript`/`response_transcript`/`rationale`) ride the message for
the UI but are **never logged** — the platform extends `_ALLOWED_LOG_KEYS`
(`copilot/app/correlation.py:60-85`) with enum-only keys and excludes the transcript
keys, exactly as `filename` is excluded there.

## Version history

### 1.0.0 — 2026-07-20
- Initial publication of all four v1 message schemas (design skeleton for the Architecture
  Defense). Producers/consumers and the `contracts/test_contracts.py` dual-conformance
  suite land with the `redteam/` agent build (MVP → Final). No breaking changes yet.

### 1.0.0 — 2026-07-21
- Added the typed error contract `error.v1.json` (`AgentError`) alongside the success
  schemas: one versioned envelope discriminating all five known failure modes
  (`target_unreachable`, `budget_exceeded`, `judge_timeout`, `no_findings`,
  `regression_detected`). Covered by the same producer/consumer/no-drift conformance
  suite. Additive — no breaking change to the existing four.
