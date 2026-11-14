# AI Red Team — adversarial evaluation platform for the OpenEMR Clinical Co-Pilot

A multi-agent platform that **continuously attacks a deployed AI clinical assistant** and
proves whether its safety defenses hold — then documents what it finds so the target can
fix it. It treats the target as an untrusted remote service (HTTP only) and its own
attacker + judge as untrusted models, with **deterministic checks as the sole authority**.

> The standard: something you could defend to a hospital CISO deciding whether an AI layer
> is safe to put in front of real physicians — continuous, reproducible, and honest.

## 🔗 The three URLs

| | |
| --- | --- |
| **This repo (AI Red Team)** | https://labs.gauntletai.com/jamesmerithew/openemr-red-team |
| **Deployed Red Team Console** | **https://red-team-console-production.up.railway.app** |
| **Target — OpenEMR/Co-Pilot repo (with the fix commits)** | https://labs.gauntletai.com/jamesmerithew/openemr-base-clean |

The **target under attack** is the deployed Co-Pilot sidecar
`https://copilot-production-5e86.up.railway.app`, behind the public
[OpenEMR](https://openemr-production-31ad.up.railway.app).

## The closed loop (find → fix → verify)

This platform attacked the deployed Co-Pilot and confirmed real **unauthenticated
information-disclosure** findings (e.g. `/ready` leaked the internal component inventory;
`/openapi.json` + `/docs` exposed the full API surface). Those were **fixed in the OpenEMR
repo** (see its `defense/week3/REMEDIATION.md`) and redeployed. The **live console now
re-runs the campaign on a schedule and shows the findings resolved** — the defense holds.
That before → after, visible on the deployed console, is the point of the platform.

## Architecture (four agents, deterministic spine)

**Orchestrator → Red Team → Judge → Documentation**, coordinating only through versioned
JSON-Schema [contracts](contracts) (+ a typed [error schema](contracts/error.v1.json)):

- **Orchestrator** (`redteam/orchestrator.py`) — deterministic priority ranking + a hard
  attack budget; decides what to attack next.
- **Red Team** (`redteam/red_team.py`) — generates + mutates attacks (Claude or a keyless
  deterministic generator behind a Protocol; a refusing generator yields *fewer* attacks,
  never false findings).
- **Judge** (`redteam/judge.py`) — an independent success/fail/partial verdict whose
  authority is a **computed deterministic invariant** (`redteam/invariants.py`), never an
  LLM vote. It is a separate agent from the Red Team — an engine never grades its own attacks.
- **Documentation** (`redteam/documentation.py`) — turns a confirmed exploit into a
  reproducible, full-schema vulnerability report; critical findings are human-gated.

Confirmed exploits become **versioned regression cases** (`redteam/store.py`): a case
passes only when the *safe invariant held* across the attack's mutation family — never
because a payload string stopped working. Full design: [ARCHITECTURE.md](ARCHITECTURE.md),
threat model: [THREAT_MODEL.md](THREAT_MODEL.md).

Standalone by design: the three small helpers it once shared with the Co-Pilot are
vendored under `redteam/_vendor/`, so this project depends on **none** of the target's code.

## Run it

```bash
python -m venv .venv && . .venv/Scripts/activate   # or .venv/bin/activate
pip install -r requirements.txt
```

**Against the deployed target (unauth surface — no key needed):**
```bash
python -m redteam.live_proof --category unauth_surface     # 1 live campaign → report
python -m redteam.materialize_live_reports                 # full vuln reports from live probes
```

**Hermetic suite + deterministic gate (zero keys, zero network — the harness proof):**
```bash
python -m redteam.runner --target hermetic --out evals/adversarial/results.json
python -m redteam.gate   --results evals/adversarial/results.json --baseline evals/adversarial/baseline.json
```

**The console locally:**
```bash
uvicorn redteam.console.app:app --port 8811      # then open http://localhost:8811
```

**Tests + lint:**
```bash
python -m pytest redteam contracts -q
python -m ruff check redteam contracts
```

## Deliverable map

| Requirement | Where |
| --- | --- |
| Multi-agent system (4 distinct roles) | [redteam/](redteam) |
| Threat model (6 categories, OWASP-mapped) | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Architecture + diagram + AI-use disclosure | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Attack suite (7 categories, OWASP-mapped, reproducible) | [evals/adversarial/](evals/adversarial) |
| Versioned inter-agent contracts + typed error schema | [contracts/](contracts) |
| Vulnerability reports (live, full-schema) | [defense/week3/reports/](defense/week3/reports) · [live_proof.md](defense/week3/live_proof.md) |
| Regression harness + deterministic gate | `redteam/store.py`, `redteam/gate.py` |
| Observability | `redteam/observability.py` + the deployed console |
| Triage report (13 findings) | [W3_TRIAGE_REPORT.md](W3_TRIAGE_REPORT.md) |
| Build-vs-configure record | [W3_BUILD_VS_CONFIGURE.md](W3_BUILD_VS_CONFIGURE.md) |
| ATO evidence packet | [W3_ATO_PACKET.md](W3_ATO_PACKET.md) |
| Platform cost analysis (100/1K/10K/100K runs) | [W3_COST_ANALYSIS.md](W3_COST_ANALYSIS.md) |

## Honest provenance

Findings are labeled `seeded` (from our threat model) vs `mutation_discovered`, run against
**our own fork on synthetic data** — never presented as novel 0-days. A green hermetic gate
only proves the harness works; the live run is the only evidence about the target.
