# USERS — who the AI Red Team platform is for

**Summary.** This platform does not serve physicians — that is the *target* Co-Pilot's job
(see the target repo's `USERS.md`). This platform serves the people responsible for deciding
whether that clinical AI is **safe to keep in front of physicians**: the application-security
engineer who must continuously test it, the hospital CISO who must sign off on the risk, and
the Co-Pilot engineering team who must fix what's found. Their shared problem is that manual,
one-time penetration testing cannot keep up with an LLM system that changes every deploy and
faces attacks that mutate. Automation is the right solution because the work is **continuous,
reproducible, and adversarial** — exactly the qualities humans-with-checklists are worst at and
a multi-agent system is best at. Every capability below traces to one of these users.

## Primary user — the Application Security Engineer / AI Red Teamer

**Who:** an AppSec engineer at a health-tech org, responsible for the Co-Pilot's security
posture. **When they hit this system:** every time the Co-Pilot is redeployed, and continuously
in between. **What they need:**

- To prove a *category* of exploit is actually closed — not that one payload string stopped
  working (a fix that only changes model behavior is worse than no fix).
- To catch **regressions** the moment a previously-closed vulnerability reappears.
- To know which attack surfaces are covered and which are untested.
- Audit-grade, reproducible evidence a colleague can act on without having been present.

**What "good" feels like:** they open the console and immediately see the system is being
attacked right now, what's holding, and what regressed — without re-running anything by hand.

## Secondary user — the Hospital CISO / security leadership

**Who:** the person who owns the decision to trust an AI layer over patient data. **What they
consume:** the continuous resilience signal, the triage report, the ATO-style evidence packet,
and the find→fix→verify proof. **What they need:** defensibility — evidence they could stand
behind in front of regulators, framed in terms of real consequence (PHI exposure → HIPAA
breach). They are the "defend it to a CISO" standard this whole project is built to.

## Tertiary user — the Co-Pilot engineering team

**Who:** the engineers who build the target. **What they consume:** the structured vulnerability
reports (reproducible by an engineer who wasn't there) and the **regression gate** that blocks a
deploy which reintroduces a closed finding.

## Workflows

1. **Continuous adversarial testing** — the platform runs bounded campaigns against the deployed
   target on a schedule; the operator watches the live console rather than running scans by hand.
2. **Discover → triage → remediate → regression-gate** — a confirmed exploit becomes a versioned
   regression case; the fix is validated; every future deploy re-verifies it.
3. **Compliance / ATO evidence generation** — the platform's own outputs (findings, coverage,
   test evidence) assemble into the evidence packet a security reviewer accepts.
4. **Regression investigation** — when a finding flips `fixed → regressed`, the operator inspects
   the exact request, response, and the deterministic invariant that fired.

## Use cases

| UC | User | Trigger | What the platform does | Why automation (not manual pen-testing) |
| --- | --- | --- | --- | --- |
| **UC-1 Continuous stress-testing** | AppSec engineer | scheduled interval | Multi-agent campaign attacks the live target, judges deterministically, stores findings | Manual prompting is one-time and non-reproducible; a human cannot re-test every deploy forever |
| **UC-2 Prove-the-fix / catch regressions** | AppSec + Co-Pilot eng | a redeploy | Re-verifies every confirmed exploit; flips `fixed → regressed` if a leak returns | Fixes validated once and never re-checked are how regressions ship silently |
| **UC-3 Mutation coverage** | AppSec engineer | a partially-successful attack | Red Team agent mutates the attack to probe for a bypass | Static payload lists go stale as attackers adapt; a human can't enumerate variants at scale |
| **UC-4 Judge integrity** | AppSec + CISO | every campaign | Pushes a known-bad fixture through the live judge and asserts it's still caught | A silently-broken detector makes a dashboard falsely green; only an automated canary catches it |
| **UC-5 Defensible sign-off** | CISO | risk review | Surfaces resilience-over-time, triage, and the ATO evidence packet | Point-in-time manual reports can't answer "is the system getting safer" |
| **UC-6 Actionable reports** | Co-Pilot eng | a confirmed exploit | Documentation agent emits a reproducible, full-schema vuln report | An exploit nobody can reproduce wastes engineering time |

## Traceability — use case → platform component

| Use case | Served by |
| --- | --- |
| UC-1 | `redteam/orchestrator.py` + `redteam/runner.py` + the deployed console |
| UC-2 | `redteam/store.py` (versioned regression store, `fixed → regressed`) |
| UC-3 | `redteam/red_team.py` + `redteam/generators/` (mutation) |
| UC-4 | judge-integrity canary (console) + `redteam/judge.py` + `redteam/invariants.py` |
| UC-5 | `redteam/observability.py` + `W3_TRIAGE_REPORT.md` + `W3_ATO_PACKET.md` |
| UC-6 | `redteam/documentation.py` + `defense/week3/reports/` |

Every use case is continuous, reproducible, or adversarial — the three properties that make an
autonomous multi-agent platform the right tool and manual penetration testing the wrong one.
