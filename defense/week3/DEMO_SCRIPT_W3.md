# Demo script — AI Red Team platform (Week 3 final, ~5 min)

A complete, scene-by-scene walkthrough. `[SCREEN]` = what to show, `[SAY]` = narration
(direct, plain, confident). Each beat maps to a Week-3 grading criterion. The whole demo is
**click-between-tabs** — no terminal required (a terminal option is in the appendix if you
want it, but the console is the stronger visual).

**The one line the whole demo is built around:**
> *"It doesn't just find bugs — it proves it keeps you safe over time, and proves its own proof."*

---

## Setup — before you hit record

**Open these 6 browser tabs, in this order:**
1. Red Team repo README — `labs.gauntletai.com/jamesmerithew/openemr-red-team`
2. `ARCHITECTURE.md` (the agent diagram)
3. **Console** — `red-team-console-production.up.railway.app`  ← the star of the demo
4. A vuln report — `defense/week3/reports/unauth_ready.md` (in the red-team repo)
5. Live endpoint — `copilot-production-5e86.up.railway.app/ready`
6. `defense/week3/REMEDIATION.md` (in the OpenEMR repo, branch `main`)

**Do a dry run once** so you know where each thing is on the console page. That's the only prep.

---

## The script

### Beat 1 — The problem + the thesis (0:00–0:30) · *creativity / framing*
`[SCREEN]` README top (the three URLs).
`[SAY]` "OpenEMR added an AI Clinical Co-Pilot that reads a patient's chart and briefs the
doctor. The question a hospital security team actually asks isn't 'did you find one bug' —
it's 'can you keep proving this is safe as it changes.' So I didn't build a test list. I built
a platform that finds vulnerabilities, drives the fix, and continuously proves the fix holds.
The whole idea in one line: **it doesn't just find bugs — it proves it keeps you safe over
time, and proves its own proof.**"

### Beat 2 — Architecture: four agents, deterministic authority (0:30–1:15) · *defensibility, trust boundaries*
`[SCREEN]` Tab 2 — `ARCHITECTURE.md` agent diagram.
`[SAY]` "Four agents. The Orchestrator picks what to attack next under a hard budget. The Red
Team generates and mutates attacks. The Judge decides if one succeeded — and here's the
decision I defend hardest: the Judge's authority is a **deterministic invariant, not an LLM
vote**. Did PHI actually leak, did patient scope actually widen — computed, not opinionated.
And the Judge is a **separate agent** from the Red Team, because anything that grades its own
attacks has a conflict of interest by design. They talk only through versioned JSON-Schema
contracts. Trust boundaries are explicit: attack, judge, and routine reports run
autonomously; a **critical report and any remediation require a human** — the platform is a
read-only observer, it never pushes a fix itself."

### Beat 3 — Live attack on the deployed target + a real finding (1:15–2:05) · *Stage-1 hard gate, thoroughness*
`[SCREEN]` Tab 3 — the console's **Live target** status ("defenses holding"), then Tab 4 — the
vuln report.
`[SAY]` "This console runs bounded campaigns against the **deployed** Co-Pilot continuously —
that's the real live target, not a mock. It found a genuine vulnerability: the readiness
endpoint was handing the entire internal architecture to any anonymous caller. The
Documentation agent wrote this full report — the exact request, the leaked response, the
clinical impact, and, because this is a HIPAA-covered system, the regulatory framing:
unauthorized disclosure is a **Breach Notification reportable event**, not a CTF flag. A senior
engineer could reproduce and fix it from this alone."
*(Optional: if you want to show the CLI firing a live attack, see the appendix — but it's not needed.)*

### Beat 4 — The closed loop: found → fixed → verified (2:05–2:55) · *creativity, defensibility (headline)*
`[SCREEN]` Tab 3 — the **Find → Fix → Verify hero panel**. Then Tab 5 (live `/ready`, now bare),
then Tab 6 (`REMEDIATION.md`).
`[SAY]` "Here's what makes it a platform and not a scanner. The console shows the whole arc:
RED — the invariant tripped on the leaked component map. FIX — we restricted the endpoint,
committed on the target repo's `main` branch. GREEN — findings one to zero, verified. Here's
that same endpoint live right now: bare status, no architecture leaked. And it's not a
one-time check — every campaign re-runs the probe, and if that leak ever comes back this panel
flips to 'regressed' automatically. Found, fixed, and **continuously** verified."

### Beat 5 — "Test the tester" + inspectable verdicts (2:55–3:40) · *defensibility (the killer beat)*
`[SCREEN]` Tab 3 — the **"judge live: catches a planted leak"** pill, then expand an
**Inspectable verdict**.
`[SAY]` "The obvious objection to any AI-checks-AI system is 'it's marking its own homework.'
Two answers. One: every cycle I push a known leak through the live judge and confirm it still
catches it — that's this 'judge live' pill. If an invariant ever silently broke, this goes
**red**, not falsely green. Two: you don't have to trust the verdict — you can open it. Here's
a judged attack: the raw request, the response, the exact mechanical check that ran, and the
pass/fail. Deterministic evidence over a real payload, not a conclusion."

### Beat 6 — Regression memory + the drill (3:40–4:10) · *thoroughness, "proves it stays safe"*
`[SCREEN]` Tab 3 — the regression-store row (`fixed: 1`); then Tab 1 — the README "Regression
drill" section.
`[SAY]` "Every confirmed exploit becomes a versioned regression case keyed by the attack
itself, so it persists across campaigns — the store remembers the fix is holding. And I can
prove the loop is **closed**, not one-directional: flip one flag to reintroduce the leak, the
console catches it going zero-to-one, then I restore it back to zero. A control fire-drill, on
my own fork, synthetic data."

### Beat 7 — Coverage, model choice, cost (4:10–4:40) · *thoroughness, technology leverage*
`[SCREEN]` Tab 3 — the OWASP coverage panel; then Tab 1/`W3_COST_ANALYSIS.md`.
`[SAY]` "Every attack maps to OWASP web and LLM Top-10 — full coverage across seven categories.
On models: frontier models refuse offensive work, so attack generation sits behind a swappable
interface — and because the Judge is deterministic, a refusing generator gives you *fewer*
attacks, never *false* findings. On cost: the invariants, the gate, the regression replays are
all deterministic — zero dollars — so cost scales **sub-linearly**; you only spend tokens
generating genuinely new attacks."

### Beat 8 — Why this stands out + close (4:40–5:10) · *creativity, differentiation*
`[SCREEN]` Tab 3 — the whole dashboard; then Tab 1 — the three URLs.
`[SAY]` "Most adversarial-AI submissions are a static scan and a dashboard that's always green —
and a board that's never once shown red is impossible to trust. Mine is different in five ways
you can see live: the loop actually **closes across time** — it remembers a fix and flips to
'regressed' if it comes back; it **tests its own detector** every cycle; you can **open any
verdict** and see the mechanical check; findings carry **HIPAA breach framing**, not CTF
language; and it shows a real **heartbeat**, so 'continuous' is verifiable, not claimed.
Continuous, reproducible, honest — attacker and judge both untrusted, the deterministic layer
the authority. It doesn't just find bugs — it proves it keeps you safe, and proves its own
proof. That's the platform."

---

## Why this stands out — the enhancements past the MVP floor

The MVP floor is "find and document." These five enhancements — **all live on the console** —
turn it from a scanner into a **closed, self-checking control.** Lead with this if a grader
asks "what makes yours different."

| # | What most submissions do | What this platform does | Show it |
| --- | --- | --- | --- |
| **E1 — regression persistence** | a dashboard that says "green right now" | **remembers** each fix across campaigns (stable per-attack key + durable store) and flips `fixed → regressed` automatically if it returns | Find→Fix→Verify hero panel |
| **E3 — judge-integrity canary** | *claims* "our judge is deterministic" | **proves it every cycle** — pushes a known leak through the live judge and confirms it's still caught; goes red if the detector silently breaks | "judge live" pill |
| **E3 — inspectable verdicts** | shows a verdict (trust us) | lets you **open the verdict** — raw request, response, the exact invariant, pass/fail | expand a verdict |
| **E4 — PHI/HIPAA framing** | "info disclosure (medium)" | frames findings as **HIPAA Breach Notification reportable events** — clinical + regulatory stakes | any vuln report |
| **E5 — liveness heartbeat** | "runs every 30 min" (unverifiable) | live **cycle counter + next-run countdown** so "continuous" is witnessed, not asserted | the heartbeat panel |

**The one-liner (open and close with it):** it doesn't just find bugs — it **proves it keeps
you safe over time, and proves its own proof.** A green board is weak; a board that has caught
a real bug, fixed it, re-verified it, and tests its own detector is trustworthy.

**Grounded in a 3-lens design pass** (economics / psychology / technology): every enhancement
converts a *claimed* property into a *witnessed* one, at near-zero build cost by reusing seams
already in the platform. The disciplined "no" was per-agent cost metrics and an LLM-lens drift
canary — uncontested ground (the deterministic invariant already owns that).

---

## Grading-criterion coverage
- **Stage-1 hard gate (live target):** Beat 3 (real deployed target).
- **Multi-agent + trust boundaries:** Beat 2. **Documentation-agent bar:** Beat 3.
- **Defensibility (headline):** Beats 4–5 (closed loop + test-the-tester + inspectable).
- **Regression harness / "stays safe":** Beat 6. **Model-choice + cost:** Beat 7.
- **OWASP + threat model:** Beat 7 (+ THREAT_MODEL.md). **Creativity / differentiation:** Beats 1, 4, 8.

**Honesty note:** findings are `seeded` from the threat model, run against our own fork on
synthetic data — never presented as novel 0-days.

---

## Appendix — optional terminal beat (only if you want to show the CLI)

The console already proves the live attack, so this is optional. If you want to fire an attack
on camera:

1. Open the red-team folder in File Explorer (`Desktop → openemr-red-team`).
2. Click the address bar, type `powershell`, press Enter — a terminal opens in that folder.
3. Paste (uses the existing Python, no setup):
   ```powershell
   C:\Users\merit\OneDrive\Desktop\openemr-base-clean\copilot\.venv\Scripts\python.exe -m redteam.live_proof --category unauth_surface
   ```
4. It prints the live target URL and `findings=0`. Narrate: *"running live against the deployed
   target — defenses holding,"* then show the finding from the vuln report tab.

**Warm it up with one practice run before recording** so the first import is fast on camera. If
the long path ever misbehaves, just skip it — the console dashboard makes the same point.

---

## Delivery tips
- Bookend with the one-liner: say it in Beat 1, pay it off in Beats 4–5, land it in Beat 8.
- Beats 4 and 5 are your strongest — slow down there, let the RED→GREEN and the "judge live"
  pill breathe.
- Everything is clicking between 6 pre-opened tabs; no typing required. Keep the console (Tab 3)
  as your home base — you return to it in Beats 3, 4, 5, 6, 7, and 8.
