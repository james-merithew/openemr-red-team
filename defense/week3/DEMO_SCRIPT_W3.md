# Demo script — AI Red Team platform (Week 3 final, ~4–5 min)

A scene-by-scene walkthrough. `[SCREEN]` = what to show, `[SAY]` = narration (your voice:
direct, plain, knowledgeable). Each beat maps to a Week-3 grading criterion.

**Before recording — open these tabs + one terminal (in the red-team repo):**
1. Red Team repo README · 2. `ARCHITECTURE.md` (diagram) · 3. Console
`red-team-console-production.up.railway.app` · 4. a vuln report
`defense/week3/reports/unauth_ready.md` · 5. live `copilot-production-5e86.up.railway.app/ready`
· 6. `defense/week3/REMEDIATION.md` in the OpenEMR repo (`main`). Warm the terminal with one
practice `python -m redteam.live_proof --category unauth_surface`.

---

### Beat 1 — The problem (0:00–0:25) · *creativity / framing*
`[SCREEN]` README top (the three URLs).
`[SAY]` "OpenEMR added an AI Clinical Co-Pilot that reads a patient's chart and briefs the
doctor. The question a hospital security team actually asks isn't 'did you find one bug' —
it's 'can you keep proving this thing is safe as it changes.' So I didn't write a test list.
I built a platform that finds vulnerabilities, drives the fix, and continuously proves the
fix holds."

### Beat 2 — Architecture: four agents, deterministic authority (0:25–1:05) · *defensibility, trust boundaries*
`[SCREEN]` `ARCHITECTURE.md` agent diagram.
`[SAY]` "Four agents. The Orchestrator picks what to attack next under a hard budget. The Red
Team generates and mutates attacks. The Judge decides if one succeeded — and here's the
decision I defend hardest: the Judge's authority is a **deterministic invariant, not an LLM
vote**. Did PHI actually leak, did patient scope actually widen — computed, not opinionated.
And the Judge is a **separate agent** from the Red Team, because a thing that grades its own
attacks has a conflict of interest by design. They talk only through versioned JSON-Schema
contracts. Trust boundaries are explicit: attack, judge, and routine reports run
autonomously; a **critical report and any remediation need a human** — the platform is a
read-only observer, it never pushes a fix itself."

### Beat 3 — Live attack on the deployed target + a real finding (1:05–1:50) · *Stage-1 hard gate, thoroughness*
`[SCREEN]` Terminal: run `python -m redteam.live_proof --category unauth_surface` (shows the
live target URL). Then switch to the vuln report tab.
`[SAY]` "This runs live against the deployed system — that's the real target URL. It found a
genuine vulnerability earlier: the readiness endpoint was handing the entire internal
architecture to any anonymous caller. The Documentation agent wrote this full report — the
exact request, the leaked response, the clinical impact, and — because this is a HIPAA-covered
system — the regulatory framing: unauthorized disclosure is a Breach Notification event, not a
CTF flag. A senior engineer could reproduce and fix it from this alone."

### Beat 4 — The closed loop: found → fixed → verified (1:50–2:40) · *creativity, defensibility*
`[SCREEN]` Console — the **Find → Fix → Verify hero panel**. Then the live `/ready` tab (now
bare), then `REMEDIATION.md`.
`[SAY]` "Here's what makes it a platform, not a scanner. The console shows the whole arc: RED
— the invariant tripped on the leaked component map. FIX — we restricted the endpoint,
committed on the target repo's main branch. GREEN — findings one to zero, verified. Here's
that same endpoint live right now: bare status, no architecture. And it isn't a one-time
check — every campaign re-runs the probe, and if that leak ever comes back this panel flips to
'regressed' automatically. Found, fixed, and continuously verified."

### Beat 5 — "Test the tester" + inspectable verdicts (2:40–3:25) · *defensibility (the killer beat)*
`[SCREEN]` Console — the **"judge live: catches a planted leak"** pill, then expand an
**Inspectable verdict**.
`[SAY]` "The obvious objection to any AI-checks-AI system is 'it's marking its own homework.'
Two answers. One: every cycle I push a known leak through the live judge and confirm it still
catches it — that's this 'judge live' pill. If an invariant ever silently broke, the board
would go red, not falsely green. Two: you don't have to trust the verdict — you can open it.
Here's a judged attack: the raw request, the response, the exact mechanical check that ran,
and the pass/fail. Deterministic evidence over a real payload, not a conclusion."

### Beat 6 — Regression memory + the drill (3:25–3:55) · *thoroughness, "proves it stays safe"*
`[SCREEN]` Console regression-store row (`fixed: 1`); README "Regression drill" section.
`[SAY]` "Every confirmed exploit becomes a versioned regression case keyed by the attack
itself, so it persists across campaigns — the store remembers the fix is holding. And I can
prove the loop is *closed*, not one-directional: flip one flag to reintroduce the leak, the
console catches it going zero-to-one, then restore it back to zero. A control fire-drill on my
own fork, synthetic data."

### Beat 7 — Coverage, model choice, cost (3:55–4:30) · *thoroughness, technology leverage*
`[SCREEN]` Console OWASP coverage + `W3_COST_ANALYSIS.md`.
`[SAY]` "Every attack maps to OWASP web and LLM Top-10 — full coverage across seven
categories. On models: frontier models refuse offensive work, so attack generation sits behind
a swappable interface — and because the Judge is deterministic, a refusing generator gives you
*fewer* attacks, never *false* findings. And cost: the invariants, the gate, the regression
replays are all deterministic — zero dollars — so cost scales sub-linearly; you only spend
tokens generating genuinely new attacks."

### Beat 8 — Why this stands out + close (4:30–5:05) · *creativity, differentiation*
`[SCREEN]` The console (whole dashboard), then the three URLs.
`[SAY]` "Most adversarial-AI submissions are a static scan and a dashboard that's always
green — and a dashboard that's never once shown red is impossible to trust. Mine is different
in five ways you can see live: the loop actually **closes across time** — it remembers a fix
and flips to 'regressed' if it comes back; it **tests its own detector** every cycle; you can
**open any verdict** and see the mechanical check; findings carry **HIPAA breach framing**,
not CTF language; and it shows a real **heartbeat**, so 'continuous' is verifiable, not
claimed. Continuous, reproducible, honest — attacker and judge both untrusted, the
deterministic layer the authority. That's the platform."

---

## Grading-criterion coverage
- **Stage-1 hard gate (live target):** Beat 3 (real URL + live run).
- **Multi-agent + trust boundaries:** Beat 2. **Documentation-agent bar:** Beat 3.
- **Defensibility (the headline):** Beats 4–5 (closed loop + test-the-tester + inspectable).
- **Regression harness / "stays safe":** Beat 6. **Model-choice decision + cost:** Beat 7.
- **OWASP + threat model:** Beat 7 + THREAT_MODEL.md. **Creativity:** the self-hardening loop, Beats 1/4.

**Note on honesty:** findings are `seeded` from the threat model, run against our own fork on
synthetic data — never presented as novel 0-days.

---

## Why this stands out — the enhancements past the MVP floor

The MVP floor is "find and document." These five enhancements — **all live on the console** —
turn it from a scanner into a **closed, self-checking control.** This is the differentiation
story; lead with it if a grader asks "what makes yours different."

| # | What most submissions do | What this platform does | Show it |
| --- | --- | --- | --- |
| **E1 — regression persistence** | a dashboard that says "green right now" | **remembers** each fix across campaigns (stable per-attack key + durable store) and flips `fixed → regressed` automatically if it returns | the Find→Fix→Verify hero panel |
| **E3 — judge-integrity canary** | *claims* "our judge is deterministic" | **proves it every cycle** — pushes a known leak through the live judge and confirms it's still caught; goes red if the detector silently breaks | the "judge live: catches a planted leak" pill |
| **E3 — inspectable verdicts** | shows a verdict (trust us) | lets you **open the verdict** — raw request, response, the exact mechanical invariant, pass/fail | expand an Inspectable verdict |
| **E4 — PHI/HIPAA framing** | "info disclosure (medium)" | frames findings as **HIPAA Breach Notification reportable events** — clinical + regulatory stakes, not CTF flags | any vuln report |
| **E5 — liveness heartbeat** | "runs every 30 min" (unverifiable) | a live **cycle counter + next-run countdown** so "continuous" is witnessed, not asserted | the heartbeat panel |

**The one-liner:** it doesn't just find bugs — it **proves it keeps you safe over time, and
proves its own proof.** A green board is weak; a board that has caught a real bug, fixed it,
re-verified it, and tests its own detector is trustworthy. That distinction is the whole point.

**Grounded in a 3-lens design pass** (economics / psychology / technology): every enhancement
was chosen because it converts a *claimed* property into a *witnessed* one, at near-zero build
cost by reusing seams already in the platform — the disciplined "no" was per-agent cost
metrics and an LLM-lens drift canary (uncontested ground; the deterministic invariant already
owns that).
