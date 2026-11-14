# Demo script — AI Red Team platform (Week 3 FINAL, ~5 min, all-live)

A live-system walkthrough. **No repos, no Markdown, no code files on screen** — only the
deployed platform, the live target, and your voice. `[SCREEN]` = what's on screen (all live),
`[SAY]` = narration (direct, confident, your voice). The line the whole demo is built around:
> *"It doesn't just find bugs — it proves it keeps you safe over time, and proves its own proof."*

---

## Setup — before you record (everything below is LIVE, no files)

**Open these 3 browser tabs:**
1. **Console** — `https://red-team-console-production.up.railway.app`  ← the star; your home base
2. **Live target `/ready`** — `https://copilot-production-5e86.up.railway.app/ready`
3. **The Co-Pilot itself, in OpenEMR** — `https://openemr-production-31ad.up.railway.app`,
   **logged in already (off-camera)**, on **Marcus Delgado's chart** with the Co-Pilot panel open.

**Prep:** log into OpenEMR before recording (don't film the password). Do one dry run so you
know where each console panel is. Use your **voice throughout**; webcam on if you're comfortable —
for a defensibility-graded demo, being the person who made the calls matters.

Optional 4th tab: `https://copilot-production-5e86.up.railway.app/openapi.json` (shows 404 — the fix).

---

## The script

### Beat 1 — The problem + the thesis (0:00–0:30)
`[SCREEN]` Tab 3 — the live Co-Pilot answering on Marcus Delgado's chart (a cited briefing).
`[SAY]` "This is a live AI Clinical Co-Pilot inside OpenEMR — it reads a patient's chart and
briefs the doctor, every claim cited to a source. It's a real system handling health data. The
question a security team actually asks isn't 'did you find one bug' — it's 'can you keep proving
this is safe as it changes.' So I built a platform that finds vulnerabilities, drives the fix,
and continuously proves the fix holds. One line: **it doesn't just find bugs — it proves it
keeps you safe over time, and proves its own proof.**"

### Beat 2 — The platform, live: four agents + deterministic authority (0:30–1:25)
`[SCREEN]` Tab 1 — the console. Scroll it top to bottom slowly as you name each agent.
`[SAY]` "This is that platform, deployed and running right now — it re-attacks the live Co-Pilot
on a schedule. Four agents. An Orchestrator picks what to attack next under a hard budget. A Red
Team generates and mutates attacks. A Judge decides if one succeeded — and here's the decision I
defend hardest: the Judge's authority is a **deterministic invariant, not an LLM vote**. Did PHI
actually leak, did patient scope actually widen — computed, not opinionated. And the Judge is a
**separate agent** from the Red Team, because anything that grades its own attacks has a conflict
of interest by design. A Documentation agent writes the reports. Trust boundaries are explicit:
attack, judge, and routine reports run autonomously; a **critical report and any remediation
need a human** — the platform is a read-only observer, it never pushes a fix itself."

### Beat 3 — Live attack on the deployed target + a real finding (1:25–2:10)
`[SCREEN]` Tab 1 — the console's **live target status** and the finding it surfaces (the hero
panel's RED row / the finding detail).
`[SAY]` "It runs bounded campaigns against the **deployed** target continuously — the real live
system, not a mock. It found a genuine vulnerability: the readiness endpoint was handing the
entire internal architecture to any anonymous caller. The platform captured the exact request,
the leaked response, and — because this is a HIPAA-covered system — framed it as a **Breach
Notification reportable event**, not a CTF flag. Clinical and regulatory stakes, stated up front."

### Beat 4 — The closed loop: found → fixed → verified (2:10–3:00) · *headline*
`[SCREEN]` Tab 1 — the **Find → Fix → Verify hero panel**. Then Tab 2 — live `/ready` (now bare).
Optional Tab 4 — `/openapi.json` → 404.
`[SAY]` "Here's what makes it a platform and not a scanner. The console shows the whole arc live:
RED — the invariant tripped on the leaked component map. FIX — we restricted the endpoint. GREEN
— findings one to zero, verified. And here's that same endpoint live right now" — *(switch to Tab
2)* — "bare status, no architecture. It's not a one-time check: every campaign re-runs the probe,
and if that leak ever comes back this panel flips to 'regressed' automatically. Found, fixed, and
**continuously** verified."

### Beat 5 — "Test the tester" + inspectable verdicts (3:00–3:45) · *the killer beat*
`[SCREEN]` Tab 1 — the **"judge live: catches a planted leak"** pill; then expand an
**Inspectable verdict**.
`[SAY]` "The obvious objection to any AI-checks-AI system is 'it's marking its own homework.' Two
answers, both live. One: every cycle the platform pushes a known leak through the live judge and
confirms it's still caught — that's this 'judge live' pill. If an invariant ever silently broke,
this goes **red**, not falsely green. Two: you don't have to trust a verdict — you can open it.
Here's a judged attack: the raw request, the response, the exact mechanical check that ran, and
the pass/fail. Deterministic evidence over a real payload, not a conclusion."

### Beat 6 — Regression memory + the drill (3:45–4:15)
`[SCREEN]` Tab 1 — the regression-store panel (`fixed: 1`) and the cycle counter.
`[SAY]` "Every confirmed exploit becomes a versioned regression case keyed by the attack itself,
so it persists across campaigns — the store remembers the fix is holding, and you can see the
cycle counter climbing, so 'continuous' is witnessed, not claimed. And the loop is **closed**,
not one-directional: reintroduce the leak with one flag, the platform catches it going
zero-to-one, then restore it to zero. A control fire-drill — my own fork, synthetic data."

### Beat 7 — Coverage, model choice, cost (4:15–4:45)
`[SCREEN]` Tab 1 — the OWASP coverage panel + the per-category resilience.
`[SAY]` "Every attack maps to OWASP web and LLM Top-10 — full coverage across seven categories.
On models: frontier models refuse offensive work, so attack generation sits behind a swappable
interface — and because the Judge is deterministic, a refusing generator gives you *fewer*
attacks, never *false* findings. On cost: the invariants, the gate, the regression replays are
all deterministic — zero dollars — so cost scales **sub-linearly**; you only spend tokens
generating genuinely new attacks."

### Beat 8 — Why this stands out + close (4:45–5:15)
`[SCREEN]` Tab 1 — the whole live dashboard.
`[SAY]` "Most adversarial-AI submissions are a static scan and a dashboard that's always green —
and a board that's never once shown red is impossible to trust. Mine is different in five ways
you just saw live: the loop **closes across time** — it remembers a fix and flips to 'regressed'
if it comes back; it **tests its own detector** every cycle; you can **open any verdict** and see
the mechanical check; findings carry **HIPAA breach framing**; and it shows a real **heartbeat**.
Continuous, reproducible, honest — attacker and judge both untrusted, the deterministic layer the
authority. It doesn't just find bugs — it proves it keeps you safe, and proves its own proof.
That's the platform."

---

## The five things that make it stand out (all visible on the live console)

| # | Most submissions | This platform | Live proof on screen |
| --- | --- | --- | --- |
| **E1 — regression persistence** | "green right now" | remembers each fix across campaigns; flips `fixed → regressed` automatically | Find→Fix→Verify hero panel |
| **E3 — judge-integrity canary** | *claims* a deterministic judge | proves it every cycle; goes red if the detector breaks | "judge live" pill |
| **E3 — inspectable verdicts** | "trust the verdict" | open it: raw payload + the exact invariant | expand a verdict |
| **E4 — PHI/HIPAA framing** | "info disclosure (medium)" | HIPAA Breach-Notification reportable event | finding detail |
| **E5 — liveness heartbeat** | "runs every 30 min" | live cycle counter + next-run countdown | heartbeat panel |

**The through-line:** a green board is weak; a board that has caught a real bug, fixed it,
re-verified it, and continuously tests its own detector is trustworthy. Every one of these
converts a *claimed* property into a *witnessed* one — chosen via a 3-lens (economics /
psychology / technology) design pass, at near-zero cost by reusing seams already in the platform.

---

## Delivery notes
- **Home base is the console (Tab 1)** — you're on it for Beats 2–8. Only leave it to show the
  live target (Beat 4) and the live Co-Pilot (Beat 1).
- **Bookend the one-liner:** say it in Beat 1, pay it off in Beats 4–5, land it in Beat 8.
- **Slow down on Beats 4 and 5** — let the RED→GREEN arc and the "judge live" pill land.
- **Nothing is read off a document.** If you want to fire an attack from a terminal live, that's
  optional; the console already proves it. (Command, if you want it:
  `…\copilot\.venv\Scripts\python.exe -m redteam.live_proof --category unauth_surface` from the
  red-team folder — warm it up once first.)
- **Honesty note to keep in mind:** findings are seeded from the threat model, run against our own
  fork on synthetic data — never presented as novel 0-days.

## Grading-criterion coverage
Stage-1 live target → Beats 1,3,4 · multi-agent + trust boundaries → Beat 2 · Documentation bar →
Beat 3 · defensibility (headline) → Beats 4–5 · regression harness → Beat 6 · model-choice + cost
→ Beat 7 · OWASP + threat model → Beat 7 · creativity / differentiation → Beats 1,4,8.
