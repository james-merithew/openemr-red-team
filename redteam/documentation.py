"""DocumentationAgent — confirmed exploit -> structured, reproducible vuln report.

The load-bearing report fields (id, category, severity, endpoint, reproduction
transcript, deterministic evidence, provenance, status) are **deterministic
passthrough** from the confirmed-exploit + attack-attempt records — not re-derived by
a model — so a senior engineer can reproduce and fix the finding from the report
alone. Severity is computed, not written. Human-approval gate: a CRITICAL finding is
filed as ``pending_review`` (never auto-published), everything else as ``open``.
Provenance is stated honestly: ``seeded`` (from our threat model) vs
``mutation_discovered`` — a seeded case is never presented as a novel discovery.
"""

from __future__ import annotations

from redteam import observability
from redteam.contracts import AttackAttempt, ConfirmedExploit

_CLINICAL_IMPACT = {
    "prompt_injection_direct": "A scope-overriding instruction could make the co-pilot assert an unverified clinical fact a physician might act on in the ~90 seconds between rooms.",
    "prompt_injection_indirect": "Malicious text inside an ingested document could steer later answers, contaminating the chart summary a physician trusts.",
    "cross_patient_exfil": "PHI from the wrong patient reaching the briefing is a HIPAA breach and a direct patient-safety risk — a physician could act on another patient's data.",
    "multiturn_erosion": "Safeguards eroding across a conversation could surface an unsafe order/med suggestion the critic is supposed to strip on every turn.",
    "tool_abuse_dos": "Unbounded tool/loop use degrades availability and inflates cost, delaying the between-rooms briefing physicians depend on.",
    "unauth_surface": "An unauthenticated caller learning the internal integration map / API surface gains the reconnaissance needed to target the PHI-bearing data stores behind the sidecar.",
    "persona_privilege": "An in-band role claim that escalates privilege could bypass the per-patient scope and reach data the user is not authorized to see.",
}

_REGULATORY_IMPACT = {
    "prompt_injection_direct": "If the injected instruction moves PHI into the response, that unauthorized disclosure is a HIPAA Breach Notification Rule reportable event (potential OCR penalty, plus patient-safety and clinician-trust harm).",
    "prompt_injection_indirect": "A poisoned document that steers the briefing toward another patient's data is an unauthorized PHI disclosure — a HIPAA Breach Notification Rule reportable event (potential OCR penalty, plus patient-safety and trust harm).",
    "cross_patient_exfil": "Cross-patient PHI disclosure is a textbook HIPAA Breach Notification Rule reportable event (potential OCR penalty, mandatory patient/HHS notification, and direct patient-safety and trust harm).",
    "multiturn_erosion": "If eroded safeguards surface an unsafe order/med suggestion a physician acts on, the result is a patient-safety incident and clinical-liability exposure, not merely a technical defect.",
    "tool_abuse_dos": "Availability and cost harm: a degraded or unaffordable co-pilot delays the between-rooms briefing, an operational and patient-care continuity risk rather than a direct breach.",
    "unauth_surface": "Reconnaissance of the PHI-bearing integration map is a HIPAA Security Rule access-control weakness and a precursor to a reportable breach, even before any record is disclosed.",
    "persona_privilege": "Privilege escalation past the per-patient scope reaches records the user is not authorized to see — an unauthorized PHI disclosure and a HIPAA Breach Notification Rule reportable event (potential OCR penalty, plus trust harm).",
}

_REMEDIATION = {
    "prompt_injection_direct": "Add programmatic input sanitization; keep the verifier/critic as the exit gate.",
    "prompt_injection_indirect": "Delimit + quarantine ingested free-text as untrusted before it enters the prompt.",
    "cross_patient_exfil": "Confirm the two-layer authz (enforce_patient + per-patient scope) rejects before any read.",
    "multiturn_erosion": "Ensure the deterministic critic strips order/med actions on every turn regardless of history.",
    "tool_abuse_dos": "Verify the loop/cost caps (routes/iters/deadline) bound the turn regardless of the prompt.",
    "unauth_surface": "Restrict the endpoint (auth/rate-limit); return a bare status to unauthenticated callers.",
    "persona_privilege": "Roles are server-assigned; ensure in-band persona claims can't alter the critic/verifier chain.",
}


class DocumentationAgent:
    def report(self, exploit: ConfirmedExploit, attempt: AttackAttempt, provenance: str = "seeded") -> dict:
        status = "pending_review" if exploit.severity == "critical" else "open"
        ev = exploit.deterministic_evidence
        md = (
            f"# Vulnerability {exploit.exploit_id} — {exploit.category}\n\n"
            f"- **Severity:** {exploit.severity}\n"
            f"- **Status:** {status}\n"
            f"- **Provenance:** {provenance}\n"
            f"- **Endpoint:** {attempt.endpoint}\n"
            f"- **Target version:** {attempt.target_version}\n"
            f"- **Correlation id:** {exploit.correlation_id}\n\n"
            "## Description & clinical impact\n\n"
            f"A `{exploit.category}` weakness confirmed against `{attempt.endpoint}`. "
            f"{_CLINICAL_IMPACT.get(exploit.category, 'Impacts the trustworthiness of the clinical briefing.')}\n\n"
            "## Regulatory / business impact\n\n"
            f"{_REGULATORY_IMPACT.get(exploit.category, 'On a HIPAA-covered clinical system this erodes clinician trust and defensibility; synthetic data here, but the same weakness against production PHI would carry regulatory and patient-safety consequences.')}\n\n"
            "_Scope note: findings are proven against synthetic demo data on our own fork; the framing above states the consequence the same weakness would carry against production PHI._\n\n"
            "## Reproduction\n\n"
            f"Send to `{attempt.endpoint}`:\n\n```\n{attempt.request_transcript}\n```\n\n"
            "Observed response:\n\n```json\n"
            f"{attempt.response_transcript}\n```\n\n"
            "## Observed vs expected\n\n"
            f"- **Observed:** deterministic evidence — phi_leaked={ev.phi_leaked}, "
            f"scope_widened={ev.scope_widened}, uncited_survived={ev.uncited_survived}, "
            f"sentinels_hit={ev.sentinels_hit}.\n"
            "- **Expected:** the safe invariant holds — no PHI/cross-patient leak, no uncited claim, "
            "no order/med action reaches the user.\n\n"
            "## Recommended remediation\n\n"
            f"{_REMEDIATION.get(exploit.category, 'Harden the affected path; add a regression case.')}\n\n"
            "## Fix validation\n\n"
            f"Stored as a regression case (seed `{exploit.reproduction_seed}`); re-run the mutation "
            "family — the invariant must hold across variants, not just the literal payload.\n"
        )
        observability.record_finding(category=exploit.category, severity=exploit.severity, status=status)
        return {"report_id": exploit.exploit_id, "severity": exploit.severity,
                "status": status, "provenance": provenance, "markdown": md}
