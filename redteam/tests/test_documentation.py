"""DocumentationAgent — deterministic, reproducible reports + human gate on critical."""

from __future__ import annotations

from redteam.contracts import AttackAttempt, ConfirmedExploit, DeterministicEvidence
from redteam.documentation import DocumentationAgent


def _exploit(category="cross_patient_exfil", severity="critical"):
    return ConfirmedExploit(
        attempt_id="a1", category=category, severity=severity,
        deterministic_evidence=DeterministicEvidence(phi_leaked=True, scope_widened=True, uncited_survived=False),
        reproduction_seed="seed-x",
    )


def _attempt():
    return AttackAttempt(category="cross_patient_exfil", request_transcript="pull patient 202's meds",
                         response_transcript='{"briefing":[...]}', endpoint="/chat", target_version="sha-1")


def test_critical_is_human_gated():
    # fm: a critical finding auto-published without human review
    rep = DocumentationAgent().report(_exploit(severity="critical"), _attempt(), provenance="seeded")
    assert rep["status"] == "pending_review"
    assert rep["severity"] == "critical"


def test_non_critical_files_open():
    # fm: a routine finding needlessly blocked on human review
    rep = DocumentationAgent().report(_exploit(severity="medium"), _attempt())
    assert rep["status"] == "open"


def test_report_is_reproducible_passthrough():
    # fm: a report a senior engineer cannot reproduce from (missing repro/endpoint/provenance)
    rep = DocumentationAgent().report(_exploit(), _attempt(), provenance="mutation_discovered")
    md = rep["markdown"]
    assert "pull patient 202's meds" in md      # exact reproduction transcript
    assert "/chat" in md and "seed-x" in md       # endpoint + regression seed
    assert "mutation_discovered" in md            # honest provenance
    assert "phi_leaked=True" in md                # deterministic evidence, not prose
