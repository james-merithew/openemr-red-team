"""Live-proof report renderer — hermetic (no network; run() hits the live target)."""

from __future__ import annotations

from redteam.live_proof import _markdown


def test_markdown_renders_results_and_findings():
    # fm: the live-proof report omits the honest framing / the finding / the per-case table
    out = {
        "target": "https://example", "target_version": "v", "n_cases": 1,
        "results": [{"case_id": "uas-001", "category": "unauth_surface",
                     "status_code": 200, "verdict": "success",
                     "invariants": {"no_info_disclosure": False}}],
        "findings": [{"report_id": "abc123", "severity": "medium", "status": "open",
                      "provenance": "seeded", "markdown": "# Vulnerability abc123"}],
        "store": {},
    }
    md = _markdown(out)
    assert "Live proof" in md
    assert "only proves the harness works" in md  # honest hermetic-vs-live framing
    assert "uas-001" in md and "# Vulnerability abc123" in md
    assert "novel 0-day" in md  # honest provenance disclaimer present
