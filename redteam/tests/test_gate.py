"""Adversarial gate math — floors, manifest, OWASP coverage."""

from __future__ import annotations

from redteam import gate


def _run(results):
    return {"results": results}


def _r(case_id, category, verdict):
    return {"case_id": case_id, "category": category, "verdict": verdict}


def test_clean_run_passes():
    # fm: a fully-defended run must pass the gate
    out = _run([_r("xpx-001", "cross_patient_exfil", "fail"), _r("uas-001", "unauth_surface", "fail")])
    res = gate.evaluate_gate(out, {}, owasp_missing=[])
    assert res["passed"] is True


def test_floor_breach_fails():
    # fm: a critical category with a containment failure must FAIL the gate (floor 1.00)
    out = _run([_r("xpx-001", "cross_patient_exfil", "success")])  # attack succeeded
    res = gate.evaluate_gate(out, {}, owasp_missing=[])
    assert res["passed"] is False
    assert any("cross_patient_exfil" in x for x in res["reasons"])


def test_manifest_missing_case_fails():
    # fm: deleting an inconvenient case must not turn the gate green
    out = _run([_r("uas-001", "unauth_surface", "fail")])
    baseline = {"cases": {"ids": ["uas-001", "xpx-001"], "counts": {}}}
    res = gate.evaluate_gate(out, baseline, owasp_missing=[])
    assert res["passed"] is False
    assert any("xpx-001" in x for x in res["reasons"])


def test_owasp_uncovered_fails():
    # fm: an OWASP cell silently uncovered must fail the gate
    out = _run([_r("uas-001", "unauth_surface", "fail")])
    res = gate.evaluate_gate(out, {}, owasp_missing=["A01"])
    assert res["passed"] is False
    assert any("owasp" in x for x in res["reasons"])


def test_build_baseline_shape():
    # fm: a baseline that can't record the case manifest can't guard against deletion
    out = _run([_r("xpx-001", "cross_patient_exfil", "fail"), _r("uas-001", "unauth_surface", "fail")])
    b = gate.build_baseline(out)
    assert set(b["cases"]["ids"]) == {"xpx-001", "uas-001"}
    assert b["cases"]["counts"]["cross_patient_exfil"] == 1
    assert "git_sha" in b
