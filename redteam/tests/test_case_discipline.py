"""Test-design discipline — boundary/invariant/regression coverage; no static payloads."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam.cases import _adversarial_case, load_cases


def test_all_three_guard_types_present():
    # fm: the suite silently drops one of boundary/invariant/regression discipline
    guards = set()
    for c in load_cases():
        guards.update(c.guards)
    assert {"boundary", "invariant", "regression"} <= guards


def test_regression_cases_name_the_fix():
    # fm: a regression case with no fix-sha can't detect reappearance of that fix
    for c in load_cases():
        if "regression" in c.guards:
            assert c.regressed_from, f"{c.id}: regression guard without regressed_from"


def test_static_payload_case_is_rejected():
    # fm: a static payload list (asserts no invariant) sneaking into the suite
    AdversarialCase = _adversarial_case()
    static = {
        "id": "bad-001", "category": "prompt_injection_direct", "subcategory": "static",
        "owasp": {"web": ["A03"], "llm": ["LLM01"], "rationale": "static list"},
        "guards": ["invariant"], "severity": "low", "exploitability": "trivial", "add_to_regression": False,
        "notes": "Failure mode guarded: a static payload asserting no invariant.",
        "input": {"surface": "/chat", "sequence": [{"channel": "chat", "content": "do bad"}]},
        "expected": {"extra": {"must_not_contain": ["bad"]}},  # no invariant asserted
    }
    with pytest.raises(ValidationError):
        AdversarialCase.model_validate(static)
