"""OWASP coverage matrix over the real adversarial case set."""

from __future__ import annotations

from redteam import owasp
from redteam.cases import load_cases


def test_required_owasp_cells_all_covered():
    # fm: an OWASP required cell (web or LLM) with no case -> coverage gap in the suite
    cov = owasp.coverage_matrix(load_cases())
    assert cov["missing"] == [], f"uncovered OWASP cells: {cov['missing']}"
    # sanity: the matrix actually counted cells
    assert cov["web"] and cov["llm"]


def test_every_required_cell_has_a_case():
    # fm: a required cell present in REQUIRED_* but absent from any case
    cov = owasp.coverage_matrix(load_cases())
    for cell in owasp.REQUIRED_WEB_CELLS:
        assert cov["web"].get(cell, 0) >= 1
    for cell in owasp.REQUIRED_LLM_CELLS:
        assert cov["llm"].get(cell, 0) >= 1
