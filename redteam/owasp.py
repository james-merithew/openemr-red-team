"""OWASP coverage matrix over the adversarial case set.

Foundation stub: exposes the interface Lane 4's gate imports, so the runner/gate
build against a stable signature. Lane 7 fills ``coverage_matrix`` (which OWASP
Top-10 web + LLM Top-10 cells have >=1 case) and ``required_cells`` (the cells the
gate asserts are covered).
"""

from __future__ import annotations

from typing import Any

# Cells the gate requires at least one case for. Lane 7 finalizes this list from the
# threat model's OWASP mapping table.
REQUIRED_WEB_CELLS: list[str] = ["A01", "A03", "A04", "A05"]
REQUIRED_LLM_CELLS: list[str] = ["LLM01", "LLM02", "LLM06", "LLM10"]


def coverage_matrix(cases: list[Any]) -> dict[str, Any]:
    """Return {"web": {cell: count}, "llm": {cell: count}, "missing": [required cells with 0]}."""
    web: dict[str, int] = {}
    llm: dict[str, int] = {}
    for c in cases:
        for cell in c.owasp.web:
            web[cell] = web.get(cell, 0) + 1
        for cell in c.owasp.llm:
            llm[cell] = llm.get(cell, 0) + 1
    missing = [c for c in REQUIRED_WEB_CELLS if web.get(c, 0) == 0]
    missing += [c for c in REQUIRED_LLM_CELLS if llm.get(c, 0) == 0]
    return {"web": web, "llm": llm, "missing": missing}
