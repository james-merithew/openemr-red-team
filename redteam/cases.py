"""Load adversarial cases from evals/adversarial/cases/ (validated by AdversarialCase).

The case schema lives in ``evals/adversarial/schema.py`` (kept out of an importable
package on purpose — see conftest.py). We load it by path via importlib so the
runner and the OWASP report share one validated loader. A case that asserts no
invariant fails to load (the schema's model_validator), so static payload lists
cannot enter the suite.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from functools import lru_cache
from typing import Any

import yaml

_REPO = pathlib.Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _REPO / "evals" / "adversarial" / "schema.py"
_DEFAULT_CASES = _REPO / "evals" / "adversarial" / "cases"


@lru_cache(maxsize=1)
def _adversarial_case() -> Any:
    name = "adversarial_schema"
    spec = importlib.util.spec_from_file_location(name, _SCHEMA_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # register so Pydantic can resolve the module's forward refs
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    mod.AdversarialCase.model_rebuild()  # resolve string annotations (from __future__ import annotations)
    return mod.AdversarialCase


def load_cases(cases_dir: str | pathlib.Path = _DEFAULT_CASES) -> list[Any]:
    """Load + validate every case; assert dir name == case.category. Returns AdversarialCase list."""
    AdversarialCase = _adversarial_case()
    d = pathlib.Path(cases_dir)
    cases = []
    for f in sorted(d.rglob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        case = AdversarialCase.model_validate(data)
        if case.category != f.parent.name:
            raise ValueError(f"case {case.id}: category {case.category!r} != dir {f.parent.name!r}")
        cases.append(case)
    return cases
