"""redteam — the adversarial evaluation platform's agent layer.

A closed loop of four agents wrapping the read-only Clinical Co-Pilot target:
Orchestrator (deterministic ranking + budget) -> Red Team (generate + mutate) ->
Judge (independent verdict, deterministic safety veto) -> Documentation
(confirmed exploit -> structured report). Agents communicate only through the
versioned message contracts in ``redteam.contracts`` (mirrors of ``contracts/*.json``).
See ``ARCHITECTURE.md``.

This project is STANDALONE: it has no dependency on the Co-Pilot code — the three small
helpers it once reused are vendored under ``redteam._vendor`` — and it attacks the
deployed Co-Pilot target over HTTP.
"""

__all__ = ["contracts"]

# Path bootstrap: put the repo root on sys.path so `import redteam` resolves whether we
# run as a pytest suite, a `python -m redteam.*` CLI, or the console app.
import pathlib as _pathlib
import sys as _sys

_ROOT = _pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))
