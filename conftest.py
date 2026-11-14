"""Put the repo root on sys.path so `redteam`, `contracts`, and the `evals/` schema
resolve under pytest / `python -m redteam.*` / the console — no installed package needed.
"""

from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
