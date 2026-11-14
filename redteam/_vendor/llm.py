"""Vendored Anthropic client factory — bounded timeout + one retry.

Behaviour-identical to the Co-Pilot's `app.graph.workers._anthropic_client`, reused by the
Claude attack generator. Accepts a settings-like object exposing `anthropic_api_key` and
(optionally) `request_deadline_s`; the ClaudeAttackGenerator degrades to canned attacks if
this is unavailable, so a missing key never blocks a run.
"""

from __future__ import annotations


def anthropic_client(s):  # noqa: ANN001 — settings-like duck type
    import anthropic

    timeout = max(1.0, float(getattr(s, "request_deadline_s", 20.0)))
    return anthropic.Anthropic(api_key=s.anthropic_api_key, timeout=timeout, max_retries=1)
