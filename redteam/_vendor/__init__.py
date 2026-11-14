"""Vendored, self-contained copies of the three small helpers the red team reused from
the Co-Pilot (`copilot/app`) when it lived in the same repo. Vendored here so this
project is fully standalone — it attacks the deployed Co-Pilot over HTTP and needs none
of its code at runtime. Kept behaviour-identical to the originals:

- `session_token` — the HMAC mint/verify contract (AUTH_TOKEN_SPEC.md), pure crypto only
  (the DB-backed `get_signing_key` is intentionally omitted; the red team mints with the
  dev key for local targets and uses no token against the prod unauth surface);
- `critic.is_unsafe_action` — the deterministic order/med-action detector an invariant reuses;
- `llm.anthropic_client` — the bounded Anthropic client factory the Claude generator reuses.
"""
