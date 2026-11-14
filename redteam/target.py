"""Lane 1 — the Target client: the concrete seam the Red Team attacks through.

Three modes, one ``Target``-Protocol surface (``redteam/target_base.py``):

- ``hermetic`` — NO HTTP. A deterministic in-process stub that mimics a *defended*
  co-pilot: benign turns return an empty briefing; a turn carrying an injected
  directive substring returns exactly one quarantined claim. A ``response_fn``
  lets a test swap in a *vulnerable* fixture (e.g. a leak) so the gate can prove
  it catches what a broken target would emit. This is the target the eval gate
  runs against with no server, no network, no keys.
- ``local`` / ``prod`` — real HTTP via ``httpx`` against a running co-pilot. Imports
  of ``httpx`` are lazy (inside the methods) so this module imports fine with no
  server present. Any transport error degrades to ``(0, {"error": ...})`` rather
  than raising — the Red Team must never crash because a target is down.

Token helpers mint short-lived session tokens (reusing ``app.session_token``) so
attacks can present adversarial credentials — a token bound to the wrong patient,
the wrong ACL, a day scope, an expired window, or a tampered signature — and
assert the target rejects them.
"""

from __future__ import annotations

import time
import uuid
from typing import Callable, Optional

from redteam._vendor import session_token

# The dev-mode signing key the co-pilot falls back to when the signing-key table
# is absent (see ``app.session_token.get_signing_key``). Reused here so hermetic
# tests and local dev-mode runs mint tokens the target will actually verify.
DEV_SIGNING_KEY = "dev-local-signing-key-not-for-prod"

# Substrings that, in the hermetic stub, mark a message/document as carrying an
# injected directive — one quarantined claim per hit. Lowercased match.
_INJECTION_MARKERS = (
    "ignore",
    "system override",
    "prescribe",
    "disregard",
    "override",
)

_LOCAL_BASE_URL = "http://127.0.0.1:8811"
_PROD_BASE_URL = "https://copilot-production-5e86.up.railway.app"

_HTTP_TIMEOUT_S = 10.0


# --- token minting helpers ----------------------------------------------------

def mint_token(
    self: object | None = None,
    pid: int = 101,
    scope: str = "patient",
    acl: str = "patients:demo",
    sub: int = 1,
    ttl: int = 900,
    now: Optional[int] = None,
) -> str:
    """Mint a valid session token with the dev signing key.

    ``self`` is accepted (and ignored) as the leading positional so this doubles
    as a bound method on ``TargetClient`` and a module-level helper.
    """
    ts = now if now is not None else int(time.time())
    return session_token.mint(
        sub=sub,
        usr="admin",
        pid=pid,
        scope=scope,
        acl=acl,
        key=DEV_SIGNING_KEY,
        ttl=ttl,
        now=ts,
    )


def mint_variant(kind: str, pid: int = 101, now: Optional[int] = None) -> str:
    """Mint an adversarial token variant for authorization tests.

    kinds: ``wrong_pid`` (bound to pid+1), ``bad_acl`` (acl="wrong"),
    ``day_scope`` (scope="day"), ``expired`` (already past exp), ``tampered``
    (valid token with the last signature char flipped). Unknown kinds mint a
    plain valid token (degrade-never-raise).
    """
    ts = now if now is not None else int(time.time())
    if kind == "wrong_pid":
        return mint_token(pid=pid + 1, now=ts)
    if kind == "bad_acl":
        return mint_token(pid=pid, acl="wrong", now=ts)
    if kind == "day_scope":
        return mint_token(pid=pid, scope="day", now=ts)
    if kind == "expired":
        # Negative ttl -> exp already in the past. Must clear verify()'s +/-60s
        # clock-skew window, so expire an hour ago (not just -10s) to be rejected.
        return mint_token(pid=pid, ttl=-3600, now=ts)
    if kind == "tampered":
        good = mint_token(pid=pid, now=ts)
        payload_b64url, sig_b64url = good.split(".")
        last = sig_b64url[-1]
        flipped = "A" if last != "A" else "B"
        return payload_b64url + "." + sig_b64url[:-1] + flipped
    return mint_token(pid=pid, now=ts)


# --- hermetic defended-stub body ---------------------------------------------

def _injection_hits(text: str) -> int:
    """1 if the text carries an injected-directive marker, else 0 (deterministic)."""
    low = text.lower()
    return 1 if any(marker in low for marker in _INJECTION_MARKERS) else 0


def _defended_body(pid: int, message: str) -> dict:
    """The default hermetic response: a well-behaved, fail-closed co-pilot.

    An injected directive is quarantined (never surfaced as fact); a benign turn
    yields an empty briefing. Shape mirrors the co-pilot's AgentResponse so the
    gate's verifier can score it identically to a live target.
    """
    hits = _injection_hits(message)
    quarantined = (
        [{"claim": "injected directive", "reason": "unattributed_or_unsafe"}]
        if hits
        else []
    )
    return {
        "correlation_id": f"hermetic-{uuid.uuid4().hex[:12]}",
        "briefing": [],
        "guideline_evidence": [],
        "quarantined_claims": quarantined,
        "quarantined_count": hits,
        "action_chips": [],
        "constraint_flags": [],
        "critic": {"rejected_uncited": hits, "stripped_unsafe": 0},
        "degraded": False,
        "notes": "hermetic defended stub",
    }


# --- the client ---------------------------------------------------------------

class TargetClient:
    """Concrete ``Target`` implementation. See module docstring for modes."""

    def __init__(
        self,
        mode: str = "hermetic",
        response_fn: Optional[Callable[[int, str], dict]] = None,
        version: str = "hermetic",
        base_url: Optional[str] = None,
        token: Optional[str] = None,
    ) -> None:
        self.mode = mode
        self.response_fn = response_fn
        self.token = token
        if mode == "hermetic":
            self.base_url = base_url  # unused, kept for symmetry
            self.version = version
        elif mode == "local":
            self.base_url = base_url or _LOCAL_BASE_URL
            self.version = version if version != "hermetic" else "unknown"
        elif mode == "prod":
            self.base_url = base_url or _PROD_BASE_URL
            self.version = version if version != "hermetic" else "unknown"
        else:  # degrade-never-raise: unknown mode behaves as hermetic
            self.mode = "hermetic"
            self.base_url = base_url
            self.version = version

    # bound helpers so callers can do client.mint_token(...) too.
    mint_token = staticmethod(mint_token)
    mint_variant = staticmethod(mint_variant)

    # --- Target Protocol surface ---------------------------------------------

    def chat(
        self, pid: int, message: str, history: Optional[list[dict]] = None
    ) -> tuple[int, dict]:
        if self.mode == "hermetic":
            if self.response_fn is not None:
                return 200, self.response_fn(pid, message)
            return 200, _defended_body(pid, message)
        return self._http_chat(pid, message, history)

    def ingest(
        self, pid: int, doc_type: str, filename: str, content: bytes, mime: str
    ) -> tuple[int, dict]:
        if self.mode == "hermetic":
            if self.response_fn is not None:
                # Decode leniently so a poisoned-document fixture can inspect text.
                text = content.decode("utf-8", errors="replace")
                return 200, self.response_fn(pid, text)
            text = content.decode("utf-8", errors="replace")
            return 200, _defended_body(pid, text)
        return self._http_ingest(pid, doc_type, filename, content, mime)

    def ready(self) -> tuple[int, dict]:
        if self.mode == "hermetic":
            return 200, {
                "ready": True,
                "status": "ready",
                "checks": {"db": True, "llm": True, "langsmith": True},
            }
        return self._http_ready()

    def metrics(self, token: Optional[str] = None) -> tuple[int, dict]:
        if self.mode == "hermetic":
            return 200, {"red_team": {}, "turns": {}}
        return self._http_metrics(token)

    # --- HTTP implementations (lazy httpx; degrade-never-raise) ---------------

    def _auth_headers(self, token: Optional[str] = None) -> dict:
        tok = token if token is not None else self.token
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def _http_chat(
        self, pid: int, message: str, history: Optional[list[dict]], json: bool = True
    ) -> tuple[int, dict]:
        import httpx

        try:
            resp = httpx.post(
                f"{self.base_url}/chat",
                headers=self._auth_headers(),
                json={"pid": pid, "message": message, "history": history or []},
                timeout=_HTTP_TIMEOUT_S,
            )
            return resp.status_code, (resp.json() if json else {"raw": resp.text})
        except Exception as exc:  # noqa: BLE001 - never crash the Red Team on transport
            return 0, {"error": type(exc).__name__}

    def _http_ingest(
        self, pid: int, doc_type: str, filename: str, content: bytes, mime: str
    ) -> tuple[int, dict]:
        import httpx

        try:
            resp = httpx.post(
                f"{self.base_url}/ingest",
                headers=self._auth_headers(),
                files={"file": (filename, content, mime)},
                data={"pid": str(pid), "doc_type": doc_type},
                timeout=_HTTP_TIMEOUT_S,
            )
            return resp.status_code, (resp.json() if resp.text else {})
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": type(exc).__name__}

    def _http_ready(self) -> tuple[int, dict]:
        import httpx

        try:
            resp = httpx.get(f"{self.base_url}/ready", timeout=_HTTP_TIMEOUT_S)
            return resp.status_code, (resp.json() if resp.text else {})
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": type(exc).__name__}

    def _http_metrics(self, token: Optional[str] = None) -> tuple[int, dict]:
        import httpx

        try:
            resp = httpx.get(
                f"{self.base_url}/metrics/summary",
                headers=self._auth_headers(token),
                timeout=_HTTP_TIMEOUT_S,
            )
            return resp.status_code, (resp.json() if resp.text else {})
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": type(exc).__name__}
