"""Session-token mint + verify — vendored HMAC contract (pure crypto, no DB).

Behaviour-identical to the Co-Pilot's `session_token` (AUTH_TOKEN_SPEC.md) so a token the
red team mints with the dev signing key verifies against a local dev-mode Co-Pilot. The
DB-backed `get_signing_key` is omitted on purpose — the red team never reads the target's
DB; it mints with the dev key for local targets and uses no token against the prod unauth
surface. Design invariants preserved: signature covers the LITERAL payload segment,
base64url no-pad, HMAC-SHA256, constant-time compare, fail-closed verify.
"""

from __future__ import annotations

import base64
import hmac
import json
from dataclasses import dataclass
from hashlib import sha256

_VALID_SCOPES = frozenset({"patient", "day"})


class TokenInvalid(Exception):
    """Any verification failure — malformed, bad signature, expired, or bad claims."""


@dataclass(frozen=True)
class Claims:
    user_id: int
    usr: str
    pid: int
    scope: str
    acl: str
    exp: int


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _sign(payload_b64url: str, key: str) -> str:
    mac = hmac.new(key.encode("utf-8"), payload_b64url.encode("ascii"), sha256).digest()
    return _b64url_encode(mac)


def mint(sub: int, usr: str, pid: int, scope: str, acl: str, key: str, ttl: int, now: int) -> str:
    payload = {
        "v": 1, "sub": int(sub), "usr": usr, "pid": int(pid), "scope": scope,
        "acl": acl, "iat": int(now), "exp": int(now) + int(ttl),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64url = _b64url_encode(payload_json.encode("utf-8"))
    return payload_b64url + "." + _sign(payload_b64url, key)


def verify(token: str, key: str, now: int, skew: int = 60) -> Claims:
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenInvalid("malformed")
    payload_b64url, sig_b64url = token.split(".")
    if not payload_b64url or not sig_b64url:
        raise TokenInvalid("malformed")
    expected = _sign(payload_b64url, key)
    if not hmac.compare_digest(expected, sig_b64url):
        raise TokenInvalid("bad_signature")
    try:
        payload = json.loads(_b64url_decode(payload_b64url))
    except Exception as exc:  # noqa: BLE001
        raise TokenInvalid("undecodable_payload") from exc
    if not isinstance(payload, dict):
        raise TokenInvalid("payload_not_object")
    if payload.get("v") != 1:
        raise TokenInvalid("bad_version")
    try:
        sub = int(payload["sub"]); usr = str(payload["usr"]); pid = int(payload["pid"])
        scope = str(payload["scope"]); acl = str(payload["acl"])
        iat = int(payload["iat"]); exp = int(payload["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenInvalid("missing_or_bad_claims") from exc
    if scope not in _VALID_SCOPES:
        raise TokenInvalid("bad_scope")
    if exp < now - skew:
        raise TokenInvalid("expired")
    if iat > now + skew:
        raise TokenInvalid("future_iat")
    return Claims(user_id=sub, usr=usr, pid=pid, scope=scope, acl=acl, exp=exp)
