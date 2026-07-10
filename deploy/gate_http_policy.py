"""HTTP bind/auth policy for independently deployable gate services.

stdlib-only. No FastAPI, no model imports.

GATE_TOKEN is the gate-service bind secret. It is intentionally distinct from:
  * GATEWAY_GATE_TOKEN -- egress outbound header toward a protected remote gate
  * X-OSSRedact-Control-Token -- appliance remote-control API

Copies of this module live under gate/, deploy/, and appliance/ and must stay
byte-identical so each tree remains standalone.
"""
from __future__ import annotations

import hmac
import os

# Capture the function object at import time so constant-time compares stay
# bound even if callers later monkeypatch hmac.compare_digest.
_COMPARE_DIGEST = hmac.compare_digest

GATE_TOKEN_ENV = 'GATE_TOKEN'
GATE_TOKEN_HEADER = 'X-OSSRedact-Gate-Token'

_LOOPBACK_HOSTS = frozenset({'127.0.0.1', '::1', 'localhost'})


def is_loopback_host(host: str | None) -> bool:
    """Exact loopback bind hosts only; no trim, no case-fold."""
    if host is None:
        return False
    return host in _LOOPBACK_HOSTS


def gate_token_required(host: str | None) -> bool:
    """Non-loopback (or empty/None) binds require a configured GATE_TOKEN."""
    return not is_loopback_host(host)


def require_gate_token_configured(host: str | None, token: str | None = None) -> str:
    """Fail startup with SystemExit when a non-loopback bind has no usable token.

    When ``token`` is omitted (or None), read ``GATE_TOKEN`` from the environment.
    Whitespace-only values are treated as unconfigured.
    Loopback binds accept a missing/empty token and return '' when unset.
    """
    if token is None:
        token = os.environ.get(GATE_TOKEN_ENV)
    if gate_token_required(host):
        if token is None or not str(token).strip():
            raise SystemExit(
                f'non-loopback bind host {host!r} requires {GATE_TOKEN_ENV} '
                f'to be set to a non-empty value before model initialization'
            )
        return str(token)
    if token is None:
        return ''
    return str(token)


def authorize_gate_request(
    presented: str | None,
    configured: str | None,
    *,
    bind_host: str | None,
) -> bool:
    """Authorize /detect and /redact.

    Loopback binds stay unauthenticated (any header accepted or absent).
    Non-loopback binds require a constant-time match of the presented header
    against the configured token. Length mismatches fail closed without raising.
    """
    if is_loopback_host(bind_host):
        return True
    if presented is None or configured is None:
        return False
    presented_s = str(presented)
    configured_s = str(configured)
    if not presented_s or not configured_s:
        return False
    try:
        return _COMPARE_DIGEST(presented_s, configured_s)
    except (TypeError, ValueError):
        return False
