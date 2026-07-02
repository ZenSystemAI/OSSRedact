"""GET /api/claude_cli/bootstrap must transparently forward Claude Code's client-config fetch upstream.

WHY THIS ROUTE EXISTS: Claude Code fetches GET ${ANTHROPIC_BASE_URL}/api/claude_cli/bootstrap on startup to load
its per-model autocompact context window (clientdata -> autoCompactWindowsCache). With no route the gate 404s it,
so a model not in CC's hardcoded fallback set (notably the default claude-opus-4-8) gets autocompact-window
source="auto", which DISABLES autocompaction -> context grows unbounded (observed: a cached prefix to ~579k that
never compacted). Gate-OFF the same fetch hits api.anthropic.com and works -> the blowup is gate-specific.

These tests prove the forward is correct AND privacy-preserving: it carries the auth/fingerprint headers, preserves
the query string, sends NO request body, returns the upstream bytes verbatim (never redacted/rehydrated), strips
cookies, and -- critically -- does NOT open a generic /api/* passthrough (unknown /api paths still 404; non-GET
still 405), so no arbitrary path or body can reach upstream unredacted. All inputs synthetic.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class _FakeUpstream:
    def __init__(self, status_code, headers, content):
        self.status_code = status_code
        self.headers = headers
        self._content = content

    @property
    def content(self):
        return self._content


class _CapturingGetClient:
    """Stub for httpx.AsyncClient that records the outbound GET and returns a canned upstream response."""
    last = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        type(self).last = {'url': url, 'headers': headers or {}}
        # A response that LOOKS like it has rehydratable PII + a placeholder token, to prove the route does NOT
        # touch the body (no redaction, no rehydration): both must come back byte-for-byte.
        return _FakeUpstream(
            200,
            {'content-type': 'application/json', 'x-request-id': 'req_boot_synthetic',
             'set-cookie': 'sess=must-not-forward', 'anthropic-ratelimit-requests-remaining': '42'},
            json.dumps({'autoCompactWindow': 200000,
                        'verbatim': 'name Jane Roy and token <PERSON_001> must survive untouched'}).encode('utf-8'),
        )

    # Present so an accidental switch to POST forwarding would be caught by the route-method tests, not here.
    async def post(self, *a, **k):  # pragma: no cover
        raise AssertionError('bootstrap route must forward via GET, never POST')


def _client(monkeypatch):
    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', _CapturingGetClient)
    _CapturingGetClient.last = None
    return TestClient(egress_proxy.app)


def test_bootstrap_route_is_registered_as_get():
    """Regression anchor: before the fix this path had no route (404); it must now exist as GET."""
    routes = {(m, getattr(r, 'path', None))
              for r in egress_proxy.app.routes
              for m in (getattr(r, 'methods', None) or [])}
    assert ('GET', '/api/claude_cli/bootstrap') in routes


def test_bootstrap_forwards_query_and_fingerprint_headers_no_body(monkeypatch):
    c = _client(monkeypatch)
    r = c.get('/api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8',
              headers={'authorization': 'Bearer synthetic-token',
                       'user-agent': 'claude-cli/2.1.195',
                       'x-stainless-os': 'Linux',
                       'x-api-key': 'sk-synthetic'})
    assert r.status_code == 200
    sent = _CapturingGetClient.last
    assert sent is not None, 'route did not forward upstream'
    # the allowlisted config selectors reach upstream: `model` is required (selects which model's window comes back)
    assert sent['url'].startswith(egress_proxy.ANTHROPIC_UPSTREAM + '/api/claude_cli/bootstrap?')
    assert 'entrypoint=cli' in sent['url']
    assert 'model=claude-opus-4-8' in sent['url']
    # the OAuth/Max + SDK fingerprint that authenticates the request as the real client is forwarded
    lk = {k.lower(): v for k, v in sent['headers'].items()}
    assert lk.get('authorization') == 'Bearer synthetic-token'
    assert lk.get('user-agent') == 'claude-cli/2.1.195'
    assert lk.get('x-stainless-os') == 'Linux'
    assert lk.get('x-api-key') == 'sk-synthetic'


def test_bootstrap_query_is_allowlisted_drops_pii_smuggling(monkeypatch):
    """Hardening (Codex review): the un-redacted bootstrap route must forward ONLY entrypoint+model, so a caller
    cannot smuggle PII upstream via an extra query param."""
    c = _client(monkeypatch)
    r = c.get('/api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8'
              '&leak=alex%40example.com&cwd=%2Fhome%2Falex%2Fsecret',
              headers={'authorization': 'Bearer t'})
    assert r.status_code == 200
    url = _CapturingGetClient.last['url']
    assert 'entrypoint=cli' in url and 'model=claude-opus-4-8' in url
    # the non-allowlisted params (and their PII values) are stripped before egress
    for forbidden in ('leak', 'example.com', 'cwd', 'alex', '%2Fhome', '/home'):
        assert forbidden not in url, f'{forbidden!r} must not reach upstream'


def test_bootstrap_returns_config_verbatim_never_redacted(monkeypatch):
    c = _client(monkeypatch)
    r = c.get('/api/claude_cli/bootstrap', headers={'authorization': 'Bearer t'})
    body = r.json()
    assert body['autoCompactWindow'] == 200000
    # the response is config coming BACK from Anthropic: it must NOT be redacted or rehydrated -- verbatim bytes.
    assert body['verbatim'] == 'name Jane Roy and token <PERSON_001> must survive untouched'


def test_bootstrap_strips_cookies_keeps_safe_headers(monkeypatch):
    c = _client(monkeypatch)
    r = c.get('/api/claude_cli/bootstrap', headers={'authorization': 'Bearer t'})
    assert 'set-cookie' not in {k.lower() for k in r.headers.keys()}
    assert r.headers.get('x-request-id') == 'req_boot_synthetic'
    assert r.headers.get('anthropic-ratelimit-requests-remaining') == '42'


def test_bootstrap_is_get_only_post_405(monkeypatch):
    """Fail CLOSED: a non-GET method must not forward a (potentially PII-bearing) body upstream."""
    c = _client(monkeypatch)
    r = c.post('/api/claude_cli/bootstrap', json={'x': 1})
    assert r.status_code == 405
    assert _CapturingGetClient.last is None, 'POST must never reach the upstream forward'


def test_no_generic_api_passthrough_unknown_paths_still_404(monkeypatch):
    """The fix is an EXACT route, not a catch-all: every other unhandled /api path must still 404 (fail closed)."""
    c = _client(monkeypatch)
    for path in ('/api/claude_cli/other', '/api/claude_cli', '/api/anything', '/v1/some_new_endpoint'):
        r = c.get(path)
        assert r.status_code == 404, f'{path} unexpectedly routed (status {r.status_code})'
    assert _CapturingGetClient.last is None, 'no unknown path may reach the upstream forward'
