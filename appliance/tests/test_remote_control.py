"""Off-device control plane (2026-06-22): a GUI on another machine must be able to manage a gate it does not
share a host with -- but only when an operator opts in with a shared secret (GATEWAY_CONTROL_TOKEN). Without
a token configured, the control API stays loopback-ONLY exactly as before (zero new exposure). With one, an
authenticated remote peer reaches the control routes; an unauthenticated remote peer still 403s.

Remote-control auth is header-only: X-OSSRedact-Control-Token. Query-string ?token= is rejected on every
control route including /api/stream (stream clients must send the header via fetch-based SSE, never the URL).

TestClient requests are NON-loopback by default (req.client.host == 'testclient'), so they exercise the
REMOTE path directly without monkeypatching _is_loopback. All inputs synthetic; no network.
Run: .venv-test/bin/python -m pytest appliance/tests/test_remote_control.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy as ep  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_TOKEN = 'correct-horse-battery-staple'


def _remote_client():
    # No _is_loopback monkeypatch -> TestClient peer reads as REMOTE.
    return TestClient(ep.app)


# --- default posture: no token => loopback-only, remote is refused -------------------------------------
def test_no_token_remote_is_refused(monkeypatch):
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', '')
    c = _remote_client()
    r = c.get('/api/live/status')
    assert r.status_code == 403
    # even a token header is meaningless when the gate has none configured
    r2 = c.get('/api/live/status', headers={'x-ossredact-control-token': _TOKEN})
    assert r2.status_code == 403


def test_healthz_is_public_and_reports_remote_control(monkeypatch):
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', '')
    c = _remote_client()
    r = c.get('/healthz')
    assert r.status_code == 200
    body = r.json()
    assert body['service'] == 'ossredact-egress'
    assert body['remote_control'] is False
    assert 'version' in body
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    assert c.get('/healthz').json()['remote_control'] is True


# --- with a token: authenticated remote control is allowed, unauthenticated is not --------------------
def test_token_header_allows_remote_read(monkeypatch):
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    c = _remote_client()
    r = c.get('/api/live/status', headers={'x-ossredact-control-token': _TOKEN})
    assert r.status_code == 200
    assert r.json()['enabled'] in (True, False)


def test_wrong_token_is_refused(monkeypatch):
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    c = _remote_client()
    assert c.get('/api/live/status', headers={'x-ossredact-control-token': 'nope'}).status_code == 403
    assert c.get('/api/live/status').status_code == 403  # missing entirely


def test_query_token_never_authenticates(monkeypatch):
    # Query-string tokens are never accepted on control routes. Stream and non-stream alike require
    # X-OSSRedact-Control-Token so credentials never land in URLs, access logs, Referer, or caches.
    # LIVE_VIEW off keeps a still-accepted query token from hanging TestClient on the SSE generator.
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    monkeypatch.setattr(ep, 'LIVE_VIEW', False)
    c = _remote_client()
    assert c.get(f'/api/live/status?token={_TOKEN}').status_code == 403
    assert c.get(f'/api/stream?token={_TOKEN}').status_code == 403
    assert c.get('/api/live/status', headers={'x-ossredact-control-token': _TOKEN}).status_code == 200


def test_stream_rejects_query_token_accepts_header(monkeypatch):
    # Direct /api/stream contract: ?token= is rejected; the correct control-token header authenticates.
    # With LIVE_VIEW off the route returns 404 after auth, proving acceptance without hanging on SSE.
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    monkeypatch.setattr(ep, 'LIVE_VIEW', False)
    c = _remote_client()
    assert c.get(f'/api/stream?token={_TOKEN}').status_code == 403
    assert c.get('/api/stream', headers={'x-ossredact-control-token': 'nope'}).status_code == 403
    assert c.get('/api/stream').status_code == 403
    r = c.get('/api/stream', headers={'x-ossredact-control-token': _TOKEN})
    assert r.status_code == 404  # auth passed; live view disabled
    assert 'live view disabled' in r.json().get('error', '')


def test_token_compare_is_length_safe(monkeypatch):
    # hmac.compare_digest must not raise on a length-mismatched candidate (just return False).
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    c = _remote_client()
    assert c.get('/api/live/status', headers={'x-ossredact-control-token': 'x'}).status_code == 403


def test_remote_write_needs_token_and_csrf(monkeypatch, tmp_path):
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    monkeypatch.setattr(ep, '_MODE_FILE', str(tmp_path / 'mode.txt'))
    c = _remote_client()
    # token but no CSRF header -> 403 (CSRF guard still applies)
    r = c.post('/api/settings', headers={'content-type': 'application/json', 'x-ossredact-control-token': _TOKEN},
               json={'mode': 'privacy'})
    assert r.status_code == 403
    # token + CSRF header -> accepted
    r2 = c.post('/api/settings', headers={'content-type': 'application/json', 'x-ossredact-control-token': _TOKEN,
                                          'x-ossredact-control': '1'}, json={'mode': 'privacy'})
    assert r2.status_code == 200, r2.text
    # token absent -> refused even with CSRF header
    r3 = c.post('/api/settings', headers={'content-type': 'application/json', 'x-ossredact-control': '1'},
                json={'mode': 'privacy'})
    assert r3.status_code == 403


# --- pure helpers ------------------------------------------------------------------------------------
def test_control_allowed_helper_matrix(monkeypatch):
    class _Req:
        def __init__(self, host, headers=None, qs=None, path='/api/live/status'):
            self.client = type('C', (), {'host': host})()
            self.headers = type('H', (), {'get': (headers or {}).get})()
            self.query_params = type('Q', (), {'get': (qs or {}).get})()
            self.url = type('U', (), {'path': path})()

    monkeypatch.setattr(ep, 'CONTROL_TOKEN', _TOKEN)
    assert ep._control_allowed(_Req('127.0.0.1'))                                   # loopback, no token needed
    assert ep._control_allowed(_Req('::1'))
    assert not ep._control_allowed(_Req('10.0.0.9'))                                # remote, no token
    assert ep._control_allowed(_Req('10.0.0.9', {'x-ossredact-control-token': _TOKEN}))  # header works anywhere
    # query token: never honored -- including the SSE feed (header-only auth on every control route)
    assert not ep._control_allowed(_Req('10.0.0.9', qs={'token': _TOKEN}, path='/api/stream'))
    assert not ep._control_allowed(_Req('10.0.0.9', qs={'token': _TOKEN}, path='/api/live/status'))
    # stream path still accepts the correct header
    assert ep._control_allowed(_Req('10.0.0.9', {'x-ossredact-control-token': _TOKEN}, path='/api/stream'))
    assert not ep._control_allowed(_Req('10.0.0.9', {'x-ossredact-control-token': 'bad'}))
    monkeypatch.setattr(ep, 'CONTROL_TOKEN', '')
    assert not ep._control_allowed(_Req('10.0.0.9', {'x-ossredact-control-token': _TOKEN}))  # no token => no remote


def test_cors_allows_explicit_origins(monkeypatch):
    monkeypatch.setattr(ep, 'CONTROL_CORS_ORIGINS', frozenset({'http://my-pc:5180'}))
    assert ep._cors_allows('http://my-pc:5180')
    assert ep._cors_allows('http://my-pc:5180/')          # trailing slash tolerated
    assert ep._cors_allows('http://localhost:5180')        # built-in regex still works
    assert not ep._cors_allows('http://evil.example')
    assert not ep._cors_allows(None)
