"""Loopback-scoped CORS for the control API (/api/* + /gate/* + /healthz) so the desktop app (Tauri webview) and a
locally-served web console can read control responses + open the SSE feed cross-origin. The redaction routes
(/v1/*) and the same-origin settings page (/) must NOT get CORS headers. This never widens access: every
control route is still loopback-PEER guarded; CORS only governs which browser ORIGINS may read the response.
All inputs synthetic.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ALLOWED = [
    'http://localhost:5180',
    'http://127.0.0.1:8011',
    'http://localhost',
    'tauri://localhost',
    'http://tauri.localhost',
    'https://tauri.localhost',
]
DISALLOWED = [
    'http://evil.example',
    'https://app.attacker.com',
    'http://localhost.evil.com',
    'http://10.0.0.5:5180',
]


def _local_client(monkeypatch):
    # peer-guard satisfied so control routes return their real payload (the middleware wraps it either way)
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    return TestClient(egress_proxy.app)


def test_origin_regex_allows_loopback_and_tauri_only():
    for o in ALLOWED:
        assert egress_proxy._CORS_ORIGIN_RE.match(o), o
    for o in DISALLOWED:
        assert not egress_proxy._CORS_ORIGIN_RE.match(o), o


def test_is_control_path_scoping():
    assert egress_proxy._is_control_path('/api/allowlist')
    assert egress_proxy._is_control_path('/api/stream')
    assert egress_proxy._is_control_path('/gate/healthz')
    assert egress_proxy._is_control_path('/gate/detect')
    assert egress_proxy._is_control_path('/healthz')
    assert not egress_proxy._is_control_path('/')
    assert not egress_proxy._is_control_path('/v1/messages')
    assert not egress_proxy._is_control_path('/v1/chat/completions')


def test_control_api_reflects_allowed_origin(monkeypatch):
    c = _local_client(monkeypatch)
    for o in ALLOWED:
        r = c.get('/api/live/status', headers={'origin': o})
        assert r.status_code == 200
        assert r.headers.get('access-control-allow-origin') == o
        assert r.headers.get('vary') == 'Origin'


def test_healthz_reflects_allowed_origin(monkeypatch):
    c = _local_client(monkeypatch)
    r = c.get('/healthz', headers={'origin': 'tauri://localhost'})
    assert r.status_code == 200
    assert r.headers.get('access-control-allow-origin') == 'tauri://localhost'



def test_gate_healthz_reflects_allowed_origin(monkeypatch):
    class _HealthyGateResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {'status': 'ok'}

    class _HealthyGateClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            return _HealthyGateResponse()

    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', _HealthyGateClient)
    c = _local_client(monkeypatch)
    r = c.get('/gate/healthz', headers={'origin': 'http://localhost:5180'})
    assert r.status_code == 200
    assert r.headers.get('access-control-allow-origin') == 'http://localhost:5180'

def test_control_api_refuses_unknown_origin(monkeypatch):
    c = _local_client(monkeypatch)
    for o in DISALLOWED:
        r = c.get('/api/live/status', headers={'origin': o})
        assert 'access-control-allow-origin' not in r.headers, o


def test_preflight_options_allowed_origin(monkeypatch):
    c = _local_client(monkeypatch)
    r = c.options('/api/allowlist', headers={'origin': 'http://localhost:5180',
                                             'access-control-request-method': 'POST'})
    assert r.status_code == 204
    assert r.headers.get('access-control-allow-origin') == 'http://localhost:5180'
    assert 'POST' in r.headers.get('access-control-allow-methods', '')
    assert 'content-type' in r.headers.get('access-control-allow-headers', '').lower()


def test_preflight_options_unknown_origin_gets_no_acao(monkeypatch):
    c = _local_client(monkeypatch)
    r = c.options('/api/allowlist', headers={'origin': 'http://evil.example',
                                             'access-control-request-method': 'POST'})
    assert r.status_code == 204
    assert 'access-control-allow-origin' not in r.headers


def test_non_control_paths_get_no_cors(monkeypatch):
    # The same-origin settings page (/) is not a cross-origin consumer; it must not get CORS headers even
    # for an otherwise-allowed origin. (A redaction route would behave the same -- is_control is False.)
    c = _local_client(monkeypatch)
    r = c.get('/', headers={'origin': 'http://localhost:5180'})
    assert 'access-control-allow-origin' not in r.headers


# --- CSRF guard on state-changing control routes (the blind-CSRF confused-deputy fix) -------------------
# A hostile page in the victim's browser can ride the victim's own 127.0.0.1 socket (so _is_loopback passes)
# and issue a CORS "simple request" (text/plain, no custom header => no preflight). CORS blocks READING the
# response but not the WRITE, so without this guard the page can flip the firewall to 'off' or poison the
# allow/denylist. The X-OSSRedact-Control header is non-safelisted -> any cross-origin sender is forced to
# preflight, which the daemon answers only for loopback/Tauri origins. These tests pin both directions.
_STATE_ROUTES = [
    ('/api/settings', {'mode': 'privacy'}),
    ('/api/allowlist', {'values': ['acme']}),
    ('/api/denylist', {'values': ['acme']}),
    ('/api/live/clear', {}),
]


def test_state_routes_reject_forged_simple_post(monkeypatch):
    # The exact attack: simple cross-origin POST, no control header. Every state-changer must 403 BEFORE any
    # state mutation (the guard returns before req.json()/_write_mode), so no file path monkeypatching needed.
    c = _local_client(monkeypatch)
    for path, body in _STATE_ROUTES:
        r = c.post(path, headers={'origin': 'http://evil.example', 'content-type': 'text/plain;charset=UTF-8'},
                   content=json.dumps(body))
        assert r.status_code == 403, (path, r.status_code, r.text)
        assert 'control' in r.text.lower(), (path, r.text)


def test_state_routes_accept_with_control_header(monkeypatch, tmp_path):
    # The legit clients (same-origin settings UI + the workbench daemon.ts) send X-OSSRedact-Control: 1.
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(tmp_path / 'allow.txt'))
    monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(tmp_path / 'deny.txt'))
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(tmp_path / 'mode.txt'))
    c = _local_client(monkeypatch)
    for path, body in _STATE_ROUTES:
        r = c.post(path, headers={'content-type': 'application/json', 'x-ossredact-control': '1'}, json=body)
        assert r.status_code == 200, (path, r.status_code, r.text)


def test_preflight_advertises_control_header(monkeypatch):
    # The preflight for an allowed origin must list x-ossredact-control so a legit cross-origin client can send
    # it; a disallowed origin still gets nothing, so its preflight (and thus the real request) is rejected.
    c = _local_client(monkeypatch)
    r = c.options('/api/settings', headers={'origin': 'http://localhost:5180',
                                            'access-control-request-method': 'POST',
                                            'access-control-request-headers': 'x-ossredact-control'})
    assert r.status_code == 204
    assert 'x-ossredact-control' in r.headers.get('access-control-allow-headers', '').lower()
    r2 = c.options('/api/settings', headers={'origin': 'http://evil.example',
                                             'access-control-request-method': 'POST',
                                             'access-control-request-headers': 'x-ossredact-control'})
    assert 'access-control-allow-headers' not in r2.headers
