"""/gate/* passthrough: the console Deep-detect route on the daemon (found missing live 2026-07-04).

Contract under test:
  - both routes refuse a non-loopback peer without a control token (same posture as every control route);
  - /gate/healthz proxies the ACTIVE gate's healthz (primary first, fallback on connection failure) and
    stamps `via`; all gates down -> 502, never a crash;
  - /gate/detect requires the CSRF header, validates the body, returns the daemon's _detect_neural spans
    (chunking + failover + cache for free), and maps a dead gate to 502;
  - /gate/detect reuses MAX_BODY_BYTES (UTF-8 wire bytes) and returns 413 before model entry when over cap.
All inputs synthetic; no network (httpx.AsyncClient is stubbed). Run:
  .venv-test/bin/python -m pytest appliance/tests/test_gate_passthrough.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy as ep  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def _client():
    return TestClient(ep.app)


class _FakeResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f'HTTP {self.status_code}')

    def json(self):
        return self._data


class _FakeAsyncClient:
    """Stub for httpx.AsyncClient: routes GET by URL from a {url_prefix: response|exception} table."""
    table = {}

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        for prefix, resp in self.table.items():
            if url.startswith(prefix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise AssertionError(f'unexpected GET {url}')


# --- posture ---------------------------------------------------------------------------------------------
def test_gate_routes_refuse_non_loopback():
    c = _client()   # TestClient peer is 'testclient' -> remote, no token configured
    assert c.get('/gate/healthz').status_code == 403
    assert c.post('/gate/detect', json={'text': 'x'}).status_code == 403


def test_gate_detect_requires_csrf_header(monkeypatch):
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    c = _client()
    assert c.post('/gate/detect', json={'text': 'x'}).status_code == 403  # loopback but no header


# --- /gate/healthz ---------------------------------------------------------------------------------------
def test_gate_healthz_proxies_primary(monkeypatch):
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    monkeypatch.setattr(ep, 'GATE_URL', 'http://primary:8001')
    monkeypatch.setattr(ep, 'GATE_FALLBACK_URL', '')
    _FakeAsyncClient.table = {'http://primary:8001': _FakeResp({'status': 'ok', 'model': 'm-large'})}
    monkeypatch.setattr(ep.httpx, 'AsyncClient', _FakeAsyncClient)
    r = _client().get('/gate/healthz')
    assert r.status_code == 200
    d = r.json()
    assert d['status'] == 'ok' and d['model'] == 'm-large' and 'primary' in d['via']


def test_gate_healthz_fails_over_to_fallback(monkeypatch):
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    monkeypatch.setattr(ep, 'GATE_URL', 'http://primary:8001')
    monkeypatch.setattr(ep, 'GATE_FALLBACK_URL', 'http://fallback:8001')
    _FakeAsyncClient.table = {
        'http://primary:8001': ConnectionError('down'),
        'http://fallback:8001': _FakeResp({'status': 'ok', 'model': 'm-base'}),
    }
    monkeypatch.setattr(ep.httpx, 'AsyncClient', _FakeAsyncClient)
    d = _client().get('/gate/healthz').json()
    assert d['status'] == 'ok' and 'fallback' in d['via']


def test_gate_healthz_all_down_is_502(monkeypatch):
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    monkeypatch.setattr(ep, 'GATE_URL', 'http://primary:8001')
    monkeypatch.setattr(ep, 'GATE_FALLBACK_URL', '')
    _FakeAsyncClient.table = {'http://primary:8001': ConnectionError('down')}
    monkeypatch.setattr(ep.httpx, 'AsyncClient', _FakeAsyncClient)
    assert _client().get('/gate/healthz').status_code == 502


# --- /gate/detect ----------------------------------------------------------------------------------------
_CSRF = {'x-ossredact-control': '1'}


def test_gate_detect_returns_daemon_spans(monkeypatch):
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)

    async def fake_detect(aclient, text, min_score=0.5):
        assert text == 'Jean Tremblay NAS 046 454 286' and min_score == 0.7
        return [{'start': 0, 'end': 13, 'label': 'person', 'tier': 1, 'conf': 0.99, 'rule': 'npu'}]

    monkeypatch.setattr(ep, '_detect_neural', fake_detect)
    r = _client().post('/gate/detect', headers=_CSRF,
                       json={'text': 'Jean Tremblay NAS 046 454 286', 'min_score': 0.7})
    assert r.status_code == 200
    assert r.json()['spans'][0]['label'] == 'person'


def test_gate_detect_dead_gate_is_502_and_bad_body_400(monkeypatch):
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)

    async def fake_none(aclient, text, min_score=0.5):
        return None

    monkeypatch.setattr(ep, '_detect_neural', fake_none)
    c = _client()
    assert c.post('/gate/detect', headers=_CSRF, json={'text': 'x'}).status_code == 502
    assert c.post('/gate/detect', headers=_CSRF, json={}).status_code == 400
    assert c.post('/gate/detect', headers=_CSRF, json={'text': 'x', 'min_score': 'nan-ish'}).status_code == 400


# --- /gate/detect body-size cap (UTF-8 wire bytes, before model entry) ------------------------------------
def test_gate_detect_accepts_valid_unicode_within_byte_cap(monkeypatch):
    """A multi-byte Unicode payload under MAX_BODY_BYTES is accepted and reaches _detect_neural."""
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    # Cap large enough for a short accented string; assert neural sees the decoded text.
    monkeypatch.setattr(ep, 'MAX_BODY_BYTES', 4096)
    seen = {'n': 0, 'text': None}

    async def fake_detect(aclient, text, min_score=0.5):
        seen['n'] += 1
        seen['text'] = text
        return [{'start': 0, 'end': len(text), 'label': 'person', 'tier': 1, 'conf': 0.9, 'rule': 'npu'}]

    monkeypatch.setattr(ep, '_detect_neural', fake_detect)
    # Synthetic French name with multi-byte chars (UTF-8 length > char length).
    text = 'Jos\u00e9e Lefebvre caf\u00e9'
    r = _client().post('/gate/detect', headers=_CSRF, json={'text': text})
    assert r.status_code == 200, r.text
    assert seen['n'] == 1, '_detect_neural must run for an in-cap payload'
    assert seen['text'] == text
    assert r.json()['spans'][0]['label'] == 'person'


def test_gate_detect_rejects_over_cap_utf8_before_neural(monkeypatch):
    """UTF-8 wire-byte overflow on /gate/detect returns 413 and never calls _detect_neural.

    Cap is counted on the request body bytes (same MAX_BODY_BYTES used by /v1), not Python char length,
    so a short multi-byte string can still trip the limit. Content-Length precheck and post-read
    backstop both apply; either path must refuse model entry.
    """
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    # 40-byte cap: a JSON body with a multi-byte text field exceeds it while remaining tiny as chars.
    monkeypatch.setattr(ep, 'MAX_BODY_BYTES', 40)
    called = {'n': 0}

    async def must_not_run(aclient, text, min_score=0.5):
        called['n'] += 1
        raise AssertionError('_detect_neural must not run for an over-cap /gate/detect body')

    monkeypatch.setattr(ep, '_detect_neural', must_not_run)
    # Force a body larger than 40 UTF-8 bytes via many multi-byte code points.
    text = 'cafe' + ('e\u0301' * 40)  # combining acute on e -> multi-byte UTF-8
    r = _client().post('/gate/detect', headers=_CSRF, json={'text': text})
    assert r.status_code == 413, f'expected 413 over-cap, got {r.status_code}: {r.text}'
    body = r.json()
    assert body.get('error'), '413 body must carry an error field'
    assert body.get('max_bytes') == 40, '413 body must report the configured max_bytes'
    assert called['n'] == 0, 'over-cap /gate/detect must reject before _detect_neural'
