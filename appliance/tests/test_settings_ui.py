"""The local settings UI for the do-not-redact allowlist (GET / + /api/allowlist on the egress proxy).

Covers: the page renders, values round-trip + go LIVE in the gate's allowlist, file-based live-reload, input
cleaning (trim/dedupe/cap), the loopback guard, and Phase 4 path-disclosure removal on allowlist / denylist /
settings JSON (no host filesystem path for local or authenticated remote callers). All inputs are synthetic.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class _Req:
    def __init__(self, host):
        self.client = type('C', (), {'host': host})()


def test_is_loopback_logic():
    assert egress_proxy._is_loopback(_Req('127.0.0.1'))
    assert egress_proxy._is_loopback(_Req('::1'))
    assert not egress_proxy._is_loopback(_Req('192.168.1.5'))
    assert not egress_proxy._is_loopback(_Req(''))


def test_clean_allow_values_trims_dedupes_caps():
    out = egress_proxy._clean_allow_values(['  Alex ', 'alex', '', 'a' * 300, 'x', 'X', 7])
    assert out == ['Alex', 'x']  # trim; case-insens dedupe keeps first spelling; drop empty/overlong/non-str


def _local_client(monkeypatch, tmp_path):
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(tmp_path / 'allowlist.txt'))
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_MTIME', -1)
    # The legit local clients (settings UI + workbench) send the CSRF control header; mirror that here.
    return TestClient(egress_proxy.app, headers={'x-ossredact-control': '1'})


def test_settings_page_renders(monkeypatch, tmp_path):
    c = _local_client(monkeypatch, tmp_path)
    r = c.get('/')
    assert r.status_code == 200
    assert 'Do-not-redact' in r.text
    assert 'Always-redact' in r.text    # denylist tab wired
    assert 'Redaction mode' in r.text   # mode switch present
    assert 'never' in r.text.lower()  # the secrets-never-exempt warning is present


def test_allowlist_roundtrip_and_goes_live(monkeypatch, tmp_path):
    c = _local_client(monkeypatch, tmp_path)
    assert c.get('/api/allowlist').json()['values'] == []  # empty to start
    r = c.post('/api/allowlist', json={'values': ['alex', 'alex@example.com', '  alex ']})
    d = r.json()
    assert d['ok'] and d['values'] == ['alex', 'alex@example.com']  # deduped
    assert c.get('/api/allowlist').json()['values'] == ['alex', 'alex@example.com']  # persisted
    # and it is LIVE in the gate's effective allowlist, case-insensitively
    al = egress_proxy.current_allowlist()
    assert egress_proxy.allowlist_mod.is_allowlisted('Alex', al)
    assert egress_proxy.allowlist_mod.is_allowlisted('alex@example.com', al)


def test_file_edit_is_live_reloaded(monkeypatch, tmp_path):
    """Editing the allowlist file by hand (not via the UI) is also picked up live, on the file's own mtime."""
    f = tmp_path / 'allowlist.txt'
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(f))
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_MTIME', -1)
    f.write_text('# comment\nmarie\n', encoding='utf-8')
    assert egress_proxy.allowlist_mod.is_allowlisted('Marie', egress_proxy.current_allowlist())
    # change the file -> the live set updates
    f.write_text('jean\n', encoding='utf-8')
    al = egress_proxy.current_allowlist()
    assert egress_proxy.allowlist_mod.is_allowlisted('jean', al)
    assert not egress_proxy.allowlist_mod.is_allowlisted('marie', al)


def test_settings_ui_is_loopback_only(monkeypatch, tmp_path):
    """The gate may serve agents on 0.0.0.0, but the allowlist editor must be unreachable over the network --
    TestClient's peer host is 'testclient' (non-loopback), so every settings route must 403."""
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(tmp_path / 'allowlist.txt'))
    c = TestClient(egress_proxy.app)  # _is_loopback NOT patched -> guard active
    assert c.get('/').status_code == 403
    assert c.get('/api/allowlist').status_code == 403
    assert c.post('/api/allowlist', json={'values': ['x']}).status_code == 403


def test_post_rejects_malformed_body(monkeypatch, tmp_path):
    c = _local_client(monkeypatch, tmp_path)
    assert c.post('/api/allowlist', json={'nope': 1}).status_code == 400
    assert c.post('/api/allowlist', json=['not', 'a', 'dict']).status_code == 400



# ---------------------------------------------------------------------------
# Phase 4: control API responses must not disclose host filesystem paths
# ---------------------------------------------------------------------------
_CONTROL_TOKEN = 'correct-horse-battery-staple'


def _remote_authed_client(monkeypatch, tmp_path):
    """Authenticated REMOTE peer (TestClient host is non-loopback). Mirrors production remote-control headers."""
    monkeypatch.setattr(egress_proxy, 'CONTROL_TOKEN', _CONTROL_TOKEN)
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(tmp_path / 'allowlist.txt'))
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_MTIME', -1)
    monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(tmp_path / 'denylist.txt'))
    monkeypatch.setattr(egress_proxy, '_DENYLIST_SIG', None)
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(tmp_path / 'mode'))
    return TestClient(
        egress_proxy.app,
        headers={
            'x-ossredact-control-token': _CONTROL_TOKEN,
            'x-ossredact-control': '1',
        },
    )


def _assert_no_path_disclosure(body: dict) -> None:
    """Authenticated control JSON must carry counts/state only -- never a host filesystem path."""
    assert isinstance(body, dict)
    assert 'path' not in body, f'control API must not disclose path, got keys={sorted(body)}'
    # Defense in depth: no residual absolute-path-looking string values (synthetic or real).
    for key, val in body.items():
        if isinstance(val, str):
            assert not val.startswith('/'), f'{key} must not be an absolute path, got {val!r}'
            assert '\\' not in val, f'{key} must not look like a filesystem path, got {val!r}'


def test_allowlist_response_omits_path_for_authenticated_remote(monkeypatch, tmp_path):
    c = _remote_authed_client(monkeypatch, tmp_path)
    r = c.get('/api/allowlist')
    assert r.status_code == 200, r.text
    body = r.json()
    assert 'values' in body and isinstance(body['values'], list)
    assert 'active_total' in body and isinstance(body['active_total'], int)
    assert 'config_values' in body and isinstance(body['config_values'], int)
    _assert_no_path_disclosure(body)


def test_denylist_response_omits_path_for_authenticated_remote(monkeypatch, tmp_path):
    c = _remote_authed_client(monkeypatch, tmp_path)
    r = c.get('/api/denylist')
    assert r.status_code == 200, r.text
    body = r.json()
    assert 'values' in body and isinstance(body['values'], list)
    assert 'active_total' in body and isinstance(body['active_total'], int)
    assert 'config_values' in body and isinstance(body['config_values'], int)
    _assert_no_path_disclosure(body)


def test_settings_response_omits_path_for_authenticated_remote(monkeypatch, tmp_path):
    c = _remote_authed_client(monkeypatch, tmp_path)
    r = c.get('/api/settings')
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get('mode') in ('privacy', 'coding', 'off')
    assert body.get('floor_always_on') is True
    assert isinstance(body.get('modes'), list)
    _assert_no_path_disclosure(body)


def test_control_list_and_settings_responses_omit_path_on_loopback(monkeypatch, tmp_path):
    """Path omission is not remote-only: local loopback clients also receive counts/state without path."""
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(tmp_path / 'allowlist.txt'))
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_MTIME', -1)
    monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(tmp_path / 'denylist.txt'))
    monkeypatch.setattr(egress_proxy, '_DENYLIST_SIG', None)
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(tmp_path / 'mode'))
    c = _local_client(monkeypatch, tmp_path)
    for route in ('/api/allowlist', '/api/denylist', '/api/settings'):
        r = c.get(route)
        assert r.status_code == 200, (route, r.text)
        _assert_no_path_disclosure(r.json())


def test_path_omission_still_requires_control_auth(monkeypatch, tmp_path):
    """Auth preconditions stay intact: remote callers without a valid control token still 403."""
    monkeypatch.setattr(egress_proxy, 'CONTROL_TOKEN', _CONTROL_TOKEN)
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(tmp_path / 'allowlist.txt'))
    monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(tmp_path / 'denylist.txt'))
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(tmp_path / 'mode'))
    c = TestClient(egress_proxy.app)  # remote peer, no auth headers
    for route in ('/api/allowlist', '/api/denylist', '/api/settings'):
        assert c.get(route).status_code == 403
        assert c.get(route, headers={'x-ossredact-control-token': 'wrong-token'}).status_code == 403