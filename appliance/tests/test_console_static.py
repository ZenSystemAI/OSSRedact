"""Gate-served console (/console): the browser GUI for a gate host without the desktop app.

Contract under test:
  - loopback-ONLY, same posture as the settings UI at '/' (a TestClient peer reads as REMOTE, so the
    403 path needs no monkeypatching; content tests monkeypatch _is_loopback like the control tests do);
  - bare /console redirects to /console/ (the build's relative asset URLs only resolve under a slash);
  - files are contained to the build dir (realpath BEFORE the prefix check -> ../ and symlinks cannot
    escape), unknown paths fall back to the SPA shell;
  - a missing build produces a 404 with a build hint, never a crash.
All inputs synthetic; no network. Run: .venv-test/bin/python -m pytest appliance/tests/test_console_static.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy as ep  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def _client():
    return TestClient(ep.app)


def _mk_build(tmp_path):
    (tmp_path / 'assets').mkdir()
    (tmp_path / 'index.html').write_text('<!doctype html><title>console-shell</title>')
    (tmp_path / 'assets' / 'app.js').write_text('console.log("app")')
    return str(tmp_path)


# --- posture: loopback-only ----------------------------------------------------------------------------
def test_console_refuses_non_loopback(tmp_path, monkeypatch):
    monkeypatch.setattr(ep, 'CONSOLE_DIR', _mk_build(tmp_path))
    c = _client()   # TestClient peer is 'testclient' -> remote
    assert c.get('/console', follow_redirects=False).status_code == 403
    assert c.get('/console/', follow_redirects=False).status_code == 403
    assert c.get('/console/assets/app.js', follow_redirects=False).status_code == 403


# --- serving -------------------------------------------------------------------------------------------
def test_console_redirects_bare_path_and_serves_build(tmp_path, monkeypatch):
    monkeypatch.setattr(ep, 'CONSOLE_DIR', _mk_build(tmp_path))
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    c = _client()
    r = c.get('/console', follow_redirects=False)
    assert r.status_code == 307 and r.headers['location'] == '/console/'
    r = c.get('/console/')
    assert r.status_code == 200 and 'console-shell' in r.text
    r = c.get('/console/assets/app.js')
    assert r.status_code == 200 and 'app' in r.text


def test_console_unknown_path_falls_back_to_spa_shell(tmp_path, monkeypatch):
    monkeypatch.setattr(ep, 'CONSOLE_DIR', _mk_build(tmp_path))
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    r = _client().get('/console/some/deep/link')
    assert r.status_code == 200 and 'console-shell' in r.text


# --- containment ---------------------------------------------------------------------------------------
def test_console_traversal_cannot_escape_build_dir(tmp_path, monkeypatch):
    build = tmp_path / 'dist'
    build.mkdir()
    (build / 'index.html').write_text('<!doctype html><title>console-shell</title>')
    secret = tmp_path / 'secret.txt'
    secret.write_text('do-not-serve')
    monkeypatch.setattr(ep, 'CONSOLE_DIR', str(build))
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    c = _client()
    # Encoded traversal reaches the handler with a '..' path segment; realpath containment must stop it.
    r = c.get('/console/%2e%2e/secret.txt')
    assert r.status_code == 404 or 'do-not-serve' not in r.text
    # A symlink INSIDE the build dir pointing outside must not escape either.
    os.symlink(str(secret), str(build / 'leak.txt'))
    r = c.get('/console/leak.txt')
    assert 'do-not-serve' not in r.text


def test_console_missing_build_hints_at_npm(tmp_path, monkeypatch):
    monkeypatch.setattr(ep, 'CONSOLE_DIR', str(tmp_path / 'nope'))
    monkeypatch.setattr(ep, '_is_loopback', lambda req: True)
    r = _client().get('/console/')
    assert r.status_code == 404
    assert 'npm run build' in r.json()['hint']
