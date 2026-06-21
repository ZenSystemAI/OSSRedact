"""Redaction MODE (privacy | coding | off) -- the one-switch UI toggle on the egress proxy, and the floor
hardening it relies on. The deterministic floor (secrets + payment cards + bank/IBAN + government/tax IDs + DOB)
must redact in EVERY mode -- 'off' is a soft-PII escape hatch, never a credential bypass. All inputs synthetic.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

FLOOR = ['secret', 'password', 'api_key', 'access_token', 'payment_card', 'card_cvv', 'card_expiry',
         'sensitive_account_id', 'bank_account', 'iban', 'routing_number', 'government_id', 'tax_id',
         'date_of_birth']
SOFT = ['person', 'organization', 'address', 'email', 'phone_number', 'ip_address']


def _set_mode(monkeypatch, tmp_path, mode):
    p = tmp_path / 'mode'
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(p))
    if mode is not None:
        p.write_text(mode + '\n')
    return p


# ---- current_mode ----------------------------------------------------------------------------------------

def test_mode_default_privacy_when_absent(monkeypatch, tmp_path):
    _set_mode(monkeypatch, tmp_path, None)
    assert egress_proxy.current_mode() == 'privacy'


def test_mode_unknown_value_falls_back_to_privacy(monkeypatch, tmp_path):
    _set_mode(monkeypatch, tmp_path, 'banana')
    assert egress_proxy.current_mode() == 'privacy'


def test_mode_reads_each_value(monkeypatch, tmp_path):
    for m in ('privacy', 'coding', 'off'):
        _set_mode(monkeypatch, tmp_path, m)
        assert egress_proxy.current_mode() == m


# ---- floor hardening (the safety invariant) --------------------------------------------------------------

def test_floor_force_redacts_in_every_mode(monkeypatch, tmp_path):
    """Every FLOOR_NEVER_EXEMPT label must be redacted under privacy, coding, AND off."""
    for mode in ('privacy', 'coding', 'off'):
        _set_mode(monkeypatch, tmp_path, mode)
        for label in FLOOR:
            assert egress_proxy.policy_allows_pii(label, {}) is True, (mode, label)


def test_floor_not_disableable_by_explicit_exclude(monkeypatch, tmp_path):
    """Even a config that names a floor label in `exclude` cannot disable it (policy-layer enforcement)."""
    _set_mode(monkeypatch, tmp_path, 'privacy')
    monkeypatch.setattr(egress_proxy, 'resolve_pii_policy',
                        lambda ctx: {'enabled': True, 'exclude': ['payment_card', 'iban', 'government_id']})
    for label in ('payment_card', 'iban', 'government_id'):
        assert egress_proxy.policy_allows_pii(label, {}) is True


# ---- mode semantics on soft PII --------------------------------------------------------------------------

def test_privacy_mode_redacts_all_soft_pii(monkeypatch, tmp_path):
    _set_mode(monkeypatch, tmp_path, 'privacy')
    for label in SOFT:
        assert egress_proxy.policy_allows_pii(label, {}) is True, label


def test_coding_mode_lets_org_through_keeps_rest(monkeypatch, tmp_path):
    _set_mode(monkeypatch, tmp_path, 'coding')
    assert egress_proxy.policy_allows_pii('organization', {}) is False   # org passes for coding agents
    for label in ('person', 'address', 'email', 'phone_number'):
        assert egress_proxy.policy_allows_pii(label, {}) is True, label
    for label in ('payment_card', 'secret', 'government_id'):            # floor unaffected
        assert egress_proxy.policy_allows_pii(label, {}) is True, label


def test_off_mode_passes_soft_pii_but_keeps_floor(monkeypatch, tmp_path):
    _set_mode(monkeypatch, tmp_path, 'off')
    for label in SOFT:
        assert egress_proxy.policy_allows_pii(label, {}) is False, label   # soft PII passes through
    for label in FLOOR:
        assert egress_proxy.policy_allows_pii(label, {}) is True, label    # floor STILL redacts


# ---- /api/settings ---------------------------------------------------------------------------------------

def _client(monkeypatch, tmp_path):
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    _set_mode(monkeypatch, tmp_path, None)
    # The legit local clients (settings UI + workbench) send the CSRF control header; mirror that here.
    return TestClient(egress_proxy.app, headers={'x-ossredact-control': '1'})


def test_settings_get_default(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    r = c.get('/api/settings')
    assert r.status_code == 200
    j = r.json()
    assert j['mode'] == 'privacy'
    assert j['modes'] == ['privacy', 'coding', 'off']
    assert j['floor_always_on'] is True


def test_settings_post_sets_and_persists(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    r = c.post('/api/settings', json={'mode': 'coding'})
    assert r.status_code == 200 and r.json() == {'ok': True, 'mode': 'coding'}
    assert egress_proxy.current_mode() == 'coding'
    assert c.get('/api/settings').json()['mode'] == 'coding'


def test_settings_post_rejects_invalid_mode(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    r = c.post('/api/settings', json={'mode': 'nuke-everything'})
    assert r.status_code == 400
    assert egress_proxy.current_mode() == 'privacy'   # unchanged


def test_settings_loopback_guarded():
    c = TestClient(egress_proxy.app)   # peer host 'testclient' is non-loopback
    assert c.get('/api/settings').status_code == 403
    assert c.post('/api/settings', json={'mode': 'off'}).status_code == 403


def test_live_status_includes_mode(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    c.post('/api/settings', json={'mode': 'off'})
    assert c.get('/api/live/status').json()['mode'] == 'off'
