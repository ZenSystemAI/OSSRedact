"""Pure redaction-core tests.

This module covers appliance/redact_core.py without importing the egress proxy, FastAPI, httpx, or EntityMap.
All values are synthetic.
"""
import builtins
import importlib.util
import os
import re
import socket


def _load_redact_core():
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'redact_core.py'))
    spec = importlib.util.spec_from_file_location('redact_core_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMap:
    def __init__(self):
        self.v2p = {}
        self.p2v = {}
        self.counters = {}

    def placeholder_for(self, value, label):
        ph = self.v2p.get(value)
        if ph is not None:
            return ph, False
        lab = re.sub(r'[^A-Z0-9]', '', label.upper()) or 'PII'
        self.counters[lab] = self.counters.get(lab, 0) + 1
        ph = f'<{lab}_{self.counters[lab]:03d}>'
        self.v2p[value] = ph
        self.p2v[ph] = value
        return ph, True

    def replay(self):
        return dict(self.p2v)


def test_pure_redact_core_uses_no_network_or_file_io(monkeypatch):
    core = _load_redact_core()

    def blocked(*_args, **_kwargs):
        raise AssertionError('pure redact_core attempted file or socket I/O')

    monkeypatch.setattr(builtins, 'open', blocked)
    monkeypatch.setattr(socket, 'socket', blocked)

    text = 'Email user@example.test and repeat user@example.test.'
    first = text.index('user@example.test')
    spans = [{'start': first, 'end': first + len('user@example.test'), 'label': 'email'}]
    emap = FakeMap()

    redacted, n = core.redact_text(text, spans, emap)
    assert n == 1
    assert redacted == 'Email <EMAIL_001> and repeat user@example.test.'

    swept, n_swept = core.sweep_known(redacted, core.build_known_re(emap), emap)
    assert n_swept == 1
    assert swept == 'Email <EMAIL_001> and repeat <EMAIL_001>.'
    assert core.rehydrate(swept, emap.replay()) == text


def test_person_sweep_preserves_lowercase_paths_and_usernames():
    core = _load_redact_core()
    text = "I'm Nadia; open /home/nadia/dev/x and log in as nadia."
    first = text.index('Nadia')
    spans = [{'start': first, 'end': first + len('Nadia'), 'label': 'person'}]
    emap = FakeMap()

    redacted, n = core.redact_text(text, spans, emap)
    assert n == 1
    swept, n_swept = core.sweep_known(redacted, core.build_known_re(emap), emap)

    assert n_swept == 0
    assert swept.count('<PERSON_001>') == 1
    assert '/home/nadia/dev/x' in swept
    assert 'as nadia' in swept
    assert core.rehydrate(swept, emap.replay()) == text
