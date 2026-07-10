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


def test_placeholder_invariant_never_remints_existing_placeholder():
    """RC4 remint guard: a span covering text that is ALREADY a <LABEL_NNN> placeholder (echoed back from a
    prior turn) must be left untouched -- never re-redacted into a NEW placeholder, which single-pass
    rehydrate cannot unwind and would leak a raw token to the local chat."""
    core = _load_redact_core()
    text = 'open /home/<FILEPATH_001>/dev/x'
    start = text.index('<FILEPATH_001>')
    spans = [{'start': start, 'end': start + len('<FILEPATH_001>'), 'label': 'file_path'}]
    emap = FakeMap()

    redacted, n = core.redact_text(text, spans, emap)
    assert n == 0, 'no new mint over an existing placeholder'
    assert redacted == text, 'placeholder text passes through unchanged'
    assert emap.v2p == {}, 'no remint entry was created (no <FILEPATH_005> -> "<FILEPATH_001>")'
    # single-pass rehydrate of the untouched text is a clean no-op -- no nested raw token survives.
    assert core.rehydrate(redacted, emap.replay()) == text

    # A span that contains a placeholder PLUS adjacent text is also vetoed (search, not just exact-match), so a
    # remint can never bury the token inside a new value.
    text2 = 'val=<EMAIL_001>x'
    s2 = text2.index('<EMAIL_001>')
    spans2 = [{'start': s2, 'end': len(text2), 'label': 'email'}]
    redacted2, n2 = core.redact_text(text2, spans2, FakeMap())
    assert n2 == 0 and redacted2 == text2

    # A span INSIDE a placeholder token is vetoed too: the neural tier tags the inner text without the
    # angle brackets ("SENSITIVEACCOUNTID_016" -> password on the xlm-r-large tier), which slips past the
    # span-value containment check and used to remint (nesting the old token's brackets around a new one).
    text3 = 'old leak wrote <SENSITIVEACCOUNTID_016> here'
    s3 = text3.index('SENSITIVEACCOUNTID_016')
    spans3 = [{'start': s3, 'end': s3 + len('SENSITIVEACCOUNTID_016'), 'label': 'password'}]
    emap3 = FakeMap()
    redacted3, n3 = core.redact_text(text3, spans3, emap3)
    assert n3 == 0 and redacted3 == text3 and emap3.v2p == {}
    # ...but ordinary text between unrelated angle brackets is NOT exempt (the enclosing token must
    # actually be a placeholder): <b>hunter2caps</b> still redacts.
    text4 = 'pw <b>hunter2caps</b> end'
    s4 = text4.index('hunter2caps')
    spans4 = [{'start': s4, 'end': s4 + len('hunter2caps'), 'label': 'password'}]
    redacted4, n4 = core.redact_text(text4, spans4, FakeMap())
    assert n4 == 1 and 'hunter2caps' not in redacted4


def test_sweep_known_keep_placeholder_veto():
    """RC3: a keep_placeholder predicate vetoes a value from the cross-turn sweep so a config change (mode toggle /
    allowlist edit) takes effect on already-minted values instead of replaying their placeholder forever. The veto
    filters BOTH build_known_re (the regex) and sweep_known (the lookup), so a vetoed value is never replaced; the
    default (no predicate) preserves the original always-replay behavior."""
    core = _load_redact_core()
    emap = FakeMap()
    emap.placeholder_for('Acme', 'organization')              # -> <ORGANIZATION_001> (soft, can be excluded)
    emap.placeholder_for('4111111111111111', 'payment_card')  # -> <PAYMENTCARD_001>  (floor, never exempt)
    text = 'Acme billed 4111111111111111 last week.'

    # veto the org (e.g. coding mode now lets organizations through); keep the card (floor stays).
    keep = lambda value, ph: not ph.startswith('<ORGANIZATION')
    known = core.build_known_re(emap, keep_placeholder=keep)
    swept, n = core.sweep_known(text, known, emap, keep_placeholder=keep)
    assert 'Acme' in swept, 'a vetoed value must pass through (not swept)'
    assert '<PAYMENTCARD_001>' in swept, 'a non-vetoed (floor) value is still swept'
    assert n == 1

    # no predicate -> both replay (unchanged default behavior).
    known2 = core.build_known_re(emap)
    swept2, n2 = core.sweep_known(text, known2, emap)
    assert '<ORGANIZATION_001>' in swept2 and '<PAYMENTCARD_001>' in swept2 and n2 == 2


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
