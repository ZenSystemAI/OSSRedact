"""Class B person-span GROWTH -- appliance twin of gate/tests/test_person_growth.py (plan 049, 2026-07-08).
propagate_repeats grows each high-conf person span to the full name before collecting propagation sources.
Loaded by explicit path (module name clash). All names INVENTED.
Run: .venv-test/bin/python -m pytest appliance/tests/test_person_growth.py -q
"""
import importlib.util
import os

_PATH = os.path.join(os.path.dirname(__file__), '..', 'privacy_gate.py')
_spec = importlib.util.spec_from_file_location('appliance_privacy_gate', _PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
propagate_repeats = _mod.propagate_repeats


def _span(start, end, label='person', conf=0.99, tier=2, rule='gpu'):
    return {'start': start, 'end': end, 'label': label, 'tier': tier, 'conf': conf, 'rule': rule}


def _grown(text, spans):
    return {(text[s['start']:s['end']], s['rule']) for s in propagate_repeats(text, spans)}


def _grown_span(text, spans):
    out = [(text[s['start']:s['end']], s['rule']) for s in propagate_repeats(text, spans) if s['rule'].endswith('+grow')]
    return out[0] if out else None


def test_partial_token_completion_and_rightward_absorb():
    text = "cadeau LOVENA PHILOMARE merci"
    i = text.index('LOVE')
    assert _grown_span(text, [_span(i, i + 4)]) == ('LOVENA PHILOMARE', 'gpu+grow')


def test_middle_token_grows_to_full_run():
    text = "Name: Jon Jean Okafor solde"
    i = text.index('Jean')
    assert _grown_span(text, [_span(i, i + 4)]) == ('Jon Jean Okafor', 'gpu+grow')


def test_right_edge_completion():
    text = "paye MAELLE DORVALINE au"
    i = text.index('MAELLE')
    assert _grown_span(text, [_span(i, i + len('MAELLE DORVALIN'))]) == ('MAELLE DORVALINE', 'gpu+grow')


def test_growth_does_not_cross_two_space_column_gap():
    text = "JON  OKAFOR extra"
    got = _grown(text, [_span(0, 3)])
    assert not any(r.endswith('+grow') for _, r in got)


def test_growth_does_not_absorb_ledger_stopword():
    text = "ALMA FONDS admis"
    got = _grown(text, [_span(0, 4)])
    assert not any(r.endswith('+grow') for _, r in got)


def test_growth_feeds_propagation_after_one_partial_catch():
    text = "vire LOUZA VILMA ARSTEVAN ok\nrow: ARSTEVAN total\nnote vilma encore"
    i = text.index('LOUZA')
    got = _grown(text, [_span(i, i + len('LOUZA VILMA'))])
    assert ('LOUZA VILMA ARSTEVAN', 'gpu+grow') in got
    repeats = {v for v, r in got if r == 'repeat'}
    assert 'ARSTEVAN' in repeats and 'vilma' in repeats


def test_low_conf_person_span_does_not_grow():
    text = "paye MAELLE DORVALINE au"
    i = text.index('MAELLE')
    got = _grown(text, [_span(i, i + len('MAELLE DORVALIN'), conf=0.5)])
    assert not any(r.endswith('+grow') for _, r in got)


# ---- Codex adversarial-review regressions (2026-07-08) ----

def test_growth_never_absorbs_log_status_words():
    # MEDIUM: 'INFO user=John Error Retrying' -- growth must not absorb 'Error'/'Retrying' into the person
    # span, and neither may propagate as name tokens (they would mask log noise document-wide).
    text = "INFO user=Johnathan Error Retrying now. Error again later. Retrying forever."
    spans = [_span(text.index('Johnathan'), text.index('Johnathan') + len('Johnathan'))]
    out = propagate_repeats(text, spans)
    for s in out:
        val = text[s['start']:s['end']]
        assert 'Error' not in val and 'Retrying' not in val, (val, s)


def test_growth_works_across_crlf_document():
    # Growth edge-completion must still fire when the line ends in \r\n (token scan treats \r as boundary).
    text = "payee MARC DE FERLANDAISE\r\nnext MARC DE FERLANDAISE\r\n"
    # model catches only 'MARC DE FERLANDAIS' (partial last token) on the first occurrence
    start = text.index('MARC')
    spans = [_span(start, start + len('MARC DE FERLANDAIS'))]
    out = propagate_repeats(text, spans)
    grown = [text[s['start']:s['end']] for s in out if s['rule'].endswith('+grow')]
    assert grown and grown[0] == 'MARC DE FERLANDAISE', out


def test_growth_denies_french_status_words():
    text = "session de Johanne Erreur Reessayer maintenant. Erreur encore."
    start = text.index('Johanne')
    spans = [_span(start, start + len('Johanne'))]
    for s in propagate_repeats(text, spans):
        val = text[s['start']:s['end']]
        assert 'Erreur' not in val and 'Reessayer' not in val, (val, s)
