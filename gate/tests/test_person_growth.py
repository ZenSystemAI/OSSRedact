"""Class B person-span GROWTH (plan 049, 2026-07-08): the neural tier catches PART of a name and the bar
clips mid-name. propagate_repeats grows each high-conf person span to the full name BEFORE collecting
propagation sources, so the whole name masks AND the completed tokens propagate doc-wide.

All names INVENTED. Run: python3 -m pytest gate/tests/test_person_growth.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import propagate_repeats  # noqa: E402


def _span(start, end, label='person', conf=0.99, tier=2, rule='gpu'):
    return {'start': start, 'end': end, 'label': label, 'tier': tier, 'conf': conf, 'rule': rule}


def _grown(text, spans):
    return {(text[s['start']:s['end']], s['rule']) for s in propagate_repeats(text, spans)}


def _grown_span(text, spans):
    """The (value, rule) of the +grow span (there should be exactly one growth per input here)."""
    out = [(text[s['start']:s['end']], s['rule']) for s in propagate_repeats(text, spans) if s['rule'].endswith('+grow')]
    return out[0] if out else None


def test_partial_token_completion_and_rightward_absorb():
    # model caught 'LOVE' of 'LOVENA PHILOMARE'; growth completes the token then absorbs the surname.
    text = "cadeau LOVENA PHILOMARE merci"
    i = text.index('LOVE')
    assert _grown_span(text, [_span(i, i + 4)]) == ('LOVENA PHILOMARE', 'gpu+grow')


def test_middle_token_grows_to_full_run():
    # 'Name: Jon Jean Okafor', model detected only the MIDDLE token 'Jean' -> grows to the full run.
    text = "Name: Jon Jean Okafor solde"
    i = text.index('Jean')
    assert _grown_span(text, [_span(i, i + 4)]) == ('Jon Jean Okafor', 'gpu+grow')


def test_right_edge_completion():
    # 'MAELLE DORVALIN' caught, trailing 'E' clipped -> completed to 'DORVALINE'.
    text = "paye MAELLE DORVALINE au"
    i = text.index('MAELLE')
    assert _grown_span(text, [_span(i, i + len('MAELLE DORVALIN'))]) == ('MAELLE DORVALINE', 'gpu+grow')


def test_growth_does_not_cross_two_space_column_gap():
    text = "JON  OKAFOR extra"     # 2 spaces between JON and OKAFOR = a column gap
    got = _grown(text, [_span(0, 3)])
    assert ('JON OKAFOR', 'gpu+grow') not in got
    assert not any(r.endswith('+grow') for _, r in got)   # nothing grew across the gap


def test_growth_does_not_absorb_ledger_stopword():
    text = "ALMA FONDS admis"       # FONDS is a ledger stopword
    got = _grown(text, [_span(0, 4)])
    assert not any(r.endswith('+grow') for _, r in got)


def test_growth_feeds_propagation_after_one_partial_catch():
    # first token barred, '...UZA SILVA' caught; growth completes 'LOUZA VILMA ARSTEVAN', then the surname
    # tokens propagate to the bare repeats later in the document.
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


def test_grown_span_keeps_label_tier_conf():
    text = "cadeau LOVENA PHILOMARE merci"
    i = text.index('LOVE')
    grown = [s for s in propagate_repeats(text, [_span(i, i + 4, conf=0.91)]) if s['rule'] == 'gpu+grow'][0]
    assert grown['label'] == 'person' and grown['tier'] == 2 and grown['conf'] == 0.91


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
