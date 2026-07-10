"""Guard the neural-span word-boundary expansion that fixes the accent/ALLCAPS partial-leak.

The model can tag only SOME subword tokens of an accented/ALLCAPS word (only 'G' of 'GENEVIEVE', only the
accented vowel of 'BELANGER'). Without expansion the rest of a real name survives literally after substitution
-- a silent partial leak on the French/Quebec text this firewall targets. expand_word_spans grows a neural span
to its full surrounding word so the whole entity is covered.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import egress_proxy  # noqa: E402

expand = egress_proxy.expand_word_spans


def _sp(start, end, label='person', tier=2, rule='gpu'):
    return {'start': start, 'end': end, 'label': label, 'tier': tier, 'rule': rule, 'conf': 1.0}


def test_fragment_expands_to_full_word():
    t = "GENEVIEVE"
    # model tagged only the leading 'G'
    out = expand(t, [_sp(0, 1)])
    assert (out[0]['start'], out[0]['end']) == (0, 9)
    assert t[out[0]['start']:out[0]['end']] == "GENEVIEVE"


def test_mid_word_accent_fragment_expands_both_directions():
    t = "BÉLANGER"
    # model tagged only the accented vowel in the middle (index 1)
    out = expand(t, [_sp(1, 2)])
    assert t[out[0]['start']:out[0]['end']] == "BÉLANGER"


def test_hyphenated_accented_name_kept_whole_for_person():
    t = "FRÉDÉRIC-ALEXANDRE"
    out = expand(t, [_sp(0, 2)])  # tagged 'FR'
    assert t[out[0]['start']:out[0]['end']] == "FRÉDÉRIC-ALEXANDRE"


def test_apostrophe_name_kept_whole():
    t = "O'NEIL"
    out = expand(t, [_sp(2, 3)])  # tagged 'N'
    assert t[out[0]['start']:out[0]['end']] == "O'NEIL"


def test_full_word_span_is_unchanged():
    t = "Tremblay"
    out = expand(t, [_sp(0, 8)])
    assert (out[0]['start'], out[0]['end']) == (0, 8)


def test_floor_spans_are_not_expanded():
    # a Tier-0 floor span is already exact; do not grow it across adjacent word chars
    t = "x4111111111111111y"
    out = expand(t, [{'start': 1, 'end': 17, 'label': 'payment_card', 'tier': 0, 'rule': 'floor:card', 'conf': 1.0}])
    assert (out[0]['start'], out[0]['end']) == (1, 17)


def test_non_person_label_does_not_cross_hyphen():
    # only person/organization treat hyphens as word-internal; an account id stops at the hyphen
    t = "AB12-CD34"
    out = expand(t, [_sp(5, 6, label='sensitive_account_id')])  # tagged 'C'
    assert t[out[0]['start']:out[0]['end']] == "CD34"


def test_word_in_context_does_not_swallow_neighbors():
    t = "et GENEVIEVE et"
    out = expand(t, [_sp(3, 4)])  # tagged 'G'
    assert t[out[0]['start']:out[0]['end']] == "GENEVIEVE"
    # surrounding ' et' words untouched
    assert out[0]['start'] == 3 and out[0]['end'] == 12
