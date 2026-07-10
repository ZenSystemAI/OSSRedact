"""Guard the always-redact denylist -- the TWIN/INVERSE of the allowlist.

The denylist is a SCANNER over raw field text (not a filter on detected spans): it FINDS occurrences of
user-declared terms the NER model missed -- internal codenames, client names, hostnames. It can only ADD
redaction, so a bad entry over-redacts (safe) but never under-redacts. These tests pin the boundary,
case-insensitivity, longest-first, MIN_TERM_LEN, NFC, and span-shape guarantees of the contract.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import denylist  # noqa: E402

build_terms = denylist.build_terms
compile_denylist = denylist.compile_denylist
find_spans = denylist.find_spans
normalize_term = denylist.normalize_term


def _matched(text, span):
    return text[span['start']:span['end']]


def test_finds_a_term_the_detector_would_miss():
    # the whole point of the denylist: a codename the NER model never flags as PII.
    pat = compile_denylist(['Bluebird'])
    text = "deploy the Bluebird build to staging"
    spans = find_spans(text, pat)
    assert len(spans) == 1
    assert _matched(text, spans[0]) == "Bluebird"


def test_match_is_case_insensitive():
    pat = compile_denylist(['Bluebird'])
    text = "the bluebird release shipped"
    spans = find_spans(text, pat)
    assert len(spans) == 1
    assert _matched(text, spans[0]) == "bluebird"


def test_token_boundary_does_not_match_inside_a_larger_word():
    pat = compile_denylist(['acme'])
    # 'acme' is a substring of 'acmecorp' but must NOT match -- boundary lookarounds guard it.
    assert find_spans("we use acmecorp internally", pat) == []


def test_token_boundary_matches_standalone_and_at_punctuation_edges():
    pat = compile_denylist(['acme'])
    # standalone, trailing period, and hyphen-joined ('-' is a non-word char so it is a boundary).
    assert len(find_spans("Acme is the client", pat)) == 1
    assert len(find_spans("ship to acme.", pat)) == 1
    spans = find_spans("the acme-corp account", pat)
    assert len(spans) == 1
    assert _matched("the acme-corp account", spans[0]).lower() == "acme"


def test_multi_word_phrase_matches_as_one_span():
    pat = compile_denylist(['Project Falcon'])
    text = "kickoff for Project Falcon next week"
    spans = find_spans(text, pat)
    assert len(spans) == 1
    assert _matched(text, spans[0]) == "Project Falcon"


def test_min_term_len_ignores_one_char_terms():
    # a 1-char term would redact the inside of everything; it is silently dropped.
    assert build_terms(['x', 'ab']) == ['ab']
    pat = compile_denylist(['x'])
    assert pat is None
    assert find_spans("x marks the box xylophone", pat) == []


def test_longest_first_one_span_covers_the_whole_phrase():
    # ['Falcon','Project Falcon'] over 'Project Falcon' must yield ONE span over the whole phrase,
    # never two overlapping/partial matches -- the longest declared term wins.
    pat = compile_denylist(['Falcon', 'Project Falcon'])
    text = "Project Falcon"
    spans = find_spans(text, pat)
    assert len(spans) == 1
    assert _matched(text, spans[0]) == "Project Falcon"


def test_empty_list_compiles_to_none_and_find_returns_empty():
    pat = compile_denylist([])
    assert pat is None
    assert find_spans("nothing to scan here", pat) == []


def test_whitespace_only_values_yield_no_terms():
    assert build_terms(['   ', '\t', '']) == []
    assert compile_denylist(['   ', '']) is None


def test_unicode_accented_term_matches_after_nfc():
    # decomposed (combining-accent) input normalizes to the same NFC form the text uses, so it matches.
    decomposed = 'André'  # 'André' as base + combining acute
    assert normalize_term(decomposed) == 'André'
    pat = compile_denylist([decomposed])
    text = "ping André about the rollout"
    spans = find_spans(text, pat)
    assert len(spans) == 1
    assert _matched(text, spans[0]) == "André"


def test_span_shape_matches_contract():
    pat = compile_denylist(['Bluebird'])
    text = "the Bluebird codename"
    spans = find_spans(text, pat)
    assert len(spans) == 1
    s = spans[0]
    # text[start:end] equals the matched substring; label/score/source per contract.
    assert text[s['start']:s['end']] == "Bluebird"
    assert s['label'] == 'custom'
    assert s['score'] == 1.0
    assert s['source'] == 'denylist'


def test_custom_label_is_overridable_but_defaults_to_custom():
    pat = compile_denylist(['Bluebird'])
    text = "Bluebird"
    assert find_spans(text, pat)[0]['label'] == 'custom'
    assert find_spans(text, pat, label='client')[0]['label'] == 'client'


def test_build_terms_dedups_case_insensitively_and_sorts_longest_first():
    terms = build_terms(['acme', 'ACME', 'Project Falcon', 'Bluebird'])
    # 'acme'/'ACME' collapse to one; order is longest-first then alphabetical.
    assert terms == ['Project Falcon', 'Bluebird', 'acme']


def test_multiple_occurrences_each_become_a_span():
    pat = compile_denylist(['Bluebird'])
    text = "Bluebird, then Bluebird again"
    spans = find_spans(text, pat)
    assert len(spans) == 2
    assert all(_matched(text, sp) == "Bluebird" for sp in spans)


def test_unicode_word_boundary_matches_python_re_unicode():
    """PARITY LOCK: token boundary must use Unicode word semantics (re.UNICODE \\w), so a term abutting a
    non-ASCII LETTER is NOT a boundary -> no match. Keeps the Python gate identical to the TS twin (whose
    JS \\w is ASCII-only and was fixed to \\p{L}\\p{N}_ for this exact case)."""
    pat = compile_denylist(['acme'])
    assert find_spans('ship acmeé now', pat) == []   # 'é' is a word char -> 'acme' is mid-word -> no match
    assert find_spans('ship éacme now', pat) == []
    assert len(find_spans('use acme-corp ok', pat)) == 1   # '-' is not a word char -> boundary -> match
    assert find_spans('an acmecorp x', pat) == []          # ASCII letter neighbour -> no match
