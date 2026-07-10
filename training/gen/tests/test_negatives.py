"""Tests for the negatives generator (Phase 3 Task 3.2, clean_fp coverage).

A PURE-NEGATIVE doctype: every row MUST have output.spans == [] and output.entities == {} (no PII labeled
ever), yet carry many explicit hard-negative look-alikes (decoys) so the model sees amounts, ISO dates,
bare numbers, ports, versions, private IPs, build hashes, city names, and bank/merchant names in clean
context. Run: .venv-test/bin/python -m pytest training/gen/tests/test_negatives.py -q
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import negatives  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_zero_spans_and_entities():
    """The defining property: pure-negative rows have NO positives at all."""
    random.seed(101)
    for _ in range(300):
        r = negatives.gen()
        assert r['output']['spans'] == []          # zero labeled spans, by construction
        assert r['output']['entities'] == {}       # derived entities are empty too


def test_offsets_exact_and_labels_in_scheme():
    """Vacuously true for the spans (there are none), but assert structure + that nothing slipped in.

    Also confirms: if any span ever existed it would be offset-exact and in the 20-set; the empty loop
    documents the contract and guards against a future regression that introduces d.field by mistake.
    """
    random.seed(102)
    for _ in range(200):
        r = negatives.gen()
        t = r['input']
        assert isinstance(t, str) and len(t) > 0
        for s, e, lab in r['output']['spans']:
            assert 0 <= s < e <= len(t)
            assert t[s:e].strip() != ""
            assert lab in _LABELS


def test_decoys_present_and_unlabeled():
    """Decoys must exist (clean_fp only works if the look-alikes are actually there) and are NEVER labeled.

    Since spans == [] is enforced elsewhere, 'never labeled' is automatic; here we assert the generator is
    not emitting empty documents: a meaningful number of decoys per row across the batch.
    """
    random.seed(103)
    total_decoys = 0
    for _ in range(120):
        r = negatives.gen()
        n = r['meta']['n_decoys']
        assert n >= 3, f"too few decoys ({n}) for a clean_fp negative"
        total_decoys += n
    assert total_decoys > 600                       # the moat: lots of clean look-alikes


def test_lookalikes_appear_in_clean_context():
    """The hard-negative shapes the spec names must actually show up in the corpus text, unlabeled.

    Aggregate over many rows: amounts ($), ISO dates, bare numeric runs, ports, version strings, private
    IPs, 64-hex build hashes, and pk_live/pk_test publishable keys should all appear across the batch.
    """
    random.seed(104)
    blob = []
    for _ in range(200):
        blob.append(negatives.gen()['input'])
    text = "\n".join(blob)
    assert "$" in text                                              # amounts
    assert re.search(r'20\d\d-\d\d-\d\d', text)                     # ISO date look-alikes
    assert re.search(r'\b\d{7,11}\b', text)                        # bare numeric runs (account look-alike)
    assert re.search(r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2\d|3[01])|127\.0\.0\.1)', text)  # private/loopback IP
    assert re.search(r'[0-9a-f]{64}', text)                        # 64-hex build hash (secret-vs-hash rule)
    assert re.search(r'pk_(?:live|test)_', text)                   # Stripe publishable key (public, NEGATIVE)
    assert re.search(r'\b\d+\.\d+\.\d+', text)                     # semver version strings


def test_lang_distribution_and_meta():
    """~65% FR / 35% EN and the doctype is tagged 'negatives'."""
    random.seed(105)
    fr = 0
    n = 800
    for _ in range(n):
        r = negatives.gen()
        assert r['meta']['doctype'] == "negatives"
        assert r['meta']['synthetic'] is True
        if r['meta']['lang'] == "fr":
            fr += 1
    frac = fr / n
    assert 0.55 <= frac <= 0.75, f"FR fraction {frac:.2f} out of expected band"


def test_explicit_lang_argument_respected():
    random.seed(106)
    for _ in range(20):
        assert negatives.gen("fr")['meta']['lang'] == "fr"
        assert negatives.gen("en")['meta']['lang'] == "en"
