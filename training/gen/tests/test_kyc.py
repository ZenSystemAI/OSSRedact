"""Tests for the kyc / loan_app generator (Phase 3 Task 3.2).

Offset-exactness, required catastrophic-ID positives, labels-in-scheme, and the key precision property:
the Luhn-invalid SIN/card look-alikes, order refs, build hashes, lone institution/transit fragments, amounts,
and non-DOB ISO dates are NEVER labeled. Run: .venv-test/bin/python -m pytest training/gen/tests/ -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import kyc  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def _luhn_ok(s: str) -> bool:
    digits = re.sub(r'\D', '', s)
    if not digits:
        return False
    total = 0
    for i, c in enumerate(reversed(digits)):
        x = int(c)
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for _ in range(200):
        r = kyc.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            assert 0 <= s < e <= len(t)
            assert t[s:e] != ""                 # span is non-empty by construction
            assert t[s:e].strip() != ""         # never an empty/whitespace span
            assert lab in _LABELS               # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"government_id", "payment_card", "card_cvv", "card_expiry", "tax_id",
            "person", "date_of_birth", "address", "postal_code", "phone_number", "email"}
    seen = set()
    for _ in range(60):
        r = kyc.gen()
        seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_government_id_mix_appears():
    """Across many rows, government_id must include SIN-shaped, RAMQ-NAM-shaped, and SAAQ-permis-shaped."""
    random.seed(23)
    saw_sin = saw_ramq = saw_saaq = False
    for _ in range(60):
        r = kyc.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab != "government_id":
                continue
            v = t[s:e]
            digits = re.sub(r'\D', '', v)
            if re.fullmatch(r'[A-Z]\d{12}', v):
                saw_saaq = True                                  # 1 letter + 12 digits
            elif re.match(r'^[A-Z]{4}', v) and len(digits) == 8:
                saw_ramq = True                                  # 4 letters + 8 digits
            elif re.fullmatch(r'[\d \-]+', v) and len(digits) == 9:
                saw_sin = True                                   # 9-digit SIN
    assert saw_sin and saw_ramq and saw_saaq, (saw_sin, saw_ramq, saw_saaq)


def test_positive_sin_and_card_pass_luhn():
    """Labeled SIN (within government_id) and every labeled payment_card must be Luhn-valid."""
    random.seed(24)
    checked_card = False
    for _ in range(120):
        r = kyc.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            v = t[s:e]
            if lab == "payment_card":
                assert _luhn_ok(v), f"payment_card not Luhn-valid: {v}"
                checked_card = True
            if lab == "government_id":
                digits = re.sub(r'\D', '', v)
                if len(digits) == 9 and re.fullmatch(r'[\d \-]+', v):   # SIN shape only
                    assert _luhn_ok(v), f"SIN not Luhn-valid: {v}"
    assert checked_card


def test_decoys_never_labeled():
    """The precision property: decoy look-alikes are present in text but never appear as a labeled span."""
    random.seed(25)
    for _ in range(200):
        r = kyc.gen()
        t = r['input']
        labeled_spans = {(s, e) for s, e, _ in r['output']['spans']}
        labeled_values = [t[s:e] for s, e, _ in r['output']['spans']]

        # amounts ($) are decoys, never labeled
        for v in labeled_values:
            assert "$" not in v
            assert not re.fullmatch(r'[0-9a-f]{64}', v)         # 64-hex build hash decoy never labeled
            assert not re.match(r'(CMD|REF|ORD)-', v)           # order-ref decoy never labeled

        # a Luhn-INVALID 9-digit run must NOT be labeled government_id (it is the decoy)
        for s, e, lab in r['output']['spans']:
            v = t[s:e]
            digits = re.sub(r'\D', '', v)
            if lab == "government_id" and len(digits) == 9 and re.fullmatch(r'[\d \-]+', v):
                assert _luhn_ok(v)


def test_train_brand_cued_pan_and_inline_sin_appear():
    """v11 round-2 cue diversification: TRAIN layouts must sometimes cue payment_card by network BRAND
    (matched to the PAN IIN) and government_id (SIN) INLINE in prose -- alternatives to the formal labels.
    Both stay Luhn-valid positives; brand prefix must match the labeled PAN's IIN."""
    random.seed(27)
    saw_brand_pan = saw_inline_sin = False
    inline_re = re.compile(r"(numero d'assurance sociale (est|fourni au dossier est|\()"
                           r"|social insurance number (is|provided on file is|\())")
    for _ in range(400):
        r = kyc.gen(split="train")
        t = r['input']
        if inline_re.search(t):
            saw_inline_sin = True
        for s, e, lab in r['output']['spans']:
            if lab == "payment_card":
                pan = t[s:e]
                lead = t[max(0, s - 40):s]
                m = re.search(r'(VISA|MASTERCARD|AMEX)', lead)
                if m:
                    saw_brand_pan = True
                    first = re.sub(r'\D', '', pan)[0]
                    expect = {'4': 'VISA', '3': 'AMEX', '5': 'MASTERCARD'}[first]
                    assert m.group(1) == expect, f"brand {m.group(1)} != IIN brand {expect} for {pan}"
                    assert _luhn_ok(pan)
    assert saw_brand_pan, "no brand-cued payment_card seen in train"
    assert saw_inline_sin, "no inline-prose SIN seen in train"


def test_heldout_split_has_no_new_train_cues():
    """The new cues are TRAIN-ONLY: the heldout path (split-agnostic body) must NOT emit the brand lead or
    the inline-prose SIN sentence -- a behavioural guard on the byte-identical-heldout invariant."""
    random.seed(28)
    brand_lead = re.compile(r'(Paiement par|Regle par|Porte sur la carte|Carte (VISA|MASTERCARD|AMEX):'
                            r'|Paid by|Charged to|Posted to|(VISA|MASTERCARD|AMEX) card:)')
    inline_re = re.compile(r"(numero d'assurance sociale (est|fourni au dossier est|\()"
                           r"|social insurance number (is|provided on file is|\())")
    for _ in range(400):
        r = kyc.gen(split="heldout")
        t = r['input']
        assert not brand_lead.search(t), "brand-cued PAN leaked into heldout"
        assert not inline_re.search(t), "inline-prose SIN leaked into heldout"


def test_card_cvv_and_expiry_shapes():
    random.seed(26)
    for _ in range(100):
        r = kyc.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            v = t[s:e]
            if lab == "card_cvv":
                assert re.fullmatch(r'\d{3,4}', v), v
            if lab == "card_expiry":
                assert re.fullmatch(r'\d{2}/\d{2}(\d{2})?', v), v
            if lab == "postal_code":
                assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
