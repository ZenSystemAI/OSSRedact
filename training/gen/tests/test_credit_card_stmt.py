"""Tests for the credit_card_stmt generator (real Desjardins Accord D / bank Visa / Amex rewards layouts).

Offset-exactness, required positives, the precision property (the MASKED card tail / every amount / every
date / interest rate / reward points / merchant name is a decoy and never labeled), the full-PAN(positive)
vs masked-tail(decoy) contrast, shape invariants (PAN Luhn-valid, masked tail asterisked, postal FSA,
account folio shape), and the train/heldout layout split (the Amex rewards-charge structure with its
Membership Rewards block + Amex masked-tail format is disjoint from training).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_credit_card_stmt.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import credit_card_stmt as ccs  # noqa: E402
import layouts                  # noqa: E402
import values as V              # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..',
                                          'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(31)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = ccs.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(32)
    need = {"person", "address", "postal_code", "payment_card", "account_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = ccs.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    random.seed(33)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = ccs.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val             # every amount (limit/balance/min payment/txn) is a decoy
                assert "*" not in val             # a masked card tail is never inside a labeled span
                assert "%" not in val             # the interest rate is a decoy
                assert " pts" not in val          # reward-point figures are decoys
                # a bare ISO date is a statement/transaction decoy -- never labeled on this doctype (no DOB)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)


def test_masked_tail_is_decoy_full_pan_is_positive():
    """The headline contrast: the full PAN on the card-on-file line is payment_card; the masked tail in the
    transaction lines is present in the text but NEVER labeled payment_card (it is a decoy)."""
    random.seed(34)
    masked_pat = re.compile(r'(\*{4}|[Xx]{4}).*\d{4}\b')
    saw_full_pan = saw_masked_in_text = 0
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = ccs.gen(split=sp)
            t = r['input']
            spans = r['output']['spans']
            cards = [t[s:e] for s, e, lab in spans if lab == "payment_card"]
            for c in cards:
                assert "*" not in c and "X" not in c and "x" not in c   # the PAN positive is never masked
                saw_full_pan += 1
            # masked tails appear in the raw text (transaction lines) ...
            if "**** " in t or re.search(r'(XXXX|xxxx|\*{4})[ -]\d{4}', t):
                saw_masked_in_text += 1
            # ... but no labeled span is ever a masked tail
            for s, e, lab in spans:
                assert not masked_pat.search(t[s:e])
    assert saw_full_pan > 0 and saw_masked_in_text > 0


def test_value_shapes():
    """PAN positives are Luhn-valid; account folios are non-masked numeric/grouped runs; postal codes are
    Quebec FSAs."""
    random.seed(35)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = ccs.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "payment_card":
                    digits = re.sub(r'\D', '', v)
                    assert len(digits) in (15, 16)
                    assert V._luhn_ok(digits), v          # full PAN must pass Luhn
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
                if lab == "account_number":
                    assert "*" not in v and "$" not in v
                    assert re.fullmatch(r'[0-9 \-]+', v), v   # grouped/bare digits only, never asterisked


def test_layouts_split_distinct():
    assert len(ccs.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(ccs.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_amex_rewards) is the ONLY one that emits a Membership Rewards points block
    # (' pts') and the Amex masked-tail format ('**** ****** *####'). The train layouts (Accord D, bank Visa)
    # never produce either -> a genuinely distinct real structure, not a reworded near-duplicate.
    assert ccs._layout_amex_rewards in held_pool
    assert ccs._layout_amex_rewards not in train_pool
    random.seed(36)
    amex_mask = re.compile(r'\*{4} \*{6} \*\d{4}')
    held_has_rewards = any((" pts" in ccs.gen(split="heldout")['input']) for _ in range(40))
    held_has_amexmask = any(amex_mask.search(ccs.gen(split="heldout")['input']) for _ in range(40))
    train_has_rewards = any((" pts" in ccs.gen(split="train")['input']) for _ in range(150))
    train_has_amexmask = any(amex_mask.search(ccs.gen(split="train")['input']) for _ in range(150))
    assert held_has_rewards and held_has_amexmask
    assert not train_has_rewards and not train_has_amexmask


def test_amex_layout_carries_amex_pan():
    """Faithfulness: the held-out Amex rewards layout must put a 15-digit AMEX PAN (34/37) on file, not a
    16-digit Visa/MC PAN. The 15-digit Amex card is part of what makes the held-out structure distinct."""
    random.seed(37)
    saw = 0
    for _ in range(120):
        r = ccs._layout_amex_rewards("fr" if random.random() < 0.5 else "en")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "payment_card":
                digits = re.sub(r'\D', '', t[s:e])
                assert len(digits) == 15, t[s:e]          # Amex PAN is 15 digits
                assert digits[:2] in ("34", "37"), t[s:e]  # Amex IIN
                assert V._luhn_ok(digits), t[s:e]
                saw += 1
    assert saw > 0
