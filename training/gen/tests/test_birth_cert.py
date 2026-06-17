"""Tests for the birth_cert generator (v11, real DCCA-Naissance + issued-acte-extract structures).

Offset-exactness, the rich relational positives (up to 4 person spans + DOB + address/postal/phone/email +
payment_card/cvv/expiry + sensitive_account_id), labels-in-scheme, the precision property (place-of-birth
city, sex marker, fee amounts, form code, non-DOB dates, province QC, Luhn-invalid card are NEVER labeled),
shape invariants, and the train/heldout layout split (held-out structure disjoint from train).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_birth_cert.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import birth_cert  # noqa: E402
import values as V  # noqa: E402
import layouts  # noqa: E402

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
    random.seed(31)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = birth_cert.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e] != ""                 # span is non-empty by construction
                assert t[s:e].strip() != ""         # never an empty/whitespace span
                assert lab in _LABELS               # only the 20 labels


def test_required_positives_present():
    random.seed(32)
    need = {"person", "date_of_birth", "address", "postal_code", "phone_number", "email",
            "payment_card", "card_cvv", "card_expiry", "sensitive_account_id"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = birth_cert.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_multiple_person_spans_relational():
    """The application form carries up to 4 person spans (requester + subject + father + mother)."""
    random.seed(33)
    saw_multi = max_persons = 0
    for _ in range(80):
        r = birth_cert.gen(split="train")
        n = sum(1 for _, _, lab in r['output']['spans'] if lab == "person")
        max_persons = max(max_persons, n)
        if n >= 3:
            saw_multi += 1
    assert max_persons >= 4, f"max person spans was {max_persons}, expected >=4"
    assert saw_multi > 0


def test_positive_card_passes_luhn():
    """Every labeled payment_card must be Luhn-valid (the declined-card decoy is Luhn-invalid)."""
    random.seed(34)
    checked = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = birth_cert.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "payment_card":
                    assert _luhn_ok(t[s:e]), f"payment_card not Luhn-valid: {t[s:e]}"
                    checked = True
    assert checked


def test_shapes():
    random.seed(35)
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = birth_cert.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
                if lab == "card_cvv":
                    assert re.fullmatch(r'\d{3,4}', v), v
                if lab == "card_expiry":
                    assert re.fullmatch(r'\d{2}/\d{2}(\d{2})?', v), v
                if lab == "sensitive_account_id":
                    # opaque alphanumeric ref / UUID -- NOT a bare numeric run (would be account_number)
                    assert not re.fullmatch(r'\d{1,11}', v), f"reg number must not be a bare numeric run: {v}"
                    assert re.search(r'[A-Za-z\-]', v), v


def test_decoys_never_labeled():
    """The precision property: this doctype's key negatives are present in text but never labeled."""
    random.seed(36)
    cities = set(V._CITIES)
    sex_markers = {"Masculin", "Feminin", "Non binaire (X)", "Male", "Female", "Non-binary (X)"}
    relationships = {"Pere", "Mere", "Father", "Mother"}
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = birth_cert.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                assert "$" not in v                              # fee amounts/total -> never labeled
                assert v not in cities                           # place-of-birth / city alone -> never labeled
                assert v not in sex_markers                      # sex marker -> never labeled
                assert v not in relationships                    # lien de parente marker -> never labeled
                assert v != "QC"                                 # province alone -> never labeled
                assert not re.match(r'(FO-11|FO-)', v)           # form code -> never labeled
                # a Luhn-INVALID PAN must never be labeled payment_card (it is the declined-card decoy)
                if lab == "payment_card":
                    assert _luhn_ok(v)
                # a bare ISO date is a request/issue decoy unless it is the cued DOB
                if re.fullmatch(r'20\d\d-\d\d-\d\d', v):
                    assert lab == "date_of_birth"
            # Date rule (contract section 5): ONLY the cued birth date is date_of_birth; every other date
            # (Section-4 request date, issue/delivery date) is a NEGATIVE decoy. The label check above is
            # one-directional (it cannot see a request date mislabeled DOB, since that value IS labeled
            # date_of_birth), so enforce the cardinality: each layout cues EXACTLY ONE birth date. If any
            # non-DOB date gets routed to date_of_birth, this count exceeds 1 and the test fails.
            dob_spans = [v for s, e, lab in r['output']['spans']
                         if lab == "date_of_birth" for v in (t[s:e],)]
            assert len(dob_spans) == 1, f"{sp}: expected exactly 1 cued DOB, got {dob_spans}"


def test_layouts_split_distinct():
    assert len(birth_cert.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(birth_cert.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_extract) is the issued acte structure: it carries a registration
    # sensitive_account_id heading + NO Section-numbered application form / NO payment block;
    # the train layout (_layout_application) carries payment_card + numbered Sections and NO reg-number heading.
    assert birth_cert._layout_extract in held_pool and birth_cert._layout_extract not in train_pool
    assert birth_cert._layout_application in train_pool

    random.seed(37)
    # structural skeletons differ: train has payment_card + "Section 1" (numbered application form),
    # heldout has the issued-acte heading "Extrait du registre" / "Extract from the register" and never a
    # payment_card. Both layouts cover sensitive_account_id (reg/document number) so train gives the model
    # in-doctype signal for the label the held-out tests (label-coverage gap fix, v11 round-3).
    held_has_regnum = held_has_payment = False
    for _ in range(40):
        r = birth_cert.gen(split="heldout")
        labs = {lab for _, _, lab in r['output']['spans']}
        held_has_regnum = held_has_regnum or ("sensitive_account_id" in labs)
        held_has_payment = held_has_payment or ("payment_card" in labs)
        assert "registre" in r['input'] or "register" in r['input']
    assert held_has_regnum and not held_has_payment

    train_has_payment = train_has_regnum = False
    for _ in range(120):
        r = birth_cert.gen(split="train")
        labs = {lab for _, _, lab in r['output']['spans']}
        train_has_payment = train_has_payment or ("payment_card" in labs)
        train_has_regnum = train_has_regnum or ("sensitive_account_id" in labs)
        assert "Section 1" in r['input']
    # train carries payment_card (structural distinction) AND now covers sensitive_account_id (gap fix);
    # heldout has no payment_card, keeping the two skeletons genuinely distinct.
    assert train_has_payment and train_has_regnum and not held_has_payment
