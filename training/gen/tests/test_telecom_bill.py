"""Tests for the telecom_bill generator (real TELUS / Videotron invoice layouts).

Offset-exactness, required header positives, the precision property (every amount / date / usage / plan /
provider name / called number is a decoy and never labeled), shape invariants, and the train/heldout layout
split (the mobility structure with the per-subscriber phone_number + call-detail-record table is disjoint
from training).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_telecom_bill.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import telecom_bill  # noqa: E402
import layouts       # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..',
                                          'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = telecom_bill.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"person", "address", "postal_code", "account_number", "phone_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = telecom_bill.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_only_doctype_labels_emitted():
    # this doctype emits exactly the 5 positive labels and nothing else (e.g. no email/iban/tax_id)
    random.seed(23)
    allowed = {"person", "address", "postal_code", "account_number", "phone_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = telecom_bill.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert seen <= allowed, f"unexpected labels emitted: {seen - allowed}"


def test_decoys_never_labeled():
    random.seed(24)
    providers = {"TELUS", "Videotron", "Bell", "Fido", "Koodo", "Virgin Plus", "Rogers"}
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = telecom_bill.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                  # amounts/balances/taxes are decoys, never labeled
                # usage figures (data / minutes / texts) are decoys -> every usage token shape, never labeled
                assert not re.search(r'\b(Go|GB|min|textos|texts)\b', val)
                # the provider/carrier name is an org negative -> never inside any labeled span
                for p in providers:
                    assert val != p
                # a bare ISO transaction/bill date is always a decoy on a telecom bill (no cued DOB here)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)


def test_provider_present_as_decoy_not_label():
    # the carrier name must actually appear in the text (so the negative is in-distribution) but never labeled
    random.seed(25)
    saw_provider_in_text = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = telecom_bill.gen(split=sp)
            t = r['input']
            if any(p in t for p in ("TELUS", "Videotron", "Bell")):
                saw_provider_in_text = True
            labeled = {t[s:e] for s, e, _ in r['output']['spans']}
            assert "TELUS" not in labeled and "Videotron" not in labeled
    assert saw_provider_in_text


def test_account_number_shape():
    # telecom customer number: bare/grouped numeric run or a letter-prefixed ref -- NOT an institution-first
    # bank account, NOT a UUID/opaque sensitive ref (collision rule 1).
    random.seed(26)
    ok = re.compile(r'^(\d{9,13}|\d{2,3}-\d{7,8}|(?:C|A|BC)\d{8,10})$')
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = telecom_bill.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "account_number":
                    assert ok.match(v), v
                    assert "-" not in v or len(v.split("-")[0]) <= 3   # never the III-TTTT-AAA bank format
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v


def test_called_number_is_decoy_in_mobility():
    # in the held-out mobility layout the subscriber's OWN service number is a phone_number positive, but
    # the call-detail-record "number called" entries (third parties) are phone-shaped DECOYS. So a mobility
    # doc must contain MORE phone-shaped tokens in text than it labels as phone_number.
    random.seed(27)
    checked = 0
    phone_re = re.compile(r'(\(\d{3}\) \d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\+1 \d{3} \d{3} \d{4}|\d{3}\.\d{3}\.\d{4})')
    for _ in range(80):
        r = telecom_bill.gen(split="heldout")
        t = r['input']
        labeled_phones = [t[s:e] for s, e, lab in r['output']['spans'] if lab == "phone_number"]
        if not labeled_phones:
            continue
        checked += 1
        n_in_text = len(phone_re.findall(t))
        assert n_in_text > len(labeled_phones)      # CDR called-numbers are present but unlabeled (decoys)
    assert checked > 0, "expected mobility docs with a labeled service number"


def test_train_terse_account_and_phone_cues_present():
    # v11 r2 recall-first: train layouts must teach the TERSE/BARE account_number cue (e.g. 'Compte <num>')
    # alongside the formal 'Numero de compte:' label, and the terse subject-phone cue. The terse account
    # value stays NUMERIC (no alphanumeric prefix on the bare path).
    random.seed(29)
    saw_terse_acct = False
    saw_phone = False
    num_acct_re = re.compile(r'^(\d{9,13}|\d{2,3}-\d{7,8})$')
    for _ in range(400):
        r = telecom_bill.gen(split="train")
        t = r['input']
        # a 'Compte ' / 'Account ' / 'No de compte' / 'Acct No' terse cue followed by a numeric account run
        if re.search(r'(?:^|\n)(?:Compte|Account|No de compte|Acct No) \d{2}', t):
            for s, e, lab in r['output']['spans']:
                if lab == "account_number" and num_acct_re.match(t[s:e]):
                    saw_terse_acct = True
        if any(lab == "phone_number" for _, _, lab in r['output']['spans']):
            saw_phone = True
    assert saw_terse_acct, "train layouts never produced a terse/bare NUMERIC account_number cue"
    assert saw_phone, "train layouts never produced a phone_number positive"


def test_layouts_split_distinct():
    assert len(telecom_bill.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(telecom_bill.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_telus_mobility) is the per-subscriber mobility structure: it is the ONLY
    # layout that emits a phone_number positive (the billed service line). The train layouts (residential,
    # helix) never do -> a genuinely distinct real structure, not a reworded near-duplicate.
    assert telecom_bill._layout_telus_mobility in held_pool
    assert telecom_bill._layout_telus_mobility not in train_pool
    # v11 r2 recall-first: train layouts now ALSO carry a phone_number positive (the subscriber's OWN service
    # number under TERSE cues -- 'Numero de service:' / 'Tel' / bare), so terse-context phones are learned in
    # training. The held-out layout stays structurally distinct: it is the ONLY one with the per-subscriber
    # call-detail-record table (decoy called-numbers > labeled service number), verified by
    # test_called_number_is_decoy_in_mobility. So both splits emit phone_number; only held-out has the CDR.
    random.seed(28)
    held_has_phone = any("phone_number" in {lab for _, _, lab in telecom_bill.gen(split="heldout")['output']['spans']}
                         for _ in range(40))
    train_has_phone = any("phone_number" in {lab for _, _, lab in telecom_bill.gen(split="train")['output']['spans']}
                          for _ in range(150))
    assert held_has_phone and train_has_phone
