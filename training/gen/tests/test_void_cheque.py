"""Tests for the void_cheque generator (v11, real Quebec/Canada void-cheque + MICR layout).

Offset-exactness, required cheque-holder positives, the precision property for THIS doctype (cheque date,
amount/$ figures, amount-in-words, cheque number, bank name + branch, company payee, lone institution code
are all decoys, never labeled), the MICR / account_number shape invariant, and the train/heldout layout
split (the business cheque -- company letterhead + authorized signatory -- is the disjoint held-out
structure). Run: .venv-test/bin/python -m pytest training/gen/tests/test_void_cheque.py -q
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import void_cheque as vc  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])

# the raw MICR ASCII run "*TRANSIT* INST ACCT*" OR the institution-first hyphenated parser form
_MICR_RAW = re.compile(r'^\*\d{5}\* \d{3} \d{7,12}\*$')
_HYPH = re.compile(r'^\d{3}-\d{4,5}-\d{6,9}$')
# org-suffix tokens that appear ONLY in company names (payee decoy + business letterhead) -- never in a
# person/address/postal/account positive
_CO_SUFFIX = set(vc._CO_SUFFIX_FR) | set(vc._CO_SUFFIX_EN)
# the public issuing-bank names printed on the cheque (always decoys)
_BANK_NAMES = set(vc._INSTITUTIONS.values()) | set(vc._BANK_FR.values())


def test_offsets_exact_and_labels_in_scheme():
    random.seed(31)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = vc.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(32)
    need = {"person", "address", "postal_code", "account_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = vc.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_only_expected_labels_emitted():
    """A cheque carries a tight positive set: person / address / postal_code / account_number ONLY. No DOB,
    no email/phone, no card -- those would be over-labeling for this doctype."""
    random.seed(33)
    allowed = {"person", "address", "postal_code", "account_number"}
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = vc.gen(split=sp)
            for _, _, lab in r['output']['spans']:
                assert lab in allowed, f"unexpected label {lab} for void_cheque"


def test_decoys_never_labeled():
    """The precision property: cheque date, $ figures, amount-in-words, cheque number, bank name + branch,
    company payee, lone institution code are decoys and never sit inside a labeled span."""
    random.seed(34)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = vc.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                          # amount figures are decoys
                assert " QC" not in val                        # city + province band is a decoy, never labeled
                assert val not in _BANK_NAMES                  # issuing-bank name is a decoy
                # no cued birth date exists on a cheque -> a bare ISO date must NEVER be a positive here
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)
                # company-suffix tokens belong to payee/letterhead decoys -> never inside any positive
                for suf in _CO_SUFFIX:
                    assert suf not in val, f"company suffix {suf!r} leaked into {lab} positive {val!r}"


def test_account_number_micr_shape():
    """account_number is EITHER the raw MICR ASCII run (*transit* inst acct*) OR the institution-first
    hyphenated form. The 3-digit institution embedded in either must be a public, valid code."""
    random.seed(35)
    valid_inst = set(vc._INSTITUTIONS)
    saw_raw = saw_hyph = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = vc.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab != "account_number":
                    continue
                v = t[s:e]
                if _MICR_RAW.match(v):
                    saw_raw = True
                    assert v.split("* ")[1].split(" ")[0] in valid_inst, v
                elif _HYPH.match(v):
                    saw_hyph = True
                    assert v.split("-")[0] in valid_inst, v
                else:
                    assert False, f"account_number not a MICR or hyphenated shape: {v!r}"
    assert saw_raw, "never produced a raw MICR account run"
    assert saw_hyph, "never produced a hyphenated account run"


def test_postal_shape():
    random.seed(36)
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = vc.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', t[s:e]), t[s:e]


def test_company_payee_is_decoy_not_person():
    """A company payee on the 'Pay to the order of' line is a DECOY (counterparty), never a person positive.
    Assert no person positive carries a company-suffix tail."""
    random.seed(37)
    saw_person = False
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = vc.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "person":
                    saw_person = True
                    assert not any(t[s:e].endswith(suf) for suf in _CO_SUFFIX), \
                        f"company payee {t[s:e]!r} mislabeled as person"
    assert saw_person, "no person positive produced"


def test_layouts_split_distinct():
    assert len(vc.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(vc.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out structure is the BUSINESS cheque (company letterhead + 'Authorized signatory:' /
    # 'Signataire autorise:' block + two signature lines) -- a skeleton the train layouts never produce
    assert vc._layout_business in held_pool and vc._layout_business not in train_pool
    assert vc._layout_personal in train_pool and vc._layout_personal_alt in train_pool

    random.seed(38)
    sig_cue = re.compile(r'(Authorized signatory:|Signataire autorise:)')
    held_has_sig = any(sig_cue.search(vc.gen(split="heldout")['input']) for _ in range(40))
    train_has_sig = any(sig_cue.search(vc.gen(split="train")['input']) for _ in range(120))
    assert held_has_sig and not train_has_sig, "signatory block must be unique to the held-out business cheque"


def test_lang_mix_roughly_65_35():
    random.seed(39)
    n = 400
    fr = sum(1 for _ in range(n) if vc.gen()['meta']['lang'] == 'fr')
    frac = fr / n
    assert 0.5 < frac < 0.8, f"FR fraction {frac:.2f} out of expected band"
