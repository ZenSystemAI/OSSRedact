"""Tests for the bank_statement generator (real big-five / RBC eStatement consumer statement layout).

Offset-exactness, required holder-identity positives, the precision property (every amount / balance /
statement+transaction date / merchant / cheque number / issuer name / branch address / toll-free / URL /
mailing barcode is a DECOY and never labeled), shape invariants (account number / postal FSA), and the
train/heldout layout split (the joint-holder structure is disjoint from training).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_bank_statement.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import bank_statement  # noqa: E402
import layouts         # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..',
                                          'labels_v20.json')))['labels'])

# the issuer / branch decoy strings the model must never redact (the bank, not the subject)
_ISSUERS = set(bank_statement._ISSUERS)
_BRANCHES = set(bank_statement._BRANCH_STREETS)


def test_offsets_exact_and_labels_in_scheme():
    random.seed(31)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = bank_statement.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(32)
    need = {"person", "address", "postal_code", "account_number", "phone_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = bank_statement.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_only_doctype_labels_emitted():
    # the holder identity block is the only PII: exactly these 5 positive labels, nothing else
    # (no email / iban / tax_id / government_id / card_* / secret etc.).
    random.seed(33)
    allowed = {"person", "address", "postal_code", "account_number", "phone_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = bank_statement.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert seen <= allowed, f"unexpected labels emitted: {seen - allowed}"


def test_decoys_never_labeled():
    random.seed(34)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = bank_statement.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                       # amounts/balances/totals are decoys, never labeled
                # a bare ISO date is a statement-period / transaction decoy (no cued DOB on a statement)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)
                # the issuer name and the bank branch address are org/address NEGATIVES -> never labeled
                assert val not in _ISSUERS
                assert val not in _BRANCHES
                # a cheque-number token is a transaction decoy, never a labeled value
                assert not re.fullmatch(r'Cheque #\d+', val)
                # the mailing barcode prefix never leaks into a labeled span
                assert "RBCPDA" not in val
                # a labeled value never contains a province/city decoy comma-joined run
                # (', Quebec ' is the layout-B savings-account province decoy form)
                assert ", PQ " not in val and ", QC " not in val and ", Quebec " not in val
                # a malformed cents-carry amount (',100 $') must never appear -- amounts stay 2-digit cents
                assert not re.search(r',\d{3,} \$', val)


def test_amounts_wellformed_two_digit_cents():
    # every emitted amount/balance decoy uses exactly 2 cents digits in BOTH styles ($#,###.## and the OQLF
    # '# ###,## $'); a cents-carry artifact (',100 $') would teach the model a malformed amount shape.
    random.seed(40)
    bad = []
    for sp in ("train", "heldout"):
        for _ in range(150):
            t = bank_statement.gen(split=sp)['input']
            bad += re.findall(r'\d+,\d{3,} \$', t)        # OQLF cents field with 3+ digits == carry bug
            bad += re.findall(r'\$[\d,]+\.\d{3,}\b', t)   # EN cents field with 3+ digits
    assert not bad, f"malformed amount(s): {bad[:5]}"


def test_issuer_and_branch_present_as_decoys():
    # the issuer name + a branch address must actually appear in text (in-distribution negatives) but the
    # holder identity block alone is labeled.
    random.seed(35)
    saw_issuer, saw_branch = False, False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = bank_statement.gen(split=sp)
            t = r['input']
            if any(i in t for i in _ISSUERS):
                saw_issuer = True
            if any(b in t for b in _BRANCHES):
                saw_branch = True
            labeled = {t[s:e] for s, e, _ in r['output']['spans']}
            assert labeled.isdisjoint(_ISSUERS)
            assert labeled.isdisjoint(_BRANCHES)
    assert saw_issuer and saw_branch


def test_account_and_postal_shapes():
    # account number: transit-account TTTTT-AAAAAAA, or the institution-first V.bank_account() form
    # (III-TTTT(T)-AAA), or a bare 7/10/11-digit run -- a NUMERIC run, never a UUID/opaque sensitive ref
    # (collision rule 1), never Luhn-card-shaped (collision rule 2).
    random.seed(36)
    acct_ok = re.compile(r'^(\d{5}-\d{6,9}|\d{3}-\d{4,5}-\d{6,9}|\d{7,11})$')
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = bank_statement.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "account_number":
                    assert acct_ok.match(v), v
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v


def test_phone_only_in_holder_contact_not_toll_free():
    # a labeled phone_number is the HOLDER's contact line only (Quebec NPA, 555-01XX block); the bank's
    # 'How to reach us' toll-free numbers are 1-8XX decoys and must never be labeled.
    random.seed(37)
    toll_free_re = re.compile(r'1[ -]8\d\d')
    saw_holder_phone = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = bank_statement.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "phone_number":
                    saw_holder_phone = True
                    v = t[s:e]
                    assert not toll_free_re.match(v), v        # never a 1-8XX toll-free
                    assert re.search(r'555', v), v             # holder phones use the 555 fictional block
    assert saw_holder_phone


def test_joint_layout_emits_two_persons():
    # the held-out joint layout puts two holders on the mailing line -> >=2 person positives in one doc;
    # the train layouts carry a single holder name.
    random.seed(38)
    saw_two = False
    for _ in range(60):
        r = bank_statement.gen(split="heldout")
        persons = [lab for _, _, lab in r['output']['spans'] if lab == "person"]
        if len(persons) >= 2:
            saw_two = True
            t = r['input']
            assert (" ET " in t) or (" AND " in t)            # the joint connector is present in text
    assert saw_two


def test_layouts_split_distinct():
    assert len(bank_statement.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(bank_statement.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_joint_statement) is the joint-holder structure: it is the ONLY layout
    # with the ' ET '/' AND ' two-name mailing line. The train layouts never produce it -> a genuinely
    # distinct real structure, not a reworded near-duplicate.
    assert bank_statement._layout_joint_statement in held_pool
    assert bank_statement._layout_joint_statement not in train_pool
    random.seed(39)
    held_has_joint = any((" ET " in bank_statement.gen(split="heldout")['input']
                          or " AND " in bank_statement.gen(split="heldout")['input'])
                         for _ in range(40))
    # the savings train layout emits a holder phone_number; the joint held-out layout never does -> the two
    # pools also differ structurally on the phone axis.
    train_has_phone = any("phone_number" in {lab for _, _, lab in bank_statement.gen(split="train")['output']['spans']}
                          for _ in range(150))
    held_has_phone = any("phone_number" in {lab for _, _, lab in bank_statement.gen(split="heldout")['output']['spans']}
                         for _ in range(60))
    assert held_has_joint
    assert train_has_phone and not held_has_phone
