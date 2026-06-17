"""Tests for the credit_report generator (Equifax CA consumer disclosure + ACROFILE held-out structure).

Offset-exactness, required identity positives, the precision property (scores / balances / masked SIN /
masked account tails / creditor org names / payment grids / non-DOB dates never labeled), shape invariants
(government_id is a Luhn-VALID SIN; masked SIN is never government_id; full account is account_number), and
the train/heldout layout split (held-out ACROFILE structure disjoint from train).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_credit_report.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import credit_report as CR  # noqa: E402
import values as V          # noqa: E402
import layouts              # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def _luhn_ok(d: str) -> bool:
    s = 0
    for i, c in enumerate(reversed(d)):
        x = int(c)
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def test_offsets_exact_and_labels_in_scheme():
    random.seed(11)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = CR.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(12)
    need = {"person", "date_of_birth", "address", "postal_code", "government_id",
            "sensitive_account_id", "account_number", "phone_number", "organization"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = CR.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    """The dense credit-report negatives must never end up inside a labeled span."""
    random.seed(13)
    masked_sin = re.compile(r'^(999-999-999|XXX-XX-\d{4})$')
    masked_tail = re.compile(r'^(XXXXXX|xxxxxx|\*{6}|XXXX|\.{4})\d{4}$')
    pmt_grid = re.compile(r'^[1-5]{24}$')
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = CR.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                       # scores/balances/limits carry $ -> never labeled
                assert not masked_sin.match(val)            # masked SIN is a decoy, never government_id
                assert not masked_tail.match(val)           # masked account tail is a decoy, never account_number
                assert not pmt_grid.match(val)              # 24-month payment grid is a decoy
                assert val + "%" not in t[s:e + 1] or "%" not in val   # utilization % is a decoy
                # a bare MM/YY or MM/DD/YY reported/opened/DLA date is a decoy unless it is the cued DOB/BDS
                if re.fullmatch(r'\d\d/\d\d(/\d\d)?', val):
                    assert lab == "date_of_birth"


def test_shape_invariants():
    """government_id = Luhn-valid 9-digit SIN ; account_number = bank-account run ; sensitive_account_id =
    an Equifax unique/file ref ; postal_code = a Quebec G/H/J FSA."""
    random.seed(14)
    acct_ok = re.compile(r'^(\d{3}-\d{4,5}-\d{6,9}|\d{7,11})$')
    # sensitive_account_id (collision rule 1): an OPAQUE alphanumeric Equifax file ref (EFX-<10 alnum>) in BOTH
    # splits, so it never collides with a bare/hyphenated numeric account_number run (v11 round-3: the held-out
    # ACROFILE FILE ref was switched from a bare 10-digit Unique Number to the opaque form to match train and
    # obey collision rule 1 -- a bare-numeric sensitive_account_id drove the account<->sensitive confusion).
    senc_ok = re.compile(r'^EFX-[A-Z0-9]{10}$')
    # a real birth date carries a 4-digit year (DD/MM/YYYY, ISO YYYY-MM-DD, or a long month-name form);
    # the bare MM/YY or MM/DD/YY reported/opened/DLA decoy shape must NEVER be a date_of_birth positive
    # (collision rule, Date rule: only a CUED birth date is date_of_birth; every other date is a decoy).
    dob_ok = re.compile(r'^(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2}|\d{1,2} \S+ \d{4}|\S+ \d{1,2}, \d{4})$')
    dob_decoy_shape = re.compile(r'^\d\d/\d\d(/\d\d)?$')   # the _mmYY() decoy shape
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = CR.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "government_id":
                    digits = re.sub(r'\D', '', v)
                    assert len(digits) == 9 and _luhn_ok(digits), v   # full Luhn-valid SIN only
                if lab == "account_number":
                    assert acct_ok.match(v), v
                if lab == "sensitive_account_id":
                    assert senc_ok.match(v), v
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
                if lab == "date_of_birth":
                    assert dob_ok.match(v), v                  # genuine 4-digit-year birth-date shape
                    assert not dob_decoy_shape.fullmatch(v), v  # never the bare MM/YY decoy date shape


def test_org_modes_both_present():
    """Collision rule 3: a LABELED employer header is organization (positive); the SAME kind of name in a
    tradeline/inquiry/banking/member line is a decoy. The creditor pool must therefore never be labeled,
    while V.company() employer headers are."""
    random.seed(16)
    saw_org_positive = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = CR.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "organization":
                    saw_org_positive = True
                    assert v not in CR._CREDITORS    # a creditor/agency name must never be a labeled org
    assert saw_org_positive


def test_layouts_split_distinct():
    assert len(CR.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(CR.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out ACROFILE layout is the terse one-line machine format; train layouts use "Field: value"
    assert CR._layout_acrofile in held_pool and CR._layout_acrofile not in train_pool
    assert CR._layout_disclosure in train_pool and CR._layout_banking in train_pool

    # structural skeleton differs: ACROFILE emits the asterisk alert banner + "SAMPLE REPORT: ACROFILE";
    # the train disclosure emits the "CONSUMER CREDIT FILE" + "Identification" labeled block.
    random.seed(17)
    held_has_acro = any("SAMPLE REPORT: ACROFILE" in CR.gen(split="heldout")['input'] for _ in range(40))
    train_has_acro = any("SAMPLE REPORT: ACROFILE" in CR.gen(split="train")['input'] for _ in range(120))
    assert held_has_acro and not train_has_acro
    # the train layouts carry the labeled "Identification"-style "Name:"/"Nom:" header the held-out lacks
    train_has_label = any(re.search(r'(?:Name:|Nom:) ', CR.gen(split="train")['input']) for _ in range(60))
    assert train_has_label


def test_no_positive_equals_decoy_in_same_doc():
    """Collision rule 3 (and the phone counterpart) must be taught POSITIONALLY: a labeled positive value
    and a hard-negative decoy of the same kind (former-employer org, creditor/daytime phone) may co-occur,
    but NEVER as byte-identical strings in one document. An identical string labeled in one place and
    unlabeled in another is contradictory token-level supervision, not a learnable contrast. V.company() and
    V.phone() have small value spaces, so without a resample guard ~0.2% of rows collided. Enforce zero."""
    import framework
    orig_field, orig_decoy, orig_row = framework.Doc.field, framework.Doc.decoy, framework.Doc.row

    def _field(self, v, lab):
        self.__dict__.setdefault("_fv", []).append((v, lab))
        return orig_field(self, v, lab)

    def _decoy(self, v):
        self.__dict__.setdefault("_dv", []).append(v)
        return orig_decoy(self, v)

    captured = []

    def _row(self):
        captured.append(self)
        return orig_row(self)

    framework.Doc.field, framework.Doc.decoy, framework.Doc.row = _field, _decoy, _row
    try:
        random.seed(19)
        collisions = []
        for sp in ("train", "heldout"):
            for _ in range(400):
                captured.clear()
                CR.gen(split=sp)
                for doc in captured:
                    decoys = set(getattr(doc, "_dv", []))
                    for v, lab in getattr(doc, "_fv", []):
                        if v in decoys:
                            collisions.append((sp, lab, v))
        assert not collisions, f"positive==decoy identical-string collisions: {collisions[:10]}"
    finally:
        framework.Doc.field, framework.Doc.decoy, framework.Doc.row = orig_field, orig_decoy, orig_row


def test_email_covered_in_both_splits():
    """v11 round-3: the held-out GEN INFO email used to be a held-out-ONLY positive (a label-coverage gap --
    train gave the model no in-doctype email signal). Train now also emits an 'Email on file:'/'Courriel au
    dossier:' email positive (~50% of train rows), so train covers what the held-out tests. Held-out keeps
    its GEN INFO email (byte-identical)."""
    random.seed(18)
    held_has_email = any("email" in {lab for _, _, lab in CR.gen(split="heldout")['output']['spans']}
                         for _ in range(40))
    train_has_email = any("email" in {lab for _, _, lab in CR.gen(split="train")['output']['spans']}
                          for _ in range(120))
    assert held_has_email and train_has_email
