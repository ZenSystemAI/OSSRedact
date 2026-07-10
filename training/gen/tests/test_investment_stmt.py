"""Tests for the investment_stmt generator (BNRI portfolio statement + BMO Ligne d'action / ConseilDirect
"Comment lire votre releve" InvestorLine insert held-out structure).

Offset-exactness, required identity positives, the precision property (holdings grid -- ticker symbols /
quantities / book + market values / amounts / portfolio totals / rates of return / FX rates / fund names /
the dealer-advisor firm name + the advisor/support phone / non-DOB dates -- never labeled), shape invariants
(account_number is a bare client/account run, NEVER a UUID sensitive_account_id), and the train/heldout
layout split (held-out BMO numbered-section insert disjoint from the train BNRI grid).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_investment_stmt.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import investment_stmt as IS  # noqa: E402
import layouts                # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(11)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = IS.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(12)
    need = {"person", "address", "postal_code", "account_number", "phone_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = IS.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_no_em_dash():
    """Contract: NO em dashes anywhere in the output text."""
    random.seed(20)
    for sp in ("train", "heldout"):
        for _ in range(60):
            t = IS.gen(split=sp)['input']
            assert "\u2014" not in t and "\u2013" not in t


def test_decoys_never_labeled():
    """The dense investment-statement negatives must never end up inside a labeled span: amounts / totals /
    market values ($), rates of return / asset-allocation %, ticker symbols, quantities, fund names, the
    dealer/advisor firm name, FX rate lines, and all non-DOB dates."""
    random.seed(13)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = IS.gen(split=sp)
            t = r['input']
            spans = r['output']['spans']
            for s, e, lab in spans:
                val = t[s:e]
                assert "$" not in val                       # amounts / totals / market values -> decoys
                assert "%" not in val                       # rates of return / allocation -> decoys
                # a dealer/advisor firm name is a third-party org -> never a labeled positive
                assert val not in IS._DEALERS
                assert val not in IS._FUNDS                 # fund/security names -> decoys
                assert val not in IS._TICKERS               # ticker symbols -> decoys
                assert val not in IS._ACCT_KINDS            # holdings-grid account-type tokens -> decoys
                # a bare ISO transaction/period/start date is a decoy (this doctype emits NO cued DOB)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)
                # the FX rate line ('1,00 USD = ... CAD') is a decoy
                assert "USD =" not in val and "CAD" not in val


def test_no_date_of_birth_emitted():
    """The investment statement carries no 'date de naissance' cue, so date_of_birth is never a positive
    (every date -- statement / period / start -- is a transaction-level decoy per the date rule)."""
    random.seed(15)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = IS.gen(split=sp)
            assert "date_of_birth" not in {lab for _, _, lab in r['output']['spans']}


def test_account_number_shape_and_never_uuid():
    """Collision rule 1: the 'Identification client #' / 'No de compte' value is account_number, emitted as a
    NUMERIC run only (an institution-first run, a bare run, or a dashed numeric) -- NEVER an opaque
    alphanumeric / UUID-shaped sensitive_account_id, and the doctype emits no sensitive_account_id at all.
    (v11 round-2: the round-1 short-alphanumeric '2YTEST' branch was removed; opaque under an account cue
    contradicted sensitive_account_id supervision and drove the account<->sensitive confusion.)"""
    random.seed(14)
    uuid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-')
    acct_ok = re.compile(r'^(\d{3}-\d{4,5}-\d{6,9}|\d{7,11}|\d{3}-\d{6})$')
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = IS.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                assert lab != "sensitive_account_id"        # this doctype emits no UUID account refs
                if lab == "account_number":
                    assert not uuid_re.match(v), v          # never a UUID
                    assert acct_ok.match(v), v              # one of the allowed client/account shapes
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v


def test_advisor_phone_is_decoy_client_phone_is_positive():
    """Identity-only policy: the CLIENT's contact phone is a phone_number positive; the dealer/advisor firm
    phone and the support hotline (1-844-...) are THIRD-PARTY -> decoys. So a labeled phone_number must never
    be the support-hotline shape, and the advisor block must keep a phone the model is NOT trained to label."""
    random.seed(16)
    hotline_re = re.compile(r'^1-8\d\d-')
    saw_phone_positive = False
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = IS.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "phone_number":
                    saw_phone_positive = True
                    assert not hotline_re.match(t[s:e])     # the support hotline is never a labeled positive
    assert saw_phone_positive


def test_no_positive_equals_decoy_in_same_doc():
    """A labeled positive value and a hard-negative decoy of the same kind (the client phone vs the advisor
    firm phone) may co-occur, but NEVER as byte-identical strings in one document -- that would be
    contradictory token-level supervision. V.phone() has a small value space, so assert zero collisions."""
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
                IS.gen(split=sp)
                for doc in captured:
                    decoys = set(getattr(doc, "_dv", []))
                    for v, lab in getattr(doc, "_fv", []):
                        if v in decoys:
                            collisions.append((sp, lab, v))
        assert not collisions, f"positive==decoy identical-string collisions: {collisions[:10]}"
    finally:
        framework.Doc.field, framework.Doc.decoy, framework.Doc.row = orig_field, orig_decoy, orig_row


def test_layouts_split_distinct():
    assert len(IS.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(IS.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out BMO insert is the numbered-section narrative; the train BNRI layout is the holdings grid.
    assert IS._layout_bmo in held_pool and IS._layout_bmo not in train_pool
    assert IS._layout_bnri in train_pool and IS._layout_bnri not in held_pool

    # structural skeleton differs: the BMO insert emits "INSERT AD F" + the numbered "How to read"/"Comment
    # lire" narrative; the BNRI train layout emits the "Sommaire du portefeuille" / "Portfolio summary"
    # holdings grid header that the held-out never produces.
    random.seed(17)
    held_has_insert = any("INSERT AD F" in IS.gen(split="heldout")['input'] for _ in range(40))
    train_has_insert = any("INSERT AD F" in IS.gen(split="train")['input'] for _ in range(120))
    assert held_has_insert and not train_has_insert

    held_has_grid = any(re.search(r'(?:Sommaire du portefeuille|Portfolio summary)',
                                  IS.gen(split="heldout")['input']) for _ in range(40))
    train_has_grid = any(re.search(r'(?:Sommaire du portefeuille|Portfolio summary)',
                                   IS.gen(split="train")['input']) for _ in range(40))
    assert train_has_grid and not held_has_grid
