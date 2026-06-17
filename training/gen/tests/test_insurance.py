"""Tests for the insurance generator (Quebec FPQ1 auto + BAC home declarations pages).

Offset-exactness, required declarations-page positives, the precision property (coverage machinery decoys --
VIN, plate, premiums, coverage limits, insurer/broker names, NON-cued dates -- never labeled), shape
invariants (policy-number collision rule 1, postal FSA), and the train/heldout layout split (the held-out
HOME structure disjoint from the auto train structures, with a distinct field skeleton).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_insurance.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import insurance  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = insurance.gen(split=sp)
            t = r['input']
            # offset-true: every span value reconstructed from (s,e) must match the value the framework
            # recorded under that label in entities (catches any span<->value drift, not a no-op tautology).
            recon = {}
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""            # never an empty/whitespace span
                assert lab in _LABELS                  # only the 20 labels
                recon.setdefault(lab, []).append(t[s:e])
            assert recon == r['output']['entities']    # spans reconstruct the recorded entities exactly


def test_required_positives_present():
    random.seed(22)
    # the defining declarations-page positives this doctype must carry
    need = {"person", "address", "postal_code", "phone_number", "sensitive_account_id", "account_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = insurance.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    random.seed(23)
    vin_re = re.compile(r'^[A-HJ-NPR-Z0-9]{17}$')        # 17-char VIN look-alike
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = insurance.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                # premiums / coverage limits carry a currency mark -> always decoys, never labeled
                assert "$" not in val
                # a 17-char VIN must never be inside a labeled span
                assert not vin_re.fullmatch(val), f"VIN labeled as {lab}: {val}"
                # the AMF form codes / insurer / broker decoys never get labeled
                assert "933 000" not in val and "F.P.Q." not in val and "Q.P.F." not in val
                assert "Assurances" not in val and "Assurance" not in val and "Courtage" not in val
                # a bare ISO date (effective/expiry/issue) is a NON-cued decoy; only a cued DOB is labeled,
                # and dob() never emits a bare 20xx-xx-xx that overlaps the iso_date() shape we decoy here.
                if re.fullmatch(r'20\d\d-\d\d-\d\d', val):
                    assert lab == "date_of_birth"


def test_policy_number_collision_rule():
    """Collision rule 1: a purely-numeric policy run -> account_number; an opaque alphanumeric ref ->
    sensitive_account_id. Never a bare numeric routed to sensitive_account_id, never an alphanumeric to
    account_number."""
    random.seed(24)
    saw_acct = saw_sid = False
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = insurance.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "account_number":
                    # purely numeric (digits, optional single hyphen grouping), no letters
                    assert re.fullmatch(r'\d{4}-\d{4,7}|\d{8,11}', v), f"bad account_number: {v}"
                    assert not any(c.isalpha() for c in v)
                    saw_acct = True
                if lab == "sensitive_account_id":
                    assert any(c.isalpha() for c in v), f"sensitive_account_id has no letters: {v}"
                    saw_sid = True
    assert saw_acct and saw_sid


def test_postal_shape_invariant():
    random.seed(25)
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = insurance.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', t[s:e])


def test_layouts_split_distinct():
    assert len(insurance.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(insurance.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout is the BAC HOME declarations page, never in the train pool
    assert insurance._layout_bac_home in held_pool and insurance._layout_bac_home not in train_pool
    # structural distinction: only the auto (train) layouts produce a VIN/plaque vehicule block; only the
    # home (heldout) layout produces a "LIEUX ASSURES" / "INSURED PREMISES" skeleton. (email is now emitted
    # by BOTH pools -- v11 r3 closed the email label-coverage gap so train covers what the held-out tests.)
    random.seed(26)
    held_has_premises = held_has_email = False
    for _ in range(40):
        r = insurance.gen(split="heldout")
        t = r['input']
        if "LIEUX ASSURES" in t or "INSURED PREMISES" in t:
            held_has_premises = True
        if "email" in {lab for _, _, lab in r['output']['spans']}:
            held_has_email = True
        # heldout (home) never emits a VIN/plaque vehicule block
        assert "VEHICULES ASSURES" not in t and "INSURED VEHICLES" not in t and "Vehicules au contrat" not in t
    train_has_vehicle = train_has_email = False
    for _ in range(120):
        r = insurance.gen(split="train")
        t = r['input']
        if "VEHICULES ASSURES" in t or "INSURED VEHICLES" in t or "Vehicules au contrat" in t:
            train_has_vehicle = True
        if "email" in {lab for _, _, lab in r['output']['spans']}:
            train_has_email = True
    assert held_has_premises and held_has_email
    # vehicle block stays train-only (structural distinction); email is now covered in BOTH pools
    assert train_has_vehicle and train_has_email


def test_form_code_family_matches_doctype():
    """Faithfulness invariant: the AMF form code is the document's identity marker, so the FPQ1 (auto) code
    family (F.P.Q. / 933 000) must appear ONLY on the auto layouts and the BAC 1503Q (home) family ONLY on
    the held-out home layout -- never crossed. Checked against the form-code masthead (first lines), where
    the code lives; random VINs/amounts deeper in the body can contain the substrings 'BAC'/'1503' by
    chance, so the assertion is scoped to the masthead, not the whole document."""
    random.seed(28)
    fpq1_set = set(insurance._FORM_CODES_AUTO)
    bac_set = set(insurance._FORM_CODES_HOME)
    for _ in range(150):
        for fn in (insurance._layout_fpq1_decl, insurance._layout_fpq1_renew):
            head = fn(random.choice(["fr", "en"]))['input'].split("\n", 4)
            head = " ".join(head[:3])           # masthead = first 3 lines (insurer + title + form code)
            assert any(c in head for c in fpq1_set), f"auto masthead missing an FPQ1 code: {head}"
            assert not any(c in head for c in bac_set), f"auto masthead leaked a BAC code: {head}"
        head = insurance._layout_bac_home(random.choice(["fr", "en"]))['input'].split("\n", 4)
        head = " ".join(head[:3])
        assert any(c in head for c in bac_set), f"home masthead missing a BAC code: {head}"
        assert not any(c in head for c in fpq1_set), f"home masthead leaked an FPQ1 code: {head}"


def test_no_em_dash_in_output():
    random.seed(27)
    for sp in ("train", "heldout"):
        for _ in range(60):
            t = insurance.gen(split=sp)['input']
            assert "\u2014" not in t          # no em dash anywhere in emitted text


def test_train_new_cue_vocabulary_present():
    """v11 round-2: the TRAIN auto layouts now teach an INLINE-PROSE government_id (full Luhn-valid SIN),
    the insurer business/registration number as tax_id (occasionally spaced), and a TERSE phone cue -- as
    ALTERNATIVES alongside the existing presentations. (Held-out HOME layout is unchanged and emits none.)"""
    random.seed(29)
    saw_gov = saw_tax = saw_tax_spaced = saw_terse_phone = False
    for _ in range(800):
        r = insurance.gen(split="train")
        t = r['input']
        labels = {lab for _, _, lab in r['output']['spans']}
        if "government_id" in labels:
            saw_gov = True
        for s, e, lab in r['output']['spans']:
            if lab == "tax_id":
                saw_tax = True
                if " " in t[s:e]:
                    saw_tax_spaced = True
        if "Tel." in t or "Cell." in t or "(cell" in t:
            saw_terse_phone = True
    assert saw_gov, "no inline-prose government_id (SIN) cue emitted in train"
    assert saw_tax and saw_tax_spaced, "no insurer tax_id cue (incl. spaced variant) emitted in train"
    assert saw_terse_phone, "no terse phone cue emitted in train"
