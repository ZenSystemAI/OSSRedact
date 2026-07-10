"""Tests for the tax_return generator (real Revenu Quebec TP-1 personal return + FP-500 GST/QST business
remittance structures).

Offset-exactness, required positives, the precision property (line numbers / amounts / barcodes /
reporting-period dates / institutional phones / form codes never labeled), shape invariants (SIN Luhn,
GST RT tax_id, postal FSA), and the train/heldout layout split (FP-500 structure disjoint from train).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_tax_return.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import tax_return  # noqa: E402
import layouts  # noqa: E402

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
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = tax_return.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    # TP-1 (train) defining labels + FP-500 (heldout) defining labels, across both splits
    need = {"person", "government_id", "date_of_birth", "address", "postal_code",  # TP-1
            "tax_id", "organization", "account_number"}                            # FP-500
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = tax_return.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"
    # phone_number is optional-per-row on TP-1 spouse layout; assert it occurs at least once over many rows
    has_phone = False
    for _ in range(120):
        if "phone_number" in {lab for _, _, lab in tax_return.gen(split="train")['output']['spans']}:
            has_phone = True
            break
    assert has_phone, "phone_number positive never emitted"


def test_decoys_never_labeled():
    """The TP-1/FP-500 negatives must never land inside a labeled span: line amounts (OQLF 'NNN,NN'),
    the prescribed-form barcode, the QC province token, the form codes, and bare ISO dates unless they are
    the cued DOB."""
    random.seed(23)
    amount_re = re.compile(r'^\d[\d ]*,\d\d$')          # _line_amount() shape: '12 345,67'
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = tax_return.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert not amount_re.match(val)         # bare line amounts are decoys, never labeled
                assert val != "QC"                      # province token is a decoy
                assert "ZZ" not in val                  # the barcode (Yxxx ZZ ...) is a decoy
                assert "FP-500" not in val and "TP-1" not in val  # form codes are decoys
                assert "\t" not in val                  # a labeled value never straddles a tab cell
                # a bare ISO date is a transaction/period/signature decoy unless it is the cued DOB
                if re.fullmatch(r'20\d\d-\d\d-\d\d', val):
                    assert lab == "date_of_birth"
                # converse of the date rule (collision rule 7): a date_of_birth positive is ONLY
                # legitimate when a birth-date cue introduces it. An UNCUED date (transaction /
                # reporting-period / signature) routed to date_of_birth is the regression this guards.
                if lab == "date_of_birth":
                    cue_ctx = t[max(0, s - 60):s]
                    assert re.search(r'naissance|birth', cue_ctx), \
                        f"date_of_birth without a birth-date cue: ...{cue_ctx!r} -> {val!r}"


def test_government_id_is_luhn_valid_sin():
    """SIN positives (government_id on TP-1) are Luhn-valid 9-digit, QC region (first digit 2/3)."""
    random.seed(24)
    seen = 0
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = tax_return.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "government_id":
                    digits = re.sub(r'\D', '', t[s:e])
                    assert len(digits) == 9
                    assert digits[0] in "23"            # Quebec SIN region
                    assert _luhn_ok(digits)             # SINs are Luhn-valid by construction
                    seen += 1
    assert seen > 0, "no government_id positive observed"


def test_tax_id_and_postal_and_org_shapes():
    random.seed(25)
    tax_id_shapes = set()
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = tax_return.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v)        # Quebec FSA G/H/J
                if lab == "tax_id":
                    # the three V.tax_id() shapes: GST/HST account (9 digits + RT + 4), QST account
                    # (10 digits + TQ + 4), or a bare 10-digit NEQ. v11 r2: the TP-1 workpaper cue may
                    # print the NEQ in a spaced group form (C.group_digits, digits identical) -- accept it.
                    if re.fullmatch(r'\d{9}RT\d{4}', v):
                        tax_id_shapes.add("gst_rt")
                    elif re.fullmatch(r'\d{10}TQ\d{4}', v):
                        tax_id_shapes.add("qst_tq")
                    elif re.fullmatch(r'\d{10}', v):
                        tax_id_shapes.add("neq")
                    elif re.fullmatch(r'\d{3} \d{3} \d{4}', v):
                        tax_id_shapes.add("neq")            # spaced NEQ workpaper variant
                    else:
                        assert False, f"unexpected tax_id shape: {v!r}"
                if lab == "account_number":
                    assert re.fullmatch(r'\d{10,11}', v), v                 # bare identification number
    # FP-500 header carries all three tax_id forms (GST RT / QST TQ / NEQ) -- the V.tax_id() family
    assert tax_id_shapes == {"gst_rt", "qst_tq", "neq"}, f"missing tax_id shapes: {tax_id_shapes}"


def test_tp1_structural_separation_from_fp500():
    """Structural separation: the FP-500 business return never emits government_id (SIN)/date_of_birth; the
    TP-1 personal return never emits the FP-500 FORM SKELETON. This is the held-out structural distinction.
    NOTE (v11 r2): the TP-1 spouse layout MAY emit a tax_id under a terse inline self-employment-workpaper
    cue. NOTE (v11 r3): the TP-1 spouse layout MAY now also emit tax_id + account_number + organization under
    a sole-proprietor business-REGISTRATION-EXTRACT block (closing the label-coverage gap vs the FP-500
    held-out) -- so organization / account_number are no longer train-exclusive-absent. What stays disjoint
    is the FP-500 STRUCTURE: the train rows never carry the FP-500 form code, the Part-1 GST/QST calculation
    table, or the reporting-period header."""
    random.seed(26)
    # train pool = TP-1 layouts only: the FP-500 form skeleton must never appear on a train row
    for _ in range(120):
        t = tax_return.gen(split="train")['input']
        assert "FP-500" not in t                                   # FP-500 form code
        assert "Calculs detailles" not in t and "Detailed GST/HST" not in t  # Part-1 calc table
        assert "Periode de declaration" not in t and "Reporting period" not in t  # FP-500 period header
    # heldout pool = FP-500 only
    for _ in range(60):
        labs = {lab for _, _, lab in tax_return.gen(split="heldout")['output']['spans']}
        assert "government_id" not in labs and "date_of_birth" not in labs
        assert "tax_id" in labs and "organization" in labs


def test_train_emits_taxid_workpaper_cue():
    """v11 r2: the TP-1 spouse layout teaches tax_id under a terse inline self-employment-workpaper cue
    (NEQ / TVQ / RT), bilingual -- a presentation the held-out FP-500 two-cell header never uses.
    NOTE (v11 r3): train tax_ids may also come from the business-registration-extract block; this test
    inspects only the workpaper-cue tax_ids (those introduced by the 'Travail autonome'/'Self-employment'
    inline cue) -- the registration block is covered by test_train_emits_business_registration_block."""
    random.seed(126)
    saw, cues = False, set()
    for _ in range(300):
        r = tax_return.gen(split="train")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "tax_id":
                ctx = t[max(0, s - 80):s]
                if not re.search(r'Travail autonome|Self-employment', ctx):
                    continue                      # registration-block tax_id, not the workpaper cue
                saw = True
                assert re.search(r'NEQ|TVQ|QST|RT', ctx), f"tax_id without a business-number cue: {ctx!r}"
                if "NEQ" in ctx:
                    cues.add("neq")
                elif "TVQ" in ctx or "QST" in ctx:
                    cues.add("tvq")
                elif "RT" in ctx:
                    cues.add("rt")
    assert saw, "train never emitted a tax_id workpaper cue"
    assert {"neq", "tvq", "rt"} <= cues, f"missing tax_id cue families in train: {cues}"


def test_train_emits_business_registration_block():
    """v11 r3: the TP-1 spouse layout teaches the THREE FP-500 business-return labels under a sole-proprietor
    business-registration-extract block -- tax_id (RT/TQ/NEQ), account_number (numeric identification run),
    organization (labeled business-name header) -- closing the label-coverage gap vs the held-out FP-500.
    The added values must match the held-out's value shapes (RT/TQ/NEQ tax_ids, bare \\d{10,11} account
    number) and the account_number must NOT be confused with a tax_id."""
    random.seed(226)
    saw_org = saw_acct = False
    org_with_taxid_and_acct = False
    for _ in range(300):
        r = tax_return.gen(split="train")
        t = r['input']
        labs = {lab for _, _, lab in r['output']['spans']}
        if "organization" in labs:
            saw_org = True
            # the registration block emits all three labels together
            assert "tax_id" in labs and "account_number" in labs
            org_with_taxid_and_acct = True
            # the business-name header cue must precede the organization span
            for s, e, lab in r['output']['spans']:
                if lab == "organization":
                    ctx = t[max(0, s - 60):s]
                    assert re.search(r"entreprise|Business name|Nom de l'entreprise", ctx), \
                        f"organization without a business-name cue: {ctx!r}"
        if "account_number" in labs:
            saw_acct = True
            for s, e, lab in r['output']['spans']:
                if lab == "account_number":
                    v = t[s:e]
                    assert re.fullmatch(r'\d{10,11}', v), f"account_number not a bare numeric run: {v!r}"
                    # the numeric identification run sits under its real cue, NOT a tax_id label
                    ctx = t[max(0, s - 60):s]
                    assert re.search(r"identification|Identification number", ctx)
    assert saw_org, "train never emitted the business-name organization positive"
    assert saw_acct, "train never emitted the account_number positive"
    assert org_with_taxid_and_acct, "registration block did not co-emit tax_id + account_number"


def test_layouts_split_distinct():
    assert len(tax_return.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(tax_return.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_fp500) is the GST/QST business remittance: tax_id + organization header,
    # no SIN/DOB -- a genuinely distinct real structure the train TP-1 layouts never produce.
    assert tax_return._layout_fp500 in held_pool and tax_return._layout_fp500 not in train_pool
    assert tax_return._layout_tp1_basic in train_pool and tax_return._layout_tp1_spouse in train_pool
    # structural skeleton differs: heldout rows carry the FP-500 GST header; train rows carry the TP-1 NAS row
    random.seed(27)
    held_has_gst = any("Numero de compte TPS/TVH" in tax_return.gen(split="heldout")['input']
                       or "GST/HST account number" in tax_return.gen(split="heldout")['input']
                       for _ in range(40))
    train_has_nas = any("assurance sociale" in tax_return.gen(split="train")['input']
                        or "Social insurance number" in tax_return.gen(split="train")['input']
                        for _ in range(40))
    assert held_has_gst and train_has_nas


def test_fp500_header_faithful_to_real_form():
    """Faithfulness lock: the real FP-500 header is 'Numero de compte TPS/TVH | Numero d'entreprise du
    Quebec (NEQ)' with NO dedicated QST-account cell. The QST account is carried under the real Revenu
    Quebec QST-registration label, not a fabricated 'Numero de compte TVQ' header cell. This guards the
    re-grounding regression (the held-out structure must match the real scaffold, not an invented field)."""
    random.seed(28)
    saw_fp500 = False
    for _ in range(60):
        t = tax_return.gen(split="heldout")['input']
        if "Numero d'entreprise du Quebec (NEQ)" in t or "Quebec enterprise number (NEQ)" in t:
            saw_fp500 = True
            # the fabricated cell label must NOT appear (real form has no such header cell)
            assert "Numero de compte TVQ" not in t and "QST account number" not in t, \
                "fabricated 'compte TVQ' header cell present -- not on the real FP-500"
            # the real GST/HST account label + the real QST-registration label must both be present
            assert ("Numero de compte TPS/TVH" in t or "GST/HST account number" in t)
            assert ("inscription au fichier de la TVQ" in t or "QST registration number" in t)
            # real header order: the GST/HST account cell precedes the NEQ cell on the same header line
            gst_lbl = "Numero de compte TPS/TVH" if "Numero de compte TPS/TVH" in t else "GST/HST account number"
            neq_lbl = "Numero d'entreprise du Quebec (NEQ)" if "Numero d'entreprise du Quebec (NEQ)" in t \
                else "Quebec enterprise number (NEQ)"
            assert t.index(gst_lbl) < t.index(neq_lbl)
    assert saw_fp500, "no FP-500 heldout row observed"
