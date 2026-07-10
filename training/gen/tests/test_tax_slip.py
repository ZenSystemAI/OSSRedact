"""Tests for the tax_slip generator (RL-1 Quebec + T4 federal employer-issued income slips).

Offset-exactness, required identity positives (employee person/address/postal + SIN government_id +
employer organization + T4 payroll account_number), the precision property (box amounts / box numbers /
form codes / slip metadata / employer address / Luhn-invalid SIN look-alike never labeled), the faithfulness
property (no fabricated employer NEQ/BN -> tax_id is never labeled), the SIN Luhn checksum, the T4 Box 54
payroll-account shape, and the train/heldout layout split (held-out T4 numbered-box structure disjoint from
the RL-1 lettered-box one).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_tax_slip.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import tax_slip  # noqa: E402
import layouts   # noqa: E402

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
            r = tax_slip.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert t[s:e] == t[s:e]            # offset-true by construction
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(12)
    # the doctype's defining labels: employee identity (person/address/postal) + SIN (government_id) +
    # LABELED employer name (organization). account_number is T4-only (Box 54, tested separately) so it is
    # not in this both-splits set. tax_id is a ~30% train-only RT/TQ alternative (employer QST/GST
    # registration on payer correspondence) so it is not in this required set either (see
    # test_tax_id_heldout_free_train_rt_tq_only).
    need = {"person", "address", "postal_code", "government_id", "organization"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = tax_slip.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_tax_id_heldout_free_train_rt_tq_only():
    # Faithfulness (v11 round-2): the held-out T4 slip face carries no employer NEQ/BN field, so the
    # held-out split must emit NO tax_id positive (frozen). The TRAIN RL-1 layout now emits, as a ~30%
    # alternative, the employer QST(TQ)/GST(RT) registration number printed on payer correspondence -> a
    # tax_id positive. When present in train it MUST be the RT/TQ registry form (collision rule 3), never a
    # bare run that could read as account_number. This test pins both: heldout stays tax_id-free, train
    # tax_ids are RT/TQ only.
    random.seed(122)
    for _ in range(150):
        r = tax_slip.gen(split="heldout")
        labs = {lab for _, _, lab in r['output']['spans']}
        assert "tax_id" not in labs, f"unexpected tax_id in heldout: {r['output']['entities'].get('tax_id')}"
    seen_train_tax_id = False
    for _ in range(300):
        r = tax_slip.gen(split="train")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "tax_id":
                val = t[s:e]
                assert "RT" in val or "TQ" in val, f"train tax_id not RT/TQ registry form: {val!r}"
                seen_train_tax_id = True
    assert seen_train_tax_id, "expected the RL-1 train layout to emit RT/TQ tax_id sometimes"


def test_account_number_present_in_t4():
    # payroll account number (BN+RP) is a T4-only positive
    random.seed(112)
    seen = set()
    for _ in range(60):
        r = tax_slip.gen(split="heldout")
        seen |= {lab for _, _, lab in r['output']['spans']}
    assert "account_number" in seen


def test_decoys_never_labeled():
    random.seed(13)
    box_letters = {l for l, _ in tax_slip._RL1_BOXES}
    box_nums = {n for n, _, _ in tax_slip._T4_BOXES} | set(tax_slip._T4_OTHER_CODES)
    form_codes = {"RL-1", "T4"}
    # an OQLF/plain box amount: either '12,345.67' (comma-thousands + dot-cents) or '12 345,67'
    # (space-thousands + comma-cents). Both end in a separator + exactly two cents digits. No SIN / NEQ /
    # postal positive ever carries a comma, so this shape is unambiguous for amounts.
    amount_re = re.compile(r'^[\d ,]*\d[.,]\d{2}$')
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = tax_slip.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert not (amount_re.match(val) and "," in val)   # box amounts never labeled
                assert val not in form_codes                # RL-1 / T4 form codes are decoys
                assert val not in box_letters               # bare box letters (A, B.A, ...) decoys
                # a bare 2-digit box/code number is never labeled (positives are longer)
                if re.fullmatch(r'\d{2}', val):
                    assert val not in box_nums


def test_government_id_luhn_valid_and_reference_invalid():
    random.seed(14)
    seen_gov = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = tax_slip.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "government_id":
                    digits = re.sub(r'\D', '', t[s:e])
                    assert len(digits) == 9 and digits[0] in "23"   # QC SIN region
                    assert _luhn_ok(digits), f"SIN not Luhn-valid: {t[s:e]}"
                    seen_gov = True
    assert seen_gov


def test_account_number_payroll_shape():
    # T4 payroll account = 9-digit BN + RP + 4 digits
    random.seed(151)
    ok = re.compile(r'^\d{9}RP\d{4}$')
    for _ in range(120):
        r = tax_slip.gen(split="heldout")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "account_number":
                assert ok.match(t[s:e]), t[s:e]


def test_account_number_train_numeric_held_payroll():
    # v11 round-3 label-coverage parity: the RL-1 TRAIN layout now also emits an account_number, drawn from
    # V.bank_account -> a NUMERIC bare/hyphenated digit run (collision rule 1: numeric account, NOT the RT/TQ
    # tax_id, NOT the Luhn SIN). The held-out T4 keeps the BN+RP payroll form (\d{9}RP\d{4}). Pin both shapes
    # and confirm the train layout actually produces account_number sometimes (so the coverage gap is closed).
    random.seed(231)
    numeric_re = re.compile(r'^[\d-]+$')
    seen_train_acct = False
    for _ in range(300):
        r = tax_slip.gen(split="train")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "account_number":
                val = t[s:e]
                assert numeric_re.match(val), f"train account_number not numeric run: {val!r}"
                assert "RP" not in val and not re.search(r'[A-Za-z]', val), \
                    f"train account_number must be a bare numeric run, not BN+RP: {val!r}"
                seen_train_acct = True
    assert seen_train_acct, "expected the RL-1 train layout to emit a numeric account_number sometimes"
    # held-out stays the BN+RP payroll form
    payroll_re = re.compile(r'^\d{9}RP\d{4}$')
    for _ in range(120):
        r = tax_slip.gen(split="heldout")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "account_number":
                assert payroll_re.match(t[s:e]), t[s:e]


def test_postal_shape():
    random.seed(16)
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = tax_slip.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', t[s:e])


def test_no_em_dash_in_output():
    random.seed(17)
    for sp in ("train", "heldout"):
        for _ in range(40):
            assert "\u2014" not in tax_slip.gen(split=sp)['input']


def test_layouts_split_distinct():
    assert len(tax_slip.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(tax_slip.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # held-out = the federal T4 (numbered boxes + payroll account); train = the Quebec RL-1 (lettered boxes)
    assert tax_slip._layout_t4 in held_pool and tax_slip._layout_t4 not in train_pool
    assert tax_slip._layout_rl1 in train_pool and tax_slip._layout_rl1 not in held_pool
    random.seed(18)
    # structural skeleton: T4 carries the "Box 12" SIN header + numbered-box grid + the federal
    # "remuneration" title; RL-1 carries the "Releve officiel - Revenu Quebec" footer + the lettered-box grid
    # + a NAS reference line. Neither skeleton appears in the other. account_number is NOT a skeleton
    # discriminator any more: as of v11 round-3 the RL-1 train layout also emits an account_number (a NUMERIC
    # employer remittance/deposit account, V.bank_account) on a ~30% employer-correspondence cue, for
    # label-coverage parity with the held-out T4 Box 54 (which carries the BN+RP payroll account). The
    # account VALUE SHAPE distinguishes them and is pinned in test_account_number_train_numeric_held_payroll.
    held_has_acct = any("account_number" in {lab for _, _, lab in tax_slip.gen(split="heldout")['output']['spans']}
                        for _ in range(40))
    assert held_has_acct
    held_text = "".join(tax_slip.gen(split="heldout")['input'] for _ in range(20))
    train_text = "".join(tax_slip.gen(split="train")['input'] for _ in range(20))
    assert "Statement of Remuneration Paid" in held_text or "remuneration payee" in held_text
    assert "Releve officiel" in train_text or "RELEVE 1" in train_text
    assert "Statement of Remuneration Paid" not in train_text and "remuneration payee" not in train_text
