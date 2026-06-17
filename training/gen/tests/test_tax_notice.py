"""Tests for the tax_notice generator (synthetic QC avis de cotisation + CRA Notice of Assessment).

Offset-exactness, required positives, the precision property (amounts / dates / masked-SIN / agency names /
lone bank fragments are never labeled), doctype shape invariants (full SIN Luhn-valid government_id, notice
number ^[QM][A-Z0-9]{10}$, NETFILE 8-char access code, account_number is a bare numeric run), and the
train/heldout layout split (CRA NoA structure held out, disjoint from the QC avis training structure).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_tax_notice.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import tax_notice  # noqa: E402
import layouts  # noqa: E402
import values as V  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = tax_notice.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"person", "address", "postal_code", "sensitive_account_id",
            "government_id", "account_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(80):
            r = tax_notice.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    random.seed(23)
    # masked-SIN forms: 'XXX XX4 286' / 'XXX-XX-1286' / '*** ** 4286' -> always a decoy, never a labeled span
    masked = re.compile(r'^(XXX XX\d \d{3}|XXX-XX-\d{4}|\*\*\* \*\* \d{4})$')
    for sp in ("train", "heldout"):
        for _ in range(250):
            r = tax_notice.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                      # all dollar amounts are decoys, never labeled
                assert "*" not in val                       # masked-SIN star form never labeled
                assert not masked.match(val)                # the masked-SIN 'XXX XX4 286' shape is a decoy
                # a bare ISO-ish date never gets labeled here (no DOB on a tax notice -> all dates are decoys)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)


def test_agency_names_never_labeled():
    """The two agency identities (Revenu Quebec / Canada Revenue Agency / Agence du revenu du Canada) and the
    public enquiry phone lines are PUBLIC institutional facts -> never inside a labeled span (no organization
    or phone_number positive on this doctype)."""
    random.seed(24)
    public_bits = ["Revenu Quebec", "Canada Revenue Agency", "Agence du revenu du Canada",
                   "1-800-959-8281", "1 800 267-6299"]
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = tax_notice.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                for bit in public_bits:
                    assert bit not in val
                assert lab not in ("organization", "phone_number")   # this doctype emits neither


def test_full_sin_luhn_valid_and_government_id():
    """Where the full SIN is shown (QC avis) it is a Luhn-valid 9-digit government_id (first digit 2/3)."""
    random.seed(25)
    saw = 0
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = tax_notice.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "government_id":
                    saw += 1
                    digits = re.sub(r'\D', '', t[s:e])
                    assert len(digits) == 9 and digits[0] in "23"
                    assert V._luhn_ok(digits)               # full SIN is Luhn-valid by construction
    assert saw > 0, "no full SIN government_id emitted"


def test_sensitive_and_account_shapes():
    random.seed(26)
    notice = re.compile(r'^[QM][A-Z0-9]{10}$')              # QC avis number
    netfile = re.compile(r'^[A-Z0-9]{8}$')                  # CRA NETFILE 8-char access code
    payref = re.compile(r'^\d{4} \d{4} \d{4}$')             # QC payment reference
    acct = re.compile(r'^\d{4,9}$')                         # bare numeric account run
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = tax_notice.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "sensitive_account_id":
                    assert notice.match(v) or netfile.match(v) or payref.match(v), v
                if lab == "account_number":
                    assert acct.match(v), v                  # never routed a notice/netfile ref here
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
                if lab == "tax_id":
                    # business/registry number: GST #########RT####, QST ##########TQ####, or NEQ
                    # (10-digit, optionally (3,3,4)-spaced). Never a SIN / amount / masked form.
                    assert re.fullmatch(r'\d{9}RT\d{4}|\d{10}TQ\d{4}|\d{10}|\d{3} \d{3} \d{4}', v), v


def test_train_tax_id_cue_present_both_styles():
    """v11 r2 recall-first: the QC avis TRAIN layout now also teaches a business-account tax_id (RT/TQ/NEQ)
    under BOTH a formal labeled cue and a terse inline cue, FR + EN -- so tax_id recall/precision improve
    WITHOUT touching the held-out CRA NoA structure. tax_id lives ONLY in the train layout here."""
    random.seed(29)
    saw_train = saw_labeled = saw_terse = saw_spaced = 0
    saw_held = 0
    for _ in range(1500):
        r = tax_notice.gen(split="train"); t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab != "tax_id":
                continue
            saw_train += 1
            ctx = t[max(0, s - 70):s]
            if any(k in ctx for k in ("relates to", "registered under", "Account concerned",
                                      "vise le compte", "Etabli pour", "Compte vise")):
                saw_terse += 1
            elif any(k in ctx for k in ("Business", "entreprise", "identification")):
                saw_labeled += 1
            if " " in t[s:e]:
                saw_spaced += 1
    for _ in range(400):
        r = tax_notice.gen(split="heldout")
        saw_held += sum(1 for _, _, lab in r['output']['spans'] if lab == "tax_id")
    assert saw_train > 0, "no tax_id positive in the train QC avis layout"
    assert saw_labeled > 0 and saw_terse > 0, "tax_id must appear under BOTH labeled and terse cues"
    assert saw_spaced > 0, "no (3,3,4)-spaced NEQ tax_id variant emitted"
    assert saw_held == 0, "tax_id must NOT leak into the held-out CRA NoA structure"


def test_netfile_code_has_letter_and_digit():
    """The NETFILE access code is 'numbers and letters' (canada.ca): forced to mix >=1 of each so it never
    collapses to an all-letter token a model could mistake for a word/password."""
    random.seed(27)
    saw = 0
    for _ in range(300):
        # the NETFILE code lives only in the CRA NoA (held-out) layout
        r = tax_notice.gen(split="heldout")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "sensitive_account_id" and re.fullmatch(r'[A-Z0-9]{8}', t[s:e]):
                saw += 1
                assert any(ch.isalpha() for ch in t[s:e]) and any(ch.isdigit() for ch in t[s:e])
    assert saw > 0, "no NETFILE access code emitted in the held-out layout"


def test_layouts_split_distinct():
    assert len(tax_notice.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(tax_notice.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out structure is the CRA NoA; the train structure is the QC avis -> different real issuers
    assert tax_notice._layout_cra_noa in held_pool and tax_notice._layout_cra_noa not in train_pool
    assert tax_notice._layout_qc_avis in train_pool and tax_notice._layout_qc_avis not in held_pool

    # structural skeletons differ: the QC avis carries the "Revenu Quebec" issuer + a full SIN government_id;
    # the CRA NoA carries the bilingual "Agence du revenu du Canada" header + a NETFILE code + a masked SIN
    # and never emits a government_id positive (the SIN is masked there).
    random.seed(28)
    train_has_govid = train_has_rq = False
    for _ in range(120):
        r = tax_notice.gen(split="train"); t = r['input']
        if "Revenu Quebec" in t:
            train_has_rq = True
        if any(lab == "government_id" for _, _, lab in r['output']['spans']):
            train_has_govid = True
    held_has_netfile = held_has_cra = held_has_govid = False
    for _ in range(120):
        r = tax_notice.gen(split="heldout"); t = r['input']
        if "Agence du revenu du Canada" in t:
            held_has_cra = True
        if "NETFILE" in t:
            held_has_netfile = True
        if any(lab == "government_id" for _, _, lab in r['output']['spans']):
            held_has_govid = True
    assert train_has_rq and train_has_govid          # QC avis: RQ issuer + full SIN government_id
    assert held_has_cra and held_has_netfile          # CRA NoA: ARC header + NETFILE access code
    assert not held_has_govid                          # CRA masks the SIN -> no government_id in the held-out
