"""Tests for the employment_lease generator (v11, real Quebec employment letter + TAL lease structures).

Offset-exactness, required positives across BOTH splits, the precision properties for THIS doctype (salary
/ rent amounts, every non-birth date, org-shaped provider mentions, and opaque HR/lease refs are NEVER
labeled), shape invariants (account format, postal FSA), and the train/heldout layout split (the lease
FORM is structurally disjoint from the prose LETTERS).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_employment_lease.py -q
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import employment_lease as EL  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])

# org-shaped provider/management names that appear ONLY as decoys (no header label)
_PROVIDERS = set(EL._PROVIDER)


def test_offsets_exact_and_labels_in_scheme():
    random.seed(31)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = EL.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e] != ""               # never an empty span
                assert t[s:e].strip() != ""       # never whitespace-only
                assert lab in _LABELS             # only the 20 labels


def test_required_positives_present():
    """The doctype's defining labels must appear across both splits."""
    random.seed(32)
    need = {"person", "organization", "address", "postal_code", "phone_number", "email", "account_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = EL.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    """Salary/rent amounts ('$'), org-shaped provider/management mentions, opaque HR/lease refs, and every
    bare date are decoys and must never sit inside a labeled span. This doctype has NO date_of_birth and NO
    sensitive_account_id positive, so ANY ISO date and ANY UUID-shaped value must be unlabeled."""
    random.seed(33)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = EL.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                                  # salary / rent amounts are decoys
                assert val not in _PROVIDERS                           # provider/management orgs are decoys
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)      # no cued DOB -> every ISO date is a decoy
                assert not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', val)  # UUID file/lease ref -> decoy


def test_decoys_present():
    """Contract rule 4 (DECOYS PRESENT): the hard-negative look-alikes must actually be EMITTED, not just
    'never mislabeled'. Without this, a regression that drops every d.decoy() would pass the rest of the
    suite vacuously while teaching the model nothing about the false-positive look-alikes (the product).
    Asserts, via the public row API only, that across both splits the doctype's decoys appear in the text
    and outside every labeled span: an amount ('$'), an org-shaped provider/management mention, a bare ISO
    transaction date, and (in the prose-letter family) the UUID-shaped HR file ref."""
    random.seed(38)
    rx_uuid = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    rx_iso = re.compile(r'20\d\d-\d\d-\d\d')

    def _unlabeled_hit(t, spans, finditer):
        """A match of `finditer` exists in text AND lies fully outside every labeled span."""
        labeled = [(s, e) for s, e, _ in spans]
        for m in finditer(t):
            ms, me = m.start(), m.end()
            if all(me <= ls or ms >= le for ls, le in labeled):
                return True
        return False

    seen_amount = seen_provider = seen_isodate = seen_uuid = 0
    saw_uuid_layout = 0
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = EL.gen(split=sp)
            t = r['input']
            spans = r['output']['spans']
            # decoys must be COUNTED as hard-negatives, never zero
            assert r['meta']['n_decoys'] > 0, "no decoys emitted -- look-alikes missing"

            if _unlabeled_hit(t, spans, lambda s: re.finditer(r'\$', s)):
                seen_amount += 1
            if any(p in t for p in _PROVIDERS) and not any(t[s:e] in _PROVIDERS for s, e, _ in spans):
                seen_provider += 1
            if _unlabeled_hit(t, spans, rx_iso.finditer):
                seen_isodate += 1
            if rx_uuid.search(t):
                saw_uuid_layout += 1
                if _unlabeled_hit(t, spans, rx_uuid.finditer):
                    seen_uuid += 1

    assert seen_amount > 0, "no amount ('$') decoy present in any row"
    assert seen_provider > 0, "no org-shaped provider/management decoy present"
    assert seen_isodate > 0, "no bare ISO transaction-date decoy present"
    assert saw_uuid_layout > 0, "the UUID-shaped HR file ref decoy never appeared"
    assert seen_uuid == saw_uuid_layout, "a UUID-shaped value appeared but was not a hard-negative decoy"


def test_account_and_postal_shapes():
    """account_number = institution-first III-TTTT(T)-AAA or a bare run; postal = Quebec G/H/J FSA."""
    random.seed(34)
    acct_ok = re.compile(r'^(\d{3}-\d{4,5}-\d{6,9}|\d{7,11})$')
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = EL.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "account_number":
                    assert acct_ok.match(v), v
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v


def test_organization_only_via_header_label():
    """organization positives are ONLY the labeled-header employer (Employeur:/Employer:/De:/From:). The same
    employer string repeated in a sign-off / letterhead line, and the provider mentions, are decoys."""
    random.seed(35)
    cues = ("Employeur:", "Employer:", "De:", "From:")
    saw_org = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = EL.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "organization":
                    saw_org = True
                    prefix = t[:s]
                    assert any(prefix.rstrip().endswith(c) for c in cues), \
                        f"organization {t[s:e]!r} not preceded by a header label"
    assert saw_org, "no organization positive produced"


def test_layouts_split_distinct():
    """len(LAYOUTS) >= 2; train and heldout pools are disjoint AND structurally different: the held-out lease
    FORM emits the section-headed 'SECTION 1 - PARTIES' / 'Locataire' / 'Tenant' skeleton and TWO person
    positives, which the prose LETTER train layouts never produce."""
    assert len(EL.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(EL.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    assert EL._layout_lease_form in held_pool and EL._layout_lease_form not in train_pool

    # structural skeleton differs: the lease-form section header appears in heldout, never in train
    held_marker = re.compile(r'SECTION 1 - PARTIES')
    train_marker = re.compile(r'(Attestation d\'emploi|RE: Employment|Mortgage credit|credit hypothecaire)')

    random.seed(36)
    held_has_form = 0
    held_has_two_persons = 0
    for _ in range(40):
        r = EL.gen(split="heldout")
        t = r['input']
        if held_marker.search(t):
            held_has_form += 1
        if sum(1 for _, _, lab in r['output']['spans'] if lab == "person") == 2:
            held_has_two_persons += 1
    assert held_has_form == 40, "held-out must always be the lease FORM"
    assert held_has_two_persons == 40, "held-out lease must carry tenant + landlord persons"

    train_has_letter = 0
    train_has_form = 0
    for _ in range(120):
        r = EL.gen(split="train")
        t = r['input']
        if train_marker.search(t):
            train_has_letter += 1
        if held_marker.search(t):
            train_has_form += 1
    assert train_has_letter > 0, "train must produce prose letters"
    assert train_has_form == 0, "the lease FORM must never appear in train"


def test_lang_mix_roughly_65_35():
    random.seed(37)
    n = 400
    fr = sum(1 for _ in range(n) if EL.gen()['meta']['lang'] == 'fr')
    frac = fr / n
    assert 0.5 < frac < 0.8, f"FR fraction {frac:.2f} out of expected band"
