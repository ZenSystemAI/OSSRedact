"""Tests for the sin_letter generator (Service Canada SIN documents, PROSE context).

Offset-exactness, required positives, the precision property (issuer / public office / program line / file
ref / Luhn-invalid SIN twin / dates never labeled), the SIN Luhn + government_id shape invariant, the
multi-occurrence property (the full SIN appears at least twice), and the train/heldout layout split (the
newcomer instructional sheet is the held-out structure, disjoint from train and structurally distinct).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_sin_letter.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import sin_letter  # noqa: E402
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
    random.seed(11)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = sin_letter.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(12)
    need = {"person", "government_id", "date_of_birth", "address", "postal_code"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = sin_letter.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_sin_is_government_id_not_tax_id():
    """The SIN is the only id in this doctype; it must be government_id, never tax_id/account_number."""
    random.seed(120)
    saw_gov = False
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = sin_letter.gen(split=sp)
            labs = {lab for _, _, lab in r['output']['spans']}
            assert "tax_id" not in labs           # SIN must not be routed to the BN/GST/QST/NEQ family
            assert "account_number" not in labs   # nor to account_number
            if "government_id" in labs:
                saw_gov = True
    assert saw_gov


def test_government_id_is_luhn_valid_sin_shape():
    """Every government_id span is a 9-digit Luhn-valid SIN (Quebec region first digit 2/3), space/hyphen
    grouped or bare."""
    random.seed(121)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = sin_letter.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab != "government_id":
                    continue
                v = t[s:e]
                digits = re.sub(r'[ -]', '', v)
                assert re.fullmatch(r'\d{9}', digits), v
                assert digits[0] in "23", v        # Quebec region
                assert _luhn_ok(digits), v         # Luhn-valid by construction


def test_sin_appears_at_least_twice():
    """The defining property of this doctype: the FULL SIN is printed at least twice in one document
    (EN block + FR block in the letter; summary + handling note in the others)."""
    random.seed(122)
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = sin_letter.gen(split=sp)
            sins = [r['input'][s:e] for s, e, lab in r['output']['spans'] if lab == "government_id"]
            assert len(sins) >= 2, sins
            assert len(set(sins)) == 1, sins        # the SAME SIN repeated, not two different numbers


def test_decoys_never_labeled():
    random.seed(13)
    issuers = {"Service Canada", "Employment and Social Development Canada",
               "Emploi et Developpement social Canada"}
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = sin_letter.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                # the public program line is never inside a labeled span
                assert sin_letter._SIN_PROGRAM_LINE not in val
                # the Bathurst registration-office address / PO box is never labeled
                assert "Bathurst" not in val and "PO Box" not in val
                # the issuer org name is never labeled (no employer-style header lifts it)
                for iss in issuers:
                    assert iss not in val
                # a file/reference number prefix is never labeled
                assert not re.search(r'(CMD|REF|ORD|NAS|SIN|DOS)-\d', val)
                # an issue/generated date is a decoy; only a CUED dob is date_of_birth
                if re.fullmatch(r'20\d\d-\d\d-\d\d', val):
                    assert lab == "date_of_birth"


def test_luhn_invalid_lookalike_never_emitted_as_positive():
    """No labeled SIN should ever fail Luhn (the bad-checksum twin, if present, must be a decoy)."""
    random.seed(123)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = sin_letter.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                digits = re.sub(r'[ -]', '', v)
                if re.fullmatch(r'\d{9}', digits) and lab == "government_id":
                    assert _luhn_ok(digits), v


# a bare grouped 9-digit run (NO file-ref prefix) -- the SIN look-alike shape (collision rule 2)
_BARE_SIN_RE = re.compile(r'(?<![A-Za-z-])(?<!\d)(\d{3}[ -]\d{3}[ -]\d{3})(?!\d)')


def test_luhn_invalid_sin_lookalike_present_and_never_labeled():
    """Collision rule 2 hard-negative for a SIN doctype: a Luhn-INVALID 9-digit SIN look-alike (bare grouped,
    NO file-ref prefix) must be PRESENT in the text (so the model learns the check-digit gate) and must NEVER
    be inside a labeled span. The earlier test only checks labeled SINs pass Luhn -- it passes vacuously if no
    look-alike is generated at all; this test forces the decoy to actually exist."""
    random.seed(124)
    seen_invalid_lookalike = False
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = sin_letter.gen(split=sp)
            t = r['input']
            labeled = [(s, e) for s, e, _ in r['output']['spans']]
            for m in _BARE_SIN_RE.finditer(t):
                digits = re.sub(r'[ -]', '', m.group(1))
                if len(digits) != 9 or _luhn_ok(digits):
                    continue
                seen_invalid_lookalike = True
                # the bad-checksum twin must not overlap any labeled span
                ms, me = m.start(1), m.end(1)
                for ls, le in labeled:
                    assert not (ms < le and ls < me), (m.group(1), sp)
    assert seen_invalid_lookalike, "no Luhn-invalid SIN look-alike decoy was ever emitted"


def test_postal_shape():
    random.seed(14)
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = sin_letter.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', t[s:e])


def _skeleton(t: str) -> frozenset:
    """A normalized structural skeleton: which structure-defining header/prose markers are present."""
    markers = [
        "Social Insurance Registration Office", "Bureau d'immatriculation",   # mailed letter masthead
        "Name on record", "Nom au dossier",                                   # letter record block
        "My Service Canada Account", "Mon dossier Service Canada",            # MSCA notice
        "File reference", "Numero de dossier",                                # MSCA file-ref line
        "Information for new people", "nouveaux arrivants",                   # newcomer sheet
        "How do I apply", "Comment demander",                                 # newcomer apply steps
        "Follow us", "Suivez-nous",                                           # newcomer social footer
    ]
    return frozenset(m for m in markers if m in t)


def test_layouts_split_distinct():
    assert len(sin_letter.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(sin_letter.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout is the newcomer instructional sheet; the two letters never produce it
    assert sin_letter._layout_newcomer in held_pool
    assert sin_letter._layout_newcomer not in train_pool
    assert sin_letter._layout_letter in train_pool and sin_letter._layout_msca in train_pool

    random.seed(15)
    # the held-out structure carries newcomer-only markers ("How do I apply" / social footer) that the
    # train structures never emit -> the skeletons are disjoint between the pools.
    held_skels = [_skeleton(sin_letter.gen(split="heldout")['input']) for _ in range(40)]
    train_skels = [_skeleton(sin_letter.gen(split="train")['input']) for _ in range(120)]
    newcomer_only = {"Information for new people", "nouveaux arrivants", "How do I apply",
                     "Comment demander", "Follow us", "Suivez-nous"}
    assert all(s & newcomer_only for s in held_skels)        # every heldout row is the newcomer sheet
    assert not any(s & newcomer_only for s in train_skels)   # no train row is
