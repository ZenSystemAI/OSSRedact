"""Tests for the saaq_licence generator (v11, real SAAQ permis-de-conduire specimen layout).

Offset-exactness, required identity positives, the precision property (the physical/administrative card
fields + the issuer org + the ICAO MRZ are never labeled), the permis-number shape invariant, and the
train/heldout layout split (the Permis Plus / MRZ structure is disjoint from train).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_saaq_licence.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import saaq_licence as M  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(11)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = M.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(12)
    need = {"government_id", "person", "date_of_birth", "address", "postal_code"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = M.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_overlap_a_labeled_span():
    """The offset-true precision invariant: every decoy (sex, class, conditions, endorsements, height, eye
    colour, reference number, issue/expiry date, the SAAQ issuer org, the Plus/CAN indicators, the ICAO MRZ
    block) lives in the text but NEVER overlaps a labeled span. Checked positionally (not by string value)
    so a surname that happens to equal an eye-colour word like BROWN is not a false failure -- the eye-colour
    DECOY span itself is still never labeled."""
    random.seed(13)
    for fn in M.LAYOUTS:
        for _ in range(120):
            r, decoys = _run_capture(fn)
            for (ds, de) in decoys:
                for (s, e, lab) in r['output']['spans']:
                    assert e <= ds or s >= de, f"label {lab} overlaps a decoy at [{ds},{de})"


def _run_capture(fn):
    """Call a layout fn, returning (row, decoy_spans). Monkeypatches framework.Doc to expose the decoys the
    layout recorded (framework.row() does not include decoys)."""
    import framework
    captured = {}
    real_row = framework.Doc.row

    def row_with_decoys(self):
        captured['decoys'] = list(self._decoys)
        return real_row(self)

    framework.Doc.row = row_with_decoys
    try:
        r = fn("fr" if random.random() < 0.65 else "en")
    finally:
        framework.Doc.row = real_row
    return r, captured.get('decoys', [])


def test_key_negatives_never_labeled():
    """Value-level guard for the SAAQ-specific negatives that are NOT person-name-collidable: the issuer org
    string, the (QC) province marker, and any non-DOB ISO date (issue/expiry).

    Crucially this enforces the date rule in BOTH directions: not only does every labeled ISO date have to be
    the cued DOB, but a row must carry EXACTLY ONE date_of_birth span. The real card prints one birth date and
    two further dates (Valide le / Expire le) that are issue/expiry DECOYS; if a generator regression ever
    routed one of those through d.field(..., 'date_of_birth') it would be ISO-shaped too and would slip past a
    one-directional 'ISO => DOB' guard, so the count invariant is what actually catches an issue/expiry-date
    -> DOB mislabel (the central collision rule for this doctype)."""
    random.seed(133)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = M.gen(split=sp)
            t = r['input']
            dob_count = 0
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "assurance automobile" not in val   # the SAAQ issuer org -> never labeled
                assert "(QC)" not in val                    # province marker -> never inside a labeled span
                # a bare ISO date is an issue/expiry decoy unless it is the cued DOB
                if re.fullmatch(r'\d{4}-\d\d-\d\d', val):
                    assert lab == "date_of_birth"
                if lab == "date_of_birth":
                    dob_count += 1
            # exactly one cued birth date; the Valide le / Expire le dates stay decoys, never a 2nd DOB
            assert dob_count == 1, f"expected 1 date_of_birth, got {dob_count} ({sp})"


def test_permis_shape_and_positive_shapes():
    random.seed(14)
    permis_re = re.compile(r'^[A-Z]\d{4}-\d{6}-\d{2}$')      # official L1531-171274-08 shape
    postal_re = re.compile(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$')
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = M.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "government_id":
                    assert permis_re.match(v), v             # 1 letter + 12 digits, hyphenated 4-6-2
                if lab == "postal_code":
                    assert postal_re.match(v), v
                if lab == "person":
                    assert v == v.upper() and v.strip() != ""   # SAAQ name lines are ALL-CAPS


def test_mrz_present_only_in_heldout_and_never_labeled():
    """The ICAO MRZ strip is the held-out Permis Plus structural marker (train layouts never produce it),
    and it is always a decoy: no labeled span ever falls inside the two-row MRZ block."""
    random.seed(15)
    held_has_mrz = any("Machine readable zone" in M.gen(split="heldout")['input'] for _ in range(40))
    train_has_mrz = any("Machine readable zone" in M.gen(split="train")['input'] for _ in range(120))
    assert held_has_mrz and not train_has_mrz
    # MRZ rows use only the A-Z0-9< alphabet; assert no labeled value is an MRZ-alphabet-only long run
    random.seed(16)
    for _ in range(120):
        r = M.gen(split="heldout")
        t = r['input']
        for s, e, lab in r['output']['spans']:
            v = t[s:e]
            assert not re.fullmatch(r'[A-Z0-9<]{20,}', v)    # an MRZ row would match; positives never do


def test_layouts_split_distinct():
    assert len(M.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(M.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_plus) is the Permis Plus + MRZ structure, never in the train pool
    assert M._layout_plus in held_pool and M._layout_plus not in train_pool
    # structural-skeleton check: the held pool emits the 'Plus' header + MRZ caption the train pool never does
    random.seed(17)
    held_plus = any("conduire Plus" in M.gen(split="heldout")['input']
                    or "licence Plus" in M.gen(split="heldout")['input'] for _ in range(40))
    train_plus = any("conduire Plus" in M.gen(split="train")['input']
                     or "licence Plus" in M.gen(split="train")['input'] for _ in range(120))
    assert held_plus and not train_plus
