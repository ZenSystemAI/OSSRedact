"""Tests for the ramq_card generator (RAMQ carte soleil + NAM list + renewal letter).

Offset-exactness, required positives (government_id NAM + person + date_of_birth), the precision property
(card-admin decoys: sex marker, issue/expiry dates, issuer org, card sequence -> never labeled), the NAM
shape + +50-female invariant + DOB-matches-NAM checksum, the official-anchor presence, and the train/heldout
layout split (the prose-letter structure disjoint from the card/list train structures).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_ramq_card.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import ramq_card  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])

_NAM_RE = re.compile(r'^[A-Z]{4} ?\d{4} ?\d{4}$')
_ISSUER = "Regie de l'assurance maladie du Quebec"


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = ramq_card.gen(split=sp)
            t = r['input']
            prev_end = -1
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels
                # spans are emitted in append order, must be strictly non-overlapping and forward-moving:
                # a labeled value can never sit inside or before a previously-labeled one (a real defect
                # the trivial "t[s:e]==t[s:e]" check could not catch).
                assert s >= prev_end, (s, prev_end, lab)
                prev_end = e


def test_required_positives_present():
    random.seed(22)
    need = {"government_id", "person", "date_of_birth"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = ramq_card.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    """The doctype's key negatives must never sit inside a labeled span."""
    random.seed(23)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = ramq_card.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                # the issuer org is a decoy in every layout -> never labeled
                assert _ISSUER not in val
                # a labeled value never straddles a tab cell
                assert " \t" not in val
                # a lone sex marker M/F is a decoy, never a government_id
                assert not (lab == "government_id" and val in ("M", "F"))


def test_nam_shape_and_plus50_female_invariant():
    """Every government_id is a structurally-valid NAM (4 alpha + 8 digit), and its month field obeys the
    +50-for-female rule (month in 1..12 -> male, 51..62 -> female). Also: the cued date_of_birth, when it
    co-occurs with a NAM, matches the NAM's encoded YY MM(+50) DD."""
    random.seed(24)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = ramq_card.gen(split=sp)
            t = r['input']
            spans = r['output']['spans']
            for s, e, lab in spans:
                if lab != "government_id":
                    continue
                v = t[s:e]
                assert _NAM_RE.match(v), v
                digits = re.sub(r'\D', '', v[4:])      # the 8 digits after the 4 letters
                assert len(digits) == 8, v
                mm = int(digits[2:4])
                assert (1 <= mm <= 12) or (51 <= mm <= 62), f"month field {mm} violates +50 rule in {v}"


def test_official_anchors_emitted():
    """The 6 official fictitious NAMs appear (as government_id) across enough samples -> the anchors are live,
    not just the synthetic shape."""
    random.seed(25)
    official = set(ramq_card._OFFICIAL_NAMS)
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(300):
            r = ramq_card.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                if lab == "government_id" and t[s:e] in official:
                    seen.add(t[s:e])
    assert len(seen) >= 5, f"too few official NAM anchors surfaced: {seen}"


def test_dob_matches_nam_in_card_and_letter():
    """In the card + letter layouts the cued DOB encodes the SAME year/month/day the NAM encodes (faithful to
    the real document, where the NAM literally encodes the birth date)."""
    random.seed(26)
    def _dob_ymd(s: str):
        m = re.match(r'^(\d{4})-(\d{2})-(\d{2})$', s)
        if m:
            return int(m.group(1)) % 100, int(m.group(2)), int(m.group(3))
        m = re.match(r'^(\d{2})/(\d{2})/(\d{4})$', s)
        if m:
            return int(m.group(3)) % 100, int(m.group(2)), int(m.group(1))
        return None  # long month-name form: skip the numeric cross-check
    checked = 0
    for layout in (ramq_card._layout_card, ramq_card._layout_letter):
        for _ in range(120):
            r = layout("fr")
            t = r['input']
            spans = r['output']['spans']
            nam = next((t[s:e] for s, e, lab in spans if lab == "government_id"), None)
            dob = next((t[s:e] for s, e, lab in spans if lab == "date_of_birth"), None)
            assert nam and dob
            d = re.sub(r'\D', '', nam[4:])
            ymd = _dob_ymd(dob)
            if ymd is None:
                continue
            yy, month, day = ymd
            nam_yy, nam_mm, nam_dd = int(d[0:2]), int(d[2:4]), int(d[4:6])
            nam_month = nam_mm - 50 if nam_mm > 50 else nam_mm
            assert (nam_yy, nam_month, nam_dd) == (yy, month, day), (nam, dob)
            checked += 1
    assert checked > 0


def test_layouts_split_distinct():
    assert len(ramq_card.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(ramq_card.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_letter) is the prose renewal letter and introduces an address + postal_code
    # mailing block in running prose that the card/list train layouts never produce -> a distinct structure
    assert ramq_card._layout_letter in held_pool and ramq_card._layout_letter not in train_pool
    assert ramq_card._layout_card in train_pool and ramq_card._layout_list in train_pool
    random.seed(27)
    held_labels = set()
    for _ in range(60):
        held_labels |= {lab for _, _, lab in ramq_card.gen(split="heldout")['output']['spans']}
    train_labels = set()
    for _ in range(120):
        train_labels |= {lab for _, _, lab in ramq_card.gen(split="train")['output']['spans']}
    # the letter carries an address + postal_code (mailing block); the train card layout now also emits a
    # cardholder mailing-address block (address + postal_code) so train covers what the held-out tests
    # (label-coverage parity). Structural distinctness is still asserted by test_held_out_is_prose_not_tabular.
    assert {"address", "postal_code"} <= held_labels
    assert {"address", "postal_code"} <= train_labels


def test_held_out_is_prose_not_tabular():
    """Structural skeleton differs: the held-out letter has a salutation sentence and no tab-delimited NAM
    grid; the train list layout is tab-delimited."""
    random.seed(28)
    saw_tab_list = False
    for _ in range(120):
        t = ramq_card.gen(split="train")['input']
        if " \t" in t:
            saw_tab_list = True
            break
    assert saw_tab_list
    prose_cue = 0
    for _ in range(60):
        t = ramq_card.gen(split="heldout")['input']
        if ("arrivera bientot a echeance" in t) or ("will expire soon" in t):
            prose_cue += 1
    assert prose_cue > 0
