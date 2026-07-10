"""Tests for the org_contrast generator (Phase 3 Task 3.2).

Offset-exactness, required positives, labels-in-scheme, and the key precision property for THIS doctype:
organization is labeled ONLY in the header block; the SAME kind of org-shaped name in a merchant/vendor
ledger line (a decoy) is NEVER labeled. Run:
    .venv-test/bin/python -m pytest training/gen/tests/test_org_contrast.py -q
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import org_contrast  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])

# org-shaped tails that appear in BOTH the header employer and the ledger vendor decoys: by construction the
# generator reuses the same name pools, so a tail like "Solutions Inc" or "Clinique" can show up on both
# sides. That is exactly the contrast under test: context (header label vs ledger line), not the string,
# decides positive vs negative.
_ORG_SUFFIX = {"Solutions Inc", "Solutions inc.", "Technologies", "Conseil", "Groupe", "Services",
               "Industries", "Logistique", "Construction", "Distribution Ltee", "Gestion", "Marketing"}
_MERCHANTS = {"IGA", "METRO", "COSTCO WHOLESALE", "AMAZON.CA", "HYDRO-QUEBEC", "BELL CANADA",
              "VIDEOTRON", "PHARMAPRIX", "TIM HORTONS", "PETRO-CANADA", "SAQ", "RONA"}


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for _ in range(200):
        r = org_contrast.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            assert 0 <= s < e <= len(t)
            assert t[s:e] != ""               # never an empty span
            assert t[s:e].strip() != ""       # never whitespace-only
            assert lab in _LABELS             # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"organization", "person", "email", "address", "postal_code"}
    seen = set()
    for _ in range(60):
        r = org_contrast.gen()
        seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_organization_only_in_header_never_ledger():
    """The precision property: a merchant/vendor in a ledger context is a decoy. We assert NO labeled span
    sits inside the ledger/transaction block, and that every organization positive precedes that block."""
    random.seed(23)
    for _ in range(200):
        r = org_contrast.gen()
        t = r['input']
        # locate the ledger header line (FR or EN); everything from there on is decoy territory
        m = re.search(r'(Releve de transactions|Transaction ledger)', t)
        assert m is not None, "ledger block missing"
        ledger_start = m.start()
        for s, e, lab in r['output']['spans']:
            # NO positive of ANY kind may live in the ledger block (it's all decoys there)
            assert e <= ledger_start, f"label {lab} ({t[s:e]!r}) leaked into ledger block"


def test_organization_positives_carry_header_label_context():
    """Every organization positive must be immediately preceded by a header label cue (Employeur:, Clinic:,
    etc.), i.e. it is the labeled-header mode, never a bare in-text org."""
    random.seed(24)
    cues = ("Employeur:", "Mon entreprise:", "Clinique:", "Societe:", "Raison sociale:", "Lieu de travail:",
            "Employer:", "My company:", "Clinic:", "Company:", "Business name:", "Workplace:",
            "Clinique de suivi:", "Fournisseur principal:", "Filiale:",
            "Follow-up clinic:", "Parent company:", "Subsidiary:")
    saw_org = False
    for _ in range(120):
        r = org_contrast.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "organization":
                saw_org = True
                prefix = t[:s]
                assert any(prefix.rstrip().endswith(c) for c in cues), \
                    f"organization {t[s:e]!r} not preceded by a header label"
    assert saw_org, "no organization positive produced"


def test_decoys_never_labeled():
    """Plain merchant names and org-shaped vendor tails appearing as decoys are never in the span set, and
    no labeled span is an amount/date decoy."""
    random.seed(25)
    for _ in range(200):
        r = org_contrast.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            val = t[s:e]
            assert val not in _MERCHANTS              # known merchant tokens are decoys
            assert "$" not in val                     # amounts are decoys
            # a bare ISO date is a ledger/decoy date here (org_contrast has no DOB positive)
            assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val)
            if lab != "organization":
                # non-org positives must not be an org-suffix token (those belong to org/decoy names only)
                assert val not in _ORG_SUFFIX


def test_lang_mix_roughly_65_35():
    random.seed(26)
    n = 400
    fr = sum(1 for _ in range(n) if org_contrast.gen()['meta']['lang'] == 'fr')
    frac = fr / n
    assert 0.5 < frac < 0.8, f"FR fraction {frac:.2f} out of expected band"
