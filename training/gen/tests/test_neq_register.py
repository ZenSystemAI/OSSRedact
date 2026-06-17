"""Tests for the neq_register generator (Quebec enterprise register, etat des renseignements).

Offset-exactness, required positives (org + person + address + postal + NEQ-as-tax_id + account_number),
the precision property (register decoys -- dates, CAE/SCIAN codes, employee counts, statut, document index
-- never labeled), shape invariants (NEQ ten-digit legal-form prefix; postal FSA; account bare run), and
the train/heldout layout split (the search-result summary structure is disjoint from the full statement).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_neq_register.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import neq_register  # noqa: E402
import layouts  # noqa: E402
import values as V  # noqa: E402

# City names that are NOT also street names: a bare city / province marker is a NEGATIVE (collision rule),
# so it must never be absorbed into a labeled address or postal_code span. (Cities like "Sherbrooke" that
# double as a street name in V._STREET_NAMES are excluded -- there the token is a legitimate street.)
_CITY_ONLY = set(V._CITIES) - set(V._STREET_NAMES)

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = neq_register.gen(split=sp)
            t = r['input']
            # offset-true: every span must round-trip against the derived entities value-list (the framework
            # records text[s:e] AT APPEND TIME, so this catches any span/value desync, not the t[s:e]==t[s:e]
            # tautology it replaces).
            ents = r['output']['entities']
            from collections import Counter
            span_pairs = Counter((lab, t[s:e]) for s, e, lab in r['output']['spans'])
            ent_pairs = Counter((lab, v) for lab, vals in ents.items() for v in vals)
            assert span_pairs == ent_pairs, (sp, span_pairs, ent_pairs)
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""         # never an empty/whitespace span
                assert lab in _LABELS               # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"organization", "person", "address", "postal_code", "tax_id", "account_number"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = neq_register.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    """The register's defining negatives: every kind of date, the CAE/SCIAN economic codes, the employee
    count, the statut/forme/regime status strings, and the document-index filing references must never end
    up inside a labeled span."""
    random.seed(23)
    statut_words = set(neq_register._STATUT_FR) | set(neq_register._STATUT_EN)
    forme_words = set(neq_register._FORME_FR) | set(neq_register._FORME_EN)
    regime_words = set(neq_register._REGIME_FR) | set(neq_register._REGIME_EN)
    activite_words = set(neq_register._ACTIVITE_FR) | set(neq_register._ACTIVITE_EN)
    doctype_words = set(neq_register._DOCTYPE_FR) | set(neq_register._DOCTYPE_EN)
    role_words = set(neq_register._ROLE_FR) | set(neq_register._ROLE_EN)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = neq_register.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                # status / legal-form / regime / activity / doc-type / role strings are NEGATIVE decoys
                assert val not in statut_words, val
                assert val not in forme_words, val
                assert val not in regime_words, val
                assert val not in activite_words, val
                assert val not in doctype_words, val
                assert val not in role_words, val
                # a bare ISO date is always a register decoy (registration/constitution/update/filing)
                assert not re.fullmatch(r'20\d\d-\d\d-\d\d', val), val
                # a labeled value never straddles a tab/role separator cell
                assert "   " not in val
                # collision rule: a city name + province marker is a NEGATIVE; it must never be absorbed
                # into a labeled address or postal_code span (the home-address builders keep city+'(QC)' as
                # d.add filler). Guards against city/province contamination of a positive span.
                if lab in ("address", "postal_code"):
                    assert not re.search(r'\bQC\b', val), val
                    assert "Quebec" not in val and "Québec" not in val, val
                    for _city in _CITY_ONLY:
                        assert _city not in val, (lab, val, _city)


def test_neq_and_postal_and_account_shapes():
    """NEQ (tax_id here) is ten digits with a 11/22/33/88 legal-form prefix; postal is a QC FSA;
    account_number (establishment number) is a bare numeric run (NOT a UUID / sensitive id)."""
    random.seed(24)
    for sp in ("train", "heldout"):
        for _ in range(120):
            r = neq_register.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "tax_id":
                    digits = re.sub(r'\s', '', v)
                    assert re.fullmatch(r'\d{10}', digits), v          # ten digits
                    assert digits[:2] in {"11", "22", "33", "88"}, v   # legal-form prefix
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v), v
                if lab == "account_number":
                    assert re.fullmatch(r'\d{7,10}', v), v             # bare run, never UUID-shaped


def test_organization_and_person_both_present_in_full_layout():
    """The defining contrast of this doctype: the SAME full statement carries BOTH an org positive
    (enterprise name) AND person positives (directors/officers) -- they must coexist, not collapse."""
    random.seed(25)
    co_occur = 0
    for _ in range(40):
        r = neq_register._layout_full("fr")
        labs = {lab for _, _, lab in r['output']['spans']}
        if "organization" in labs and "person" in labs:
            co_occur += 1
    assert co_occur >= 35, co_occur


def test_layouts_split_distinct():
    assert len(neq_register.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(neq_register.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout is the compact search-result summary; the full statement is train-only
    assert neq_register._layout_search in held_pool and neq_register._layout_search not in train_pool
    assert neq_register._layout_full in train_pool and neq_register._layout_full not in held_pool
    # structural distinction: the full statement always emits a director list (account_number establishment
    # block + multiple person rows); the search summary never does (no establishment number, <=1 person).
    random.seed(26)
    full_has_account = any("account_number" in {lab for _, _, lab in neq_register.gen(split="train")['output']['spans']}
                           for _ in range(60))
    held_has_account = any("account_number" in {lab for _, _, lab in neq_register.gen(split="heldout")['output']['spans']}
                           for _ in range(60))
    assert full_has_account and not held_has_account
    # the search summary header marker ('search result') never appears in the full statement
    random.seed(27)
    train_text = "".join(neq_register.gen(split="train")['input'] for _ in range(20))
    held_text = "".join(neq_register.gen(split="heldout")['input'] for _ in range(20))
    assert ("recherche" in held_text.lower() or "search result" in held_text.lower())
    assert ("administrateurs --" in train_text.lower() or "list of directors" in train_text.lower())
    assert "résultat de la recherche" not in train_text.lower() and "search result" not in train_text.lower()
