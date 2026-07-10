"""Tests for the re-grounded flinks_stmt generator (v11, real tab-delimited Flinks layout).

Offset-exactness, required header positives, the precision property (transaction decoys never labeled),
shape invariants, and the train/heldout layout split (held-out structure disjoint from train).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_flinks.py -v
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import flinks  # noqa: E402
import layouts  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(11)
    for sp in ("train", "heldout"):
        for _ in range(150):
            r = flinks.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                assert 0 <= s < e <= len(t)
                assert t[s:e].strip() != ""        # never an empty/whitespace span
                assert lab in _LABELS              # only the 20 labels


def test_required_header_positives_present():
    random.seed(12)
    need = {"person", "date_of_birth", "address", "postal_code", "account_number", "sensitive_account_id"}
    seen = set()
    for sp in ("train", "heldout"):
        for _ in range(60):
            r = flinks.gen(split=sp)
            seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_decoys_never_labeled():
    random.seed(13)
    for sp in ("train", "heldout"):
        for _ in range(200):
            r = flinks.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                val = t[s:e]
                assert "$" not in val                       # amounts/balances are decoys, never labeled
                assert " \t" not in val                     # a labeled value never straddles a tab cell
                # a bare ISO date is a transaction decoy unless it is the cued DOB
                if re.fullmatch(r'20\d\d-\d\d-\d\d', val):
                    assert lab == "date_of_birth"


def test_postal_and_account_and_uuid_shapes():
    random.seed(14)
    acct_ok = re.compile(r'^(\d{3}-\d{4,5}-\d{6,9}|\d{7,11})$')
    for sp in ("train", "heldout"):
        for _ in range(100):
            r = flinks.gen(split=sp)
            t = r['input']
            for s, e, lab in r['output']['spans']:
                v = t[s:e]
                if lab == "postal_code":
                    assert re.match(r'^[GHJ]\d[A-Z] ?\d[A-Z]\d$', v)
                if lab == "sensitive_account_id":
                    assert re.match(r'^[0-9a-f]{8}-', v)     # the UUID connection ids
                if lab == "account_number":
                    assert acct_ok.match(v), v               # institution-first or bare run


def test_layouts_split_distinct():
    assert len(flinks.LAYOUTS) >= 2
    train_pool, held_pool = layouts.split_pools(flinks.LAYOUTS)
    assert set(train_pool).isdisjoint(set(held_pool))
    # the held-out layout (_layout_joint) introduces a JOINT holder (' ET '/' AND ' -> 2 person spans in one
    # row) that the train layouts (single holder) never produce -> a genuinely distinct structure. (IBAN
    # appears in BOTH splits now, so it is no longer the distinctness signal -- it needs train coverage.)
    assert flinks._layout_joint in held_pool and flinks._layout_joint not in train_pool
    random.seed(15)
    def _max_persons(split):
        return max(sum(1 for _, _, lab in flinks.gen(split=split)['output']['spans'] if lab == 'person')
                   for _ in range(80))
    assert _max_persons("heldout") == 2     # joint holders only in the held-out structure
    assert _max_persons("train") == 1        # train layouts are single-holder
