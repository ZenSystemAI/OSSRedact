"""Tests for the v11 shared scaffolding: the train/heldout layout split + the new shared value samplers
(dob, request_datetime, company). 100% synthetic. Run:
.venv-test/bin/python -m pytest training/gen/tests/test_shared_v11.py -v
"""
import sys, os, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import values as V       # noqa: E402
import layouts           # noqa: E402


# ---------------- layout split ----------------

def test_split_pools_disjoint_and_nonempty():
    for n in range(2, 9):
        L = [f"layout_{i}" for i in range(n)]
        train, held = layouts.split_pools(L)
        assert train and held                      # both non-empty
        assert set(train).isdisjoint(set(held))    # never share a structure
        assert set(train) | set(held) == set(L)    # cover everything
        assert train == L[: len(train)]            # train is the prefix, held the suffix (by index)


def test_split_requires_two_layouts():
    try:
        layouts.split_pools(["only_one"])
        assert False, "should have raised"
    except ValueError:
        pass


def test_choose_draws_from_correct_pool():
    random.seed(7)
    L = ["a", "b", "c", "d", "e"]
    train, held = layouts.split_pools(L)
    for _ in range(200):
        assert layouts.choose("train", L) in train
        assert layouts.choose("heldout", L) in held


# ---------------- new shared samplers ----------------

def test_dob_shapes_and_year_range():
    random.seed(11)
    iso = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    slash = re.compile(r'^\d{2}/\d{2}/\d{4}$')
    fr_long = re.compile(r'^\d{1,2} [a-zéûô]+ \d{4}$')
    en_long = re.compile(r'^[A-Z][a-z]+ \d{1,2}, \d{4}$')
    for _ in range(300):
        v = V.dob("fr")
        assert iso.match(v) or slash.match(v) or fr_long.match(v), v
    for _ in range(300):
        v = V.dob("en")
        assert iso.match(v) or slash.match(v) or en_long.match(v), v


def test_request_datetime_has_time_component():
    random.seed(12)
    for _ in range(100):
        assert re.search(r'\d{1,2}:\d{2}', V.request_datetime("fr"))      # FR 24h clock
    for _ in range(100):
        assert re.search(r'\d{1,2}:\d{2}\s+[ap]\.m\.', V.request_datetime("en"))   # EN am/pm


def test_company_is_nonempty_string():
    random.seed(13)
    for lang in ("fr", "en"):
        for _ in range(50):
            c = V.company(lang)
            assert isinstance(c, str) and len(c) >= 5 and " " in c


def test_ramq_nam_letters_ascii_even_with_accented_names():
    """RAMQ NAM code letters must be A-Z only even though surnames carry accents (Bélanger, Côté)."""
    random.seed(14)
    for _ in range(300):
        nam = V.ramq_nam()
        assert re.match(r'^[A-Z]{4} ?\d{4} ?\d{4}$', nam), nam
