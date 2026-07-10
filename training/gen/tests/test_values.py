"""Property tests for synthetic value generators (Phase 3 Task 3.2 foundation).

Verifies the checkable invariants: Luhn validity (and decoy invalidity), RAMQ +50-female month, Quebec
postal FSA + excluded letters, QC phone NPA, IBAN mod-97, account format, public-vs-private IP split.
Run many iterations so format branches are all exercised. 100% synthetic. Run:
.venv-test/bin/python -m pytest training/gen/tests/test_values.py -v
"""
import sys, os, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import values as V  # noqa: E402


def _digits(s):
    return re.sub(r'\D', '', s)


def test_sin_luhn_valid_and_decoy_invalid():
    random.seed(1)
    for _ in range(300):
        s = V.sin(valid=True)
        d = _digits(s)
        assert len(d) == 9 and d[0] in "23" and V._luhn_ok(d)
    for _ in range(300):
        assert not V._luhn_ok(_digits(V.sin(valid=False)))


def test_card_luhn_valid_and_lengths():
    random.seed(2)
    for _ in range(300):
        d = _digits(V.payment_card(valid=True))
        assert len(d) in (15, 16) and V._luhn_ok(d)
    for _ in range(200):
        assert not V._luhn_ok(_digits(V.payment_card(valid=False)))


def test_ramq_female_month_offset():
    random.seed(3)
    # female -> month field 51..62
    for _ in range(50):
        nam = V.ramq_nam(sex="F", month=6)
        d = _digits(nam)
        assert d[2:4] == "56"
    for _ in range(50):
        nam = V.ramq_nam(sex="M", month=6)
        assert _digits(nam)[2:4] == "06"
    # shape: 4 letters then 8 digits
    nam = V.ramq_nam()
    assert re.match(r'^[A-Z]{4} ?\d{4} ?\d{4}$', nam)


def test_postal_quebec_fsa_and_excluded_letters():
    random.seed(4)
    excluded = set("DFIOQUWZ")
    for _ in range(300):
        pc = V.postal_code().replace(" ", "")
        assert pc[0] in "GHJ"
        letters = [pc[0], pc[2], pc[4]]
        assert not (set(letters) & excluded)
        assert re.match(r'^[A-Z]\d[A-Z]\d[A-Z]\d$', pc)


def test_phone_uses_quebec_npa():
    random.seed(5)
    npas = {"514", "438", "450", "579", "418", "581", "367", "819", "873", "263", "468"}
    for _ in range(200):
        ph = V.phone()
        d = _digits(ph)
        # last 10 digits are NPA+NXX+last4 (drop a leading country code if present)
        d10 = d[-10:]
        assert d10[:3] in npas and d10[3:6] == "555"


def test_iban_mod97():
    random.seed(6)
    def mod97(s):
        s = re.sub(r'\s', '', s).upper()
        s2 = s[4:] + s[:4]
        return int(''.join(str(ord(c) - 55) if c.isalpha() else c for c in s2)) % 97
    for _ in range(100):
        assert mod97(V.iban(valid=True)) == 1
    bad = sum(mod97(V.iban(valid=False)) != 1 for _ in range(100))
    assert bad >= 95   # the vast majority of decoys must fail mod-97


def test_bank_account_hyphen_form():
    random.seed(7)
    seen_hyphen = False
    for _ in range(200):
        a = V.bank_account(form="hyphen")
        assert re.match(r'^\d{3}-\d{4,5}-\d{6,9}$', a)
        seen_hyphen = True
    assert seen_hyphen


def test_ip_public_vs_private_split():
    random.seed(8)
    priv = re.compile(r'^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)')
    for _ in range(200):
        assert not priv.match(V.public_ip())
    for _ in range(200):
        assert priv.match(V.private_ip())


def test_uuid_shape():
    random.seed(9)
    assert re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', V.uuid4())
