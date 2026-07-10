"""Tests for the system_log generator (Phase 3 Task 3.2).

Offset-exactness, required positives (ip_address + file_path), labels-in-scheme, and the key precision
property: infrastructure noise (private/loopback IPs, ports, PIDs, timestamps, versions, build hashes) is
NEVER labeled, and every ip_address positive is a routable PUBLIC IP (research doc section 5/7).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_system_log.py -q
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import system_log  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def _octets(ip):
    return [int(o) for o in ip.split('.')]


def _is_private(ip):
    """RFC1918 / loopback / link-local -> True (these must NEVER be ip_address)."""
    if not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
        return False
    a, b, c, dd = _octets(ip)
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:                       # loopback
        return True
    if a == 169 and b == 254:          # link-local
        return True
    return False


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for _ in range(200):
        r = system_log.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            assert 0 <= s < e <= len(t)
            assert t[s:e].strip() != ""        # never an empty/whitespace span
            assert lab in _LABELS              # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"ip_address", "file_path"}
    seen = set()
    for _ in range(60):
        r = system_log.gen()
        seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"
    # the sprinkled positives should also surface across 60 rows
    assert {"person", "email", "username"} & seen, "expected at least one of person/email/username"


def test_ip_positives_are_public_only():
    """The load-bearing rule: a labeled ip_address is NEVER a private/loopback/link-local address."""
    random.seed(23)
    for _ in range(300):
        r = system_log.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "ip_address":
                v = t[s:e]
                assert re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', v), f"bad ip shape {v!r}"
                assert not _is_private(v), f"private/loopback IP labeled as ip_address: {v}"


def test_decoys_never_labeled():
    random.seed(24)
    for _ in range(300):
        r = system_log.gen()
        t = r['input']
        labeled = {(s, e) for s, e, _ in r['output']['spans']}
        labeled_vals = {t[s:e] for s, e in labeled}
        # loopback must never appear as a positive value
        assert "127.0.0.1" not in labeled_vals
        for s, e, lab in r['output']['spans']:
            v = t[s:e]
            # an ISO timestamp (date or date+clock) is always a decoy, never labeled
            assert not re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.*', v), f"timestamp labeled: {v}"
            assert not re.fullmatch(r'20\d\d-\d\d-\d\d', v), f"bare ISO date labeled: {v}"
            # the dotted-numeric checks must skip ip_address (a public IP is dotted-numeric by design)
            if lab == "ip_address":
                continue
            # a bare numeric run (pid/port/code/latency) is never a positive in this doctype
            assert not re.fullmatch(r'\d+', v), f"bare number labeled: {v}"
            # a version string (semver) is never labeled
            assert not re.fullmatch(r'v?\d+\.\d+\.\d+.*', v), f"version labeled: {v}"


def test_label_set_is_subset_of_doctype_scope():
    """system_log only ever emits these labels (no government_id, payment_card, etc. leaking in)."""
    random.seed(25)
    allowed = {"ip_address", "file_path", "person", "email", "username"}
    seen = set()
    for _ in range(200):
        r = system_log.gen()
        seen |= {lab for _, _, lab in r['output']['spans']}
    assert seen <= allowed, f"unexpected labels: {seen - allowed}"
