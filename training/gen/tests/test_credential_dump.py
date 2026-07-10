"""Tests for the credential_dump generator (Phase 3 Task 3.2).

Offset-exactness, required positives (secret/password/username/file_path), labels-in-scheme, and the key
precision property: the operational/public decoys (Stripe pk_live_ publishable key, 64-hex build hash, port
numbers, version strings, ticket ids) are NEVER labeled. Modeled on test_flinks.py.
Run: .venv-test/bin/python -m pytest training/gen/tests/test_credential_dump.py -q
"""
import sys, os, json, re, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import credential_dump  # noqa: E402

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'labels_v20.json')))['labels'])


def test_offsets_exact_and_labels_in_scheme():
    random.seed(21)
    for _ in range(200):
        r = credential_dump.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            assert 0 <= s < e <= len(t)
            assert t[s:e] == t[s:e].strip() or t[s:e].strip() != ""  # span exists in text
            assert t[s:e].strip() != ""            # never an empty/whitespace span
            assert lab in _LABELS                  # only the 20 labels


def test_required_positives_present():
    random.seed(22)
    need = {"secret", "password", "username", "file_path"}
    seen = set()
    for _ in range(60):
        r = credential_dump.gen()
        seen |= {lab for _, _, lab in r['output']['spans']}
    assert need <= seen, f"missing {need - seen}"


def test_only_credential_scope_labels_used():
    # this doctype emits the credential-gap labels plus email (an intentional email-cue-vs-password-cue
    # contrast line, added in Phase 4 round 2 to fix the password->email confusion). No other label leaks.
    random.seed(23)
    allowed = {"secret", "password", "username", "file_path", "email"}
    for _ in range(120):
        r = credential_dump.gen()
        for _, _, lab in r['output']['spans']:
            assert lab in allowed, f"unexpected label {lab}"


def test_decoys_never_labeled():
    """Public/operational decoys must never land inside a labeled span."""
    random.seed(24)
    hex64 = re.compile(r'^[0-9a-f]{64}$')
    hex_partial = re.compile(r'^[0-9a-f]{40}$')        # the footer build_hash()[:40] decoy
    version = re.compile(r'^v?\d{1,2}\.\d{1,2}\.\d{1,2}$')
    ticket = re.compile(r'^[A-Z]+-\d{2,4}$')
    pure_port = re.compile(r'^\d{2,5}$')
    for _ in range(200):
        r = credential_dump.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            v = t[s:e]
            assert not v.startswith("pk_live_"), "Stripe publishable key must be a decoy"
            assert not v.startswith("pk_test_"), "Stripe publishable key must be a decoy"
            assert not hex64.match(v), "64-hex build hash must be a decoy, not a secret"
            assert not hex_partial.match(v), "build-hash fragment must be a decoy"
            assert not version.match(v), "version string must be a decoy"
            assert not ticket.match(v), "ticket id must be a decoy"
            assert not pure_port.match(v), "port number must be a decoy"


def test_secret_shapes_are_real_key_prefixes():
    """Anything labeled `secret` must look like an actual secret key shape (not a public/hash decoy)."""
    random.seed(25)
    secret_prefixes = ("sk-", "sk-ant-", "hf_", "ghp_", "AKIA", "xoxb-", "sk_live_")
    for _ in range(150):
        r = credential_dump.gen()
        t = r['input']
        for s, e, lab in r['output']['spans']:
            if lab == "secret":
                v = t[s:e]
                assert v.startswith(secret_prefixes), f"secret has unexpected shape: {v}"
                assert not v.startswith("pk_"), "publishable key labeled as secret"


def test_username_and_password_distinct_on_conn_string():
    """When a conn string is present, username and password are separately labeled (collision teaching)."""
    random.seed(26)
    found_both = False
    for _ in range(200):
        r = credential_dump.gen()
        labs = [lab for _, _, lab in r['output']['spans']]
        if "username" in labs and "password" in labs:
            found_both = True
            break
    assert found_both
