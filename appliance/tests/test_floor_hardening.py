"""Floor-hardening regression tests -- locks the six hard-floor bypasses found + fixed by the 2026-06-20
adversarial stress sweep (workflow wvhp4xiyl, 21 confirmed leaks). Each must STAY closed.

Torch-free: exercises the deterministic Tier-0 floor (privacy_gate), the secret floor (secrets_scan), the
always-redact denylist, and the egress sensitive-NAMED-key force-redaction directly -- no model, no network.
Run: .venv-test/bin/python -m pytest appliance/tests/test_floor_hardening.py -q
"""
import json
import os
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import privacy_gate as pg          # noqa: E402
import secrets_scan                # noqa: E402
import denylist as dl              # noqa: E402
import egress_proxy as ep          # noqa: E402

ZW = '​'  # zero-width space


def _covers(text, val):
    """A Tier-0 span masks `val` if some span's [start,end) over the ORIGINAL text contains the value (after
    stripping the interleaved Cf chars so a zero-width-broken value still counts)."""
    for s in pg.tier0_spans(text):
        seg = text[s['start']:s['end']]
        if val in seg or val in pg._strip_format_chars(seg)[0]:
            return True
    return False


# ---- RC3: zero-width / format-char interleaving must not bypass the digit/IBAN/secret floor --------------
def test_rc3_zero_width_card_iban_govid_caught():
    assert _covers('Card ' + ZW.join('4111111111111111') + ' end.', '4111111111111111')
    assert _covers('IBAN ' + ZW.join('FR7630006000011234567890189') + '.', 'FR7630006000011234567890189')
    assert _covers('NAS ' + ZW.join('046454286') + '.', '046454286')


def test_rc3_all_format_codepoints():
    for zwc in ('​', '‌', '‍', '⁠', '­'):  # ZWSP ZWNJ ZWJ WORD-JOINER SOFT-HYPHEN
        assert _covers('Card ' + zwc.join('4111111111111111') + '.', '4111111111111111'), zwc


def test_rc3_zero_width_secret_caught():
    sk = 'sk-test-1234567890abcdefABCDEF'
    spans = secrets_scan.secret_spans('api_key = "' + ZW.join(sk) + '"')
    assert any(sk in s_text or sk in pg._strip_format_chars(s_text)[0]
               for s_text in [('api_key = "' + ZW.join(sk) + '"')[s['start']:s['end']] for s in spans])


# ---- RC2: glued SIN -- Luhn-precise (catches the real SIN, rejects code identifiers) ---------------------
def test_rc2_glued_luhn_sin_caught():
    # 046454286 is a Luhn-valid 9-digit SIN; glued to a word it must still be caught (government_id floor)
    assert _covers('JaneDoe046454286', '046454286')
    assert _covers('X046454286', '046454286')
    assert any(s['rule'] == 'tier0:digit_glued' and s['label'] == 'government_id'
               for s in pg.tier0_spans('JaneDoe046454286'))


def test_rc2_glued_does_not_over_redact_code():
    # the FP regression the naive glued rule caused: code identifiers with embedded digit runs must NOT redact
    for t in ('translateY(123456789px)', 'seed1234567890', 'createdAt1700000000', 'user000123456789', 'x123456789y'):
        assert not any(s['rule'] == 'tier0:digit_glued' for s in pg.tier0_spans(t)), t


def test_rc2_cued_account_caught_glued():
    # a non-Luhn account glued to a CUE word is still caught (context_cued, now 9-19 digits)
    assert _covers('account 0781234567', '0781234567')


def test_rc2_business_number_not_mislabeled_sin():
    # a 9-digit Luhn run + RT/RP program-account suffix is a GST/QST Business Number, NOT a SIN -- the glued
    # rule must suppress it (parity with the clean DIGIT_RUN path + the gate), UNLESS a SIN cue forces it.
    assert not any(s['rule'] == 'tier0:digit_glued' for s in pg.tier0_spans('046454286RT0001'))
    assert _covers('SIN 046454286', '046454286')  # the real SIN is still caught


# ---- RC2b: separator-class bypasses (TAB/control whitespace, dot-grouped) --------------------------------
def test_rc2b_control_whitespace_separators_caught():
    for sep in ('\t', '\x0b', '\x0c', '\r', '\n', '\x1c', '\x1f'):
        assert _covers('card ' + sep.join('4111111111111111'), '4111111111111111'), repr(sep)
    assert _covers('SIN ' + '\t'.join('046454286'), '046454286')


def test_rc2b_dot_grouped_card_and_ssn_caught():
    assert _covers('my card is 4111.1111.1111.1111 thanks', '4111.1111.1111.1111')
    assert _covers('SSN 123.45.6789 on file', '123.45.6789')


def test_rc2b_dotted_card_is_luhn_gated():
    # a NON-Luhn 4-4-4-4 dotted run is not a card -> must not be promoted by the separated-card rule
    assert not any(s['rule'] == 'tier0:card_sep' for s in pg.tier0_spans('build 1234.5678.9012.3456 ok'))


# ---- RC2c: Unicode No-category digits (super/subscript) + percent-encoded separators -------------------
def _sup(d):
    return ''.join({'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵',
                    '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}[c] for c in d)


def test_rc2c_superscript_digit_card_caught():
    # superscript digits are Unicode category No; \d misses them, but _normdigits folds them to ASCII so the
    # full digit floor engages (NFKC-reconstructable card must not leave verbatim).
    sup = _sup('4111111111111111')
    assert _covers('card ' + sup, sup)
    assert any(s['label'] == 'payment_card' for s in pg.tier0_spans('card ' + sup))


def test_rc2c_percent_encoded_space_card_caught():
    card = '4111%201111%201111%201111'   # urllib.parse.quote('4111 1111 1111 1111')
    assert _covers('card=' + card, card)
    assert any(s['label'] == 'payment_card' and s['rule'] == 'tier0:card_sep' for s in pg.tier0_spans('card=' + card))


# ---- RC1: card_cvv + card_expiry now have a deterministic, cue-anchored Tier-0 floor --------------------
def test_rc1_cvv_caught_with_cue():
    for t, v in [('security code 123', '123'), ('cvc: 123', '123'),
                 ('My card is 4111111111111111, cvv 123, expiry 08/27', '123')]:
        assert any(s['label'] == 'card_cvv' and pg._normseps(t)[s['start']:s['end']] == v
                   for s in pg.tier0_spans(t)), t


def test_rc1_expiry_caught_with_cue():
    for t, v in [('expiry 08/27', '08/27'), ('Pay with 5555555555554444 exp 12/2026 cvc 4827', '12/2026')]:
        assert any(s['label'] == 'card_expiry' and v in pg._normseps(t)[s['start']:s['end']]
                   for s in pg.tier0_spans(t)), t


def test_rc1_bare_digits_without_cue_not_redacted():
    # the CVV/expiry rules are cue-anchored: a stray 3-digit number or generic date must NOT blanket-redact
    assert not any(s['label'] == 'card_cvv' for s in pg.tier0_spans('there were 123 results'))
    assert not any(s['label'] == 'card_expiry' for s in pg.tier0_spans('the meeting is 08/27'))


# ---- RC6: NFD-normalized denylist term still matched -----------------------------------------------------
def test_rc6_nfd_denylist_term_caught():
    pat = dl.compile_denylist(['café-secret', 'Bluebird'])
    nfd = unicodedata.normalize('NFD', 'The café-secret recipe.')
    spans = dl.find_spans(nfd, pat)
    assert spans, 'NFD-encoded term must match'
    assert unicodedata.normalize('NFC', nfd[spans[0]['start']:spans[0]['end']]).lower() == 'café-secret'


def test_rc6_denylist_boundary_still_respected():
    pat = dl.compile_denylist(['cafe-secret'])
    assert dl.find_spans('cafe-secretly is fine', pat) == []


# ---- RC4 / RC5 / [14]: sensitive-NAMED-key force-redaction (incl. card keys + JSON-string tool args) -----
class _FakeMap:
    """Minimal EntityMap stand-in: deterministic placeholder per value (enough to assert force-redaction)."""
    def __init__(self):
        self._n = {}

    def placeholder_for(self, value, label):
        key = label.upper().replace('_', '')
        self._n.setdefault(key, 0)
        self._n[key] += 1
        return f'<{key}_{self._n[key]:03d}>', value


def test_rc5_mdp_card_keys_force_redacted_by_label():
    node = {'mdp': 'MotDePasse#2024Quebec', 'card_expiry': '11/29', 'cvv': '123',
            'access_token': 'opaqueTOKENvalue1234567abcXYZ'}
    n = ep.force_redact_secret_keys(node, _FakeMap())
    assert n == 4
    assert node['mdp'].startswith('<SECRET') and node['access_token'].startswith('<SECRET')
    assert node['card_expiry'].startswith('<CARDEXPIRY') and node['cvv'].startswith('<CARDCVV')
    assert 'MotDePasse#2024Quebec' not in json.dumps(node)
    assert '11/29' not in json.dumps(node) and '123' not in json.dumps(node)


def test_rc4_json_string_tool_args_descended():
    # OpenAI tool_calls.arguments is JSON-in-a-string; an opaque credential under a secret key inside must redact
    args = json.dumps({'access_token': 'opaqueTOKENvalue1234567abcXYZ', 'note': 'hello'})
    node = {'tool_calls': [{'function': {'name': 'f', 'arguments': args}}]}
    n = ep.force_redact_secret_keys(node, _FakeMap())
    assert n == 1
    assert 'opaqueTOKENvalue1234567abcXYZ' not in json.dumps(node)
    # the args remain valid JSON and the non-secret field is untouched
    reparsed = json.loads(node['tool_calls'][0]['function']['arguments'])
    assert reparsed['note'] == 'hello' and reparsed['access_token'].startswith('<SECRET')


def test_keyed_redaction_leaves_non_sensitive_untouched():
    node = {'username': 'alice', 'note': 'a benign note', 'count': 5}
    n = ep.force_redact_secret_keys(node, _FakeMap())
    assert n == 0 and node == {'username': 'alice', 'note': 'a benign note', 'count': 5}


# ---- Codex ChatGPT-PLAN path: identity/routing headers must survive forwarding (else plan auth is rejected) -
class _FakeHeaders:
    def __init__(self, d):
        self._d = d

    def items(self):
        return self._d.items()


class _FakeReq:
    def __init__(self, headers):
        self.headers = _FakeHeaders(headers)


def test_codex_plan_routing_headers_forwarded():
    import responses_adapter as ra
    req = _FakeReq({
        'authorization': 'Bearer oauth-token', 'content-type': 'application/json',
        'chatgpt-account-id': 'acct-uuid', 'originator': 'codex_cli_rs', 'session_id': 'sess-1',
        'openai-beta': 'responses=experimental',
        'cookie': 'do-not-forward', 'x-evil': 'nope',
    })
    fwd = ra.fwd_headers_responses(req)
    # the ChatGPT-plan path needs these to authorize plan usage at the backend
    for h in ('authorization', 'chatgpt-account-id', 'originator', 'session_id', 'openai-beta'):
        assert h in fwd, f'{h} must forward for the Codex plan path'
    # anything not on the allowlist is still stripped (no cookie / arbitrary header leakage)
    assert 'cookie' not in fwd and 'x-evil' not in fwd
