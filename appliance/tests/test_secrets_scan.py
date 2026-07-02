"""Behavioral coverage for the deterministic secret floor (appliance/secrets_scan.py).

This is the ALWAYS-on, model-free credential detector -- the single most security-critical piece of the
firewall. It had zero behavioral tests; this file pins (a) every provider shape fires, (b) the context
rules (conn-string password, generic key=value) fire on real shapes, (c) the entropy backstop catches a
bare AWS-secret-shaped blob, and (d) the false-positive filters (git SHA, UUID, all-digit, sequential)
do NOT nuke benign tokens -- the regression that would break the coding-assistant use case.

All tokens here are SYNTHETIC shapes (fake values that merely match the regexes), never real keys.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from secrets_scan import secret_spans, is_benign_token, shannon, _is_sequential  # noqa: E402


def _hits(text, **kw):
    """Set of detected substrings."""
    return {text[s['start']:s['end']] for s in secret_spans(text, **kw)}


def _detected(text, token, **kw):
    return token in _hits(text, **kw)


# ---------------------------------------------------------------------------
# (a) every high-precision provider shape fires
# ---------------------------------------------------------------------------
def test_aws_access_key():
    tok = 'AKIA' + 'IOSFODNN7EXAMPLE'          # AKIA + 16 [0-9A-Z]
    assert _detected(f'export AWS_KEY={tok} done', tok)


def test_gcp_api_key():
    tok = 'AIza' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r'  # AIza + 35
    assert len(tok) == 4 + 35
    assert _detected(f'key {tok}', tok)


def test_github_token():
    tok = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'  # ghp_ + 36
    assert _detected(f'token {tok} here', tok)


def test_github_pat():
    tok = 'github_pat_' + 'A1b2C3d4E5f6G7h8I9j0K1'  # github_pat_ + 22
    assert _detected(f'{tok}', tok)


def test_slack_token():
    tok = 'xoxb-' + 'A1b2C3d4E5f6'
    assert _detected(f'slack {tok}', tok)


def test_stripe_secret_key():
    tok = 'sk_live_' + 'A1b2C3d4E5f6G7h8'
    assert _detected(f'stripe {tok}', tok)


def test_openai_key():
    tok = 'sk-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'  # 24
    assert _detected(f'openai {tok}', tok)


def test_openai_proj_key():
    tok = 'sk-proj-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'
    assert _detected(f'openai {tok}', tok)


def test_anthropic_key():
    tok = 'sk-ant-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'
    assert _detected(f'claude {tok}', tok)


def test_google_oauth():
    tok = 'ya29.' + 'A1b2C3d4E5f6G7h8I9j0K1l2'
    assert _detected(f'oauth {tok}', tok)


def test_jwt():
    tok = 'eyJ' + 'A1b2C3d4E5' + '.eyJ' + 'A1b2C3d4E5' + '.' + 'A1b2C3d4E5'
    assert _detected(f'auth {tok}', tok)


def test_private_key_block():
    block = ('-----BEGIN PRIVATE KEY-----\n'
             'MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8FAKEKEYBODYabcdefghij\n'
             '-----END PRIVATE KEY-----')
    hits = _hits(f'key:\n{block}\n')
    assert any('BEGIN PRIVATE KEY' in h and 'END PRIVATE KEY' in h for h in hits)


# ---------------------------------------------------------------------------
# (b) context rules: connection-string password + generic key=value
# ---------------------------------------------------------------------------
def test_conn_string_flags_password_group_only():
    text = 'DATABASE_URL=postgres://dbuser:Sup3rSecretPw@db.host:5432/app'
    assert _detected(text, 'Sup3rSecretPw')          # the password is flagged
    assert not _detected(text, 'dbuser')             # the username is not


def test_generic_assign_snake_case_cue():
    # the cue `secret` is glued inside JWT_SECRET -- the \b-less rule must still fire
    assert _detected('JWT_SECRET=Sup3rSecretValue123', 'Sup3rSecretValue123')


def test_generic_assign_quoted_value():
    assert _detected("api_key = 'Ab12Cd34Ef56Gh78'", 'Ab12Cd34Ef56Gh78')


def test_generic_assign_ignores_short_value():
    # value-shape gate: < 8 opaque chars is not flagged (avoids nuking ordinary config)
    assert not _detected('token = abc', 'abc')


def test_non_secret_assignment_not_flagged():
    # no secret cue -> ordinary code/config assignment must never be flagged
    assert _hits('name = "Alex Martin"') == set()
    assert _hits('count = 42') == set()


# ---------------------------------------------------------------------------
# (c) entropy backstop: bare AWS-secret-shaped 40-char blob
# ---------------------------------------------------------------------------
def test_entropy_backstop_catches_high_entropy_blob():
    tok = 'wJalrXUtnFEMI4K7MDENGbPxRfiCYzEXAMPLEKEY'  # 40 chars, high entropy, not hex-only
    assert len(tok) == 40
    assert shannon(tok) >= 4.2
    assert _detected(f'secret={tok}', tok)


def test_entropy_backstop_can_be_disabled():
    tok = 'wJalrXUtnFEMI4K7MDENGbPxRfiCYzEXAMPLEKEY'
    # with the backstop off, a bare blob with no provider prefix / cue is not flagged
    assert not _detected(f'blob {tok}', tok, entropy_backstop=False)


# ---------------------------------------------------------------------------
# (d) false-positive filters: benign tokens must NOT be flagged (coding use case)
# ---------------------------------------------------------------------------
def test_git_sha40_not_flagged():
    sha = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b'  # 40 lowercase hex = commit/content hash
    assert len(sha) == 40
    assert is_benign_token(sha)
    assert not _detected(f'commit {sha} is fine', sha)


def test_git_sha256_not_flagged():
    sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # 64 hex
    assert is_benign_token(sha)
    assert not _detected(f'hash {sha}', sha)


def test_uuid_not_flagged_as_secret():
    uuid = 'ea36fc28-1234-4abc-9def-0123456789ab'
    assert is_benign_token(uuid)
    assert not _detected(f'id {uuid}', uuid)


def test_all_digit_blob_not_flagged():
    blob = '1234567890' * 4  # 40 digits
    assert is_benign_token(blob)
    assert not _detected(f'num {blob}', blob)


def test_sequential_token_filtered():
    assert _is_sequential('abcdefghij')
    assert is_benign_token('abcdefghij')


def test_two_char_token_filtered():
    assert is_benign_token('ababababababababababababababababababab')


# ---------------------------------------------------------------------------
# (d) launch-audit coverage gaps: GCP-under-underscore, npm, pypi, PGP BLOCK
# ---------------------------------------------------------------------------
def test_gcp_key_caught_even_glued_after_underscore():
    tok = 'AIzaSyB1234567890abcdefghijklmnopqrstuv'  # AIza + 35
    assert _detected(f'key={tok}', tok)                       # bare
    assert _detected(f'GOOGLE_API_KEY_{tok}_v2', tok)         # glued inside an identifier (the old \\b missed this)


def test_npm_token_caught():
    tok = 'npm_' + 'abcdefghijklmnopqrstuvwxyz0123456789'    # npm_ + 36
    assert _detected(f'//registry.npmjs.org/:_authToken={tok}', tok)


def test_pypi_token_caught():
    tok = 'pypi-AgEIcHlwaS5vcmcCJD00' + 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'
    assert _detected(f'TWINE_PASSWORD={tok}', tok)


def test_pgp_private_key_block_caught():
    pem = '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF...redacted...==\n-----END PGP PRIVATE KEY BLOCK-----'
    sp = secret_spans(pem)
    assert sp and sp[0]['subtype'] == 'private_key_block'


def test_plain_rsa_private_key_still_caught():
    pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...x...==\n-----END RSA PRIVATE KEY-----'
    sp = secret_spans(pem)
    assert sp and sp[0]['subtype'] == 'private_key_block'


def test_french_credential_keywords_fire():
    # FR-first product: French password/secret assignment forms must redact the value (synthetic shapes).
    assert _hits("motdepasse=Ete2024SoleilX") == {"Ete2024SoleilX"}
    assert _hits("mot_de_passe: Xy7kLp9qrabc") == {"Xy7kLp9qrabc"}
    assert _hits("mdp=Tr3mblayX2024") == {"Tr3mblayX2024"}
    assert _hits("jeton=abc123XYZ789tok") == {"abc123XYZ789tok"}
    assert _hits("cle_api=sk9f8a7b6c5d4e3f2a") == {"sk9f8a7b6c5d4e3f2a"}


def test_french_keywords_do_not_overredact_benign_prose():
    # ordinary French prose with a short low-entropy token must NOT be flagged
    assert _hits("le nom du chat est minou123 hihi") == set()
    assert _hits("la date limite est 2024-01-01 environ") == set()


def test_header_space_delimited_tokens_fire():
    # opaque bearer/token/apikey/basic in HTTP-header / curl / log form (no '='/':' delimiter)
    assert _hits("Authorization: Bearer tGzv3JOkF0XG5Qx2TlKWIA") == {"tGzv3JOkF0XG5Qx2TlKWIA"}
    assert _hits("apikey deadbeefcafe1234567890abcdef9876543210fedcba") == {"deadbeefcafe1234567890abcdef9876543210fedcba"}
    assert _hits("X-Auth-Token: AbCd1234EfGh5678IjKl9012MnOp") == {"AbCd1234EfGh5678IjKl9012MnOp"}
    assert _hits("Basic dXNlcjpwYXNzd29yZDEyMzQ1") == {"dXNlcjpwYXNzd29yZDEyMzQ1"}


def test_twilio_key_fires():
    assert _hits("api key SK1234567890abcdef1234567890abcdef live") == {"SK1234567890abcdef1234567890abcdef"}


def test_auth_keywords_do_not_overredact_prose():
    # keyword followed by ordinary prose (short next token, or spaces) must NOT fire
    assert _hits("the api key generation process is documented") == set()
    assert _hits("he was the flag bearer of bad news today") == set()
    assert _hits("token expiration handling needs review") == set()
    assert _hits("SKU12345678 is the product code") == set()


def test_glued_provider_secrets():
    # specific-prefix keys catch even when glued to surrounding word chars
    assert _hits("tokenghp_16C7e42F292c6912E7710c838347Ae178B4axyz") == {"ghp_16C7e42F292c6912E7710c838347Ae178B4axyz"}
    assert "AKIAIOSFODNN7EXAMPLE" in _hits("my AKIAIOSFODNN7EXAMPLExyz key")


def test_sk_prefix_keys_stay_bounded_no_fp():
    # sk-/rk_ prefixes are common inside words (task-, risk-); must NOT false-positive
    assert _hits("the task-master-flow-handler-1234 runs") == set()
    assert _hits("at risk-management-2024-planning now") == set()


def test_conn_string_at_in_password():
    assert _hits("postgres://admin:S3cr3tP@ssw0rd!xy@db.host:5432/app") == {"S3cr3tP@ssw0rd!xy"}
    assert _hits("mysql://u:simplepass@localhost/db") == {"simplepass"}


def test_code_expression_values_are_not_secrets():
    """generic_assign FP (live incident 2026-07-02): a cue-bearing IDENTIFIER assigned a CALL or SUBSCRIPT
    expression minted a code fragment as a floor secret (`_NUM_SECRET_RE = re.compile(r'...` -> `re.compile(r`),
    which then broke tool-arg rehydration for every later edit of the source line. A dotted identifier
    immediately opening `(` / `[` is code, never a credential."""
    assert _hits("_NUM_SECRET_RE = re.compile(r'(?i)pin')") == set()
    assert _hits("API_KEY_RE = re.compile(r'aki[a-z]+')") == set()
    assert _hits("SECRET_MAP = config[env_name] or default") == set()
    assert _hits("token = base64.b64encode(payload)") == set()
    assert _hits("client_secret = os.environ.get('CS')") == set()


def test_code_expression_veto_does_not_weaken_real_secrets():
    # values merely containing parens/brackets elsewhere stay eligible...
    assert _hits("password = P@ss(word)1x") == {"P@ss(word)1x"}
    # ...and ordinary opaque assignments still fire
    assert _hits("JWT_SECRET=v8Xq2mZk9TbL4nRw") == {"v8Xq2mZk9TbL4nRw"}
    assert _hits("mot_de_passe: 'Tr0ub4dor&3xyz'") == {"Tr0ub4dor&3xyz"}


def test_cued_dotted_secret_keeps_floor_only_call_shape_vetoed():
    """Re-review 2026-07-02: the deterministic generic_assign floor must NOT be weakened for a bare dotted /
    constant value after a credential cue -- only the unambiguous call/subscript shape is vetoed. A real
    dotted API token (SG.aB3c...) was leaking; it floors again."""
    assert _hits("api_key = SG.aB3cD4eF.gH5iJ6kL") == {"SG.aB3cD4eF.gH5iJ6kL"}
    assert _hits("apikey=v1abc.def456.ghi789xyz") == {"v1abc.def456.ghi789xyz"}
    assert _hits("secret = a1b2c3.d4e5f6xyz") == {"a1b2c3.d4e5f6xyz"}
    # the actual incident shape (call/subscript) is still vetoed
    assert _hits("_NUM_SECRET_RE = re.compile(r'(?i)pin')") == set()
    assert _hits("SECRET_MAP = config[env_name] or default") == set()
