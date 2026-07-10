"""Mode-coherence SPEC TABLE -- the executable contract for label x mode redaction policy (lane delta,
2026-07-02 fat-floor incident response).

Live incident (2026-07-02): the GPU NER, out-of-distribution on coding traffic, minted junk INTO floor labels
(whole paths as sensitive_account_id, identifiers as password) -- and because floor privileges are merge-sticky,
un-allowlistable, redacted in 'off' mode, AND withheld from tool-call arguments, an agent received a literal
placeholder as a file path and wrote a junk directory: Write(<SENSITIVEACCOUNTID_004>/bench2.py). The repair
(fat-floor diet: demote_model_floor / uuid demotion / sensitive_ref / path narrowing) re-drew the policy surface,
so this module pins the WHOLE surface as one literal table -- every label x every mode -- instead of the
scattered per-label assertions in test_settings_mode.py. If a future change moves ANY cell, the failing
pytest.param id names the exact label+mode that diverged.

The table encodes the post-diet semantics:
  - FLOOR (deterministic tier-0 provenance or plausibility-vetted model credential ONLY): redacts in every
    mode, never allowlist-exempt, withheld from tool-call arguments (anti-exfiltration).
  - sensitive_date: NEVER redacts at the egress in any mode (wire-level date policy, operator decision
    2026-07-02); GATEWAY_REDACT_DATES=1 is the escape hatch restoring privacy-mode date redaction.
    date_of_birth is floor and unaffected.
  - coding mode additionally passes organization / ip_address / uuid (+ the default 'username' exclude).
  - off mode: floor + user denylist ('custom') only; every soft label passes.
  - soft labels (incl. the demoted 'sensitive_ref' and 'uuid'): allowlist-exemptible, rehydrate in tool args.
  - denylist 'custom': force-redacted in every mode (it only ever ADDS redaction).

HERMETIC by construction (see conftest.py rationale): every policy input egress_proxy reads live -- mode file,
gateway-config.yaml, allowlist/denylist files, REDACT_DATES -- is monkeypatched per test, so a populated
~/.ossredact on a developer box or the operator's live config can neither fail nor (worse) silently pass a cell.
All values synthetic.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy  # noqa: E402
import allowlist as allowlist_mod  # noqa: E402
import denylist as denylist_mod  # noqa: E402
import tool_arg_policy  # noqa: E402
from privacy_gate import FLOOR_LABELS  # noqa: E402


# ----------------------------------------------------------------------------------------------------------
# THE SPEC TABLE. One row per label the appliance can mint; columns = (floor?, redacts-in-privacy,
# redacts-in-coding, redacts-in-off). 'floor?' doubles as the withheld-from-tool-args / never-allowlist-exempt
# column: the three floor privileges are ONE property with ONE membership set (privacy_gate.FLOOR_LABELS ==
# egress FLOOR_NEVER_EXEMPT == tool_arg_policy._FLOOR_CANON), which the structural tests below pin.
# Booleans are written out literally -- no derivation -- so a reviewer can read the whole policy at a glance
# and a diff on this table IS the policy change review.
# ----------------------------------------------------------------------------------------------------------
SPEC_TABLE = [
    # label                    floor  privacy coding  off
    # -- credentials (deterministic secrets_scan floor; model claims survive only the plausibility vet) -----
    ('secret',                 True,  True,   True,   True),
    ('password',               True,  True,   True,   True),
    ('api_key',                True,  True,   True,   True),
    ('access_token',           True,  True,   True,   True),
    # -- payment cards (tier-0 Luhn/cue floor) ---------------------------------------------------------------
    ('payment_card',           True,  True,   True,   True),
    ('card_cvv',               True,  True,   True,   True),
    ('card_expiry',            True,  True,   True,   True),
    # -- bank / account (tier-0 floor; a MODEL claim of these labels demotes to soft 'sensitive_ref') --------
    ('sensitive_account_id',   True,  True,   True,   True),
    ('account_number',         True,  True,   True,   True),
    ('bank_account',           True,  True,   True,   True),
    ('iban',                   True,  True,   True,   True),
    ('routing_number',         True,  True,   True,   True),
    # -- government / identity (tier-0 floor; model claims demote to 'sensitive_ref' likewise) ---------------
    ('government_id',          True,  True,   True,   True),
    ('tax_id',                 True,  True,   True,   True),
    ('date_of_birth',          True,  True,   True,   True),   # floor: NOT covered by the wire-level date pass
    # -- soft PII: redacts in privacy AND coding, passes in off ----------------------------------------------
    ('person',                 False, True,   True,   False),
    ('address',                False, True,   True,   False),
    ('phone_number',           False, True,   True,   False),
    ('email',                  False, True,   True,   False),
    ('postal_code',            False, True,   True,   False),
    ('file_path',              False, True,   True,   False),  # narrowed to the home-dir username upstream
    ('sensitive_ref',          False, True,   True,   False),  # the demoted model bank/account/gov-id claim
    # -- soft PII the coding overlay ALSO passes (org/ip/uuid: load-bearing in agent traffic, RC2/2026-07-02)
    ('organization',           False, True,   False,  False),
    ('ip_address',             False, True,   False,  False),
    ('uuid',                   False, True,   False,  False),  # demoted from the account floor 2026-07-02
    # -- always-pass soft labels ------------------------------------------------------------------------------
    ('username',               False, False,  False,  False),  # DEFAULT_EXCLUDE: low-sensitivity, high-noise
    ('sensitive_date',         False, False,  False,  False),  # wire-level date policy: never redacts at egress
    # -- the user ALWAYS-redact dictionary: force-redacted in every mode (only ever ADDS redaction) ----------
    ('custom',                 False, True,   True,   True),
]

MODES = ('privacy', 'coding', 'off')
_TABLE_BY_LABEL = {row[0]: row for row in SPEC_TABLE}
_MODE_COL = {'privacy': 2, 'coding': 3, 'off': 4}


@pytest.fixture
def policy_env(monkeypatch, tmp_path):
    """Hermetic policy inputs: fresh mode file, ABSENT config (-> DEFAULT_CONFIG), empty allowlist/denylist,
    REDACT_DATES at its default False (it is read from the env at import, so the module attribute -- which
    resolve_pii_policy reads live -- is the correct patch point, same as test_settings_mode). _CONFIG/_CONFIG_MTIME
    are reset because load_config caches the last-read config in module globals: without the reset, a config
    loaded by an EARLIER test module (or the operator's live gateway-config.yaml via GATEWAY_CONFIG) would keep
    resolving here and make cells runner-dependent. Returns a setter: policy_env('coding')."""
    mode_file = tmp_path / 'mode'
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(mode_file))
    monkeypatch.setattr(egress_proxy, 'CONFIG_PATH', str(tmp_path / 'no-such-gateway-config.yaml'))
    monkeypatch.setattr(egress_proxy, '_CONFIG', {})
    monkeypatch.setattr(egress_proxy, '_CONFIG_MTIME', -1)
    allow_file = tmp_path / 'allowlist.txt'
    allow_file.write_text('')
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(allow_file))
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST_MTIME', -1)
    monkeypatch.setattr(egress_proxy, '_ALLOWLIST', set())
    deny_file = tmp_path / 'denylist.txt'
    deny_file.write_text('')
    monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(deny_file))
    monkeypatch.setattr(egress_proxy, '_DENYLIST_SIG', None)
    monkeypatch.setattr(egress_proxy, 'REDACT_DATES', False)

    def set_mode(mode):
        mode_file.write_text(mode + '\n')
    return set_mode


# ---- 1. the matrix: policy_allows_pii over EVERY cell -----------------------------------------------------

def _matrix_cells():
    for label, _floor, privacy, coding, off in SPEC_TABLE:
        for mode, expected in (('privacy', privacy), ('coding', coding), ('off', off)):
            # id names the exact cell so a divergence reads e.g. "uuid-coding-expects-pass" in the report
            yield pytest.param(label, mode, expected,
                               id=f"{label}-{mode}-expects-{'redact' if expected else 'pass'}")


@pytest.mark.parametrize('label,mode,expected', list(_matrix_cells()))
def test_policy_matrix_cell(policy_env, label, mode, expected):
    """Each table cell asserted against the LIVE policy resolution (mode file + DEFAULT_CONFIG + wire-level
    date policy), not against a reimplementation -- so overlay-ordering bugs in resolve_pii_policy fail here."""
    policy_env(mode)
    assert egress_proxy.policy_allows_pii(label, {}) is expected, (
        f'{label} in {mode} mode: expected {"redact" if expected else "pass-through"}')


@pytest.mark.parametrize('mode,expected', [
    pytest.param('privacy', True, id='dates-env-privacy-redacts-again'),
    pytest.param('coding', False, id='dates-env-coding-still-passes'),
    pytest.param('off', False, id='dates-env-off-still-passes'),
])
def test_redact_dates_escape_hatch(policy_env, monkeypatch, mode, expected):
    """GATEWAY_REDACT_DATES=1 restores ONLY the old privacy-mode date redaction; the coding overlay and 'off'
    keep passing dates (RC5: semver/timestamps are indistinguishable from dates by value). The floor row
    date_of_birth must be indifferent to the hatch in both positions -- it is not a 'date' category member."""
    monkeypatch.setattr(egress_proxy, 'REDACT_DATES', True)
    policy_env(mode)
    assert egress_proxy.policy_allows_pii('sensitive_date', {}) is expected
    assert egress_proxy.policy_allows_pii('date_of_birth', {}) is True


# ---- 2. tool-arg withholding: is_floor_placeholder over every label's placeholder forms --------------------

def _mint_forms(label):
    """Both live mint shapes for a label: the appliance entity-map form strips non-alnum ('sensitive_account_id'
    -> <SENSITIVEACCOUNTID_001>, exactly entity_map.placeholder_for's re.sub) and the gate form keeps internal
    underscores (<SENSITIVE_ACCOUNT_ID_001>). The 2026-07-02 incident placeholder was the appliance form;
    tool_arg_policy canonicalizes both via _label_key, and this test proves neither shape escapes the predicate."""
    appliance = re.sub(r'[^A-Z0-9]', '', label.upper()) or 'PII'
    gate = label.upper()
    return sorted({f'<{appliance}_001>', f'<{gate}_001>'})


@pytest.mark.parametrize('label,floor', [
    pytest.param(row[0], row[1], id=f"{row[0]}-{'withheld' if row[1] else 'rehydrates'}")
    for row in SPEC_TABLE])
def test_tool_arg_withholding_matches_floor_column(label, floor):
    """A placeholder is withheld from EXECUTED tool arguments exactly when its label sits in a floor row --
    soft labels (incl. sensitive_ref/uuid/file_path) MUST rehydrate there, or the agent writes junk paths
    again (the Write(<SENSITIVEACCOUNTID_004>/bench2.py) failure class). 'custom' rehydrates: the denylist
    guards outbound redaction, not tool-arg exfiltration (its values are user-chosen terms, not credentials)."""
    for ph in _mint_forms(label):
        assert tool_arg_policy.is_floor_placeholder(ph) is floor, ph


def test_tool_arg_replay_suppresses_floor_rows_plus_sensitive_ref(monkeypatch):
    """Whole-map check: tool_arg_replay drops the floor rows' placeholders PLUS 'sensitive_ref' -- the
    demoted model-identity label keeps the one floor privilege that is pure downside-protection (stay
    literal in executed tool args, anti-exfil; adversarial review 2026-07-02) -- and ONLY those. Synthetic
    values here are neither UUID- nor path-shaped, so the identity-class value-shape migration exceptions
    (covered in test_floor_diet) do not fire. Strict mode is a separate opt-in knob; pin the env off."""
    monkeypatch.delenv('GATEWAY_TOOL_ARG_STRICT', raising=False)
    replay, withheld_phs = {}, set()
    for i, (label, floor, *_rest) in enumerate(SPEC_TABLE):
        ph = f"<{re.sub(r'[^A-Z0-9]', '', label.upper())}_{i + 1:03d}>"
        replay[ph] = f'synthetic-{label}'
        if floor or label == 'sensitive_ref':
            withheld_phs.add(ph)
    out = tool_arg_policy.tool_arg_replay(replay)
    assert set(replay) - set(out) == withheld_phs


def test_tool_arg_unparseable_placeholder_fails_closed():
    """Defensive contract: an unparseable token is treated as floor (withheld). '<EMAIL_01>' has only two
    counter digits -- outside the \\d{3,} contract -- so it must NOT parse into a rehydratable soft label."""
    assert tool_arg_policy.is_floor_placeholder('not-a-placeholder') is True
    assert tool_arg_policy.is_floor_placeholder('<EMAIL_01>') is True


# ---- 3. allowlist exemption: soft labels only (apply_allowlist floor guard) --------------------------------

@pytest.mark.parametrize('label,floor', [
    pytest.param(row[0], row[1], id=f"{row[0]}-{'never-exempt' if row[1] else 'exemptible'}")
    for row in SPEC_TABLE if row[0] != denylist_mod.DENY_LABEL])
def test_allowlist_exemption_soft_labels_only(label, floor):
    """The user do-not-redact dictionary drops a span ONLY when its label is soft: declaring the exact text of
    a floor value safe must never work (no legitimate 'allowlist my own credit card' use case; fail-closed).
    Asserted against the shared apply_allowlist (the guard is baked into the filter, not left to callers)."""
    text = 'synthetic-allow-me'
    spans = [{'start': 0, 'end': len(text), 'label': label}]
    allow = allowlist_mod.build_allow_set([text])
    kept = allowlist_mod.apply_allowlist(spans, text, allow)
    if floor:
        assert kept == spans, f'floor label {label} must survive an exact-text allowlist hit'
    else:
        assert kept == [], f'soft label {label} must be exemptible by an exact-text allowlist hit'


def test_denylist_custom_force_redacts_in_every_mode(policy_env):
    """The 'custom' spec row's never-exempt guarantee lives at TWO enforcement points, neither of which is
    apply_allowlist (hence its exclusion from the parametrization above): (1) policy_allows_pii force-redacts
    DENY_LABEL in every mode -- asserted here; (2) process_field injects denylist spans AFTER its allowlist
    filter, so an always-redact term wins over a do-not-redact one by construction (see the dspans comment in
    egress_proxy.process_field). Note the shared apply_allowlist helper alone would NOT protect a 'custom'
    span ('custom' is not in FLOOR_LABELS); today no appliance path routes denylist spans through it."""
    for mode in MODES:
        policy_env(mode)
        assert egress_proxy.policy_allows_pii(denylist_mod.DENY_LABEL, {}) is True, mode


# ---- 4. structural consistency: the table and the code share ONE membership reality ------------------------

def test_floor_rows_are_exactly_FLOOR_LABELS():
    """The table's floor column IS privacy_gate.FLOOR_LABELS -- no label may hold floor privileges (merge
    stickiness, never-exempt, every-mode redaction, tool-arg withholding) without a row here, and vice versa.
    This is the check that would have flagged the pre-2026-07-01 account_number floor-parity hole."""
    assert {row[0] for row in SPEC_TABLE if row[1]} == set(FLOOR_LABELS)


def test_floor_membership_single_source_of_truth():
    """The three floor privilege sets must be the SAME set object/derivation: egress FLOOR_NEVER_EXEMPT is
    privacy_gate.FLOOR_LABELS, and tool_arg_policy's canonical key set is derived from it 1:1."""
    assert egress_proxy.FLOOR_NEVER_EXEMPT is FLOOR_LABELS
    expected_canon = {re.sub(r'[^a-z0-9]', '', lbl.casefold()) for lbl in FLOOR_LABELS}
    assert tool_arg_policy._FLOOR_CANON == expected_canon


def test_table_covers_every_category_label_and_nothing_unknown():
    """Completeness both ways: every CATEGORY_LABELS label has a spec row (a new category cannot ship without
    declaring its mode behavior here), and every row is a label the code actually knows -- a category label,
    a credential floor label (credentials live outside CATEGORY_LABELS; they are secrets, not policy-tunable
    PII), or the denylist label. A typo'd row fails instead of silently asserting a nonexistent label."""
    table_labels = {row[0] for row in SPEC_TABLE}
    category_labels = {lab for labs in egress_proxy.CATEGORY_LABELS.values() for lab in labs}
    assert category_labels <= table_labels, category_labels - table_labels
    known = category_labels | set(FLOOR_LABELS) | {denylist_mod.DENY_LABEL}
    assert table_labels <= known, table_labels - known


def test_no_coding_excluded_category_contains_a_floor_label(policy_env):
    """The coding overlay works by CATEGORY exclusion, so a floor label sharing a category with a passed soft
    label would be silently released in coding mode (the exact fat-floor coupling that motivated demoting
    'uuid' out of 'account' instead of excluding 'account'). Assert against the LIVE resolved coding policy,
    not a hardcoded list, so any future overlay extension is re-checked automatically. (policy_allows_pii
    short-circuits on FLOOR_NEVER_EXEMPT anyway -- defense in depth -- but category hygiene keeps the exclude
    semantics honest rather than relying on the short-circuit.)"""
    policy_env('coding')
    pol = egress_proxy.resolve_pii_policy({})
    for cat in pol.get('exclude') or []:
        labs = set(egress_proxy.CATEGORY_LABELS.get(cat, [cat]))
        assert not (labs & set(FLOOR_LABELS)), (cat, labs & set(FLOOR_LABELS))


def test_mode_overlay_exclude_sets_are_exact(policy_env):
    """Pin the resolved overlay wholesale: privacy excludes exactly {username, date} (the default exclude +
    the wire-level date policy), coding adds exactly {org, ip, uuid}, off flips enabled False. A stray
    category creeping into (or out of) an overlay moves a matrix cell above AND this set -- two independent
    failure signatures for the morning review."""
    policy_env('privacy')
    pol = egress_proxy.resolve_pii_policy({})
    assert pol.get('enabled', True) is True
    assert set(pol.get('exclude') or []) == {'username', 'date'}
    policy_env('coding')
    pol = egress_proxy.resolve_pii_policy({})
    assert pol.get('enabled', True) is True
    assert set(pol.get('exclude') or []) == {'username', 'date', 'org', 'ip', 'uuid'}
    policy_env('off')
    pol = egress_proxy.resolve_pii_policy({})
    assert pol.get('enabled', True) is False
