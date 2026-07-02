"""Floor tests for the DEPLOYED appliance gate (appliance/privacy_gate.py tier0_spans).

Validates two backports made off-prod (the live redeploy is a separate, operator-gated step):
  - F14: the IBAN mod-97 deterministic backstop (the deployed floor previously had NO IBAN catch).
  - Finding A: Canadian Business Number suppression + SIN-cue override.

Torch-free (regex only). 100% synthetic / public ISO + Luhn test vectors; no real PII.
Loaded by explicit path because gate/privacy_gate.py shares the module name 'privacy_gate'.
Run: .venv-test/bin/python -m pytest appliance/tests/ -v
"""
import importlib.util
import os

_PATH = os.path.join(os.path.dirname(__file__), '..', 'privacy_gate.py')
_spec = importlib.util.spec_from_file_location('appliance_privacy_gate', _PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
tier0_spans = _mod.tier0_spans
PrivacyGate = _mod.PrivacyGate
show = _mod.show


def labset(text):
    return {(s['label'], text[s['start']:s['end']]) for s in tier0_spans(text)}


def labels(text):
    return {s['label'] for s in tier0_spans(text)}


def _span(text, value, label, start_at=0):
    i = text.index(value, start_at)
    return {'start': i, 'end': i + len(value), 'label': label, 'tier': 0, 'conf': 1.0, 'rule': 'test'}


# ---- F14: IBAN deterministic backstop ----
def test_appliance_iban_mod97_backstop():
    assert ('iban', 'GB82WEST12345698765432') in labset('solde IBAN GB82WEST12345698765432 fin')
    # a mod-97-INVALID lookalike is NOT emitted as iban (the model can still catch it)
    assert 'iban' not in labels('ref GB82WEST12345698765433 fin')


def test_appliance_iban_with_internal_spaces():
    assert ('iban', 'GB82 WEST 1234 5698 7654 32') in labset('IBAN GB82 WEST 1234 5698 7654 32 .')


def test_appliance_iban_lowercase_and_hyphenated():
    assert ('iban', 'gb82west12345698765432') in labset('IBAN gb82west12345698765432 .')
    assert ('iban', 'GB82-WEST-1234-5698-7654-32') in labset('IBAN GB82-WEST-1234-5698-7654-32 .')


# ---- Finding A: Business Number suppression + SIN-cue override ----
def test_appliance_suppresses_business_number():
    assert 'government_id' not in labels('TPS 046454286 RT0001')
    assert 'government_id' not in labels('Business number 046454286 RT0001')  # word-bounded cue (not substring)


def test_appliance_sin_cue_overrides_bn():
    # never-leak guarantee: a SIN cue before the number forces emission even with a BN-looking suffix
    assert 'government_id' in labels('NAS 046454286 RT0001')


def test_appliance_still_emits_bare_sin():
    assert ('government_id', '046454286') in labset('NAS 046454286')


# ---- Label-aware dedup: case-significant credentials stay lossless ----
def test_appliance_redact_case_sensitive_password_variants_lossless(monkeypatch):
    text = "primary AbC123xy backup abc123xy repeat abc123xy."
    spans = [_span(text, "AbC123xy", "password"), _span(text, "abc123xy", "password")]
    gate = PrivacyGate(None)
    monkeypatch.setattr(gate, 'detect', lambda _text, min_score=0.5: spans)
    redacted, mapping, _ = gate.redact(text)
    assert redacted.count("<PASSWORD_001>") == 1
    assert redacted.count("<PASSWORD_002>") == 2
    assert mapping == {"<PASSWORD_001>": "AbC123xy", "<PASSWORD_002>": "abc123xy"}
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_appliance_demo_show_does_not_print_raw_input_or_map_value(capsys):
    class FakeGate:
        def redact(self, text, min_score=0.5):
            return (
                "Contact <EMAIL_001>",
                {"<EMAIL_001>": "demo.user@example.test"},
                [{"label": "email", "tier": 0}],
            )

    show(FakeGate(), "Contact demo.user@example.test")
    out = capsys.readouterr().out
    assert "demo.user@example.test" not in out
    assert "Contact <EMAIL_001>" in out
    assert "MAP_KEYS: ['<EMAIL_001>']" in out
    assert "ROUNDTRIP OK: True" in out


# ---- Date-shaped digit runs classify as sensitive_date, not sensitive_account_id (RC5 follow-up) ----
# DIGIT_RUN_RE swallows hyphenated/compact dates (8-10 digits -> the 7-19 account bucket), which minted
# SENSITIVEACCOUNTID for every datestamp/filename/beta tag and survived coding mode's `date` exclusion.
def test_iso_date_is_date_not_account_id():
    t = 'deployed on 2026-07-01 at noon'
    assert ('sensitive_date', '2026-07-01') in labset(t)
    assert 'sensitive_account_id' not in labels(t)


def test_iso_date_with_glued_log_hour_is_date():
    # "2026-07-01 09:30:00" -- the run stops at the colon, swallowing the hour into the digit run
    t = 'at 2026-07-01 09:30:00 the job ran'
    assert 'sensitive_account_id' not in labels(t)
    assert any(l == 'sensitive_date' for l, v in labset(t))


def test_dmy_and_compact_dates_are_dates():
    assert 'sensitive_account_id' not in labels('due 01-07-2026 ok')
    assert ('sensitive_date', '20260701') in labset('build 20260701 shipped')


def test_dob_cue_floors_date_but_french_negation_ne_does_not():
    """Prose DOB backstop (2026-07-02) + its re-review fix: a birth cue near a date upgrades it to the FLOOR
    date_of_birth (bare dates otherwise pass on the wire in every mode), BUT the FR "born" form must not
    match the negation "ne" -- one of the commonest French words -- or it force-floors dates all over
    Quebec-French prose."""
    # born cues -> floor date_of_birth
    assert ('date_of_birth', '1985-03-12') in labset('né le 1985-03-12')
    assert ('date_of_birth', '1990-06-01') in labset('née 1990-06-01')
    assert ('date_of_birth', '12/03/1985') in labset('born 12/03/1985')
    assert ('date_of_birth', '1985-03-12') in labset('date de naissance du titulaire du compte: 1985-03-12')
    # the negation "ne" must NOT floor a nearby date -- it stays a passthrough sensitive_date
    assert ('sensitive_date', '2024-01-15') in labset('la fonction ne retourne rien depuis 2024-01-15')
    assert 'date_of_birth' not in labels('la fonction ne retourne rien depuis 2024-01-15')
    # a plain date with no birth cue is untouched
    assert ('sensitive_date', '2026-07-01') in labset('shipped 2026-07-01 today')


def test_beta_tag_date_suffix_not_account_id():
    # the real-world regression: a feature-flag tag with a trailing date got a SENSITIVEACCOUNTID placeholder
    t = 'enable context-1m-2025-08-07 today'
    assert 'sensitive_account_id' not in labels(t)


def test_space_grouped_runs_and_sins_still_caught():
    # space-grouped digits are account-shaped (real groupings use spaces) -- NOT reclassified as dates
    assert 'sensitive_account_id' in labels('ref 2026 07 01 99 noted')
    # SIN (9 digits, hyphen-grouped) keeps its government_id floor -- widths reject the D-M-Y shape
    assert 'government_id' in labels('SIN 046-454-286 on file')
    # compact 8-digit runs that cannot be a real date stay account ids
    assert 'sensitive_account_id' in labels('acct 20269999 ok')


# ---- UUID demotion (fat-floor diet, 2026-07-02): deterministic catch, SOFT label ----
# UUIDs are load-bearing session/request ids in agent traffic; the old 'sensitive_account_id' mint gave every
# UUID full floor privilege (merge-sticky, un-allowlistable, redacted in 'off', withheld from tool args) --
# a live agent received a literal placeholder as a file path. The catch stays deterministic (conf 0.99); only
# the label's privileges changed. Mode semantics (privacy redacts / coding+off pass) live in test_floor_diet.
def test_uuid_minted_as_soft_uuid_label_not_account_floor():
    t = 'Session ID 446062b5-366a-4a17-d308-8a7cb0524be4 ouverte.'
    assert ('uuid', '446062b5-366a-4a17-d308-8a7cb0524be4') in labset(t)
    assert 'sensitive_account_id' not in labels(t)
    span = next(s for s in tier0_spans(t) if s['label'] == 'uuid')
    assert span['rule'] == 'tier0:uuid' and span['conf'] == 0.99 and span['tier'] == 0


def test_uuid_label_never_enters_floor_and_digit_run_floor_unchanged():
    # 'uuid' must NEVER gain floor privileges (the whole point of the demotion)...
    assert 'uuid' not in _mod.FLOOR_LABELS
    # ...while the compact 7-19 digit-run bucket keeps minting the account floor exactly as before (the
    # deterministic digit-run guarantee is deliberately NOT part of the diet).
    assert ('sensitive_account_id', '81234567') in labset('account 81234567 active')
    assert 'sensitive_account_id' in _mod.FLOOR_LABELS
