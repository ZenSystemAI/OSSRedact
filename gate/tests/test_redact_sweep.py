"""PrivacyGate.redact() contract: label-aware placeholder dedup + the Finding-C repeated-value sweep.

The gate services (gate_service_gpu.py / gate_service_cpu.py) chunk long text via detect_chunked and then
delegate the ACTUAL redaction to PrivacyGate.redact(text, spans=...). This suite pins that delegated logic
WITHOUT a model: spans are injected directly, so we can simulate a detector that catches a repeated value at
SOME occurrences and misses it at others -- exactly the Finding-C leak the sweep closes. The positional-only
loop the services used before did neither dedup nor sweep.

Torch-free (PrivacyGate(None) = floor-only, and we inject spans). 100% synthetic inputs; no real PII.
Run: .venv-test/bin/python -m pytest gate/tests/test_redact_sweep.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import PrivacyGate  # noqa: E402
from privacy_gate import show  # noqa: E402


def _span(text, value, label, start_at=0):
    i = text.index(value, start_at)
    return {'start': i, 'end': i + len(value), 'label': label, 'tier': 0, 'conf': 1.0, 'rule': 'test'}


def test_sweep_masks_repeated_value_missed_positionally():
    # The detector caught the FIRST occurrence only (model miss at the 2nd) -- the sweep must mask the rest.
    g = PrivacyGate(None)
    text = "Email jane.doe@acme.test now. Then again jane.doe@acme.test for the records."
    spans = [_span(text, "jane.doe@acme.test", "email")]  # only the first occurrence detected
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert "jane.doe@acme.test" not in redacted              # 2nd occurrence swept verbatim-free
    assert redacted.count("<EMAIL_001>") == 2                # both occurrences share ONE placeholder
    assert mapping == {"<EMAIL_001>": "jane.doe@acme.test"}
    assert PrivacyGate.rehydrate(redacted, mapping) == text  # lossless round-trip


def test_casefold_dedup_same_value_one_placeholder():
    # Two case variants of the same email, both DETECTED -> one shared placeholder (not EMAIL_001 + EMAIL_002).
    g = PrivacyGate(None)
    text = "Write to Bob@Acme.test or bob@acme.test."
    spans = [_span(text, "Bob@Acme.test", "email"), _span(text, "bob@acme.test", "email")]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert len(mapping) == 1
    assert redacted.count("<EMAIL_001>") == 2
    assert "<EMAIL_002>" not in redacted
    # rehydrate restores a same-PII value at both spots (casefold collision -> first-wins is acceptable)
    assert PrivacyGate.rehydrate(redacted, mapping).lower() == text.lower()


def test_case_sensitive_password_variants_are_lossless():
    # Password-like values that differ only by case are different secrets and must not share a placeholder.
    g = PrivacyGate(None)
    text = "primary AbC123xy then backup abc123xy."
    spans = [_span(text, "AbC123xy", "password"), _span(text, "abc123xy", "password")]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert redacted.count("<PASSWORD_001>") == 1
    assert redacted.count("<PASSWORD_002>") == 1
    assert mapping == {"<PASSWORD_001>": "AbC123xy", "<PASSWORD_002>": "abc123xy"}
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_case_sensitive_password_sweep_uses_exact_placeholder():
    # The detector caught both case variants once, then missed an exact repeat of the second value.
    g = PrivacyGate(None)
    text = "primary AbC123xy backup abc123xy repeat abc123xy."
    spans = [_span(text, "AbC123xy", "password"), _span(text, "abc123xy", "password")]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert "abc123xy" not in redacted
    assert redacted.count("<PASSWORD_001>") == 1
    assert redacted.count("<PASSWORD_002>") == 2
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_sweep_is_case_insensitive():
    # Detected once as "Jane Tremblay"; a later ALL-CAPS occurrence must still be masked.
    g = PrivacyGate(None)
    text = "Client Jane Tremblay. Signed: JANE TREMBLAY."
    spans = [_span(text, "Jane Tremblay", "person")]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert "JANE TREMBLAY" not in redacted
    assert redacted.count("<PERSON_001>") == 2


def test_sweep_never_corrupts_an_inserted_placeholder():
    # A short detected value that happens to be a substring of the placeholder token must not rewrite the
    # placeholder the positional pass produced. _sweep_known runs only on the gaps between placeholders.
    g = PrivacyGate(None)
    text = "ref EMAIL and email a@b.test and EMAIL again"
    spans = [_span(text, "a@b.test", "email")]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert redacted.count("<EMAIL_001>") == 1   # the standalone word "EMAIL" is < detected value, not swept
    assert mapping == {"<EMAIL_001>": "a@b.test"}
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_multi_entity_round_trip():
    g = PrivacyGate(None)
    text = "NAS 046 454 286, courriel a@b.ca, carte 4539148803436467, encore a@b.ca."
    # floor-only detection (no model) catches all of these deterministically
    redacted, mapping, _ = g.redact(text)
    assert "046 454 286" not in redacted
    assert "4539148803436467" not in redacted
    assert "a@b.ca" not in redacted
    assert redacted.count("<EMAIL_001>") == 2          # repeated email -> one placeholder, both masked
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_empty_and_clean_text():
    g = PrivacyGate(None)
    assert g.redact("", spans=[]) == ("", {}, [])
    clean = "Le service tourne sur le port 8080, aucune donnee ici."
    redacted, mapping, _ = g.redact(clean)
    assert redacted == clean and mapping == {}


def test_demo_show_does_not_print_raw_input_or_map_value(capsys):
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


# ---- Codex review 2026-06-17 (gate /redact fix) regression pins ----

def test_overlapping_injected_spans_do_not_leak_tail():
    # Codex FINDING 1: an external caller of the spans= API may pass OVERLAPPING spans. Without a union guard the
    # positional cursor jumps backward and re-appends covered text -> a leak. redact() now runs merge_spans first.
    g = PrivacyGate(None)
    text = "token abcdefgh"
    spans = [
        {'start': 6, 'end': 14, 'label': 'secret', 'tier': 0, 'conf': 0.9, 'rule': 'test'},   # outer "abcdefgh"
        {'start': 8, 'end': 10, 'label': 'password', 'tier': 0, 'conf': 0.9, 'rule': 'test'},  # inner "cd"
    ]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert 'abcdefgh' not in redacted and 'efgh' not in redacted, 'no covered text may survive (overlap union)'
    # the union span covers 6..14; rehydrate restores the original covered text losslessly
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_sweep_handles_placeholder_shaped_user_text():
    # Codex FINDING 2: when a KNOWN value itself contains a placeholder-shaped substring, the old sweep split the
    # redacted string on the GENERIC placeholder shape and skipped the value's other occurrences. The sweep now
    # splits only on the placeholders THIS redaction inserted, so the repeated occurrence is masked.
    g = PrivacyGate(None)
    value = 'tok_<EMAIL_001>_x'                                   # a value containing a placeholder shape
    text = value + ' then again ' + value
    first = text.index(value)
    spans = [{'start': first, 'end': first + len(value), 'label': 'secret', 'tier': 0, 'conf': 0.9, 'rule': 'test'}]
    redacted, mapping, _ = g.redact(text, spans=spans)
    assert value not in redacted, 'the repeated placeholder-shaped value must be swept, not skipped'
    assert redacted.count('<SECRET_001>') == 2
    assert PrivacyGate.rehydrate(redacted, mapping) == text
