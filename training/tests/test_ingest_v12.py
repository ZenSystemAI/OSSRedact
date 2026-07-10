"""Hermetic tests for the v12 public-data ingest (plan 048). No network, synthetic rows only.

Run: .venv-test/bin/python -m pytest training/tests/test_ingest_v12.py -v
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ingest'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from label_map_v12 import (AI4PRIVACY, GRETEL, NEMOTRON, PRIVY, V20, MAPPINGS,  # noqa: E402
                           map_gretel_entities, map_spans)
from convert_public import _literal, _privy_span  # noqa: E402


def test_all_map_targets_valid():
    ok = V20 | {"O", "@street", "@postal"}
    for name, m in MAPPINGS.items():
        assert set(m.values()) <= ok, name


def test_ai4privacy_person_and_dob():
    text = "Dear Ms Nexharie Sojinu, born 1987-05-22."
    raw = [(5, 7, "TITLE"), (8, 16, "GIVENNAME"), (17, 23, "SURNAME"), (30, 40, "DATEOFBIRTH")]
    unknown = {}
    spans = map_spans(text, raw, AI4PRIVACY, unknown)
    assert unknown == {}
    # TITLE -> O; GIVENNAME+SURNAME stay two person spans (BIO merges them at train time)
    assert spans == [[8, 16, "person"], [17, 23, "person"], [30, 40, "date_of_birth"]]


def test_street_components_merge_city_drops():
    #        0         1         2         3         4
    #        0123456789012345678901234567890123456789012345
    text = "at 87 Avenida De La Estrella, Springfield 90210"
    raw = [(3, 5, "BUILDINGNUM"), (6, 28, "STREET"), (30, 41, "CITY"), (42, 47, "ZIPCODE")]
    spans = map_spans(text, raw, AI4PRIVACY, {})
    assert spans == [[3, 28, "address"], [42, 47, "postal_code"]]
    assert text[42:47] == "90210"
    assert text[3:28] == "87 Avenida De La Estrella"


def test_street_far_apart_do_not_merge():
    text = "ship to 12 Main St and later to 99 Oak Ave thanks"
    raw = [(8, 18, "STREET"), (32, 42, "STREET")]
    spans = map_spans(text, raw, AI4PRIVACY, {})
    assert spans == [[8, 18, "address"], [32, 42, "address"]]


def test_wire_policy_negatives_map_to_O():
    text = "Age 44, seen 2024-01-05 12:00, url https://x.io, MAC 00:1B:44:11:3A:B7"
    raw = [(4, 6, "AGE"), (13, 23, "DATE"), (35, 47, "URL"), (53, 70, "MACADDRESS")]
    assert map_spans(text, raw, AI4PRIVACY, {}) == []


def test_unknown_label_tallied_not_silently_dropped():
    unknown = {}
    spans = map_spans("abc FOO bar", [(4, 7, "SOME_NEW_LABEL")], AI4PRIVACY, unknown)
    assert spans == []
    assert unknown == {"SOME_NEW_LABEL": 1}


def test_out_of_bounds_span_dropped():
    assert map_spans("short", [(0, 99, "GIVENNAME"), (3, 3, "SURNAME")], AI4PRIVACY, {}) == []


def test_overlap_keeps_first_by_start():
    text = "card 4111 1111 1111 1111 exp"
    raw = [(5, 24, "CREDITCARDNUMBER"), (10, 24, "CREDITCARDNUMBER")]
    spans = map_spans(text, raw, AI4PRIVACY, {})
    assert spans == [[5, 24, "payment_card"]]


def test_nemotron_repr_string_spans_parse():
    field = "[{'start': 3, 'end': 8, 'text': 'Jason', 'label': 'first_name'}]"
    parsed = _literal(field)
    spans = map_spans("I, Jason, apply.", [(m["start"], m["end"], m["label"]) for m in parsed],
                      NEMOTRON, {})
    assert spans == [[3, 8, "person"]]


def test_nemotron_pin_is_password_routing_is_O():
    text = "PIN 4432 routing 021000021"
    raw = [(4, 8, "pin"), (17, 26, "bank_routing_number")]
    assert map_spans(text, raw, NEMOTRON, {}) == [[4, 8, "password"]]


def test_gretel_entities_value_list():
    ents = [{"entity": "Urvashi Jaggi", "types": ["name"]},
            {"entity": "2015-07-26", "types": ["date_of_birth"]},
            {"entity": "Guernsey", "types": ["country"]},
            {"entity": "UID-PRWBO4TB", "types": ["unique_identifier"]}]
    out, ambiguous = map_gretel_entities(ents, GRETEL, {})
    assert not ambiguous
    assert out == {"person": ["Urvashi Jaggi"], "date_of_birth": ["2015-07-26"],
                   "sensitive_account_id": ["UID-PRWBO4TB"]}


def test_gretel_ambiguous_value_drops_row():
    ents = [{"entity": "12345", "types": ["account_number"]},
            {"entity": "12345", "types": ["ssn"]}]
    _, ambiguous = map_gretel_entities(ents, GRETEL, {})
    assert ambiguous


def test_privy_span_both_shapes():
    assert _privy_span({"entity_type": "PERSON", "entity_value": "x",
                        "start_position": 1, "end_position": 5}) == (1, 5, "PERSON")
    assert _privy_span("{'label': 'US_SSN', 'start': 2, 'end': 13}") == (2, 13, "US_SSN")


def test_privy_presidio_mapping():
    text = '{"user": "Jean Roy", "ssn": "078-05-1120"}'
    raw = [(10, 18, "PERSON"), (29, 40, "US_SSN")]
    spans = map_spans(text, raw, PRIVY, {})
    assert spans == [[10, 18, "person"], [29, 40, "government_id"]]


def test_spans_align_with_trainer_labeler():
    """End-to-end: mapped spans feed char_label_array_from_spans exactly like train rows."""
    from labeling import char_label_array_from_spans
    text = "Contact Marie Tremblay at 7096, chemin Principale G5A 4J4"
    raw = [(8, 22, "GIVENNAME"), (26, 49, "STREET"), (50, 57, "ZIPCODE")]
    spans = map_spans(text, raw, AI4PRIVACY, {})
    canon = sorted(V20)
    cl = char_label_array_from_spans(text, spans, canon)
    assert cl[8] == "person" and cl[21] == "person"
    assert cl[26] == "address" and cl[48] == "address"
    assert cl[50] == "postal_code" and cl[56] == "postal_code"
    assert cl[7] is None and cl[49] is None
