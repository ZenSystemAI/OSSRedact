"""Unit tests for the carrier-wrap booster (plan 026 option A, appliance/name_carrier.py).

Pure module -- no gate, no egress, no heavy deps. `name_shaped` is the latency gate; `carrier_person_spans`
is the offset-mapping logic. The model's actual recall/precision is proven separately against the live gate
(validation/carrier_recall_probe.py) and the wiring through redact_body is in test_egress_e2e.py.
All names synthetic."""
import os
import sys
import asyncio

# import the appliance module directly (no third-party deps)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from name_carrier import name_shaped, carrier_person_spans, CARRIER_PREFIX  # noqa: E402

_P = len(CARRIER_PREFIX)


# --- name_shaped: the cheap "is this a bare personal name?" latency gate ------------------------
def test_name_shaped_accepts_real_names():
    for v in ['Priya McCallum', 'Jean', 'Nguyen Thanh Hai', 'Fatima Al-Rashid',
              "O'Brien", 'José', 'Marie-Claire Tremblay', '  Bjorn Sigurdsson  ']:
        assert name_shaped(v), v


def test_name_shaped_rejects_non_names():
    for v in ['', 'x', 'SKU-9931', '2026-01-15', 'user_id', 'a@b.com', 'active123',
              'Order #4471', 'one two three four five', 'a' * 61, '42', '   ']:
        assert not name_shaped(v), v


# --- carrier_person_spans: map a person verdict on the carrier back to value coords -------------
def _mock(spans):
    async def _fn(text):
        return spans
    return _fn


def _run(coro):
    return asyncio.run(coro)


def test_carrier_maps_person_span_to_value_coords():
    value = 'Priya McCallum'                       # carrier = "The customer is Priya McCallum."
    span = {'start': _P, 'end': _P + len(value), 'label': 'person', 'conf': 0.99, 'tier': 1}
    out = _run(carrier_person_spans(_mock([span]), value))
    assert out == [{'start': 0, 'end': len(value), 'label': 'person', 'conf': 0.99,
                    'tier': 1, 'rule': 'gpu:carrier'}]


def test_carrier_returns_empty_on_no_person():
    assert _run(carrier_person_spans(_mock([]), 'Priya McCallum')) == []


def test_carrier_returns_none_on_gate_error_none():
    # detect_fn returns None when the gate is unreachable -> caller can mark degraded/fail closed
    async def _none(text):
        return None
    assert _run(carrier_person_spans(_none, 'Priya McCallum')) is None


def test_carrier_ignores_non_person_labels():
    value = 'Priya McCallum'
    span = {'start': _P, 'end': _P + len(value), 'label': 'organization', 'conf': 0.9, 'tier': 1}
    assert _run(carrier_person_spans(_mock([span]), value)) == []


def test_carrier_clips_span_that_bleeds_into_scaffold():
    # a person span that starts inside the "...is " scaffold is clipped to the value region, never negative
    value = 'Priya McCallum'
    span = {'start': _P - 3, 'end': _P + len(value), 'label': 'person', 'conf': 0.9, 'tier': 1}
    out = _run(carrier_person_spans(_mock([span]), value))
    assert len(out) == 1 and out[0]['start'] == 0 and out[0]['end'] == len(value)


def test_carrier_clips_span_past_value_end():
    value = 'Priya McCallum'                        # span runs into the trailing "."
    span = {'start': _P, 'end': _P + len(value) + 1, 'label': 'person', 'conf': 0.9, 'tier': 1}
    out = _run(carrier_person_spans(_mock([span]), value))
    assert len(out) == 1 and out[0]['end'] == len(value)
