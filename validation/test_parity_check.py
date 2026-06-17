#!/usr/bin/env python3
"""Unit tests for the pure metrics in parity_check.py (numpy only -- no model needed).

Run: .venv-test/bin/python -m pytest validation/test_parity_check.py -v
The model runners (_run_torch/_run_onnx) need torch+onnxruntime+the weights and are
exercised on P620, not here.
"""
import numpy as np
import pytest

from parity_check import per_token_cosine, argmax_agreement, parity_verdict, TIER_THRESHOLDS


def test_cosine_identical_is_one():
    a = np.array([[1.0, 2.0, 3.0], [-4.0, 0.5, 2.0]])
    cos = per_token_cosine(a, a)
    assert cos.shape == (2,)
    assert np.allclose(cos, 1.0)


def test_cosine_orthogonal_is_zero():
    a = np.array([[1.0, 0.0]])
    b = np.array([[0.0, 1.0]])
    assert np.allclose(per_token_cosine(a, b), 0.0)


def test_cosine_zero_vector_is_zero_not_nan():
    a = np.array([[0.0, 0.0, 0.0]])
    b = np.array([[1.0, 2.0, 3.0]])
    cos = per_token_cosine(a, b)
    assert np.isfinite(cos).all()
    assert cos[0] == 0.0


def test_cosine_shape_mismatch_raises():
    with pytest.raises(ValueError):
        per_token_cosine(np.zeros((2, 3)), np.zeros((2, 4)))


def test_argmax_identical_full_parity():
    a = np.array([[0.1, 0.9], [0.8, 0.2], [0.3, 0.7]])
    overall, pii, n, npii = argmax_agreement(a, a, o_index=0)
    assert overall == 1.0 and pii == 1.0 and n == 3


def test_argmax_one_flip():
    a = np.array([[0.1, 0.9], [0.9, 0.1]])   # argmax: [1, 0]
    b = np.array([[0.1, 0.9], [0.1, 0.9]])   # argmax: [1, 1]  -> token 1 flips
    overall, _pii, n, _npii = argmax_agreement(a, b)
    assert n == 2 and overall == 0.5


def test_pii_argmax_restricts_to_nonO_tokens():
    # o_index=0. Token 0 is O in both (agreement irrelevant to pii rate);
    # token 1 is PII in both and agrees -> pii parity should be 1.0.
    a = np.array([[0.9, 0.1, 0.0], [0.1, 0.8, 0.1]])  # argmax [0, 1]
    b = np.array([[0.8, 0.2, 0.0], [0.1, 0.7, 0.2]])  # argmax [0, 1]
    overall, pii, n, npii = argmax_agreement(a, b, o_index=0)
    assert overall == 1.0 and pii == 1.0 and npii == 1


def test_pii_argmax_catches_a_pii_flip():
    # o_index=0. Token 1: ref predicts PII class 1, export predicts O -> a PII flip.
    a = np.array([[0.9, 0.1], [0.1, 0.9]])  # argmax [0, 1]
    b = np.array([[0.9, 0.1], [0.9, 0.1]])  # argmax [0, 0]
    overall, pii, n, npii = argmax_agreement(a, b, o_index=0)
    assert npii == 1 and pii == 0.0 and overall == 0.5


def test_verdict_passes_above_thresholds():
    v = parity_verdict(min_cosine=0.9995, mean_cosine=0.99999, argmax_rate=1.0, pii_argmax_rate=1.0)
    assert v['ok'] is True
    assert all(c['pass'] for c in v['checks'].values())


def test_verdict_fails_on_low_pii_parity():
    # cosine + overall argmax fine, but a PII token flipped -> must fail closed.
    v = parity_verdict(min_cosine=0.5, mean_cosine=0.9999, argmax_rate=0.9999, pii_argmax_rate=0.95)
    assert v['ok'] is False
    assert v['checks']['pii_argmax_parity']['pass'] is False


def test_verdict_fails_on_low_cosine():
    v = parity_verdict(min_cosine=0.2, mean_cosine=0.97, argmax_rate=1.0, pii_argmax_rate=1.0)
    assert v['ok'] is False
    assert v['checks']['mean_cosine']['pass'] is False


# --- tier presets: the deployed v11r5-base dynamic INT8 numbers ---
DEPLOYED_INT8 = dict(min_cosine=0.641, mean_cosine=0.998, argmax_rate=0.997, pii_argmax_rate=0.981)


def test_int8_tier_passes_a_good_int8_export():
    t = TIER_THRESHOLDS['int8']
    v = parity_verdict(**DEPLOYED_INT8, cos_threshold=t['cos'], argmax_threshold=t['argmax'],
                       pii_argmax_threshold=t['pii_argmax'])
    assert v['ok'] is True  # 0.998/0.997/0.981 clears the int8 bar (0.99/0.99/0.97)


def test_f16_tier_rejects_the_same_int8_numbers():
    t = TIER_THRESHOLDS['f16']
    v = parity_verdict(**DEPLOYED_INT8, cos_threshold=t['cos'], argmax_threshold=t['argmax'],
                       pii_argmax_threshold=t['pii_argmax'])
    assert v['ok'] is False  # the f16 bar (0.999) is too strict for int8 -- the false-FAIL we fixed


def test_int8_tier_still_blocks_a_pii_recall_collapse():
    # the broken static int8 (pii-argmax 0.143) must FAIL even under the looser int8 bar
    t = TIER_THRESHOLDS['int8']
    v = parity_verdict(min_cosine=-0.3, mean_cosine=0.834, argmax_rate=0.875, pii_argmax_rate=0.143,
                       cos_threshold=t['cos'], argmax_threshold=t['argmax'], pii_argmax_threshold=t['pii_argmax'])
    assert v['ok'] is False
    assert v['checks']['pii_argmax_parity']['pass'] is False


def test_pii_threshold_defaults_to_argmax_when_unset():
    # back-compat: omitting pii_argmax_threshold reuses argmax_threshold
    v = parity_verdict(min_cosine=0.9, mean_cosine=0.9991, argmax_rate=0.9991, pii_argmax_rate=0.9991,
                       cos_threshold=0.999, argmax_threshold=0.999)
    assert v['ok'] is True
    assert v['checks']['pii_argmax_parity']['threshold'] == 0.999
