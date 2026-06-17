"""Unit test for the entity-F1 compute_metrics in train_suite.py.

train_suite imports torch at module top, so this runs where torch is available (gpu-host venv-pii):
    /opt/ossredact/.venv-pii/bin/python training/tests/test_compute_metrics.py
It also works under pytest in any env that has torch+numpy+seqeval.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import numpy as np
import train_suite


def _setup():
    train_suite.load_labels(os.path.join(os.path.dirname(__file__), '..', 'labels_v20.json'))


def test_returns_three_keys_and_perfect_person_is_cat_f1_1():
    _setup()
    bp = train_suite.label2id['B-person']
    ip = train_suite.label2id['I-person']
    o = train_suite.label2id['O']
    # one row, gold = [pad] B-person I-person O [pad]; pred identical on the real tokens
    labels = np.array([[-100, bp, ip, o, -100]])
    preds = np.array([[0, bp, ip, o, 0]])
    out = train_suite.compute_metrics((preds, labels))
    assert set(out) >= {'macro_f1', 'cat_f1', 'micro_f1'}
    for v in out.values():
        assert 0.0 <= v <= 1.0
    assert out['cat_f1'] == 1.0  # person is catastrophic + perfectly predicted


def test_missed_catastrophic_entity_drives_cat_f1_to_zero():
    _setup()
    bp = train_suite.label2id['B-person']
    o = train_suite.label2id['O']
    labels = np.array([[bp, -100]])
    preds = np.array([[o, -100]])  # person entity missed entirely
    out = train_suite.compute_metrics((preds, labels))
    assert out['cat_f1'] == 0.0


if __name__ == '__main__':
    test_returns_three_keys_and_perfect_person_is_cat_f1_1()
    test_missed_catastrophic_entity_drives_cat_f1_to_zero()
    print('compute_metrics tests OK')
