"""CROSS-DOMAIN FLOOR PARITY (Python <-> TS twin).

The Python gate's privacy_gate.FLOOR_LABELS and the TS core's redaction-core FLOOR_LABELS are supposed to be
the SAME set 1:1 (labels.ts says so in a comment). They are the hard floor: never allowlist-exempt, force-
redacted in every mode. If they drift, the looser side LEAKS -- e.g. `account_number` was floored in TS +
trained into the model (labels_v20.json) + emitted by the deployed model (config.json id2label) but MISSING
from the Python floor, so a model-predicted account number shipped unredacted under off/coding/allowlist.
This test fails on ANY future drift, not just that one label. Torch-free, pure text parse of the TS source.
Run: .venv-test/bin/python -m pytest appliance/tests/test_floor_label_parity.py -q
"""
import os
import re
import sys

_APPLIANCE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_APPLIANCE)
sys.path.insert(0, _APPLIANCE)
from privacy_gate import FLOOR_LABELS  # noqa: E402

_LABELS_TS = os.path.join(_REPO, 'packages', 'redaction-core', 'src', 'labels.ts')
_EGRESS_PY = os.path.join(_APPLIANCE, 'egress_proxy.py')
_GATE_PY = os.path.join(_REPO, 'gate', 'privacy_gate.py')


def _parse_ts_set(name):
    """Extract the single-quoted members of `export const <name>: ... = new Set<string>([ ... ])` from the TS twin."""
    src = open(_LABELS_TS, encoding='utf-8').read()
    m = re.search(r'export const ' + re.escape(name) + r'\b.*?=\s*new Set<string>\(\[(.*?)\]\)', src, re.S)
    assert m, f'{name} not found in {_LABELS_TS}'
    return set(re.findall(r"'([^']+)'", m.group(1)))


def _parse_py_frozenset(path, name):
    """Extract the single-quoted members of `<name> = frozenset({ ... })` from a Python source file by text.

    Parsed (not imported) so the gate twin can be checked alongside the appliance one without the two
    same-named `privacy_gate` modules colliding on sys.path."""
    src = open(path, encoding='utf-8').read()
    m = re.search(re.escape(name) + r'\s*=\s*frozenset\(\{(.*?)\}\)', src, re.S)
    assert m, f'{name} not found in {path}'
    return set(re.findall(r"'([^']+)'", m.group(1)))


def test_python_floor_labels_match_ts_floor_labels_1to1():
    ts_floor = _parse_ts_set('FLOOR_LABELS')
    py_floor = set(FLOOR_LABELS)
    assert py_floor == ts_floor, (
        f'FLOOR drift -> the looser side leaks. only in Python: {py_floor - ts_floor}; '
        f'only in TS: {ts_floor - py_floor}')


def test_gate_and_appliance_floor_labels_match():
    # the two Python floors (gate detection twin + appliance egress twin) must stay identical: the gate's
    # merge-stickiness and the egress force-redact guard both read FLOOR_LABELS, and a gate-side miss can
    # downgrade a floor span before egress ever sees it.
    gate_floor = _parse_py_frozenset(_GATE_PY, 'FLOOR_LABELS')
    assert set(FLOOR_LABELS) == gate_floor, (
        f'gate/appliance FLOOR drift. only in appliance: {set(FLOOR_LABELS) - gate_floor}; '
        f'only in gate: {gate_floor - set(FLOOR_LABELS)}')


def test_account_number_is_floored_everywhere():
    # explicit regression guard for the 2026-06-27 leak: the model EMITS account_number (config.json id2label),
    # so it must be hard-floored on every twin, not treated as a soft/allowlist-exempt label.
    assert 'account_number' in FLOOR_LABELS
    assert 'account_number' in _parse_ts_set('FLOOR_LABELS')
    assert 'account_number' in _parse_py_frozenset(_GATE_PY, 'FLOOR_LABELS')


def test_account_number_in_egress_account_category():
    # the friendly-category map (egress_proxy.CATEGORY_LABELS['account']) must list account_number too, so the
    # restrictive-allowlist + exclude plumbing treats it as a money/account label. Parsed (no torch/web import).
    src = open(_EGRESS_PY, encoding='utf-8').read()
    m = re.search(r"'account':\s*\[(.*?)\]", src)
    assert m, "CATEGORY_LABELS['account'] not found in egress_proxy.py"
    assert 'account_number' in set(re.findall(r"'([^']+)'", m.group(1)))
