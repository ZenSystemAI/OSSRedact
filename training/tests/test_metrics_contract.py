"""Torch-free policy tests for checkpoint-selection vs shipping-floor label sets.

These two sets intentionally diverge: organization and address influence trainer
checkpoint selection (cat_f1) but must not silently expand the strict ship bar.

Public module: training/metrics_contract.py
  CHECKPOINT_SELECTION_LABELS  (15, includes organization/address)
  SHIP_FLOOR_LABELS            (13, excludes organization/address)

Run: .venv-test/bin/python -m pytest training/tests/test_metrics_contract.py -v
Do not import torch or train_suite here.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from metrics_contract import (  # noqa: E402
    CHECKPOINT_SELECTION_LABELS,
    SHIP_FLOOR_LABELS,
)


# Exact membership frozen from train_suite.CATASTROPHIC (15) and
# validation/bar_check_v11.CATASTROPHIC (13). Renames only; policy unchanged.
_SELECTION_EXPECTED = frozenset({
    "government_id", "payment_card", "card_cvv", "card_expiry", "secret", "password",
    "account_number", "iban", "sensitive_account_id", "email", "person", "date_of_birth",
    "tax_id", "organization", "address",
})

_SHIP_FLOOR_EXPECTED = frozenset({
    "government_id", "payment_card", "card_cvv", "card_expiry", "secret", "password",
    "account_number", "iban", "sensitive_account_id", "email", "person", "date_of_birth",
    "tax_id",
})


def test_checkpoint_selection_has_fifteen_labels():
    assert isinstance(CHECKPOINT_SELECTION_LABELS, (set, frozenset))
    assert len(CHECKPOINT_SELECTION_LABELS) == 15
    assert CHECKPOINT_SELECTION_LABELS == _SELECTION_EXPECTED


def test_ship_floor_has_thirteen_labels():
    assert isinstance(SHIP_FLOOR_LABELS, (set, frozenset))
    assert len(SHIP_FLOOR_LABELS) == 13
    assert SHIP_FLOOR_LABELS == _SHIP_FLOOR_EXPECTED


def test_organization_and_address_in_selection_only():
    """Org/address reward cat_f1 checkpoint choice but stay outside the strict release bar."""
    for lab in ("organization", "address"):
        assert lab in CHECKPOINT_SELECTION_LABELS
        assert lab not in SHIP_FLOOR_LABELS


def test_ship_floor_is_strict_subset_of_selection():
    assert SHIP_FLOOR_LABELS < CHECKPOINT_SELECTION_LABELS
    assert CHECKPOINT_SELECTION_LABELS - SHIP_FLOOR_LABELS == {"organization", "address"}


def test_shared_catastrophic_ids_present_in_both():
    """Core leak-direction IDs remain in both policies (no accidental drop on rename)."""
    shared = (
        "government_id", "payment_card", "card_cvv", "card_expiry", "secret", "password",
        "account_number", "iban", "sensitive_account_id", "email", "person", "date_of_birth",
        "tax_id",
    )
    for lab in shared:
        assert lab in CHECKPOINT_SELECTION_LABELS
        assert lab in SHIP_FLOOR_LABELS


def test_no_torch_or_train_suite_dependency():
    """metrics_contract must stay importable in the torch-free CI process."""
    import importlib
    mod = importlib.import_module("metrics_contract")
    assert not hasattr(mod, "torch")
    src = open(mod.__file__, encoding="utf-8").read()
    assert "import torch" not in src
    assert "train_suite" not in src
