"""Torch-free label policies for training metrics."""

CHECKPOINT_SELECTION_LABELS = frozenset({
    "government_id",
    "payment_card",
    "card_cvv",
    "card_expiry",
    "secret",
    "password",
    "account_number",
    "iban",
    "sensitive_account_id",
    "email",
    "person",
    "date_of_birth",
    "tax_id",
    "organization",
    "address",
})

SHIP_FLOOR_LABELS = frozenset({
    "government_id",
    "payment_card",
    "card_cvv",
    "card_expiry",
    "secret",
    "password",
    "account_number",
    "iban",
    "sensitive_account_id",
    "email",
    "person",
    "date_of_birth",
    "tax_id",
})
