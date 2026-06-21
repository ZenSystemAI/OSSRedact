"""A1: force-redact STRING values under secret-named JSON keys (tool_use.input / function_call.arguments)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import egress_proxy as E  # noqa: E402


class _FakeMap:
    def __init__(self): self.n = 0
    def placeholder_for(self, value, label):
        self.n += 1
        return f"<{label.upper()}_{self.n:03d}>", True


def test_secret_keyed_values_redacted():
    m = _FakeMap()
    body = {"input": {"password": "R00tPass!verySecret2", "api_key": "AbCd1234EfGh",
                      "creds": {"auth_token": "Zx9KmQ2wErTy"}}}
    n = E.force_redact_secret_keys(body, m)
    assert n == 3
    assert body["input"]["password"].startswith("<SECRET_")
    assert body["input"]["api_key"].startswith("<SECRET_")
    assert body["input"]["creds"]["auth_token"].startswith("<SECRET_")


def test_french_secret_keys():
    m = _FakeMap()
    body = {"motdepasse": "Ete2024Soleil", "mdp": "Tr3mblay2024", "jeton": "abc123tokenlong"}
    assert E.force_redact_secret_keys(body, m) == 3


def test_non_secret_keys_untouched():
    m = _FakeMap()
    body = {"host": "db.example.com", "username": "jdupont", "token_count": "12345",
            "max_tokens": "4096", "token_type": "Bearer", "description": "the password field"}
    assert E.force_redact_secret_keys(body, m) == 0
    assert body["host"] == "db.example.com"


def test_schema_definitions_not_redacted():
    # a tool/json schema: 'password' is a KEY whose VALUE is a dict (the property def), not a string
    m = _FakeMap()
    body = {"properties": {"password": {"type": "string", "description": "db password"},
                           "api_key": {"type": "string"}}}
    assert E.force_redact_secret_keys(body, m) == 0
    assert body["properties"]["password"] == {"type": "string", "description": "db password"}


def test_already_placeholder_value_skipped():
    m = _FakeMap()
    body = {"password": "<SECRET_001>"}
    assert E.force_redact_secret_keys(body, m) == 0


def test_numeric_secret_values_redacted():
    # A1 (numeric leaf): a NUMERIC value under a sensitive key carries no text cue and was skipped by the
    # str-only path -- it shipped verbatim. Must now redact to the key's floor label.
    m = _FakeMap()
    body = {"cvv": 834, "card_number": 4539148803436467, "password": 12345678,
            "ssn": 123456789, "pin": 5571, "otp": 991823}
    n = E.force_redact_secret_keys(body, m)
    assert n == 6, body
    assert all(isinstance(body[k], str) and body[k].startswith("<") for k in body), body
    assert body["cvv"].startswith("<CARD_CVV_")
    assert body["card_number"].startswith("<PAYMENT_CARD_")
    assert body["password"].startswith("<SECRET_")
    assert body["ssn"].startswith("<GOVERNMENT_ID_")
    assert body["pin"].startswith("<SECRET_") and body["otp"].startswith("<SECRET_")


def test_numeric_non_secret_keys_untouched():
    # plain numeric config/usage fields and BOOLEANS under any key must never redact
    m = _FakeMap()
    body = {"count": 42, "max_tokens": 4096, "port": 8080, "temperature": 0.7, "secret_enabled": True}
    assert E.force_redact_secret_keys(body, m) == 0
    assert body == {"count": 42, "max_tokens": 4096, "port": 8080, "temperature": 0.7, "secret_enabled": True}


def test_identity_and_dob_keys():
    m = _FakeMap()
    body = {"dob": "1980-04-12", "national_id": 887766554, "sin": "046 454 286"}
    assert E.force_redact_secret_keys(body, m) == 3
    assert body["dob"].startswith("<DATE_OF_BIRTH_")
    assert body["national_id"].startswith("<GOVERNMENT_ID_")
    assert body["sin"].startswith("<GOVERNMENT_ID_")
