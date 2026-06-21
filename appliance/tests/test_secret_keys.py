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
