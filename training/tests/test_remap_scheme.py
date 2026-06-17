import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from remap_scheme import remap_entities  # noqa: E402


def test_bank_and_routing_become_account_number():
    e = {"bank_account": ["73364244"], "routing_number": ["81850"]}
    out = remap_entities(e)
    assert sorted(out["account_number"]) == ["73364244", "81850"]
    assert "bank_account" not in out and "routing_number" not in out


def test_sensitive_account_id_uuid_stays_else_account_number():
    e = {"sensitive_account_id": ["446062b5-366a-fa17-d308-8a7cb0524be4", "8174981223"]}
    out = remap_entities(e)
    assert out["sensitive_account_id"] == ["446062b5-366a-fa17-d308-8a7cb0524be4"]
    assert out["account_number"] == ["8174981223"]


def test_keys_tokens_become_secret_password_kept():
    e = {"api_key": ["hf_x"], "access_token": ["tok_y"], "password": ["p@ss"]}
    out = remap_entities(e)
    assert sorted(out["secret"]) == ["hf_x", "tok_y"]
    assert out["password"] == ["p@ss"]


def test_sensitive_date_dropped_dob_kept():
    e = {"sensitive_date": ["2026-06-07"], "date_of_birth": ["10 JANVIER 1997"]}
    out = remap_entities(e)
    assert "sensitive_date" not in out
    assert out["date_of_birth"] == ["10 JANVIER 1997"]


def test_organization_kept():
    e = {"organization": ["Services Conseil Quebec Ltee"]}
    assert remap_entities(e)["organization"] == ["Services Conseil Quebec Ltee"]
