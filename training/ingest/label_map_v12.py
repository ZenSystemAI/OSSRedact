#!/usr/bin/env python3
"""Public-dataset label schemas -> our v20 canonical scheme (plan 048, v12 mix).

Every source label must be listed in its source dict, mapped to one of:
  - a v20 canonical label (training/labels_v20.json)
  - "O"        -> deliberately unlabeled. This is the wire-policy negative signal: dates, ages,
                  demographics, URLs etc. appear in the text but train as O, teaching the model
                  NOT to redact categories the gate never redacts.
  - "@street"  -> street-family address component. Adjacent @street spans merge into ONE
                  `address` span. Our corpus labels only the civic street line as `address`
                  (verified against pii-merged-v11r9c: city/province between address and
                  postal_code are UNLABELED), so locality labels (city/state/region/country)
                  map to "O", never to address -- label consistency with our 54k rows beats
                  "safe direction" here.
  - "@postal"  -> postal/zip code -> `postal_code` (its own span, never merged into address).

A label present in the data but absent from its source dict is a HARD ERROR at conversion time
(strict policy): the converter aborts with a histogram so the map stays provably complete.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_V20_PATH = Path(__file__).resolve().parent.parent / "labels_v20.json"
V20 = set(json.loads(_V20_PATH.read_text())["labels"])
_TARGETS = V20 | {"O", "@street", "@postal"}

# ai4privacy/pii-masking-openpii-1m -- privacy_mask[].label
AI4PRIVACY = {
    "GIVENNAME": "person", "SURNAME": "person", "MIDDLENAME": "person", "LASTNAME": "person",
    "FIRSTNAME": "person", "NAME": "person",
    "TITLE": "O", "PREFIX": "O",
    "DATEOFBIRTH": "date_of_birth", "DATE": "O", "TIME": "O", "AGE": "O", "SEX": "O", "GENDER": "O",
    "EMAIL": "email", "TELEPHONENUM": "phone_number", "PHONENUMBER": "phone_number",
    "STREET": "@street", "BUILDINGNUM": "@street", "SECONDARYADDRESS": "@street",
    "CITY": "O", "REGION": "O", "STATE": "O", "COUNTY": "O", "COUNTRY": "O",
    "ZIPCODE": "@postal",
    "PASSPORTNUM": "government_id", "IDCARDNUM": "government_id",
    "DRIVERLICENSENUM": "government_id", "SOCIALNUM": "government_id",
    "TAXNUM": "tax_id",
    "CREDITCARDNUMBER": "payment_card",
    "USERNAME": "username", "PASSWORD": "password",
    "IPADDRESS": "ip_address", "URL": "O", "USERAGENT": "O", "MACADDRESS": "O",
    "ACCOUNTNUM": "account_number", "IBAN": "iban", "BIC": "O",  # BIC/SWIFT: institution-level, public
    "ORGANIZATION": "organization", "COMPANYNAME": "organization",
}

# nvidia/Nemotron-PII -- spans[].label (python-repr string field)
NEMOTRON = {
    "first_name": "person", "middle_name": "person", "last_name": "person", "name": "person",
    "date_of_birth": "date_of_birth", "date": "O", "time": "O", "date_time": "O",
    "age": "O", "gender": "O", "race_ethnicity": "O", "religious_belief": "O",
    "political_view": "O", "sexuality": "O", "marital_status": "O", "nationality": "O",
    "occupation": "O", "employment_status": "O", "education": "O", "blood_type": "O",
    "biometric_identifier": "O",  # revisit if firewall stress ever surfaces one (plan 048)
    "email": "email", "phone_number": "phone_number", "fax_number": "phone_number",
    "street_address": "@street", "city": "O", "county": "O", "state": "O", "country": "O",
    "postcode": "@postal", "zipcode": "@postal", "coordinate": "O",
    "ssn": "government_id", "passport_number": "government_id",
    "driver_license_number": "government_id", "national_id": "government_id",
    "certificate_license_number": "government_id", "tax_id": "tax_id",
    "medical_record_number": "sensitive_account_id", "health_plan_id": "sensitive_account_id",
    "employee_id": "sensitive_account_id", "customer_id": "sensitive_account_id",
    "device_identifier": "sensitive_account_id",
    "account_number": "account_number", "bank_routing_number": "O", "swift_bic": "O",
    "iban": "iban", "credit_card_number": "payment_card", "credit_card": "payment_card",
    "cvv": "card_cvv", "card_expiry": "card_expiry", "pin": "password", "password": "password",
    "username": "username", "user_name": "username",
    "ipv4": "ip_address", "ipv6": "ip_address", "ip_address": "ip_address",
    "mac_address": "O", "url": "O", "user_agent": "O",
    "vehicle_identifier": "O", "license_plate": "O",
    "organization": "organization", "company_name": "organization",
    "amount": "O", "currency": "O",
    # surfaced by strict mode on the 2026-07-04 audit (3k-row sample):
    "api_key": "secret", "http_cookie": "secret",  # session cookies are bearer credentials
    "credit_debit_card": "payment_card",
    "health_plan_beneficiary_number": "sensitive_account_id",
    "unique_id": "sensitive_account_id",
    "education_level": "O", "language": "O",
}

# gretelai/gretel-pii-masking-en-v1 -- entities[].types[0] (python-repr string field, NO offsets)
GRETEL = {
    "name": "person", "first_name": "person", "last_name": "person", "full_name": "person",
    "date_of_birth": "date_of_birth", "date": "O", "time": "O", "age": "O", "gender": "O",
    "email": "email", "phone_number": "phone_number", "fax_number": "phone_number",
    "street_address": "@street", "address": "@street",
    "city": "O", "state": "O", "county": "O", "country": "O", "postcode": "@postal",
    "zipcode": "@postal",
    "ssn": "government_id", "passport_number": "government_id",
    "driver_license_number": "government_id", "national_id": "government_id",
    "license_plate": "O", "tax_id": "tax_id",
    "medical_record_number": "sensitive_account_id", "employee_id": "sensitive_account_id",
    "customer_id": "sensitive_account_id", "unique_identifier": "sensitive_account_id",
    "account_number": "account_number", "bank_routing_number": "O", "swift_bic": "O",
    "iban": "iban", "credit_card_number": "payment_card", "cvv": "card_cvv", "pin": "password",
    "password": "password", "username": "username", "api_key": "secret",
    "ipv4": "ip_address", "ipv6": "ip_address", "mac_address": "O", "url": "O",
    "company_name": "organization", "organization": "organization",
    "coordinate": "O", "biometric_identifier": "O", "blood_type": "O", "occupation": "O",
    "job_title": "O", "department": "O", "certificate_license_number": "government_id",
    "vehicle_identifier": "O", "device_identifier": "sensitive_account_id",
    "amount": "O", "currency": "O", "currency_code": "O",
    # surfaced by strict mode on the 2026-07-04 audit (3k-row sample):
    "user_name": "username", "date_time": "O",
    "health_plan_beneficiary_number": "sensitive_account_id",
}

# beki/privy -- Presidio-style span labels (spans arrive as stringified dicts)
PRIVY = {
    "PERSON": "person", "EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone_number",
    "CREDIT_CARD": "payment_card", "IBAN_CODE": "iban", "US_BANK_NUMBER": "account_number",
    "US_SSN": "government_id", "US_ITIN": "government_id", "US_PASSPORT": "government_id",
    "PASSPORT": "government_id", "US_DRIVER_LICENSE": "government_id",
    "DRIVER_LICENSE": "government_id", "UK_NHS": "sensitive_account_id",
    "MEDICAL_LICENSE": "government_id", "AU_ABN": "tax_id", "AU_ACN": "tax_id",
    "AU_TFN": "tax_id", "AU_MEDICARE": "sensitive_account_id",
    "IP_ADDRESS": "ip_address", "MAC_ADDRESS": "O", "URL": "O", "DOMAIN_NAME": "O",
    "DATE_TIME": "O", "NRP": "O", "TITLE": "O", "CRYPTO": "secret",
    # LOCATION in privy payloads mixes cities with full addresses; O for label consistency with
    # our corpus (street-only address convention). Revisit from the --audit histogram if the
    # street-address share turns out material.
    "LOCATION": "O", "GPE": "O", "ORGANIZATION": "organization", "ORG": "organization",
    "US_LICENSE_PLATE": "O",
    # surfaced by strict mode on the 2026-07-04 audit (3k-row sample):
    "O": "O",  # privy emits explicit O spans
    "PASSWORD": "password", "IMEI": "sensitive_account_id",
    "COORDINATE": "O", "AGE": "O",
    # FINANCIAL is privy's generic financial-value bucket (amounts, issuers); the redactable
    # financial shapes arrive as CREDIT_CARD / US_BANK_NUMBER / IBAN_CODE. Precision-first -> O.
    "FINANCIAL": "O",
}

MAPPINGS = {"ai4privacy": AI4PRIVACY, "nemotron": NEMOTRON, "gretel": GRETEL, "privy": PRIVY}

for _name, _m in MAPPINGS.items():
    _bad = {t for t in _m.values() if t not in _TARGETS}
    if _bad:
        raise ValueError(f"label_map_v12.{_name}: targets not in v20/O/@street/@postal: {_bad}")

# Separator allowed between two @street components for them to merge into one address span.
_MERGE_GAP = re.compile(r"^[\s,.·\-–]{0,3}$")


class UnknownLabels(Exception):
    def __init__(self, source: str, counts: dict):
        self.source, self.counts = source, counts
        super().__init__(f"{source}: unmapped source labels {dict(counts)} -- extend label_map_v12.py")


def map_spans(text: str, raw_spans: list, mapping: dict, unknown: dict) -> list:
    """raw_spans: [(start, end, source_label)] -> our [[start, end, v20_label]].

    Applies MAP/DROP, merges adjacent @street runs into one `address` span, emits @postal as
    `postal_code`. Unknown labels are tallied into `unknown` (caller enforces strict policy);
    their spans are skipped. Out-of-bounds / empty spans are dropped.
    """
    n = len(text)
    mapped = []
    for s, e, lab in raw_spans:
        tgt = mapping.get(lab)
        if tgt is None:
            unknown[lab] = unknown.get(lab, 0) + 1
            continue
        if tgt == "O":
            continue
        s, e = int(s), int(e)
        if not (0 <= s < e <= n):
            continue
        mapped.append((s, e, tgt))
    mapped.sort(key=lambda x: x[0])

    out = []
    i = 0
    while i < len(mapped):
        s, e, tgt = mapped[i]
        if tgt == "@postal":
            out.append([s, e, "postal_code"])
            i += 1
        elif tgt == "@street":
            gs, ge = s, e
            j = i + 1
            while (j < len(mapped) and mapped[j][2] == "@street"
                   and _MERGE_GAP.match(text[ge:mapped[j][0]])):
                ge = max(ge, mapped[j][1])
                j += 1
            out.append([gs, ge, "address"])
            i = j
        else:
            out.append([s, e, tgt])
            i += 1

    # Defensive: drop any span overlapping an earlier one (sources should not overlap, but a
    # merged address can swallow a zip if a source double-labels; keep the first-by-start).
    final, last_end = [], -1
    for s, e, lab in sorted(out, key=lambda x: (x[0], -(x[1] - x[0]))):
        if s < last_end:
            continue
        final.append([s, e, lab])
        last_end = e
    return final


def map_gretel_entities(entities: list, mapping: dict, unknown: dict):
    """Gretel has values without offsets -> our legacy value-list format {label: [values]}.

    Returns (entities_dict, ambiguous) where ambiguous=True means the same value string mapped to
    two different v20 labels in this row -- the find()-based labeler cannot disambiguate, so the
    caller drops the row.
    """
    by_value = {}
    for ent in entities:
        val = ent.get("entity")
        types = ent.get("types") or []
        if not val or not types:
            continue
        tgt = None
        for t in types:
            m = mapping.get(t)
            if m is None:
                unknown[t] = unknown.get(t, 0) + 1
            elif tgt is None:
                tgt = m
        if tgt in (None, "O"):
            continue
        if tgt == "@street":
            tgt = "address"
        elif tgt == "@postal":
            tgt = "postal_code"
        if val in by_value and by_value[val] != tgt:
            return {}, True
        by_value[val] = tgt
    ents = {}
    for val, lab in by_value.items():
        ents.setdefault(lab, []).append(val)
    return ents, False
