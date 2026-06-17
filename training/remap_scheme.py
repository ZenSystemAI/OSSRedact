#!/usr/bin/env python3
"""Remap a v8 (23-label) dataset row's entities to the 20-label scheme (design spec section 4).

Migration (old 23 -> new 20):
  bank_account, routing_number          -> account_number
  sensitive_account_id (UUID shape)     -> sensitive_account_id (kept)
  sensitive_account_id (numeric/other)  -> account_number
  api_key, access_token                 -> secret
  sensitive_date                        -> DROPPED (becomes a trained negative)
  organization                          -> organization (existing labels are employers/issuers = stay)
  everything else in KEEP               -> unchanged
  any unknown legacy label              -> DROPPED (becomes a negative)

Operates on the value-list entity format ({label: [values]}). Phase 3 replaces this with
offset-true generation; this script is only the cheap Phase-1 validate-gate remap of v8.
"""
import json, re, sys
from pathlib import Path

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
KEEP = {"person", "email", "phone_number", "address", "postal_code", "date_of_birth", "government_id",
        "payment_card", "card_cvv", "card_expiry", "iban", "tax_id", "ip_address", "file_path", "username",
        "organization", "password"}


def remap_entities(ents):
    out = {}

    def add(lab, v):
        out.setdefault(lab, [])
        if v not in out[lab]:
            out[lab].append(v)

    for lab, vals in ents.items():
        for v in vals:
            if not v:
                continue
            if lab in ("bank_account", "routing_number"):
                add("account_number", v)
            elif lab == "sensitive_account_id":
                add("sensitive_account_id" if UUID_RE.match(v.strip()) else "account_number", v)
            elif lab in ("api_key", "access_token"):
                add("secret", v)
            elif lab == "sensitive_date":
                continue  # dropped -> negative
            elif lab in KEEP:
                add(lab, v)
            # any unknown legacy label is dropped (becomes a negative)
    return out


def main():
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    n = 0
    with open(dst, 'w', encoding='utf-8') as w:
        for line in open(src, encoding='utf-8'):
            if not line.strip():
                continue
            r = json.loads(line)
            r['output']['entities'] = remap_entities(r['output']['entities'])
            w.write(json.dumps(r, ensure_ascii=False) + '\n')
            n += 1
    print(f"remapped {n} rows -> {dst}")


if __name__ == '__main__':
    main()
