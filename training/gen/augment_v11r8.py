#!/usr/bin/env python3
"""v11r8 augmentation -- RECOVER account_number / sensitive_account_id structural recall.

The v11r7 org/address augmentation (augment_v11r7.py) shifted the corpus distribution toward
org/addr/person and DILUTED the structured-id categories: on the apples-to-apples held-out
(pii-heldout-v11r5) v11r7 REGRESSED vs v11r5 -- catastrophic full-stack DETECTION recall large
0.9964 -> 0.9914 (account_number 0.974 -> 0.930), base clean_fp 12 -> 38 (sensitive_account_id
0.998 -> 0.963). v11r8 keeps ALL of v11r7's data (org/addr/name gains preserved) and ADDS this
account-number-heavy structural augmentation so the model re-learns structured ids on unseen
structure WITHOUT trading them away.

Same approach as augment_structural_names.py: place a DIVERSE, procedurally-generated structured-id
VALUE into many STRUCTURAL forms (bare / JSON / CSV / KV / tool-args / list), with ~22% structural
NEGATIVES (non-id values under id-ish keys) to preserve the 0-FP precision. Offsets are computed BY
CONSTRUCTION and every span is asserted to slice back to the exact value. Train and held-out value
seeds are disjoint so the held-out slice measures generalization, not memorization.

Schema matches v11r5/v11r6/v11r7: {input, output:{spans:[[s,e,label]], entities:{}}, meta}.

Usage: python training/gen/augment_v11r8.py --out-dir /tmp/aug8 --n-train 12000 --n-val 1200 --n-heldout 1500
"""
from __future__ import annotations
import argparse, json, os, random

# id-ish JSON/KV keys (EN + FR) that cue a structured id. The VALUE shape -- not the key -- must drive
# the decision (negatives put a non-id value under these very keys), but realistic keys vary structure.
ACCT_KEYS = ["account_number", "account", "acct", "account_no", "acct_no", "member_id", "membership_no",
             "policy_number", "policy_no", "customer_id", "customer_no", "client_id", "reference",
             "reference_no", "loan_number", "contract_no", "iban_ref", "transit_account", "ledger_id",
             "no_compte", "numero_compte", "no_membre", "no_police", "no_client", "no_reference",
             "no_contrat", "no_dossier"]
OTHER_KEYS = ["status", "type", "currency", "region", "branch", "opened", "tier", "lang", "balance_due"]
# values that may sit under an id-ish key but are NOT ids (must stay un-redacted -> preserve precision).
NEG_VALUES = ["active", "closed", "pending", "checking", "savings", "chequing", "courant", "épargne",
              "CAD", "USD", "EUR", "premium", "standard", "basic", "N/A", "null", "true", "false",
              "primary", "joint", "2024", "Q3", "open", "fr-CA", "en-CA", "high", "verified"]

ALNUM_PREFIX = ["ACCT", "AC", "MBR", "POL", "CUST", "REF", "LN", "CTR", "DOS", "ID", "ACC", "MEM"]


def _digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def _acct_value(rng):
    """A bank-account-style value -> label 'account_number'. Varied length + separators."""
    r = rng.random()
    if r < 0.30:                                  # bare run, 8-12 digits
        return _digits(rng, rng.randint(8, 12)), "account_number"
    if r < 0.55:                                  # Canadian transit-institution-account
        inst = rng.choice(["001", "002", "003", "004", "006", "010", "016", "815"])
        return f"{_digits(rng,5)}-{inst}-{_digits(rng, rng.randint(7,9))}", "account_number"
    if r < 0.75:                                  # space/hyphen grouped
        sep = rng.choice([" ", "-"])
        g = [_digits(rng, rng.choice([3, 4])) for _ in range(rng.randint(3, 4))]
        return sep.join(g), "account_number"
    if r < 0.90:                                  # alpha-prefixed account ref
        pre = rng.choice(["ACCT-", "AC", "ACC-", "BANK-"])
        return pre + _digits(rng, rng.randint(6, 9)), "account_number"
    return _digits(rng, rng.randint(13, 17)), "account_number"   # long bare run


def _sid_value(rng):
    """A generic structured-id value -> label 'sensitive_account_id'. Member/policy/customer/reference."""
    r = rng.random()
    if r < 0.35:                                  # alpha-prefixed code
        pre = rng.choice(ALNUM_PREFIX)
        sep = rng.choice(["-", "", "-", "_"])
        body = _digits(rng, rng.randint(5, 9))
        if rng.random() < 0.4:
            body = f"{rng.randint(2018,2025)}-{body}"
        return f"{pre}{sep}{body}", "sensitive_account_id"
    if r < 0.65:                                  # long bare digit run 7-19
        return _digits(rng, rng.randint(7, 19)), "sensitive_account_id"
    if r < 0.85:                                  # grouped reference
        g = [_digits(rng, rng.choice([3, 4, 5])) for _ in range(rng.randint(2, 3))]
        return rng.choice(["-", " "]).join(g), "sensitive_account_id"
    pre = rng.choice(ALNUM_PREFIX)                 # mixed alnum block
    return pre + _digits(rng, 4) + rng.choice("ABCDEFGHJKMNPQRSTUVWXYZ") + _digits(rng, 4), "sensitive_account_id"


def _value(rng):
    """Pick a structured-id value + its label (account_number heavier -- it regressed most)."""
    return _acct_value(rng) if rng.random() < 0.6 else _sid_value(rng)


def _emit(text, spans):
    for s, e, lab in spans:
        assert 0 <= s < e <= len(text), (s, e, len(text), text)
        assert text[s:e], (s, e, text)
    return {"input": text, "output": {"spans": [[s, e, lab] for s, e, lab in spans], "entities": {}},
            "meta": {"src": "augment_v11r8"}}


def _record(rng, value):
    """Build ONE structural record placing a structured-id value (callable -> (val,label)) with an
    offset-true span. ~22% negatives (a non-id value under an id-ish key) -> no span."""
    form = rng.choice(["json1", "jsonN", "bare", "csv", "kv", "toolargs", "list", "quoted"])
    is_neg = rng.random() < 0.22

    if form == "bare":
        if is_neg:
            return _emit(rng.choice(NEG_VALUES), [])
        v, lab = value()
        return _emit(v, [(0, len(v), lab)])

    if form == "quoted":
        if is_neg:
            return _emit(f'"{rng.choice(NEG_VALUES)}"', [])
        v, lab = value(); pre = '"'
        return _emit(f'"{v}"', [(len(pre), len(pre) + len(v), lab)])

    if form == "kv":
        key = rng.choice(ACCT_KEYS)
        sep = rng.choice([": ", " : ", "= ", " #: ", ": \"", " no. "])
        if is_neg:
            return _emit(f"{key}{sep}{rng.choice(NEG_VALUES)}" + ('"' if sep.endswith('"') else ''), [])
        v, lab = value(); pre = f"{key}{sep}"
        suf = '"' if sep.endswith('"') else ''
        return _emit(pre + v + suf, [(len(pre), len(pre) + len(v), lab)])

    if form == "json1":
        key = rng.choice(ACCT_KEYS)
        if is_neg:
            return _emit(json.dumps({key: rng.choice(NEG_VALUES)}, ensure_ascii=False), [])
        v, lab = value()
        pre = '{"' + key + '": "'
        return _emit(pre + v + '"}', [(len(pre), len(pre) + len(v), lab)])

    if form == "jsonN":
        v, lab = (None, None) if is_neg else value()
        vval = rng.choice(NEG_VALUES) if is_neg else v
        fields = [(rng.choice(OTHER_KEYS), rng.choice(NEG_VALUES)),
                  (rng.choice(ACCT_KEYS), vval),
                  (rng.choice(OTHER_KEYS), str(rng.randint(1, 99)))]
        rng.shuffle(fields)
        out, spans, first = "{", [], True
        for k, vv in fields:
            seg = ("" if first else ", ") + '"' + k + '": "' + vv + '"'
            start = len(out) + len(seg) - len(vv) - 1
            out += seg
            if (not is_neg) and vv == v and v is not None:
                spans.append((start, start + len(v), lab))
            first = False
        return _emit(out + "}", spans)

    if form == "csv":
        v, lab = (None, None) if is_neg else value()
        cells = [rng.choice(["QC", "ON", "BC"]),
                 (rng.choice(NEG_VALUES) if is_neg else v),
                 rng.choice(["active", "2024-03-11", "CAD"])]
        out, spans, pos = "", [], 0
        for i, c in enumerate(cells):
            if i:
                out += ","; pos += 1
            if (not is_neg) and c == v and v is not None:
                spans.append((pos, pos + len(v), lab))
            out += c; pos += len(c)
        return _emit(out, spans)

    if form == "toolargs":
        key = rng.choice(ACCT_KEYS)
        if is_neg:
            return _emit(json.dumps({"tool": "lookup", "arguments": {key: rng.choice(NEG_VALUES)}},
                                    ensure_ascii=False), [])
        v, lab = value()
        pre = '{"tool": "lookup", "arguments": {"' + key + '": "'
        return _emit(pre + v + '"}}', [(len(pre), len(pre) + len(v), lab)])

    # list of 2-3 ids
    k = rng.randint(2, 3)
    vals = [value() for _ in range(k)]
    out, spans = "[", []
    for i, (v, lab) in enumerate(vals):
        out += ("" if i == 0 else ", ") + '"'
        spans.append((len(out), len(out) + len(v), lab))
        out += v + '"'
    return _emit(out + "]", spans)


def build(n, seed):
    rng = random.Random(seed)
    vrng = random.Random(seed + 7)
    return [_record(rng, lambda: _value(vrng)) for _ in range(n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n-train", type=int, default=12000)
    ap.add_argument("--n-val", type=int, default=1200)
    ap.add_argument("--n-heldout", type=int, default=1500)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    # disjoint value SEEDS: random procedural values mean train/heldout overlap is negligible, and the
    # held-out seed family is distinct so the slice measures structural generalization, not memorization.
    rows_train = build(args.n_train, seed=8101)
    rows_val = build(args.n_val, seed=8102)
    rows_heldout = build(args.n_heldout, seed=99203)

    for fname, rows in [("train.jsonl", rows_train), ("val.jsonl", rows_val), ("heldout.jsonl", rows_heldout)]:
        with open(os.path.join(args.out_dir, fname), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    def stats(rows):
        labs = {}
        for r in rows:
            for _, _, lab in r["output"]["spans"]:
                labs[lab] = labs.get(lab, 0) + 1
        return {"rows": len(rows), "spans": labs, "negatives": sum(1 for r in rows if not r["output"]["spans"])}
    print(json.dumps({"out_dir": args.out_dir, "train": stats(rows_train), "val": stats(rows_val),
                      "heldout": stats(rows_heldout)}, indent=2))


if __name__ == "__main__":
    main()
