#!/usr/bin/env python3
"""v11r9 digit-contrast NEGATIVES: long digit runs under clearly-BENIGN keys -> EMPTY span (never redacted).

The v11r7/r8 regression was the model labeling ANY 8-19 digit run as account_number / sensitive_account_id
(account FP 61->548, said FP 56->600) and stealing probability mass from dob. The base corpus teaches "digit
run under an ACCOUNT key (compte/account/iban) = redact"; this slice teaches the CONTRAST: the SAME digit-run
shapes under non-PII keys (order_id, tracking, build, port, sku, run_id, ...) are NOT sensitive and must pass.
It is the active counterweight to the org/address aug that lets the digit-ID labels stay precise.

Every row is offset-trivial (no spans). Forms: json / kv-cue / prose / csv / list, FR + EN, digit runs sized
8-19 to overlap the digit-ID band exactly so the contrast is sharp. Output schema matches the other
generators: {"input": text, "output": {"spans": [], "entities": {}}, "meta": {"src": "augment_digit_contrast"}}.
"""
import argparse
import json
import os
import random
import string

# clearly-NON-PII numeric-id keys (EN + FR). A long digit run under any of these must NOT be redacted.
BENIGN_KEYS = [
    "order_id", "order_number", "order", "tracking", "tracking_number", "sku", "build", "build_number",
    "port", "pid", "line", "offset", "seq", "sequence", "batch_id", "run_id", "job_id", "request_id",
    "version_code", "commit_count", "ticket", "issue", "revision", "checksum_seed", "frame", "row",
    "no_commande", "no_suivi", "no_lot", "no_ticket", "no_serie", "numero_commande", "code_produit",
]
CUE_PREFIX = [
    "Order", "Order number", "Tracking", "Tracking number", "SKU", "Build", "Port", "Ticket", "Job", "Run",
    "Request", "Batch", "Sequence", "Revision", "Commande no", "Suivi", "Lot no", "Billet no", "Serie",
]
PROSE = [
    "{cue} {num} is now {state}.", "We shipped {cue} {num} this morning.", "See {cue} {num} for details.",
    "{cue} {num} failed and was retried.", "La {cuefr} {num} a ete traitee.", "Le {cuefr} {num} est pret.",
    "Reference {cue} {num} in your reply.", "{cue} {num} completed in 3.2s.",
]
CUEFR = ["commande", "livraison", "tache", "demande", "sequence", "version"]
STATE = ["queued", "shipped", "in transit", "delivered", "active", "closed", "pending", "done"]


def _luhn_ok(s):
    d = [int(c) for c in s][::-1]
    t = 0
    for i, x in enumerate(d):
        if i % 2:
            x *= 2
            x = x - 9 if x > 9 else x
        t += x
    return t % 10 == 0


def _digits(rng, lo=8, hi=19):
    # NEVER emit a Luhn-valid 13-19 digit run: a card-shaped negative would teach the model that a real
    # payment card is benign. If we land on one, bump the last digit so it fails Luhn (stays the same length).
    n = rng.randint(lo, hi)
    s = "".join(str(rng.randint(0, 9)) for _ in range(n))
    if n >= 13 and _luhn_ok(s):
        last = (int(s[-1]) + 1) % 10
        s = s[:-1] + str(last)
        if _luhn_ok(s):  # +1 still valid only if it wrapped; +5 guarantees a different residue
            s = s[:-1] + str((int(s[-1]) + 5) % 10)
    return s


def _grouped(rng):
    # space/hyphen grouped run, derived from a Luhn-SAFE base (a spaced 16-digit Luhn number is still a
    # card to the floor), e.g. 4820-1147-2290 or 482 011 472 998
    base = _digits(rng, 8, 16)
    sep = rng.choice(["-", " "])
    out, i = [], 0
    while i < len(base):
        step = rng.randint(3, 4)
        out.append(base[i:i + step])
        i += step
    return sep.join(out)


def _phone_fmt(rng):
    # phone-SHAPED but BENIGN: lives under a non-phone key/cue (order/sku/build), so it teaches the model that a
    # XXX-XXX-XXXX shape is not always a phone_number -- precision for the over-firing phone label. (Phone has no
    # Tier-0 floor, so no floor conflict.) NEVER emitted under a tel/call/mobile cue (that would teach a miss).
    a, b, c = rng.randint(200, 999), rng.randint(200, 999), rng.randint(0, 9999)
    sep = rng.choice(["-", ".", " "])
    style = rng.random()
    if style < 0.45:
        return f"{a}{sep}{b}{sep}{c:04d}"
    if style < 0.75:
        return f"({a}) {b}-{c:04d}"
    return f"1-{a}-{b}-{c:04d}"


def _alnum_id(rng):
    # alphanumeric ID shape (like a customer/sid token) but under an order/sku/tracking cue -> BENIGN. Counterweight
    # to the sid-postal contrast, which boosted sid recall at a precision cost (sid prec ~0.88): this teaches that
    # the same shape under a NON-account cue is not sensitive_account_id.
    pre = rng.choice(["ORD", "SKU", "TRK", "LOT", "REF", "INV", "PO", "BLD", "BATCH"])
    body = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(rng.randint(6, 11)))
    return f"{pre}-{body}" if rng.random() < 0.7 else f"{pre}{body}"


def _num(rng):
    r = rng.random()
    if r < 0.16:
        return _phone_fmt(rng)
    if r < 0.34:
        return _alnum_id(rng)
    if r < 0.52:
        return _grouped(rng)
    return _digits(rng)


def _emit(text):
    return {"input": text, "output": {"spans": [], "entities": {}}, "meta": {"src": "augment_digit_contrast"}}


def _record(rng):
    form = rng.choice(["json", "json", "cue", "cue", "prose", "csv", "list", "kv"])
    num = _num(rng)
    if form == "json":
        key = rng.choice(BENIGN_KEYS)
        # ~half numeric leaf, half string leaf (both must stay un-redacted)
        val = int(num.replace("-", "").replace(" ", "")) if (num.isdigit() and rng.random() < 0.5) else num
        extra = {rng.choice(["status", "etat", "type"]): rng.choice(STATE)}
        obj = {key: val, **extra} if rng.random() < 0.6 else {key: val}
        return _emit(json.dumps(obj, ensure_ascii=False))
    if form == "kv":
        return _emit(f"{rng.choice(BENIGN_KEYS)}: {num}")
    if form == "cue":
        return _emit(f"{rng.choice(CUE_PREFIX)} {num}")
    if form == "csv":
        cols = [rng.choice(CUE_PREFIX), num, rng.choice(STATE)]
        rng.shuffle(cols)
        return _emit(",".join(str(c) for c in cols))
    if form == "list":
        nums = [_num(rng) for _ in range(rng.randint(2, 4))]
        return _emit(rng.choice(["IDs: ", "Refs: ", "Lots: "]) + ", ".join(nums))
    # prose
    t = rng.choice(PROSE).format(cue=rng.choice(CUE_PREFIX), cuefr=rng.choice(CUEFR),
                                 num=num, state=rng.choice(STATE))
    return _emit(t)


def build(n, seed):
    rng = random.Random(seed)
    return [_record(rng) for _ in range(n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n-train", type=int, default=3000)
    ap.add_argument("--n-val", type=int, default=300)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    for split, n, seed in [("train", args.n_train, 901), ("val", args.n_val, 902)]:
        rows = build(n, seed)
        path = os.path.join(args.out_dir, f"digit_contrast_{split}.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{split}: {len(rows)} rows -> {path}")


if __name__ == "__main__":
    main()
