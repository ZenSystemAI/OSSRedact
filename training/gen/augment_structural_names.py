#!/usr/bin/env python3
"""Plan 026 option B -- training augmentation for the person-name recall gap.

The deployed xlm-roberta detector misses person names in TWO measured situations (plan 026):
  (1) STRUCTURAL form -- a name as a bare value / JSON `"key":"value"` / CSV cell / `key: value`
      line, with no surrounding prose to cue it (the dominant shape in the egress's real traffic).
  (2) RARE / diverse surnames -- the v11r5 corpus name pool is almost entirely Quebecois + common
      Anglo (gen/values.py: Tremblay/Gagnon/Roy ... ; John/Sarah ...), so out-of-distribution
      surnames score zero even in prose.

This generator emits offset-true rows in the v11r5 schema -- {input, output:{spans:[[s,e,label]],
entities:[]}, meta} -- that put a WIDE, diverse, rare given+surname distribution into STRUCTURAL
contexts, PLUS structural negatives (non-name values under name-ish keys) so the model keeps
discriminating (preserve the measured 0-FP precision). Train and eval name pools are DISJOINT so
the heldout slice measures generalization to UNSEEN rare names, not memorization.

Offsets are computed BY CONSTRUCTION (build the string, record where the name was inserted) and
every emitted span is asserted to slice back to the exact name -- a single off-by-one would corrupt
the BIO labels. Deterministic (seeded); pure stdlib.

Usage:
  python training/gen/augment_structural_names.py --out-dir /tmp/aug --n-train 6000 --n-val 700 --n-heldout 1000
"""
from __future__ import annotations
import argparse, json, os, random

# --- diverse, lower-frequency given names + surnames across many regions (synthetic use; not real
# individuals). Deliberately spans South/East/SE-Asian, African, Arabic, Eastern-European, Latin,
# Nordic, Greek, Persian, Turkish, Indigenous-adjacent, etc. -- the distribution v11r5 lacked. ---
GIVEN = [
    "Priya", "Anjali", "Oluwaseun", "Chidi", "Nguyen", "Thanh", "Mateusz", "Dmitri", "Fatima",
    "Bjorn", "Xiomara", "Thandiwe", "Aarav", "Ishaan", "Mei", "Hiroshi", "Yuki", "Wei", "Ji-woo",
    "Seo-yeon", "Kwame", "Amara", "Zanele", "Sipho", "Layla", "Omar", "Yusuf", "Khadija", "Ravi",
    "Sunita", "Tomasz", "Katarzyna", "Dragan", "Vesna", "Sven", "Ingrid", "Freya", "Mateo", "Camila",
    "Joaquin", "Rosario", "Dimitris", "Eleni", "Arash", "Parisa", "Emre", "Elif", "Ayodele", "Folake",
    "Tariq", "Nadia", "Bao", "Linh", "Suresh", "Deepa", "Kenji", "Sakura", "Bilal", "Zara",
]
SURNAME = [
    "McCallum", "Venkataraman", "Adeyemi", "Wojcik", "Kowalczyk", "Al-Rashid", "Sigurdsson", "Beltran",
    "Mkhize", "Okonkwo", "Nakamura", "Subramanian", "Chowdhury", "Bandyopadhyay", "Karthikeyan",
    "Dlamini", "Achterberg", "Vandermeulen", "Pawlak", "Nowakowski", "Stoyanova", "Petrov", "Haradinaj",
    "Brannigan", "Castellanos", "Quintero", "Vasquez", "Papadopoulos", "Stavros", "Esfahani", "Tehrani",
    "Yilmaz", "Demir", "Abebe", "Tesfaye", "Ferreira", "Magalhaes", "Bjornsson", "Lindqvist",
    "Saetang", "Wattana", "Phommachanh", "Ramaswamy", "Krishnamurthy", "Olufemi", "Babatunde",
    "Zielinski", "Szymanski", "Novak", "Horvat", "Mihaylova", "Antonopoulos", "Mardirossian", "Ghorbani",
    "Ozdemir", "Kaya", "Mwangi", "Otieno", "Pereira", "Goncalves", "Halvorsen", "Solberg",
]

# negative VALUES that may sit under a name-ish key but are NOT persons (must NOT be labeled person).
NEG_VALUES = [
    "active", "pending", "approved", "completed", "cancelled", "draft", "archived", "Premium Plan",
    "Standard", "Basic", "Enterprise", "USD", "CAD", "en-CA", "fr-CA", "high", "low", "medium",
    "true", "false", "null", "north", "south", "v2", "beta", "production",
]
# name-ish JSON/KV keys (EN + FR) and non-name keys, to vary structure.
NAME_KEYS = ["customer_name", "client", "full_name", "contact", "assignee", "owner", "beneficiary",
             "applicant", "account_holder", "user", "nom_client", "titulaire", "demandeur", "name"]
OTHER_KEYS = ["id", "status", "plan", "region", "code", "type", "tier", "lang", "active"]


def _full_name(rng):
    """1-4 token person name from the diverse pools."""
    given = rng.choice(GIVEN)
    r = rng.random()
    if r < 0.12:
        return given                                   # 1 token (given only)
    if r < 0.82:
        return f"{given} {rng.choice(SURNAME)}"          # 2 tokens (given + surname)
    if r < 0.95:
        return f"{given} {rng.choice(GIVEN)} {rng.choice(SURNAME)}"   # 3 tokens (given + middle + surname)
    return f"{given} {rng.choice(SURNAME)}-{rng.choice(SURNAME)}"     # hyphenated double surname


def _emit(text, spans):
    for s, e, lab in spans:
        assert 0 <= s < e <= len(text), (s, e, len(text), text)
    # entities must be a DICT ({label:[values]}) -- train_suite uses the entities path when spans is
    # empty (negatives), and char_label_array iterates entities.items(). {} -> all-O (correct negative).
    return {"input": text, "output": {"spans": [[s, e, lab] for s, e, lab in spans], "entities": {}},
            "meta": {"src": "augment_structural_names"}}


def _record(rng, names):
    """Build ONE structural record placing `names` (a callable -> name) with offset-true person spans.
    ~25% of records are negatives (a non-name value under a name-ish key) -> no person span."""
    form = rng.choice(["json1", "jsonN", "bare", "csv", "kv", "toolargs", "list", "quoted"])
    is_neg = rng.random() < 0.25

    def name():
        return names()

    if form == "bare":
        if is_neg:
            return _emit(rng.choice(NEG_VALUES), [])
        nm = name()
        return _emit(nm, [(0, len(nm), "person")])

    if form == "quoted":
        if is_neg:
            v = rng.choice(NEG_VALUES); return _emit(f'"{v}"', [])
        nm = name(); pre = '"'
        return _emit(f'"{nm}"', [(len(pre), len(pre) + len(nm), "person")])

    if form == "kv":
        key = rng.choice(NAME_KEYS)
        sep = rng.choice([": ", " : ", "= ", ": \""])
        if is_neg:
            return _emit(f"{key}{sep}{rng.choice(NEG_VALUES)}" + ('"' if sep.endswith('"') else ''), [])
        nm = name(); pre = f"{key}{sep}"
        suf = '"' if sep.endswith('"') else ''
        return _emit(pre + nm + suf, [(len(pre), len(pre) + len(nm), "person")])

    if form == "json1":
        key = rng.choice(NAME_KEYS)
        if is_neg:
            return _emit(json.dumps({key: rng.choice(NEG_VALUES)}, ensure_ascii=False), [])
        nm = name()
        pre = '{"' + key + '": "'
        text = pre + nm + '"}'
        return _emit(text, [(len(pre), len(pre) + len(nm), "person")])

    if form == "jsonN":
        # multi-key object with the name among other fields
        nm = None if is_neg else name()
        nval = rng.choice(NEG_VALUES) if is_neg else nm
        parts, spans = ["{"], []
        fields = [(rng.choice(OTHER_KEYS), str(rng.randint(1000, 99999))),
                  (rng.choice(NAME_KEYS), nval),
                  (rng.choice(OTHER_KEYS), rng.choice(NEG_VALUES))]
        rng.shuffle(fields)
        cur = "{"
        out = "{"
        first = True
        for k, v in fields:
            seg = ("" if first else ", ") + '"' + k + '": "' + v + '"'
            start = len(out) + len(seg) - len(v) - 1   # position of v inside the just-added segment
            out += seg
            if (not is_neg) and v == nm and nm is not None:
                spans.append((start, start + len(nm), "person"))
            first = False
        out += "}"
        # verify the recorded span actually points at the name
        return _emit(out, spans)

    if form == "csv":
        nm = None if is_neg else name()
        cells = [str(rng.randint(1000, 9999)),
                 (rng.choice(NEG_VALUES) if is_neg else nm),
                 rng.choice(["QC", "ON", "active", "2024-03-11", "CAD"])]
        out, spans, pos = "", [], 0
        for i, c in enumerate(cells):
            if i:
                out += ","; pos += 1
            if (not is_neg) and c == nm and nm is not None:
                spans.append((pos, pos + len(nm), "person"))
            out += c; pos += len(c)
        return _emit(out, spans)

    if form == "toolargs":
        key = rng.choice(NAME_KEYS)
        if is_neg:
            return _emit(json.dumps({"tool": "lookup", "arguments": {key: rng.choice(NEG_VALUES)}},
                                    ensure_ascii=False), [])
        nm = name()
        pre = '{"tool": "lookup", "arguments": {"' + key + '": "'
        text = pre + nm + '"}}'
        return _emit(text, [(len(pre), len(pre) + len(nm), "person")])

    # list of 2-3 names
    k = rng.randint(2, 3)
    nms = [name() for _ in range(k)]
    out, spans = "[", []
    for i, nm in enumerate(nms):
        seg = ("" if i == 0 else ", ") + '"'
        out += seg
        spans.append((len(out), len(out) + len(nm), "person"))
        out += nm + '"'
    out += "]"
    return _emit(out, spans)


def build(n, names, seed):
    rng = random.Random(seed)
    return [_record(rng, names) for _ in range(n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n-train", type=int, default=6000)
    ap.add_argument("--n-val", type=int, default=700)
    ap.add_argument("--n-heldout", type=int, default=1000)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    # DISJOINT name pools: train uses the first 70% of each pool, heldout/val the last 30% (unseen rares).
    gcut, scut = int(len(GIVEN) * 0.7), int(len(SURNAME) * 0.7)
    train_given, eval_given = GIVEN[:gcut], GIVEN[gcut:]
    train_surn, eval_surn = SURNAME[:scut], SURNAME[scut:]

    def train_names(_rng=random.Random(1)):
        return None  # placeholder, replaced below

    # closures over disjoint pools
    def mk(given_pool, surn_pool, seed):
        rng = random.Random(seed)
        def f():
            g = rng.choice(given_pool); r = rng.random()
            if r < 0.12: return g
            if r < 0.82: return f"{g} {rng.choice(surn_pool)}"
            if r < 0.95: return f"{g} {rng.choice(given_pool)} {rng.choice(surn_pool)}"
            return f"{g} {rng.choice(surn_pool)}-{rng.choice(surn_pool)}"
        return f

    rows_train = build(args.n_train, mk(train_given, train_surn, 11), seed=101)
    rows_val = build(args.n_val, mk(train_given, train_surn, 12), seed=102)       # val: train-pool names (in-dist val)
    rows_heldout = build(args.n_heldout, mk(eval_given, eval_surn, 13), seed=103)  # heldout: UNSEEN rare names

    for fname, rows in [("train.jsonl", rows_train), ("val.jsonl", rows_val), ("heldout.jsonl", rows_heldout)]:
        with open(os.path.join(args.out_dir, fname), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    # stats
    def npos(rows):
        return sum(1 for r in rows if r["output"]["spans"])
    print(json.dumps({
        "out_dir": args.out_dir,
        "train": {"rows": len(rows_train), "with_person": npos(rows_train)},
        "val": {"rows": len(rows_val), "with_person": npos(rows_val)},
        "heldout": {"rows": len(rows_heldout), "with_person": npos(rows_heldout)},
        "train_pool": {"given": len(train_given), "surname": len(train_surn)},
        "heldout_pool_disjoint": {"given": len(eval_given), "surname": len(eval_surn)},
    }, indent=2))


if __name__ == "__main__":
    main()
