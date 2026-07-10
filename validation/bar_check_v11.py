#!/usr/bin/env python3
"""Check a v11 model-alone eval (eval_labelaware JSON) against the STRICT ship bar (design spec 3.8):
  - catastrophic tier (13 labels): recall >= 0.99 AND precision >= 0.97
  - overall (all in-scope): labeled-recall >= 0.97 AND precision >= 0.93
  - no in-scope label below 0.93 F1
Measured MODEL-ALONE. Also prints the per-doctype breakdown (which real structures discriminate vs saturate)
and the floor-drag (full-stack precision vs model-alone). Usage: python bar_check_v11.py <eval.json> [...]
"""
import json
import sys
from pathlib import Path

TRAINING_DIR = Path(__file__).resolve().parents[1] / "training"
sys.path.insert(0, str(TRAINING_DIR))
from metrics_contract import SHIP_FLOOR_LABELS


def check(path):
    r = json.load(open(path))
    m = r['modes']['model']; pl = m['per_label']
    print(f"\n{'='*74}\n{r['model']}  rows={r['n_rows']}   MODEL-ALONE vs STRICT BAR\n{'='*74}")
    print(f"overall: labeled-recall={m['labeled_recall']:.4f}  precision={m['precision']:.4f}  "
          f"F1={m['f1']:.4f}  clean_fp={m['clean_fp']}")
    fails = []
    if m['labeled_recall'] < 0.97: fails.append(f"overall recall {m['labeled_recall']:.4f} < 0.97")
    if m['precision'] < 0.93: fails.append(f"overall precision {m['precision']:.4f} < 0.93")

    print(f"\n{'label':22} {'tier':4} {'gold':>6} {'recall':>7} {'prec':>7} {'F1':>7}  flags")
    for lab in sorted(pl):
        d = pl[lab]; is_ship_floor = lab in SHIP_FLOOR_LABELS; flag = []
        if is_ship_floor:
            if d['recall_labeled'] < 0.99: flag.append('R<.99'); fails.append(f"{lab} (cat) R={d['recall_labeled']:.4f}<0.99")
            if d['precision'] < 0.97: flag.append('P<.97'); fails.append(f"{lab} (cat) P={d['precision']:.4f}<0.97")
        if d['f1'] < 0.93: flag.append('F1<.93'); fails.append(f"{lab} F1={d['f1']:.4f}<0.93")
        print(f"{lab:22} {'CAT' if is_ship_floor else 'op':4} {d['gold']:>6} {d['recall_labeled']:>7.3f} "
              f"{d['precision']:>7.3f} {d['f1']:>7.3f}  {','.join(flag)}")

    ship_floor = [pl[lab] for lab in SHIP_FLOOR_LABELS if lab in pl]
    cg = sum(d['gold'] for d in ship_floor) or 1
    cr = sum(d['gold'] * d['recall_labeled'] for d in ship_floor) / cg
    cp_den = sum(d['pred'] for d in ship_floor) or 1
    cp = sum(d['pred'] * d['precision'] for d in ship_floor) / cp_den
    print(f"\ncatastrophic tier (gold-weighted): recall={cr:.4f}  precision={cp:.4f}")

    fu = r['modes'].get('full', {})
    if fu:
        print(f"floor-drag: full-stack precision={fu.get('precision',0):.4f} vs model-alone={m['precision']:.4f} "
              f"(clean_fp full={fu.get('clean_fp')} vs model={m['clean_fp']})")

    print(f"\nVERDICT: {'*** PASS ***' if not fails else f'FAIL ({len(fails)} criteria)'}")
    for f in fails:
        print("   -", f)

    bd = r.get('per_doctype_model', {})
    if bd:
        print(f"\nper-doctype (model-alone) -- real-structure generalization (held-out structures are unseen):")
        print(f"   {'doctype':22} {'rows':>5} {'gold':>6} {'recall':>7} {'prec':>7} {'cleanFP':>8}")
        for dt, d in sorted(bd.items(), key=lambda x: -x[1].get('gold_spans', 0)):
            print(f"   {dt:22} {d['rows']:>5} {d['gold_spans']:>6} {d['labeled_recall']:>7.3f} "
                  f"{d['precision']:>7.3f} {d['clean_fp']:>8}")
    lf = r.get('lang_full', {})
    if lf:
        print("\nFR/EN (full):", {k: f"R={v['labeled_recall']:.3f} fp={v['fp']}" for k, v in lf.items()})
    return fails


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: python bar_check_v11.py <eval.json> [...]", file=sys.stderr)
        return 2

    allf = {}
    for p in argv:
        allf[p] = check(p)
    print(f"\n{'='*74}\nSUMMARY:")
    for p, f in allf.items():
        print(f"  {p}: {'PASS' if not f else f'FAIL ({len(f)})'}")
    return 1 if any(allf.values()) else 0


if __name__ == '__main__':
    raise SystemExit(main())
