#!/usr/bin/env python3
"""Evaluate a trained PII token-classifier on a .jsonl set and report per-label + person P/R/F1.

Mirrors train_suite.py's offset-true gold alignment (char_label_array_from_spans). Used to measure the
v11r6 structural-name retrain: the GAIN on structural_names_heldout.jsonl (disjoint rare surnames) and
NO-REGRESSION on val.jsonl, run identically for v11r6 vs the v11r5 baseline.

Preds are decoded with the MODEL's own config.id2label (robust if a checkpoint's id ordering differs);
gold tags use the dataset's labels.json scheme. seqeval compares the resulting tag strings.
"""
from __future__ import annotations
import argparse, json, os
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification
from seqeval.metrics import classification_report
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from labeling import char_label_array, char_label_array_from_spans, token_char_label  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', required=True)
    ap.add_argument('--data', required=True, help='a .jsonl file')
    ap.add_argument('--labels', default='', help='labels.json; default = sibling of --data')
    ap.add_argument('--max-len', type=int, default=512)
    ap.add_argument('--bs', type=int, default=32)
    args = ap.parse_args()

    labels_path = args.labels or str(Path(args.data).parent / 'labels.json')
    CANON = json.loads(Path(labels_path).read_text())['labels']

    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForTokenClassification.from_pretrained(args.model)
    dev = 'cuda' if torch.cuda.is_available() else 'cpu'
    model.to(dev).eval()
    id2label_model = {int(k): v for k, v in model.config.id2label.items()}

    rows = [json.loads(l) for l in open(args.data, encoding='utf-8') if l.strip()]
    true_tags, pred_tags = [], []
    for i in range(0, len(rows), args.bs):
        batch = rows[i:i + args.bs]
        texts = [r['input'] for r in batch]
        enc = tok(texts, return_offsets_mapping=True, truncation=True,
                  max_length=args.max_len, padding=True, return_tensors='pt')
        offsets = enc.pop('offset_mapping')
        with torch.no_grad():
            logits = model(**{k: v.to(dev) for k, v in enc.items()}).logits
        preds = logits.argmax(-1).cpu().numpy()
        for j, r in enumerate(batch):
            text = r['input']
            spans = r['output'].get('spans')
            cl = (char_label_array_from_spans(text, spans, CANON) if spans
                  else char_label_array(text, r['output'].get('entities', {}), CANON))
            tt, pt, prev = [], [], None
            for k, (a, b) in enumerate(offsets[j].tolist()):
                if a == b:                      # special / pad token: skip both streams together
                    prev = None
                    continue
                cur = token_char_label(text, cl, a, b)
                if cur is None:
                    tt.append('O'); prev = None
                else:
                    tt.append(f"{'I' if prev == cur else 'B'}-{cur}"); prev = cur
                pt.append(id2label_model[int(preds[j][k])])
            true_tags.append(tt); pred_tags.append(pt)

    rep = classification_report(true_tags, pred_tags, output_dict=True, zero_division=0)
    # seqeval returns numpy float64/int64 -> coerce to native Python so json.dumps works.
    def f(x):
        return round(float(x), 4)
    pers = rep.get('person', {})
    out = {
        'model': args.model, 'data': args.data, 'n': len(rows),
        'macro_f1': f(rep.get('macro avg', {}).get('f1-score', 0.0)),
        'micro_f1': f(rep.get('micro avg', {}).get('f1-score', 0.0)),
        'person': {'precision': f(pers.get('precision', 0.0)), 'recall': f(pers.get('recall', 0.0)),
                   'f1': f(pers.get('f1-score', 0.0))},
        'person_support': int(pers.get('support', 0)),
        'per_label': {k: {'p': f(v['precision']), 'r': f(v['recall']), 'f1': f(v['f1-score']),
                          'n': int(v['support'])}
                      for k, v in rep.items() if k not in ('macro avg', 'micro avg', 'weighted avg')},
    }
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
