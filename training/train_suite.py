#!/usr/bin/env python3
"""Unified suite trainer: full-fine-tune ANY encoder (distilbert-multilingual / xlm-roberta-base/-large) into a
PII token-classifier, reading the label scheme from the dataset's labels.json (composite-address v6 scheme).
Same value-span -> BIO-via-offset-mapping alignment as the original NPU trainer. --dry-run verifies alignment.
"""
from __future__ import annotations
import argparse, json, os
from pathlib import Path
import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import (AutoTokenizer, AutoModelForTokenClassification, TrainingArguments, Trainer,
                          DataCollatorForTokenClassification)
from seqeval.metrics import classification_report
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from labeling import char_label_array, char_label_array_from_spans  # noqa: E402

CANON = []; BIO = []; label2id = {}; id2label = {}

# Catastrophic tier (design spec section 4): checkpoint selection is weighted on these labels' entity-F1,
# not eval_loss, because leak-direction errors on these are the costly ones.
CATASTROPHIC = {"government_id", "payment_card", "card_cvv", "card_expiry", "secret", "password",
                "account_number", "iban", "sensitive_account_id", "email", "person", "date_of_birth",
                "tax_id"}

def load_labels(labels_path):
    global CANON, BIO, label2id, id2label
    d = json.loads(Path(labels_path).read_text())
    CANON = d['labels']; BIO = d['bio']
    label2id = {t: i for i, t in enumerate(BIO)}
    id2label = {i: t for t, i in label2id.items()}

class TCDataset(Dataset):
    def __init__(self, path, tok, max_len=256):
        self.rows = [json.loads(l) for l in open(path, encoding='utf-8') if l.strip()]
        self.tok = tok; self.max_len = max_len
    def __len__(self):
        return len(self.rows)
    def __getitem__(self, i):
        r = self.rows[i]; text = r['input']
        spans = r['output'].get('spans')   # Phase 3 (v10) offset-true path; falls back to find for v9-remap
        cl = (char_label_array_from_spans(text, spans, CANON) if spans
              else char_label_array(text, r['output']['entities'], CANON))
        enc = self.tok(text, return_offsets_mapping=True, truncation=True, max_length=self.max_len)
        labels, prev = [], None
        for (a, b) in enc['offset_mapping']:
            if a == b:
                labels.append(-100); prev = None; continue
            cur = cl[a] if a < len(cl) else None
            if cur is None:
                labels.append(label2id['O']); prev = None
            else:
                pref = 'I' if prev == cur else 'B'
                labels.append(label2id[f'{pref}-{cur}']); prev = cur
        enc.pop('offset_mapping'); enc['labels'] = labels
        return enc

def preprocess_logits_for_metrics(logits, labels):
    # Argmax on-device so the Trainer accumulates predicted class ids (1 int/token) instead of the full
    # 41-way logits at eval gather. ~41x less eval memory: avoids OOM on the shared GPU during evaluation.
    return logits.argmax(dim=-1)


def compute_metrics(eval_pred):
    # preds are already argmaxed by preprocess_logits_for_metrics (NOT raw logits).
    preds, labels = eval_pred
    true_tags, pred_tags = [], []
    for p_row, l_row in zip(preds, labels):
        tt, pt = [], []
        for p, l in zip(p_row, l_row):
            if l == -100:
                continue
            tt.append(id2label[int(l)])
            pt.append(id2label[int(p)])
        true_tags.append(tt)
        pred_tags.append(pt)
    rep = classification_report(true_tags, pred_tags, output_dict=True, zero_division=0)
    macro = rep.get("macro avg", {}).get("f1-score", 0.0)
    cat = [rep[l]["f1-score"] for l in CATASTROPHIC if l in rep]
    cat_f1 = float(np.mean(cat)) if cat else 0.0
    return {"macro_f1": float(macro), "cat_f1": cat_f1,
            "micro_f1": float(rep.get("micro avg", {}).get("f1-score", 0.0))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default='FacebookAI/xlm-roberta-base')
    ap.add_argument('--data', default='/opt/ossredact/datasets/pii-merged-v6')
    ap.add_argument('--labels', default='')
    ap.add_argument('--out', required=True)
    ap.add_argument('--epochs', type=float, default=3.0)
    ap.add_argument('--bs', type=int, default=16)
    ap.add_argument('--lr', type=float, default=3e-5)
    ap.add_argument('--max-len', type=int, default=256)
    ap.add_argument('--trust-remote-code', action='store_true',
                    help='needed for bases with custom modeling code (e.g. EuroBERT)')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    data = Path(args.data)
    load_labels(args.labels or (data / 'labels.json'))
    os.environ.setdefault('HF_HUB_OFFLINE', '0')  # allow first-time base download
    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=args.trust_remote_code)
    if args.dry_run:
        ds = TCDataset(data / 'train.jsonl', tok, args.max_len)
        for idx in [0, 1, 2]:
            enc = ds[idx]; toks = tok.convert_ids_to_tokens(enc['input_ids'])
            pairs = [(t, id2label[l]) for t, l in zip(toks, enc['labels']) if l != -100 and id2label[l] != 'O']
            print('TEXT:', ds.rows[idx]['input'][:120]); print('  NON-O:', pairs[:24]); print()
        return
    model = AutoModelForTokenClassification.from_pretrained(
        args.base, num_labels=len(BIO), id2label=id2label, label2id=label2id,
        ignore_mismatched_sizes=True, trust_remote_code=args.trust_remote_code)
    train_ds = TCDataset(data / 'train.jsonl', tok, args.max_len)
    val_ds = TCDataset(data / 'val.jsonl', tok, args.max_len)
    collator = DataCollatorForTokenClassification(tok)
    targs = TrainingArguments(
        output_dir=args.out, num_train_epochs=args.epochs, per_device_train_batch_size=args.bs,
        per_device_eval_batch_size=32, learning_rate=args.lr, weight_decay=0.01, warmup_ratio=0.05,
        fp16=True, logging_steps=100, eval_strategy='epoch', save_strategy='epoch', save_total_limit=1,
        report_to=[], seed=42, load_best_model_at_end=True,
        metric_for_best_model='cat_f1', greater_is_better=True)
    trainer = Trainer(model=model, args=targs, train_dataset=train_ds, eval_dataset=val_ds,
                      data_collator=collator, tokenizer=tok,
                      compute_metrics=compute_metrics,
                      preprocess_logits_for_metrics=preprocess_logits_for_metrics)
    trainer.train(); trainer.save_model(args.out); tok.save_pretrained(args.out)
    print(json.dumps({'saved': args.out, 'base': args.base, 'labels': len(BIO)}, indent=2))

if __name__ == '__main__':
    main()
