#!/usr/bin/env python3
"""Pre-window a v11 corpus into the SAME char chunks the gate uses at inference (gate_service_gpu._chunks:
600 chars / 80 overlap, line-aware). Training on these chunks makes the train input distribution identical to
inference (the gate chunks every doc), eliminates max_len truncation loss (a 600-char chunk is ~300 tokens,
well under 512), and trains the model on MID/TAIL chunks it would otherwise never see (e.g. a credit_report
tradeline chunk, a long flinks transaction tail). Offset-true: each chunk keeps only the spans FULLY inside
it, re-based to the chunk. PII values are < the 80-char overlap, so every span lands fully in >=1 chunk; a
straddling span (only if longer than the overlap) is counted and reported (expected 0).

Pure stdlib (no tokenizer). Usage: python build_windows.py --in <dir> --out <dir>
"""
from __future__ import annotations
import sys, os, json, argparse, shutil, collections

CHUNK_CHARS, CHUNK_OVERLAP = 600, 80


def _windows(s, base, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    n = len(s); i = 0
    while i < n:
        end = min(i + size, n)
        if end < n:
            j = s.rfind(' ', max(i + size - overlap, i + 1), end)
            if j > i:
                end = j
        yield s[i:end], base + i
        if end >= n:
            break
        i = max(end - overlap, i + 1)


def _chunks(text, size=CHUNK_CHARS):
    buf, start, pos = '', 0, 0
    for ln in text.splitlines(keepends=True):
        if len(ln) > size:
            if buf:
                yield buf, start; buf = ''
            yield from _windows(ln, pos); pos += len(ln); start = pos; continue
        if buf and len(buf) + len(ln) > size:
            yield buf, start; buf, start = '', pos
        buf += ln; pos += len(ln)
    if buf:
        yield buf, start


def window_row(row, dropped):
    text = row['input']; spans = row['output'].get('spans') or []
    out = []
    for ch, off in _chunks(text):
        end = off + len(ch)
        csp = []
        for s, e, lab in spans:
            if s >= off and e <= end:                       # fully inside this chunk
                csp.append([s - off, e - off, lab])
            elif s < end and e > off:                       # straddles a boundary (should not happen, <80 char)
                dropped[lab] += 1
        ents = {}
        for s, e, lab in csp:
            ents.setdefault(lab, []).append(ch[s:e])
        meta = dict(row.get('meta', {})); meta['windowed'] = True
        out.append({'input': ch, 'output': {'spans': csp, 'entities': ents}, 'meta': meta})
    return out


def process(in_path, out_path, dropped):
    rows_in = rows_out = 0
    with open(out_path, 'w', encoding='utf-8') as w:
        for line in open(in_path, encoding='utf-8'):
            if not line.strip():
                continue
            rows_in += 1
            for wr in window_row(json.loads(line), dropped):
                w.write(json.dumps(wr, ensure_ascii=False) + '\n'); rows_out += 1
    return rows_in, rows_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    dropped = collections.Counter()
    for fn in ('train.jsonl', 'val.jsonl', 'test.jsonl'):
        src = os.path.join(args.inp, fn)
        if not os.path.exists(src):
            continue
        ri, ro = process(src, os.path.join(args.out, fn), dropped)
        print(f"{fn}: {ri} docs -> {ro} chunks ({ro/ri:.2f}x)")
    lp = os.path.join(args.inp, 'labels.json')
    if os.path.exists(lp):
        shutil.copy(lp, os.path.join(args.out, 'labels.json'))
    if dropped:
        print("WARNING: spans dropped at chunk boundaries (value longer than overlap):", dict(dropped))
    else:
        print("OK: no spans dropped at chunk boundaries (every value fully contained in >=1 chunk)")


if __name__ == '__main__':
    main()
