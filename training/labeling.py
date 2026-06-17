#!/usr/bin/env python3
"""Torch-free char-level label assignment for the PII trainer + harness.

Two paths, both returning a list[Optional[str]] of length len(text): the canonical label owning each char,
or None (O). Labels not in `canon` are skipped (treated as O).

 - char_label_array_from_spans: offset-true. Phase 3 (v10) rows carry output.spans = [[start,end,label]].
   No text.find, so no find-failures and no substring/duplicate ambiguity.
 - char_label_array: legacy value-list path (output.entities = {label:[values]}); locates each value via
   text.find. Kept so pre-v10 datasets (e.g. pii-merged-v9-remap) still train + eval unchanged.
"""
from __future__ import annotations


def char_label_array_from_spans(text, spans, canon):
    n = len(text)
    charlab = [None] * n
    # longest span first so a shorter contained span cannot override a real one (defensive; the generators
    # should never emit overlapping spans).
    for s, e, lab in sorted(spans, key=lambda x: -(x[1] - x[0])):
        if lab not in canon:
            continue
        for k in range(max(0, s), min(e, n)):
            if charlab[k] is None:
                charlab[k] = lab
    return charlab


def char_label_array(text, ents, canon):
    n = len(text)
    charlab = [None] * n
    taken = [False] * n
    spans = []
    for lab, vals in ents.items():
        if lab not in canon:
            continue
        for v in vals:
            if not v:
                continue
            start = 0
            while True:
                i = text.find(v, start)
                if i < 0:
                    break
                spans.append((i, i + len(v), lab))
                start = i + len(v)
    spans.sort(key=lambda s: -(s[1] - s[0]))
    for s, e, lab in spans:
        if any(taken[s:e]):
            continue
        for k in range(s, e):
            taken[k] = True
            charlab[k] = lab
    return charlab
