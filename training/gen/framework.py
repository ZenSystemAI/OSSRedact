#!/usr/bin/env python3
"""Offset-true document builder for the Phase 3 PII corpus (design spec section 5).

The whole point: record each labeled value's char span AT APPEND TIME, so text[start:end] == value BY
CONSTRUCTION. This eliminates the text.find() step (and its find-failures on repeated/substring values)
that the legacy value-list pipeline relied on.

Usage:
    d = Doc(doctype='flinks_stmt', lang='fr')
    d.add("Titulaire: ")              # negative/filler text (never labeled)
    d.field("Marie Tremblay", "person")
    d.add("\\nSolde ")
    d.decoy("1 234,56 $")             # hard negative: in the text, deliberately NOT labeled
    row = d.row()                     # -> {input, output:{spans, entities}, meta}

`spans` is the offset-true source of truth. `entities` is derived (value-lists) for backward-compat with
the legacy harness/trainer and for human readability. Decoys live in the text but never in spans/entities;
the model learns them as O (this is how hard-negative look-alikes teach precision).
"""
from __future__ import annotations


class Doc:
    def __init__(self, doctype: str = '', lang: str = 'fr'):
        self.doctype = doctype
        self.lang = lang
        self._parts: list[str] = []
        self._len = 0
        self._spans: list[tuple[int, int, str]] = []
        self._decoys: list[tuple[int, int]] = []

    def add(self, text: str) -> 'Doc':
        """Append negative/filler text (never labeled)."""
        if text:
            self._parts.append(text)
            self._len += len(text)
        return self

    def field(self, value: str, label: str) -> 'Doc':
        """Append a labeled PII value, recording its exact (start, end, label) span."""
        s = self._len
        self._parts.append(value)
        self._len += len(value)
        self._spans.append((s, self._len, label))
        return self

    def decoy(self, value: str) -> 'Doc':
        """Append a hard-negative look-alike: present in the text, deliberately NOT labeled."""
        s = self._len
        self._parts.append(value)
        self._len += len(value)
        self._decoys.append((s, self._len))
        return self

    def text(self) -> str:
        return ''.join(self._parts)

    def row(self) -> dict:
        text = self.text()
        ents: dict[str, list[str]] = {}
        for s, e, lab in self._spans:
            ents.setdefault(lab, []).append(text[s:e])
        return {
            'input': text,
            'output': {
                'spans': [[s, e, lab] for (s, e, lab) in self._spans],
                'entities': ents,
            },
            'meta': {'doctype': self.doctype, 'lang': self.lang, 'synthetic': True,
                     'n_decoys': len(self._decoys)},
        }
