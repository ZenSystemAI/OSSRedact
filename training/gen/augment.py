#!/usr/bin/env python3
"""Inference-matching augmenters for the PII corpus (Phase 3 Task 3.3).

Real documents (PDF extraction, bank statements, forms) arrive ALL-CAPS, with NBSP separators, and with
unicode dashes. The model must be robust to these. Each augmenter here is LENGTH-PRESERVING (every char
maps to exactly one char), so the offset-true spans stay valid: text[start:end] still slices the value,
just cased/spaced/dashed differently. After transforming the text, the derived entities value-lists are
rebuilt from the (unchanged) span offsets.

Use: pick an augmenter (or compose) on a FRACTION of generated rows in build_dataset.py. The originals
stay too, so the model sees both clean and perturbed forms.
"""
from __future__ import annotations
import copy

# Length-preserving (1 char -> 1 char) accent fold. Models PDF/OCR extraction that drops Quebec-French
# accents (real docs carry them; some extractors strip them). 1->many folds (oe/ae) are deliberately
# omitted so offsets stay exact, exactly like _upper_char guards uppercasing below.
_ACCENT_MAP = str.maketrans(
    "àâäáãçčéèêëěíìîïñóòôöõšúùûüýÿžÀÂÄÁÃÇČÉÈÊËĚÍÌÎÏÑÓÒÔÖÕŠÚÙÛÜÝŸŽ",
    "aaaaacceeeeeiiiinooooosuuuuyyzAAAAACCEEEEEIIIINOOOOOSUUUUYYZ",
)

_NBSP = " "
_ENDASH = "–"
_EMDASH = "—"


def _upper_char(c: str) -> str:
    u = c.upper()
    return u if len(u) == 1 else c   # never let a 1->many uppercasing (e.g. ss) change length


def _rebuild(row: dict, new_text: str) -> dict:
    out = copy.deepcopy(row)
    out['input'] = new_text
    ents: dict[str, list[str]] = {}
    for s, e, lab in out['output']['spans']:
        ents.setdefault(lab, []).append(new_text[s:e])
    out['output']['entities'] = ents
    out['meta'] = dict(out.get('meta', {}))
    out['meta']['aug'] = out['meta'].get('aug', '')
    return out


def caps(row: dict) -> dict:
    """ALL-CAPS the whole document (length-preserving)."""
    t = ''.join(_upper_char(c) for c in row['input'])
    r = _rebuild(row, t); r['meta']['aug'] = 'caps'; return r


def nbsp(row: dict) -> dict:
    """Replace ASCII spaces with NBSP (defeats naive whitespace splitting; length-preserving)."""
    t = row['input'].replace(' ', _NBSP)
    r = _rebuild(row, t); r['meta']['aug'] = 'nbsp'; return r


def dashes(row: dict) -> dict:
    """Replace ASCII hyphens with unicode en/em dashes (PDF extraction artifact; length-preserving)."""
    t = row['input'].replace('-', _ENDASH)
    r = _rebuild(row, t); r['meta']['aug'] = 'dashes'; return r


def accents(row: dict) -> dict:
    """Fold Quebec-French accents to ASCII (length-preserving; PDF/OCR extraction artifact)."""
    t = row['input'].translate(_ACCENT_MAP)
    r = _rebuild(row, t); r['meta']['aug'] = 'accents'; return r


def augmenters() -> dict:
    """Registry of length-preserving augmenters keyed by name."""
    return {'caps': caps, 'nbsp': nbsp, 'dashes': dashes, 'accents': accents}
