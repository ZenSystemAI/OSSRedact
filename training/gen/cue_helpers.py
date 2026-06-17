#!/usr/bin/env python3
"""Shared cue/format helpers for the v11 round-2 recall-first cue diversification.

NEW module (values.py stays FROZEN). These helpers only FORMAT values that the existing V.* samplers
already produce -- they add the terse / inline / brand / positional CUE vocabulary the held-out layouts
use, so TRAIN layouts can teach those cue-types WITHOUT copying held-out STRUCTURES. The point (recall-
first, design spec 3.8 catastrophic tier R>=0.99): the model must learn that a payment_card can be cued
by a network brand, a government_id by inline prose, an account_number by bare position -- not only by a
formal 'Field:' label. Caller seeds `random`.
"""
from __future__ import annotations


def brand_label(card: str, lang: str = "en") -> str:
    """Network brand for a payment_card PAN, by IIN prefix, so a brand-cued line names the network that
    matches the digits (VISA 4xxx / MASTERCARD 5xxx / AMEX 3xxx). Tolerant of grouped/hyphen/bare forms."""
    d = card.strip().lstrip()
    first = next((c for c in d if c.isdigit()), "4")
    if first == "4":
        return "VISA"
    if first == "3":
        return "AMEX"
    if first == "5":
        return "MASTERCARD"
    return "VISA"


def group_digits(run: str, sizes=(3, 3, 4), sep: str = " ") -> str:
    """Regroup a bare digit run into a spaced/sep form (e.g. '8811471049' -> '881 147 1049'). Used to
    teach the spaced registry/business-number variant some real docs print. Non-digits are stripped first;
    if the run length does not fit `sizes`, the trailing group absorbs the remainder."""
    s = "".join(c for c in run if c.isdigit())
    if not s:
        return run
    parts, i = [], 0
    for n, sz in enumerate(sizes):
        if i >= len(s):
            break
        # last declared group absorbs everything left
        if n == len(sizes) - 1:
            parts.append(s[i:])
            i = len(s)
        else:
            parts.append(s[i:i + sz])
            i += sz
    if i < len(s):
        parts.append(s[i:])
    return sep.join(parts)
