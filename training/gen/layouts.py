#!/usr/bin/env python3
"""Deterministic train/heldout layout-pool split for the real-structure held-out eval (v11).

Operator data strategy (2026-06-15): the held-out eval must use REAL document STRUCTURES DISTINCT from
training, so the corpus does NOT saturate (the v10 problem: xlm-r-large hit 1.0) and the eval measures
STRUCTURAL generalization -- the proxy for redacting real documents whose exact layout we never saw, and
the lever that closes the train->real gap.

Mechanism: each scaffold-grounded generator exposes `LAYOUTS` = a list of >=2 distinct real-grounded
structural variant builders. We partition that list BY INDEX into a train-only prefix and a heldout-only
suffix (disjoint). build_dataset draws from the train pool (split='train'); build_heldout draws from the
heldout pool (split='heldout'). Because the partition is by fixed index (not seeded), the two splits NEVER
share a structure. Values are always fresh-sampled (the two builders seed `random` differently), so values
never overlap either -- this isolates the STRUCTURE axis as the thing the held-out actually tests.

Order convention: list the MOST structurally-distinct / hardest variant(s) LAST so the held-out gets a
genuinely different real structure, not a reworded near-duplicate.
"""
from __future__ import annotations
import random


def split_pools(layouts, heldout_frac: float = 0.34):
    """Partition a LAYOUTS list into (train_pool, heldout_pool), disjoint, by index.

    The last k = max(1, round(heldout_frac*N)) layouts are held-out-only; the rest are train-only.
    Always leaves >=1 layout in each pool. Requires N>=2 (a doctype with a single structure cannot give the
    held-out an unseen structure -- give it >=2 real variants, or reserve the whole doctype heldout-only at
    the corpus level)."""
    n = len(layouts)
    if n < 2:
        raise ValueError(f"need >=2 layouts to split train/heldout, got {n}")
    k = max(1, round(heldout_frac * n))
    k = min(k, n - 1)                       # always keep >=1 train layout
    return layouts[: n - k], layouts[n - k:]


def choose(split: str, layouts, heldout_frac: float = 0.34, rng=random):
    """Pick one layout builder from the train- or heldout-partition. `rng` defaults to the module-level
    `random`, which the caller (build_dataset / build_heldout) seeds -- same convention as the generators."""
    train_pool, heldout_pool = split_pools(layouts, heldout_frac)
    pool = train_pool if split == "train" else heldout_pool
    return rng.choice(pool)
