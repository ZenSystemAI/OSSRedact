#!/usr/bin/env python3
"""Replay / scoring harness for the egress redactor -- "observability becomes a regression suite".

The live gate is invisible in production, so detection-precision changes were being made blind. This harness
replays coding-agent-style traffic FIXTURES through a redactor and scores it on the axes that matter for the
live-gate (precision-first) path:

  - RECALL          : planted PII that MUST redact. A surviving must_redact token is a LEAK -- a hard failure.
  - OVER-REDACTION  : non-PII tokens (ports, versions, IPs, model names, code constants) that SHOULD pass
                      through. A redacted one is a false positive -- the live-gate's central pain on code.
  - REHYDRATION     : the local round-trip restores the original bytes exactly.
  - CACHE-STABILITY : replaying the same field twice in one session is byte-identical (prompt-cache safe).

It is decoupled from any specific redactor: callers inject `redact_fn(text, session) -> (redacted_text,
replay_map)`. Wire it to egress_proxy.redact_body for the current pipeline, or to a candidate config/model to
score a change BEFORE shipping it. detector choice lives in the caller's redact_fn: pass a no-op detector to
score the DETERMINISTIC tier-0 + policy layer offline (no GPU), or a real /detect client to also score neural.

No raw PII is ever stored here -- fixtures use synthetic values. Only `redact_core` (pure, dependency-free) is
imported, so the harness itself stays torch/network-free and CI-runnable.

A fixture is a dict:
    {'name': str, 'text': str, 'must_redact': [substr, ...], 'benign': [substr, ...]}
`must_redact` substrings are (synthetic) PII that must disappear from the output; `benign` substrings are
non-PII that must survive verbatim.
"""
import os

import redact_core


def score_case(case, redact_fn):
    """Replay one fixture twice in a fresh session and score it. Returns a per-case result dict."""
    session = 'replay-' + os.urandom(6).hex()
    out, replay_map = redact_fn(case['text'], session)
    # A second identical turn in the SAME session must be byte-stable (freeze / stable minting).
    out2, _ = redact_fn(case['text'], session)

    leaked = [tok for tok in case.get('must_redact', ()) if tok in out]                 # FN: PII survived
    over = [tok for tok in case.get('benign', ()) if tok in case['text'] and tok not in out]  # FP: benign redacted
    return {
        'name': case['name'],
        'out': out,
        'leaked_pii': leaked,
        'over_redacted': over,
        'rehydrate_ok': redact_core.rehydrate(out, replay_map) == case['text'],
        'cache_stable': out2 == out,
    }


def score(cases, redact_fn):
    """Score a fixture list against a redactor. Returns an aggregate scorecard.

    recall_ok is the HARD guarantee (no planted PII leaked); over_redaction is the precision footprint to drive
    down; all_rehydrate_ok / all_cache_stable guard the round-trip and prompt-cache invariants.
    """
    results = [score_case(c, redact_fn) for c in cases]
    return {
        'results': results,
        'leaks': sorted((r['name'], tok) for r in results for tok in r['leaked_pii']),
        'over_redaction': sorted((r['name'], tok) for r in results for tok in r['over_redacted']),
        'all_rehydrate_ok': all(r['rehydrate_ok'] for r in results),
        'all_cache_stable': all(r['cache_stable'] for r in results),
        'recall_ok': not any(r['leaked_pii'] for r in results),
        'over_redaction_count': sum(len(r['over_redacted']) for r in results),
    }
