#!/usr/bin/env python3
"""Plan 026 option A -- prove the carrier-wrap booster against a live gate. PII-free (synthetic names).

The xlm-roberta person detector scores ZERO on a rare name presented as a BARE structural value
(a JSON value / short arg) -- no prose to cue it -- and there is no Tier-0 floor for names, so it
would leak through the egress. The booster (appliance/name_carrier.py) re-scans a name-shaped value
inside a prose carrier and maps the verdict back. This script runs the REAL module against a REAL
gate and reports recall (names recovered from bare-miss) + a false-positive spot check.

No internal host is committed: the gate URL defaults to $OSSREDACT_GATE_URL, else localhost:8001.
  OSSREDACT_GATE_URL=http://<gate-host>:8001 python3 validation/carrier_recall_probe.py
"""
import os
import sys
import json
import asyncio
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'appliance'))
from name_carrier import carrier_person_spans, name_shaped  # noqa: E402

GATE = os.environ.get('OSSREDACT_GATE_URL', 'http://localhost:8001').rstrip('/') + '/detect'


def _detect_sync(text, min_score=0.5):
    body = json.dumps({'text': text, 'min_score': min_score}).encode()
    req = urllib.request.Request(GATE, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read()).get('spans', [])


async def detect_fn(text, min_score=0.5):
    # mirror egress _detect_neural's contract: spans list, or None on gate error
    try:
        return await asyncio.to_thread(_detect_sync, text, min_score)
    except Exception as e:
        print(f'[gate error] {type(e).__name__}', flush=True)
        return None


async def bare_has_person(value):
    spans = await detect_fn(value)
    return bool(spans) and any(s.get('label') == 'person' for s in spans)


# realistic, diverse, lower-frequency REAL-WORLD names (not fantasy). Synthetic test data.
NAMES = ['Priya McCallum', 'Nguyen Thanh Hai', 'Oluwaseun Adeyemi', 'Mateusz Wojcik',
         'Anjali Venkataraman', 'Dmitri Kowalczyk', 'Fatima Al-Rashid', 'Bjorn Sigurdsson',
         'Xiomara Beltran', 'Thandiwe Mkhize']
# non-name short values that ARE name-shaped lexically -- must NOT be recovered as persons (precision)
NON_NAMES = ['active', 'pending', 'Premium Plan', 'Customer Service', 'Standard', 'Completed']


async def main():
    print(f'gate = {GATE}\n')
    bare_miss = recovered = 0
    print('name                       name_shaped  bare-scan  carrier-booster')
    for nm in NAMES:
        shaped = name_shaped(nm)
        bare = await bare_has_person(nm)
        if not bare:
            bare_miss += 1
        boosted = bool(await carrier_person_spans(detect_fn, nm)) if shaped else False
        if boosted:
            recovered += 1
        print(f'  {nm:<24} {str(shaped):<11} {"HIT" if bare else "miss":<9} {"HIT" if boosted else "MISS"}')
    fp = [v for v in NON_NAMES if name_shaped(v) and await carrier_person_spans(detect_fn, v)]
    print(f'\n  bare-form misses: {bare_miss}/{len(NAMES)}')
    print(f'  carrier-booster recall (names recovered): {recovered}/{len(NAMES)}')
    print(f'  false positives on non-name values: {len(fp)}/{len(NON_NAMES)} {fp}')

if __name__ == '__main__':
    asyncio.run(main())
