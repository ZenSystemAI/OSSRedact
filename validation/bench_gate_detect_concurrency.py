#!/usr/bin/env python3
"""Sweep DETECT concurrency against the live :8001 detector to find the optimum. Read-only, synthetic text.
Also runs an ASYNC variant (httpx if present) to match the egress's real concurrency model, not just threads."""
import json, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

URL = "http://127.0.0.1:8001/detect"
_T = ("Customer {name} ({email}) at {org}, invoice INV-{n}, ship {addr}, phone {phone}, account 0{n}-12345, "
      "rep {name2} handled order #{n} card ending {cc}; escalated to billing for {org} re ticket {n}.")
_F = {"name": "Marguerite Beaulieu", "name2": "Tobias Nakamura", "email": "m.beaulieu@northwind-logistics.example",
      "org": "Northwind Logistics Inc", "addr": "4471 rue Sherbrooke Montreal QC H2X 1E9", "phone": "514-555-0182", "cc": "4319"}


def chunks(n):
    return [_T.format(n=1000 + i, **_F) for i in range(n)]


def call(text):
    body = json.dumps({"text": text, "min_score": 0.5}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        json.loads(r.read())


def run(cs, workers):
    t0 = time.perf_counter()
    if workers == 1:
        for c in cs:
            call(c)
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(call, cs))
    return (time.perf_counter() - t0) * 1000.0


def main():
    for _ in range(3):
        call(chunks(1)[0])  # warm
    N = 40
    cs = chunks(N)
    print(f"thread-pool sweep, N={N} fields (~best of 3 runs each):")
    print(f"{'workers':>8} {'total_ms':>9} {'per_call':>9} {'vs seq':>8}")
    base = None
    for w in (1, 2, 3, 4, 6, 8, 12, 16):
        runs = [run(cs, w) for _ in range(3)]
        ms = min(runs)
        if w == 1:
            base = ms
        print(f"{w:>8} {ms:>9.0f} {ms/N:>8.1f} {(base/ms if ms else 0):>7.2f}x")
    print("\n>1.0x = faster than sequential; <1.0x = SLOWER (GPU/GIL contention dominates).")

    # async variant (matches egress asyncio model) if httpx is importable in this interpreter
    try:
        import asyncio, httpx
    except Exception:
        print("\n(httpx not available in this interpreter -> skipping async variant; thread sweep is representative)")
        return

    async def acall(client, text):
        await client.post(URL, json={"text": text, "min_score": 0.5})

    async def arun(cs, conc):
        sem = asyncio.Semaphore(conc)
        async with httpx.AsyncClient(timeout=60) as client:
            async def one(c):
                async with sem:
                    await acall(client, c)
            t0 = time.perf_counter()
            await asyncio.gather(*[one(c) for c in cs])
            return (time.perf_counter() - t0) * 1000.0

    print(f"\nasyncio sweep (egress model), N={N}:")
    print(f"{'conc':>8} {'total_ms':>9} {'per_call':>9} {'vs seq':>8}")
    abase = None
    for conc in (1, 2, 3, 4, 8):
        runs = [asyncio.run(arun(cs, conc)) for _ in range(3)]
        ms = min(runs)
        if conc == 1:
            abase = ms
        print(f"{conc:>8} {ms:>9.0f} {ms/N:>8.1f} {(abase/ms if ms else 0):>7.2f}x")


if __name__ == "__main__":
    main()
