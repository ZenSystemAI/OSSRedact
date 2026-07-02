# Gate detector latency + detect-concurrency sweep (2026-06-21)

> **PII-free.** Synthetic fields only (made-up names/emails/orgs), measured against the LIVE deployed detector.
> Nothing was forwarded to any upstream API; the benchmark hits only `127.0.0.1:8001/detect` (raw spans, no
> substitution). Reproduce with `validation/bench_gate_detect_concurrency.py` + `bench_gate_detect_latency.py`.

## Why this run exists

A workflow latency audit hypothesized the **sequential per-field `/detect` loop was the dominant request
latency** (estimated 20-60ms/call x N fields = "seconds"), and we shipped a concurrent loop
(`collect_detected_fields`, `GATEWAY_DETECT_CONCURRENCY`, default 8). Per the work-discipline rule we then
**measured before trusting the table** -- against the actual deployed gate, not an estimate. The measurement
overturned the hypothesis.

## Setup

- Host: a GB10 (Grace Blackwell) box; the gate container's detector = `gate_service_gpu.py` serving
  `ZenSystemAI/ossredact-pii-large` (XLM-R-large, fp16, CUDA), warm (16h uptime).
- Detector is **loopback** (`127.0.0.1:8001`), **single CUDA stream**, **sync FastAPI handler** (Starlette
  threadpool), no tensor batching.
- Client: stdlib `urllib` + `ThreadPoolExecutor`. N=40 synthetic ~250-char fields with embedded entities so the
  NER does real work. Best-of-3 per cell.

## Results

Single warm call: **~6-8 ms** (loopback + warm GPU), NOT the 20-60ms the audit assumed.

Concurrency sweep, N=40 fields:

| workers | total ms | per-call ms | vs sequential |
|--:|--:|--:|--:|
| 1 | 263 | 6.6 | 1.00x (baseline) |
| **2** | **246** | **6.1** | **1.07x (optimum)** |
| 3 | 254 | 6.3 | 1.04x |
| 4 | 268 | 6.7 | 0.98x |
| 6 | 338 | 8.5 | 0.78x |
| 8 | 381 | 9.5 | 0.69x |
| 12 | 494 | 12.3 | 0.53x |
| 16 | 511 | 12.8 | 0.51x |

## Conclusions

1. **The detector is fast (~6-8ms/call) and the per-field loop was never "seconds."** The original audit's
   20-60ms/call assumption was wrong for a loopback + warm GPU.
2. **Client concurrency does NOT parallelize this detector.** One CUDA stream + GIL-bound post-processing
   (tokenize / `softmax().cpu().numpy()` / Python BIO decode) means concurrent requests CONTEND. Optimum is ~2
   (+7%, near noise); **>=6 regresses sharply** (8 = 0.69x = 31% SLOWER). The shipped default of 8 was a
   regression.
3. **Fix applied:** `GATEWAY_DETECT_CONCURRENCY` default 8 -> **2**. The concurrency machinery is kept (tested,
   and the substrate for a future batched endpoint) but capped low; raise only if the detector becomes remote
   (RTT to hide) or batched (P2).
4. **The real latency lever was the cache-bust fix**, not detector fan-out: the opaque-thinking change stops the
   gate mutating the cached prefix every turn, which restores Anthropic prompt caching (the "context maxed / 5h
   usage climbs fast" symptom = the whole prompt re-processing each turn). The LRU `_DETECT_CACHE` fix
   (was: froze at 4096 entries) keeps repeated system-prompt/history fields as ~0ms cache hits.

## Bearing on the P2 (batched `/detect`) decision

A batched GPU endpoint targets exactly the single-stream underutilization measured here. But at ~6-8ms/call with
the cache absorbing repeated fields, the gate's share of per-turn latency after the cache-bust fix is small.
**Recommendation stands: deploy the committed fix, measure real per-turn latency end-to-end, and only build P2
if the gate scan is still a meaningful fraction.** This sweep is the detector-isolated baseline for that decision.
