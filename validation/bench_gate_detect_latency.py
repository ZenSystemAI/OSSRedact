#!/usr/bin/env python3
"""Read-only latency benchmark for the OSSRedact GPU detector (:8001).

Measures the wall-clock difference between SEQUENTIAL per-field /detect calls (the old egress behavior) and
8-way CONCURRENT calls (the new behavior shipped in egress_proxy.collect_detected_fields), against the LIVE
detector. Synthetic text only (no real PII, nothing forwarded upstream). Stdlib only.

Run on the detector host (the /detect detector binds loopback): python3 bench_gate_detect_latency.py
"""
import json, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

URL = "http://127.0.0.1:8001/detect"
CONC = 8

# Representative ~500-char fields with embedded entities so the NER does real work (names/emails/orgs/numbers/paths).
_TEMPLATES = [
    "Customer {name} ({email}) at {org} called about invoice INV-{n}. Ship to {addr}. Phone {phone}. "
    "Notes: follow up re account 0{n}-0{n}-12345 and confirm the SIN on file. The rep {name2} handled it. "
    "Prior ticket referenced order #{n} and a card ending {cc}. Escalated to billing for {org}.",
    "def process_{w}(user):\n    # {name} reported a bug in {org}'s pipeline at /home/{w}/src/app.py\n"
    "    record = {{'email': '{email}', 'phone': '{phone}', 'note': 'contact {name2} or {email2}'}}\n"
    "    return record  # ref ticket {n}, account 1{n}-22-{n}",
    "Meeting notes {name} / {name2}: discussed the {org} migration. Action items: email {email}, call {phone}, "
    "update the address {addr}. Budget approved for Q{n}. Legacy creds rotated. Follow up with {org} security. "
    "The contract id is CT-{n}-{n} and the renewal is next month per {name2}.",
]
_F = {"name": "Marguerite Beaulieu", "name2": "Tobias Nakamura", "email": "m.beaulieu@northwind-logistics.example",
      "email2": "t.nakamura@example.org", "org": "Northwind Logistics Inc", "addr": "4471 rue Sherbrooke, Montreal QC H2X 1E9",
      "phone": "514-555-0182", "cc": "4319", "w": "alex"}


def make_chunks(n):
    out = []
    for i in range(n):
        t = _TEMPLATES[i % len(_TEMPLATES)]
        out.append(t.format(n=1000 + i, **_F))
    return out


def call(text):
    body = json.dumps({"text": text, "min_score": 0.5}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as r:
        j = json.loads(r.read())
    return (time.perf_counter() - t0) * 1000.0, len(j.get("spans", []))


def run_seq(chunks):
    t0 = time.perf_counter()
    per = [call(c)[0] for c in chunks]
    return (time.perf_counter() - t0) * 1000.0, per


def run_conc(chunks, workers=CONC):
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        per = [x[0] for x in ex.map(lambda c: call(c), chunks)]
    return (time.perf_counter() - t0) * 1000.0, per


def main():
    # warm up (detector is already warm at 16h uptime; this just primes the TCP path + measures single-call latency)
    warm = [call(make_chunks(1)[0])[0] for _ in range(3)]
    print(f"warmup single-call latency ms: {[round(x,1) for x in warm]}  (median ~{round(sorted(warm)[len(warm)//2],1)}ms)\n")
    print(f"{'N':>4} {'seq_ms':>9} {'conc8_ms':>9} {'speedup':>8} {'seq/call':>9} {'conc/call':>9}")
    for n in (5, 10, 20, 40, 80):
        chunks = make_chunks(n)
        # alternate to avoid one mode eating a transient: run conc first then seq, average is fine for a ratio
        c_ms, c_per = run_conc(chunks)
        s_ms, s_per = run_seq(chunks)
        sp = s_ms / c_ms if c_ms else 0
        print(f"{n:>4} {s_ms:>9.0f} {c_ms:>9.0f} {sp:>7.2f}x {s_ms/n:>8.1f} {c_ms/n:>8.1f}")
    print("\nseq = old serial per-field loop; conc8 = new concurrent loop (GATEWAY_DETECT_CONCURRENCY=8).")
    print("per-call >> conc/call means the GPU is NOT the only floor (HTTP/CPU overlap is being recovered).")


if __name__ == "__main__":
    main()
