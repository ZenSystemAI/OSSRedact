# Cache stability + autocompaction closure (2026-06-27)

> **PII-free.** The automated proof uses synthetic cued entities only (made-up codenames "Falcon"/"Tango")
> against a loopback mock upstream. No real Anthropic credentials were used and nothing was sent to
> api.anthropic.com. Reproduce with `validation/m5_live_cache_proof.py`.

## Why this run exists

The operator's "context balloons one-shot / 5h usage climbs fast" symptom had two root causes, both
already fixed at HEAD and unit-tested:

1. **Prompt-cache busting.** The pass-3 known-value sweep applies the WHOLE (growing) entity map to
   every field every turn, so a value first minted on a LATER turn was retroactively redacted into the
   re-sent system prefix, shifting its bytes and busting Anthropic's prompt cache (the whole prefix
   re-processed every turn). Fix: the freeze memo ("redact once, replay verbatim") -- commit `79b9e60`,
   unit test `test_egress_e2e.py::test_prompt_cache_freeze_keeps_prefix_bytes_stable_across_turns`.
2. **Autocompaction silently disabled.** Claude Code's `GET /api/claude_cli/bootstrap` 404'd through
   the gate, so for `claude-opus-4-8` (not in CC's hardcoded fallback window set) the
   `autoCompactWindow` source resolved to `"auto"`, and CC gates BOTH autocompact paths on
   `source != "auto"` -- the conversation then grew unbounded (we observed a cached prefix marching to
   ~579k tokens that never auto-compacted). Fix: forward the bootstrap route -- commit `d038d7b`,
   unit test `appliance/tests/test_bootstrap_passthrough.py`.

Both fixes were proven only against **fake upstreams in unit tests**. This run closes the gap with an
**automated live harness** that drives the real `egress_proxy.app` end-to-end.

## Automated proof (run 2026-06-27)

Harness: `validation/m5_live_cache_proof.py` (model-free, credential-free; runs in CI like
`m5_live_b5_proof.py`). A cue-detector is monkeypatched onto `egress_proxy._detect_neural` so the real
`/v1/messages` handler + `redact_body` run end-to-end without a neural gate; `FAIL_OPEN=1` keeps it
tier0-safe. Two `/v1/messages` turns with an IDENTICAL system prefix; turn 2 introduces a NEW
`codename:`-cued entity (`Falcon`) that, without freeze, mints into the map and is swept back into the
re-sent prefix.

Run command: `.venv-test/bin/python validation/m5_live_cache_proof.py`

Result: **ALL PASS** (exit 0).

```
turn-1 system (freeze ON): 'The Falcon dashboard is owned by codename: <ORGANIZATION_001> today.'
turn-2 system (freeze ON): 'The Falcon dashboard is owned by codename: <ORGANIZATION_001> today.'
control   (freeze OFF) t1: 'The Falcon dashboard is owned by codename: <ORGANIZATION_001> today.'
control   (freeze OFF) t2: 'The <ORGANIZATION_002> dashboard is owned by codename: <ORGANIZATION_001> today.'
bootstrap status/window : 200 / 200000

--- context-ballooning closure live checks ---
  [PASS] freeze ON: turn-2 system prefix == turn-1 (byte-identical)
  [PASS] freeze ON: turn-1 system still carries Falcon RAW (divergence is real)
  [PASS] freeze ON: Tango redacted in the prefix (turn 1 did work)
  [PASS] freeze OFF (control): turn-2 prefix DIVERGES from turn-1
  [PASS] freeze OFF (control): Falcon swept OUT of the re-sent prefix on turn 2
  [PASS] bootstrap: proxy forwards /api/claude_cli/bootstrap (200)
  [PASS] bootstrap: numeric autoCompactWindow returned
```

### What this proves (and what it does not)

- **Non-circular cache proof.** We assert the bytes WE emit upstream (the redacted system prefix) are
  byte-identical turn-over-turn -- the exact precondition Anthropic's cache requires -- NOT a
  mock-chosen `cache_read`. The freeze-OFF control proves the run genuinely exercises the divergence
  (turn-2 prefix shifts `Falcon` -> `<ORGANIZATION_002>`), so the freeze is what makes it stable.
- **Compaction enabler.** The proxy forwards `/api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8`
  and a numeric `autoCompactWindow` (200000) arrives -- the condition that flips CC's window source off
  `"auto"` so its autocompact paths can engage.
- **Not exercised here:** CC-side compaction itself. Only a real Claude Code client drives CC's
  `autoCompactWindowsCache` resolver and its `nLe()` autocompact gate. That is the live proof below.

## Live real-session proof (operator-run procedure)

Not run in this execution -- the `ossredact-gate-cpu` / `ossredact-egress` user services were
**inactive** at execution time and a live proof needs the operator's interactive Claude Code client +
real Anthropic credentials (not used here). The proxy-layer fixes above are proven; the steps below are
for the operator to capture the CC-side evidence.

### Setup

1. Start the services (or use the Phase 1 Firewall switch in the desktop console):
   `systemctl --user start ossredact-gate-cpu ossredact-egress`
2. Route a real `claude-opus-4-8` Claude Code session at the gate: flip "Route Claude Code" in the
   console, or set `ANTHROPIC_BASE_URL=http://127.0.0.1:8011` in `~/.claude/settings.json`. Run a long
   multi-turn session.
3. Confirm `GATEWAY_FREEZE_PREFIX` is on in the running unit (default is `1`):
   `systemctl --user show ossredact-egress -p Environment` (absent = default-on).

### What to confirm

- `prompt_cache=HIT` on turn 2+ EVERY turn. Tail the usage log:
  `journalctl --user -u ossredact-egress -f` and read the `[egress] usage ... prompt_cache=HIT|MISS`
  line (emitted by `_log_usage`, `egress_proxy.py:1603`). `MISS` every turn == the prefix is still
  busting (freeze not engaging / CC injecting a per-turn nonce into the system block).
- NO `map_evicted_present` lines (the FIFO-eviction placeholder-churn residual). If they appear in a
  very long session, raise `GATEWAY_MAP_MAX` above the session's entity count and note it here.
- CC's context bar **auto-compacts at the window** and does NOT march unbounded toward ~579k tokens
  (the original symptom). Record turn-by-turn `input` / `cache_read` and the compaction event.

### Contingency (if the live proof fails -- do NOT stall, diagnose then record)

- `prompt_cache=MISS` every turn: verify `ANTHROPIC_BASE_URL` truly points at the gate; verify
  `GATEWAY_FREEZE_PREFIX=1` in the running unit; verify CC's system prefix is genuinely byte-stable. If
  CC injects a per-turn timestamp/nonce into the system block, that is an upstream-client cause, not
  the gate -- record it as out-of-gate and stop.
- No compaction: `curl -s "http://127.0.0.1:8011/api/claude_cli/bootstrap?entrypoint=cli&model=<id>"`
  with a real auth header and confirm the REAL upstream returns a numeric `autoCompactWindow` for the
  EXACT model id CC is using. If the model id differs from `claude-opus-4-8`, substitute it everywhere
  (the autocompact window is per-model) and re-test.

## Status

- Proxy layer: **PROVEN** (automated live harness, all PASS).
- CC-client compaction layer: **procedure documented; not exercised this run** (services inactive; no
  live CC client or credentials used). Operator to run and append results here.
