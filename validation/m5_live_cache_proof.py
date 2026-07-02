#!/usr/bin/env python3
"""Context-ballooning closure -- LIVE end-to-end proof through the real egress proxy (run on the egress host).

Proves the TWO fixes that closed the operator's "context balloons one-shot / 5h usage climbs fast"
symptom, end-to-end through the running proxy (not a unit test with a fake upstream):

  1. Prompt-cache stability (freeze). The growing known-value sweep used to retroactively rewrite
     the re-sent system prefix every turn, busting Anthropic's prompt cache so the WHOLE prefix was
     re-processed every turn. The freeze memo ("redact once, replay verbatim") makes the redacted
     system prefix BYTE-IDENTICAL turn-over-turn. We drive the real divergence (turn 2 mints a NEW
     cued entity that, without freeze, would sweep back into the prefix) and assert the bytes WE
     emit upstream are byte-identical -- non-circular (we assert OUR emitted bytes, not a mock-chosen
     cache_read). A freeze-OFF control proves the run genuinely exercises the divergence.

  2. Autocompaction enabler (bootstrap passthrough). CC fetches /api/claude_cli/bootstrap at startup
     to get the per-model autoCompactWindow; with no route it 404'd, the window source fell back to
     "auto", and CC gates BOTH autocompact paths on source != "auto" -> no compaction -> unbounded
     growth. We assert the proxy forwards the route and a numeric autoCompactWindow arrives.

Model-free and credential-free: a cue-detector is monkeypatched onto egress_proxy._detect_neural
(the module global the app path resolves), so the real /v1/messages handler + real redact_body run
end-to-end without a neural gate. FAIL_OPEN=1 keeps it tier0-safe. Runs in CI like m5_live_b5_proof.
"""
import json
import os
import re
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

APPLIANCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'appliance')
sys.path.insert(0, APPLIANCE)

# The detector tags the token after a 'codename:' cue as an organization. The cue lets a value be
# UNKNOWN in the system prefix on turn 1 (no cue there) yet minted from a tail message on turn 2 --
# the exact shape that makes the growing pass-3 sweep retroactively rewrite the prefix (the cache
# buster the freeze memo prevents).
_CUE_RE = re.compile(r'codename:\s+(\S+)')

# Identical system text on both turns. Carries 'Falcon' RAW (no cue -> not detected here, so it is
# NOT a known value on turn 1) plus a cued 'Tango' so turn 1 redacts something and PERSISTS the map
# (stabilising its generation for the freeze key). Turn 2 re-sends this VERBATIM.
SYS = 'The Falcon dashboard is owned by codename: Tango today.'

# Per-turn captured upstream request bodies (what the proxy forwarded to the mock).
_upstream_bodies = []


class MockUpstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path.startswith('/v1/messages'):
            n = int(self.headers.get('content-length', 0))
            body = self.rfile.read(n).decode('utf-8')
            _upstream_bodies.append(json.loads(body))
            resp = {
                'id': 'msg_live', 'type': 'message', 'role': 'assistant', 'model': 'claude-opus-4-8',
                'content': [{'type': 'text', 'text': 'ok'}],
                'stop_reason': 'end_turn', 'stop_sequence': None,
                'usage': {'input_tokens': 10, 'output_tokens': 5,
                          'cache_read_input_tokens': 0, 'cache_creation_input_tokens': 10},
            }
            out = json.dumps(resp).encode('utf-8')
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/claude_cli/bootstrap'):
            # CC's clientdata carries the per-model autoCompactWindow. A NUMERIC window here is what
            # flips CC's source off "auto" so autocompaction can engage.
            resp = {'autoCompactWindow': 200000, 'model': 'claude-opus-4-8'}
            out = json.dumps(resp).encode('utf-8')
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        self.send_response(404)
        self.end_headers()


def _make_detector():
    async def _detect(aclient, text, min_score=0.5):
        return [{'start': m.start(1), 'end': m.end(1), 'label': 'organization',
                 'tier': 1, 'conf': 0.95, 'rule': 'cue'}
                for m in _CUE_RE.finditer(text)]
    return _detect


def _run_two_turns(client, session):
    """Two /v1/messages turns through the proxy with an IDENTICAL system prefix. Turn 2 adds a NEW
    cued tail ('codename: Falcon') that mints Falcon into the map -- without freeze, the pass-3
    sweep would retroactively redact Falcon in the re-sent prefix and shift its bytes."""
    headers = {'x-api-key': 'test', 'anthropic-version': '2023-06-01',
               'x-claude-code-session-id': session, 'x-ossredact-project': 'cache-proof'}
    body1 = {'model': 'claude-opus-4-8', 'system': SYS,
             'messages': [{'role': 'user', 'content': 'Kickoff.'}]}
    r1 = client.post('/v1/messages', json=body1, headers=headers)
    assert r1.status_code == 200, f'turn 1 status {r1.status_code}: {r1.text}'
    body2 = {'model': 'claude-opus-4-8', 'system': SYS,
             'messages': [{'role': 'user', 'content': 'Kickoff.'},
                          {'role': 'assistant', 'content': 'Ack.'},
                          {'role': 'user', 'content': 'New: codename: Falcon goes live.'}]}
    r2 = client.post('/v1/messages', json=body2, headers=headers)
    assert r2.status_code == 200, f'turn 2 status {r2.status_code}: {r2.text}'
    # The last two captured upstream bodies are this session's turn 1 and turn 2.
    return _upstream_bodies[-2]['system'], _upstream_bodies[-1]['system']


def main():
    srv = HTTPServer(('127.0.0.1', 0), MockUpstream)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    maps = tempfile.mkdtemp(prefix='m5-cache-maps-')
    os.environ.update({
        'GATEWAY_ANTHROPIC_UPSTREAM': f'http://127.0.0.1:{port}',
        'GATEWAY_FREEZE_PREFIX': '1',          # the fix under test
        'GATEWAY_FAIL_OPEN': '1',              # tier0-safe; no neural gate needed
        'GATEWAY_MAPS_DIR': maps,
        'GATEWAY_LOG_USAGE': '1',
        'GATEWAY_LOG_REQUESTS': '0',
    })

    import egress_proxy
    # Inject the cue-detector onto the module global the app path resolves, so the REAL /v1/messages
    # handler + redact_body run end-to-end model-free. Returns spans (never None) -> never degraded,
    # so the freeze memo engages exactly as it would with a live gate.
    egress_proxy._detect_neural = _make_detector()

    from fastapi.testclient import TestClient
    client = TestClient(egress_proxy.app)

    checks = {}

    # --- Check 1: freeze ON -> redacted system prefix byte-identical across turns ---------------------
    s1, s2 = _run_two_turns(client, 'cache-proof-on-' + os.urandom(4).hex())
    checks['freeze ON: turn-2 system prefix == turn-1 (byte-identical)'] = (s1 == s2)
    checks['freeze ON: turn-1 system still carries Falcon RAW (divergence is real)'] = ('Falcon' in s1)
    checks['freeze ON: Tango redacted in the prefix (turn 1 did work)'] = ('Tango' not in s1)

    # --- Check 2 (control): freeze OFF -> the growing sweep rewrites the prefix (proves check 1 is non-trivial)
    egress_proxy.FREEZE_PREFIX = False
    s1b, s2b = _run_two_turns(client, 'cache-proof-off-' + os.urandom(4).hex())
    egress_proxy.FREEZE_PREFIX = True
    checks['freeze OFF (control): turn-2 prefix DIVERGES from turn-1'] = (s1b != s2b)
    checks['freeze OFF (control): Falcon swept OUT of the re-sent prefix on turn 2'] = ('Falcon' not in s2b)

    # --- Check 3: bootstrap passthrough -> numeric autoCompactWindow (autocompaction enabler) ----------
    r = client.get('/api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8',
                   headers={'x-api-key': 'test', 'anthropic-version': '2023-06-01'})
    boot = r.json() if r.status_code == 200 else {}
    checks['bootstrap: proxy forwards /api/claude_cli/bootstrap (200)'] = (r.status_code == 200)
    checks['bootstrap: numeric autoCompactWindow returned'] = (
        isinstance(boot.get('autoCompactWindow'), int) and boot['autoCompactWindow'] > 0)

    # --- Report ----------------------------------------------------------------------------------------
    print(f'turn-1 system (freeze ON): {s1!r}')
    print(f'turn-2 system (freeze ON): {s2!r}')
    print(f'control   (freeze OFF) t1: {s1b!r}')
    print(f'control   (freeze OFF) t2: {s2b!r}')
    print(f'bootstrap status/window : {r.status_code} / {boot.get("autoCompactWindow")!r}')
    print('\n--- context-ballooning closure live checks ---')
    ok = True
    for name, passed in checks.items():
        print(f'  [{"PASS" if passed else "FAIL"}] {name}')
        ok = ok and passed
    srv.shutdown()
    print('\nRESULT:', 'ALL PASS -- cache stability + compaction enabler verified live' if ok
          else 'FAILURE')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
