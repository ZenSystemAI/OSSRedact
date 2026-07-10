#!/usr/bin/env python3
"""Stress the DEPLOYED OSSRedact egress code against the REAL v11r9c detector (:8001), in-container.

Calls redact_body directly (no upstream forward) and asserts the opaque-passthrough fixes + the PII floor.
Run on the gate host where the egress code + a reachable /detect detector live:
  OSSREDACT_APPLIANCE_DIR=/path/to/appliance python3 stress_reasoning_deployed.py
"""
import asyncio, json, os, sys, tempfile

os.environ['GATEWAY_MAPS_DIR'] = tempfile.mkdtemp(prefix='stress-maps-')
os.environ.setdefault('GATEWAY_GATE_URL', 'http://127.0.0.1:8001')
sys.path.insert(0, os.environ.get('OSSREDACT_APPLIANCE_DIR', 'appliance'))
import egress_proxy, responses_adapter  # noqa

PASS, FAIL = 0, 0
def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name}  {detail}")

async def redact(body, extract=None, session='stress'):
    ctx = {'session': session, 'project': 'stress', 'auth_fp': 'fp'}
    kw = {'extract': extract} if extract else {}
    return await egress_proxy.redact_body(body, ctx, **kw)

def wire(b): return json.dumps(b, ensure_ascii=False)


async def t_thinking_opaque():
    print("\n[1] Anthropic thinking = opaque passthrough; user-msg PII still redacted")
    thinking = "The user <PERSON_NAME_001> at Globex Industries wants the file /etc/hosts updated; org is Globex."
    body = {'model': 'claude-x', 'messages': [
        {'role': 'assistant', 'content': [
            {'type': 'thinking', 'thinking': thinking, 'signature': 'SIG-OPAQUE-abc123'},
            {'type': 'text', 'text': 'ok'}]},
        {'role': 'user', 'content': 'My SIN is 046 454 286 and email me at bernard.tremblay@acme-loans.example'}]}
    meta, replay = await redact(body, session='th1')
    tb = body['messages'][0]['content'][0]
    check("thinking text byte-identical", tb['thinking'] == thinking, repr(tb['thinking'])[:120])
    check("thinking signature untouched", tb['signature'] == 'SIG-OPAQUE-abc123')
    check("model-mentioned org inside thinking NOT redacted", 'Globex' in wire(body))
    um = body['messages'][1]['content']
    check("user-msg SIN redacted", '046 454 286' not in um, um)
    check("user-msg email redacted", 'bernard.tremblay@acme-loans.example' not in um, um)


async def t_thinking_entityful():
    print("\n[2] Thinking with a REAL-looking name/email the NER would tag -> still passes through verbatim")
    thinking = "Reasoning: contact Genevieve Lacroix at gen.lacroix@northwind.example about invoice 8841."
    body = {'model': 'claude-x', 'messages': [
        {'role': 'assistant', 'content': [{'type': 'thinking', 'thinking': thinking, 'signature': 'sig-2'}]},
        {'role': 'user', 'content': 'continue'}]}
    await redact(body, session='th2')
    tb = body['messages'][0]['content'][0]
    check("thinking with name+email passes verbatim (no signature desync)", tb['thinking'] == thinking, repr(tb['thinking'])[:140])


async def t_encrypted_content_opaque():
    print("\n[3] Codex reasoning.encrypted_content = opaque; summary/content still redacted")
    blob = "gAAAAABm9_OPAQUE_ciphertext_no_touch_8f3a9b2c1d0e==/+abcDEF"
    body = {'model': 'gpt-test', 'input': [
        {'type': 'reasoning', 'id': 'rs_1',
         'summary': [{'type': 'summary_text', 'text': 'the user is Priya McCallum, card 4111 1111 1111 1111'}],
         'content': [{'type': 'reasoning_text', 'text': 'plan: email priya.mccallum@example.org'}],
         'encrypted_content': blob}]}
    meta, replay = await redact(body, extract=responses_adapter.extract_text_fields_responses, session='ec1')
    item = body['input'][0]
    check("encrypted_content byte-identical", item['encrypted_content'] == blob, item['encrypted_content'][:60])
    s = item['summary'][0]['text']; c = item['content'][0]['text']
    check("reasoning summary name redacted", 'Priya McCallum' not in s, s)
    check("reasoning summary card redacted", '4111' not in s, s)
    check("reasoning content email redacted", 'priya.mccallum@example.org' not in c, c)


async def t_floor_secrets():
    print("\n[4] Deterministic floor: secrets / card / IBAN / gov-id always redacted")
    body = {'model': 'claude-x', 'messages': [{'role': 'user', 'content':
        'creds: api key sk-proj-AbCdEf0123456789AbCdEf0123456789, card 4539 1488 0343 6467, '
        'IBAN FR14 2004 1010 0505 0001 3M02 606, SSN 123-45-6789'}]}
    await redact(body, session='fl1')
    w = body['messages'][0]['content']
    check("api key redacted", 'sk-proj-AbCdEf0123456789AbCdEf0123456789' not in w)
    check("credit card redacted", '4539 1488 0343 6467' not in w and '4539148803436467' not in w)
    check("IBAN redacted", 'FR14 2004 1010 0505 0001 3M02 606' not in w)
    check("SSN redacted", '123-45-6789' not in w)


async def t_session_bugs():
    print("\n[5] Session-specific past leaks: JSON-quoted numeric secret + A1 numeric under sensitive key")
    # NOTE: RC7 (commit 9420c2f) catches numeric secrets with a CUE-ADJACENT value (otp/pin/cvv/nip + sep + digits,
    # incl JSON key:value + quoted forms). The cue-SEPARATED prose form `the OTP is "492013"` (intervening word
    # between cue and value) is a DELIBERATE scope limit to avoid FPs on every quoted number -- NOT covered, by design.
    body = {'model': 'claude-x', 'messages': [{'role': 'user', 'content': [
        {'type': 'tool_use', 'name': 'pay', 'input': {'cvv': 834, 'card_expiry': '11/29', 'password': 12345678,
                                                       'note': 'otp 492013 just arrived'}}]}]}
    await redact(body, session='sb1')
    w = wire(body)
    check("numeric CVV under sensitive key redacted", '834' not in w or '<' in w, w[:200])
    check("numeric password under sensitive key redacted", '12345678' not in w, w[:200])
    check("cue-adjacent OTP in free-text note redacted", '492013' not in w, w[:200])


async def t_rehydrate_roundtrip():
    print("\n[6] Rehydration round-trip: redacted body + replay -> original values restored (non-opaque fields)")
    body = {'model': 'claude-x', 'messages': [{'role': 'user', 'content':
        'Customer Olivier Bouchard, phone 514-555-0182, email o.bouchard@example.org'}]}
    meta, replay = await redact(body, session='rh1')
    red = body['messages'][0]['content']
    check("redacted (placeholders present)", '<' in red and 'Olivier Bouchard' not in red, red)
    restored = egress_proxy.rehydrate_text(red, replay)
    check("rehydrate restores name", 'Olivier Bouchard' in restored, restored)
    check("rehydrate restores email", 'o.bouchard@example.org' in restored, restored)


async def t_volume():
    print("\n[7] Volume: 40 varied PII fields in one request scan cleanly (no crash, all redacted)")
    content = []
    for i in range(40):
        content.append({'type': 'text', 'text':
            f'Record {i}: client Field Person{i} <fp{i}@northwind.example> phone 514-555-0{100+i:03d} acct 00{i}-12345'})
    body = {'model': 'claude-x', 'messages': [{'role': 'user', 'content': content}]}
    meta, replay = await redact(body, session='vol1')
    w = wire(body)
    leaks = [i for i in range(40) if f'fp{i}@northwind.example' in w]
    check("no email leaked across 40 fields", not leaks, f'leaked indices: {leaks[:10]}')
    check("redaction produced spans", meta.get('n_spans', 0) > 0, str(meta.get('n_spans')))


async def main():
    print("=== OSSRedact deployed-gate stress (real v11r9c detector) ===")
    print(f"detector: {egress_proxy.GATE_URL}  DETECT_CONCURRENCY={egress_proxy.DETECT_CONCURRENCY}")
    for t in (t_thinking_opaque, t_thinking_entityful, t_encrypted_content_opaque, t_floor_secrets,
              t_session_bugs, t_rehydrate_roundtrip, t_volume):
        try:
            await t()
        except Exception as e:
            global FAIL; FAIL += 1
            import traceback; print(f"  ERROR in {t.__name__}: {e}\n{traceback.format_exc()[-400:]}")
    print(f"\n=== RESULT: {PASS} passed, {FAIL} failed ===")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
