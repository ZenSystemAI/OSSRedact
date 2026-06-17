"""Unit tests for the OpenAI Responses-API adapter (appliance/responses_adapter.py).

WHY this file exists: Codex CLI speaks /v1/responses ONLY, so the Responses adapter is the sole privacy filter
on that route. The headline guarantee is EXHAUSTIVE extraction -- every user-supplied text location in a
Responses request (string `input`, array `input` items with string OR typed-part content, and top-level
`instructions`) must be surfaced for redaction; missing ANY of them leaks that field verbatim upstream. These
tests assert that guarantee directly (PII placed in each location is masked, zero raw value survives in the
forwarded body) plus a lossless round-trip through the response + streaming rehydrators.

HOW it runs with no heavy deps: responses_adapter is pure stdlib (json + re), so we import it by ABSOLUTE path
(mirroring test_egress_e2e's collision-proof loader -- the bare name could otherwise be shadowed) and never
touch fastapi/httpx/the NPU stack. The "redaction" here is a deterministic manual placeholder swap over the
extractor's in-place Field handles, so the test pins the ADAPTER's plumbing (extract + rehydrate), with NO
network and NO proxy.

100% SYNTHETIC data. No real PII anywhere.
Run: .venv-test/bin/python -m pytest appliance/tests/test_responses_adapter.py -q
"""
import os
import re
import json
import base64
import importlib.util

import pytest

# --- import the appliance responses_adapter by absolute path (bare name could be shadowed by a future
#     same-named module elsewhere in the repo; load it explicitly the way test_egress_e2e loads its modules).
_APPLIANCE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_RA_PATH = os.path.join(_APPLIANCE, 'responses_adapter.py')
_spec = importlib.util.spec_from_file_location('responses_adapter_under_test', _RA_PATH)
ra = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ra)

# Match the PRODUCTION placeholder grammar (egress_proxy._PH_TOKEN_RE): a label may carry INTERNAL underscores
# (gate-form <PHONE_NUMBER_001> / <SENSITIVE_ACCOUNT_ID_001>), so [A-Z0-9_]+ before the final '_\d{3,}'. The old
# [A-Z0-9]+ missed multi-underscore labels, so a leaked <PHONE_NUMBER_001> would slip past the no-survivor asserts.
_PH_RE = re.compile(r'<[A-Z0-9_]+_\d{3,}>')


def _swap_all(fields, value, placeholder):
    """Manual deterministic 'redaction': replace `value` with `placeholder` in every extracted field that
    contains it, writing back IN PLACE via the Field handle. Returns the count of fields touched."""
    n = 0
    for f in fields:
        if value in f.text:
            f.write(f.text.replace(value, placeholder))
            n += 1
    return n


# ---------------------------------------------------------------------------
# (a) STRING input: PII in a plain-string `input` is extracted + redacted.
# ---------------------------------------------------------------------------
def test_extract_string_input_redacted():
    email = 'marie.gagnon@example.com'
    ph = '<EMAIL_001>'
    body = {'model': 'gpt-test', 'input': f'Please email {email} today.'}

    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 1, 'string `input` must be surfaced as exactly one field'

    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: raw value in string input leaked to the forwarded body'
    assert ph in wire and _PH_RE.search(wire)


# ---------------------------------------------------------------------------
# (b) ARRAY input with input_text parts: PII in a typed content part is redacted;
#     non-text parts (input_image / input_file) are left intact.
# ---------------------------------------------------------------------------
def test_extract_array_input_text_parts_redacted():
    secret = 'Dossier-QX77182'
    ph = '<ACCOUNT_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'role': 'user', 'type': 'message', 'content': [
                {'type': 'input_text', 'text': f'Open case {secret} now.'},
                {'type': 'input_image', 'image_url': 'https://example.test/x.png'},  # never touched
            ]},
            # a bare-string content item in the SAME array must also be caught
            {'role': 'user', 'content': f'Reminder about {secret}.'},
            # an echoed assistant turn with an output_text part also carries the value
            {'role': 'assistant', 'content': [{'type': 'output_text', 'text': f'Noted {secret}.'}]},
        ],
    }

    fields = ra.extract_text_fields_responses(body)
    n = _swap_all(fields, secret, ph)
    assert n == 3, f'expected the two text parts + one string-content item surfaced, got {n}'
    assert body['input'][0]['content'][1]['type'] == 'input_image', 'non-text part must be left intact'

    wire = json.dumps(body, ensure_ascii=False)
    assert secret not in wire, 'PRIVACY FAILURE: raw value in an array-input text part leaked upstream'
    assert ph in wire


# ---------------------------------------------------------------------------
# (c) INSTRUCTIONS: PII in the top-level `instructions` field is redacted.
# ---------------------------------------------------------------------------
def test_extract_instructions_redacted():
    name = 'Genevieve Cliquot-Beaumont'
    ph = '<PERSON_001>'
    body = {'model': 'gpt-test',
            'instructions': f'You are the assistant for {name}.',
            'input': 'Hello.'}

    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, name, ph) == 1, '`instructions` must be surfaced as a field'

    wire = json.dumps(body, ensure_ascii=False)
    assert name not in wire, 'PRIVACY FAILURE: raw value in `instructions` leaked to the forwarded body'
    assert ph in wire


# ---------------------------------------------------------------------------
# EXHAUSTIVENESS: a single value placed in ALL THREE locations at once is masked
# everywhere -- zero raw survivors in the forwarded body (the never-leak guarantee).
# ---------------------------------------------------------------------------
def test_extract_all_locations_zero_survivors():
    val = 'marc-andre.dubois@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'instructions': f'Operator contact: {val}.',
        'input': [
            {'role': 'user', 'content': f'string-form {val}'},
            {'role': 'user', 'content': [{'type': 'input_text', 'text': f'part-form {val}'}]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    touched = _swap_all(fields, val, ph)
    assert touched == 3, f'all three text-bearing locations must be redacted, only {touched} were'

    wire = json.dumps(body, ensure_ascii=False)
    occurrences = wire.count(val)
    assert occurrences == 0, (
        f'PRIVACY FAILURE: {occurrences} verbatim copies of the sensitive value still leak upstream')


# ---------------------------------------------------------------------------
# LEAK PATH (1): function_call_output.output -- the echoed tool RESULT is model-visible
# text. Cover BOTH the string form and the array-of-parts form; each must redact + rehydrate.
# ---------------------------------------------------------------------------
def test_extract_function_call_output_string_redacted_and_roundtrip():
    sin = 'SIN 046-454-286'
    ph = '<SIN_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call_output', 'call_id': 'call_1',
             'output': f'Lookup result: client {sin} verified.'},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, sin, ph) == 1, 'string `output` of function_call_output must be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert sin not in wire, 'PRIVACY FAILURE: raw value in function_call_output.output (string) leaked upstream'
    assert ph in wire

    # rehydration round-trip restores the real value when the field appears in a response `output` item
    resp = {'output': [{'type': 'function_call_output', 'call_id': 'call_1',
                        'output': f'Lookup result: client {ph} verified.'}]}
    ra.rehydrate_responses_response(resp, {ph: sin})
    assert resp['output'][0]['output'] == f'Lookup result: client {sin} verified.'
    assert not _PH_RE.search(json.dumps(resp))


def test_extract_function_call_output_array_parts_redacted_and_roundtrip():
    addr = '4500 rue Sherbrooke Ouest'
    ph = '<ADDRESS_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call_output', 'call_id': 'call_2', 'output': [
                {'type': 'input_text', 'text': f'Mailing address on file: {addr}.'},
                {'type': 'input_image', 'image_url': 'https://example.test/scan.png'},  # never touched
            ]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, addr, ph) == 1, 'array-part `output` text of function_call_output must be surfaced'
    assert body['input'][0]['output'][1]['type'] == 'input_image', 'non-text output part must be left intact'

    wire = json.dumps(body, ensure_ascii=False)
    assert addr not in wire, 'PRIVACY FAILURE: raw value in function_call_output.output (array) leaked upstream'
    assert ph in wire

    resp = {'output': [{'type': 'function_call_output', 'call_id': 'call_2', 'output': [
        {'type': 'input_text', 'text': f'Mailing address on file: {ph}.'},
    ]}]}
    ra.rehydrate_responses_response(resp, {ph: addr})
    assert resp['output'][0]['output'][0]['text'] == f'Mailing address on file: {addr}.'
    assert not _PH_RE.search(json.dumps(resp))


# ---------------------------------------------------------------------------
# LEAK PATH (2): function_call.arguments -- the echoed tool-call argument JSON string is
# model-visible. PII embedded in a JSON string value must be redacted (and rehydrated JSON-safely).
# ---------------------------------------------------------------------------
def test_extract_function_call_arguments_redacted_and_roundtrip():
    phone = '438-555-0147'
    ph = '<PHONE_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'call_3', 'name': 'sms_send',
             'arguments': json.dumps({'to': phone, 'body': f'call {phone}'})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # FIX 3: the arguments JSON is PARSED and each inner string VALUE is surfaced as its own clean field (so the
    # gate NER detects a bare name far better than the JSON blob). Both 'to' and 'body' carry the phone -> two
    # fields, both redacted, and each write re-serializes the parsed object back into a valid JSON arguments string.
    assert _swap_all(fields, phone, ph) == 2, 'each PII-bearing value inside the arguments JSON must be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert phone not in wire, 'PRIVACY FAILURE: raw value in function_call.arguments leaked upstream'
    assert ph in wire
    # arguments stays a syntactically valid JSON string after the placeholder swap, with both values redacted
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert isinstance(rebuilt, dict), 'arguments must remain valid JSON'
    assert rebuilt['to'] == ph and rebuilt['body'] == f'call {ph}', 'both JSON values redacted in place'

    # rehydrate JSON-safely when the function_call appears in a response `output` item
    resp = {'output': [{'type': 'function_call', 'call_id': 'call_3', 'name': 'sms_send',
                        'arguments': json.dumps({'to': ph, 'body': f'call {ph}'})}]}
    ra.rehydrate_responses_response(resp, {ph: phone})
    args = json.loads(resp['output'][0]['arguments'])
    assert args['to'] == phone and args['body'] == f'call {phone}', 'function_call.arguments must rehydrate'
    assert not _PH_RE.search(json.dumps(resp))


# ---------------------------------------------------------------------------
# LEAK PATH (3): a `refusal` content part -- the model's refusal text is model-visible and
# can echo a sensitive value back. It must redact + rehydrate like any other content text.
# ---------------------------------------------------------------------------
def test_extract_refusal_content_part_redacted_and_roundtrip():
    name = 'Genevieve Cliquot-Beaumont'
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'role': 'assistant', 'content': [
                {'type': 'refusal', 'refusal': f'I cannot share records for {name}.'},
            ]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, name, ph) == 1, 'a refusal content part must be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert name not in wire, 'PRIVACY FAILURE: raw value in a refusal content part leaked upstream'
    assert ph in wire

    # rehydrate when a refusal part appears in a response `output` message item
    resp = {'output': [{'type': 'message', 'role': 'assistant', 'content': [
        {'type': 'refusal', 'refusal': f'I cannot share records for {ph}.'},
    ]}]}
    ra.rehydrate_responses_response(resp, {ph: name})
    assert resp['output'][0]['content'][0]['refusal'] == f'I cannot share records for {name}.'
    assert not _PH_RE.search(json.dumps(resp))


# ---------------------------------------------------------------------------
# LEAK PATH (4): top-level prompt.variables -- every string value of a stored-prompt
# template substitution is model-visible and must redact (and round-trip).
# ---------------------------------------------------------------------------
def test_extract_prompt_variables_redacted_and_roundtrip():
    email = 'marc-andre.dubois@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'prompt': {
            'id': 'pmpt_abc123',
            'version': '2',
            'variables': {
                'customer_email': email,
                'greeting': f'Bonjour, contactez {email}.',
                'order_id': 'fixed-noPII',
            },
        },
        'input': 'Run the template.',
    }
    fields = ra.extract_text_fields_responses(body)
    # two of the three variable values carry the PII; both must be surfaced
    assert _swap_all(fields, email, ph) == 2, 'every PII-bearing prompt.variables string must be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: raw value in prompt.variables leaked upstream'
    assert ph in wire
    assert body['prompt']['variables']['order_id'] == 'fixed-noPII', 'non-PII variable left intact'


def test_extract_prompt_variables_input_text_part_redacted():
    """A prompt variable whose value is an input_text part ({type:'input_text', text}) is also surfaced."""
    val = 'Dossier-QX77182'
    ph = '<ACCOUNT_001>'
    body = {
        'model': 'gpt-test',
        'prompt': {
            'id': 'pmpt_xyz',
            'variables': {'ctx': {'type': 'input_text', 'text': f'Open case {val}.'}},
        },
        'input': 'go',
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, val, ph) == 1, 'an input_text-part prompt variable must be surfaced'
    wire = json.dumps(body, ensure_ascii=False)
    assert val not in wire, 'PRIVACY FAILURE: raw value in an input_text prompt variable leaked upstream'


# ---------------------------------------------------------------------------
# EXHAUSTIVENESS (all four leak paths at once): one value placed in function_call_output.output,
# function_call.arguments, a refusal part, AND prompt.variables -- zero raw survivors upstream.
# ---------------------------------------------------------------------------
def test_extract_all_leak_paths_zero_survivors():
    val = 'sophie.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'prompt': {'id': 'pmpt_1', 'variables': {'op': f'operator {val}'}},
        'input': [
            {'type': 'function_call', 'call_id': 'c1', 'name': 'send',
             'arguments': json.dumps({'to': val})},
            {'type': 'function_call_output', 'call_id': 'c1', 'output': f'sent to {val}'},
            {'role': 'assistant', 'content': [{'type': 'refusal', 'refusal': f'cannot reach {val}'}]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    touched = _swap_all(fields, val, ph)
    assert touched == 4, f'all four model-visible leak paths must be redacted, only {touched} were'

    wire = json.dumps(body, ensure_ascii=False)
    assert wire.count(val) == 0, 'PRIVACY FAILURE: a value still leaks upstream from a model-visible field'


# ---------------------------------------------------------------------------
# RESPONSE ROUND-TRIP: a synthetic Responses `output` (message content parts +
# top-level output_text + a function_call args JSON string) rehydrates losslessly.
# ---------------------------------------------------------------------------
def test_response_roundtrip_lossless():
    email = 'sophie.tremblay@example.com'
    ph = '<EMAIL_001>'
    replay = {ph: email}
    resp = {
        'id': 'resp_test',
        'output': [
            {'id': 'msg_1', 'type': 'message', 'role': 'assistant', 'status': 'completed',
             'content': [{'type': 'output_text', 'text': f'I will write to {ph}.'}]},
            {'id': 'fc_1', 'type': 'function_call', 'name': 'send_email', 'call_id': 'call_1',
             'arguments': json.dumps({'to': ph, 'note': f'see {ph}'})},
        ],
        'output_text': f'I will write to {ph}.',
    }

    ra.rehydrate_responses_response(resp, replay)

    msg_text = resp['output'][0]['content'][0]['text']
    assert msg_text == f'I will write to {email}.', 'assistant message text must restore the real value'
    fc_args = json.loads(resp['output'][1]['arguments'])
    assert fc_args['to'] == email and fc_args['note'] == f'see {email}', 'function_call args must rehydrate'
    assert resp['output_text'] == f'I will write to {email}.', 'convenience output_text must rehydrate'
    assert not _PH_RE.search(json.dumps(resp)), 'no placeholder may survive rehydration in local-visible text'


def test_response_roundtrip_json_safe_args():
    """A real value containing quotes/backslashes must not break the function_call arguments JSON."""
    ph = '<NAME_001>'
    tricky = 'a"b\\c'
    args_json = json.dumps({'raw': ph, 'note': f'see {ph}'})
    out = ra.rehydrate_json_string(args_json, {ph: tricky})
    parsed = json.loads(out)   # still valid JSON after substitution
    assert parsed['raw'] == tricky and parsed['note'] == f'see {tricky}'


# ---------------------------------------------------------------------------
# STREAMING: response.output_text.delta events reassemble + rehydrate, even when
# a placeholder is SPLIT across two deltas; function_call args buffer + flush at
# .done; other events pass through.
# ---------------------------------------------------------------------------
def _collect_stream(events, replay):
    """Drive transform_responses_event over a list of raw SSE-event byte blocks; return the concatenated
    transformed output as text (None results -- buffered -- are dropped)."""
    carry, tool_acc = {}, {}
    out = []
    for raw in events:
        res = ra.transform_responses_event(raw, replay, carry, tool_acc)
        if res is not None:
            out.append(res.decode('utf-8'))
    return '\n\n'.join(out)


def _delta_event(text, oi=0, ci=0):
    return (b'event: response.output_text.delta\n'
            b'data: ' + json.dumps({'type': 'response.output_text.delta',
                                    'delta': text, 'item_id': 'msg_1',
                                    'output_index': oi, 'content_index': ci}).encode('utf-8'))


def test_stream_text_delta_rehydrated_split_placeholder():
    email = 'luc.bernard@example.com'
    ph = '<EMAIL_001>'
    replay = {ph: email}
    # split the placeholder "<EMAIL_001>" across two deltas: "...write to <EMA" | "IL_001> now."
    events = [
        b'event: response.created\ndata: ' + json.dumps({'type': 'response.created'}).encode('utf-8'),
        _delta_event('Sure, I will write to <EMA'),
        _delta_event('IL_001> now.'),
        (b'event: response.output_text.done\n'
         b'data: ' + json.dumps({'type': 'response.output_text.done', 'item_id': 'msg_1',
                                 'output_index': 0, 'content_index': 0,
                                 'text': f'Sure, I will write to {ph} now.'}).encode('utf-8')),
    ]
    out = _collect_stream(events, replay)
    # the rehydrated email is emitted intact and is never half-rendered as a stray placeholder fragment
    assert email in out, 'streamed text must rehydrate the placeholder even when split across deltas'
    assert not _PH_RE.search(out), 'no full placeholder may survive in the streamed output'
    assert 'response.created' in out, 'non-text events pass through'


def test_stream_function_call_args_buffer_and_flush():
    val = 'Dossier-QX77182'
    ph = '<ACCOUNT_001>'
    replay = {ph: val}
    full = json.dumps({'case': ph})
    cut = len(full) // 2
    events = [
        (b'event: response.function_call_arguments.delta\n'
         b'data: ' + json.dumps({'type': 'response.function_call_arguments.delta',
                                 'item_id': 'fc_1', 'delta': full[:cut]}).encode('utf-8')),
        (b'event: response.function_call_arguments.delta\n'
         b'data: ' + json.dumps({'type': 'response.function_call_arguments.delta',
                                 'item_id': 'fc_1', 'delta': full[cut:]}).encode('utf-8')),
        (b'event: response.function_call_arguments.done\n'
         b'data: ' + json.dumps({'type': 'response.function_call_arguments.done',
                                 'item_id': 'fc_1'}).encode('utf-8')),
    ]
    # the two delta events buffer (return None); only .done emits, carrying the full rehydrated args
    carry, tool_acc = {}, {}
    r1 = ra.transform_responses_event(events[0], replay, carry, tool_acc)
    r2 = ra.transform_responses_event(events[1], replay, carry, tool_acc)
    r3 = ra.transform_responses_event(events[2], replay, carry, tool_acc)
    assert r1 is None and r2 is None, 'argument-delta fragments must be buffered, not emitted raw'
    assert r3 is not None
    payload = json.loads(r3.decode('utf-8').split('data: ', 1)[1])
    args = json.loads(payload['arguments'])
    assert args['case'] == val, 'flushed function_call args must rehydrate to the real value'
    assert not _PH_RE.search(r3.decode('utf-8'))


def test_stream_completed_snapshot_rehydrated():
    """The terminal response.completed event embeds a full response object -> its output is rehydrated too."""
    email = 'nadia.roy@example.com'
    ph = '<EMAIL_001>'
    replay = {ph: email}
    ev = (b'event: response.completed\n'
          b'data: ' + json.dumps({
              'type': 'response.completed',
              'response': {'id': 'resp_1', 'output': [
                  {'type': 'message', 'role': 'assistant',
                   'content': [{'type': 'output_text', 'text': f'Contacted {ph}.'}]}],
                  'output_text': f'Contacted {ph}.'}}).encode('utf-8'))
    carry, tool_acc = {}, {}
    res = ra.transform_responses_event(ev, replay, carry, tool_acc).decode('utf-8')
    assert email in res and not _PH_RE.search(res), 'snapshot output in response.completed must rehydrate'


# ===========================================================================
# AGENTIC LEAK PATHS (Codex CLI). The extractor uses a defensive RECURSIVE free-text sweep gated by a structural-
# key DENY-LIST -- NOT a narrow allow-list -- so every agentic item type's free text is surfaced for redaction,
# including item types not yet enumerated. Each test plants synthetic PII in one agentic field, redacts via the
# Field handles, asserts zero raw survivors on the wire, and (where a response shape exists) rehydrates back.
# ===========================================================================
def test_shell_call_commands_list_redacted_and_roundtrip():
    """shell_call.action.commands is a LIST of command strings -> each element surfaced + written back in place."""
    path = '/home/marie.gagnon/.ssh/id_rsa'
    ph = '<PATH_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'shell_call', 'id': 'sc_1', 'call_id': 'call_1', 'status': 'completed',
             'action': {'type': 'exec', 'commands': [f'cat {path}', f'shred {path}']}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, path, ph) == 2, 'each command string in the list must be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert path not in wire, 'PRIVACY FAILURE: a raw path in shell_call.action.commands leaked upstream'
    assert body['input'][0]['action']['commands'] == [f'cat {ph}', f'shred {ph}'], 'list writeback must be in place'

    # rehydrate the echoed shell command list in a response output item
    resp = {'output': [{'type': 'shell_call', 'id': 'sc_1', 'action': {
        'type': 'exec', 'commands': [f'cat {ph}', f'shred {ph}']}}]}
    ra.rehydrate_responses_response(resp, {ph: path})
    assert resp['output'][0]['action']['commands'] == [f'cat {path}', f'shred {path}']
    assert not _PH_RE.search(json.dumps(resp))


def test_shell_call_output_redacted_and_roundtrip():
    """shell_call_output.stdout / stderr carry echoed tool output -> redacted by the sweep, rehydrated recursively."""
    secret = 'AKIA-SYNTH-EXAMPLE-KEY'
    ph = '<SECRET_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'shell_call_output', 'id': 'so_1', 'call_id': 'call_1',
             'stdout': f'AWS key found: {secret}', 'stderr': f'warning near {secret}'},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, secret, ph) == 2, 'both stdout and stderr must be surfaced'
    assert secret not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: shell_call_output leaked upstream'

    resp = {'output': [{'type': 'shell_call_output', 'id': 'so_1',
                        'stdout': f'AWS key found: {ph}', 'stderr': f'warning near {ph}'}]}
    ra.rehydrate_responses_response(resp, {ph: secret})
    assert resp['output'][0]['stdout'] == f'AWS key found: {secret}'
    assert resp['output'][0]['stderr'] == f'warning near {secret}'
    assert not _PH_RE.search(json.dumps(resp))


def test_apply_patch_call_diff_redacted_and_roundtrip():
    """apply_patch_call.operation.diff is a patch body that can carry PII from the user's codebase."""
    email = 'jean.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'apply_patch_call', 'id': 'ap_1', 'call_id': 'call_1', 'status': 'completed',
             'operation': {'type': 'update_file', 'path': 'src/contact.py',
                           'diff': f'@@\n-contact = ""\n+contact = "{email}"\n'}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 1, 'the patch diff must be surfaced'
    assert email not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: apply_patch diff leaked upstream'

    resp = {'output': [{'type': 'apply_patch_call', 'id': 'ap_1',
                        'operation': {'type': 'update_file', 'path': 'src/contact.py',
                                      'diff': f'+contact = "{ph}"'}}]}
    ra.rehydrate_responses_response(resp, {ph: email})
    assert resp['output'][0]['operation']['diff'] == f'+contact = "{email}"'
    assert not _PH_RE.search(json.dumps(resp))


def test_code_interpreter_call_code_redacted_and_roundtrip():
    """code_interpreter_call.code (and its logs) carry model-visible code that can embed PII."""
    phone = '514-555-0199'
    ph = '<PHONE_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'code_interpreter_call', 'id': 'ci_1', 'status': 'completed',
             'code': f'PHONE = "{phone}"\nsend(PHONE)',
             'outputs': [{'type': 'logs', 'logs': f'dialed {phone}'}]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, phone, ph) == 2, 'both the code and the logs must be surfaced'
    assert phone not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: code_interpreter code leaked'

    resp = {'output': [{'type': 'code_interpreter_call', 'id': 'ci_1', 'code': f'PHONE = "{ph}"'}]}
    ra.rehydrate_responses_response(resp, {ph: phone})
    assert resp['output'][0]['code'] == f'PHONE = "{phone}"'
    assert not _PH_RE.search(json.dumps(resp))


def test_mcp_call_arguments_and_output_redacted_and_roundtrip():
    """mcp_call.arguments / output / error are all model-visible MCP tool I/O -> all surfaced + rehydrated."""
    account = 'Dossier-ZZ99-7781'
    ph = '<ACCOUNT_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'mcp_call', 'id': 'mc_1', 'server_label': 'crm', 'name': 'lookup',
             'arguments': json.dumps({'case': account}),
             'output': f'record for {account} loaded',
             'error': f'partial match on {account}'},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, account, ph) == 3, 'mcp_call arguments + output + error must all be surfaced'
    assert account not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: mcp_call leaked upstream'
    assert body['input'][0]['name'] == 'lookup', 'tool name (deny-list) must be left intact'

    # rehydrate the echoed mcp_call in a response output item (recursive walk covers output + error)
    resp = {'output': [{'type': 'mcp_call', 'id': 'mc_1', 'name': 'lookup',
                        'output': f'record for {ph} loaded', 'error': f'partial match on {ph}'}]}
    ra.rehydrate_responses_response(resp, {ph: account})
    assert resp['output'][0]['output'] == f'record for {account} loaded'
    assert resp['output'][0]['error'] == f'partial match on {account}'
    assert not _PH_RE.search(json.dumps(resp))


def test_custom_tool_call_input_redacted():
    """custom_tool_call.input (free-form custom-tool grammar payload) is model-visible and must redact."""
    name = 'Genevieve Cliquot-Beaumont'
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'custom_tool_call', 'id': 'ctc_1', 'call_id': 'call_1', 'name': 'grammar_tool',
             'input': f'Rewrite this letter for {name}.'},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, name, ph) == 1, 'custom_tool_call.input must be surfaced'
    assert name not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: custom_tool_call.input leaked'
    assert body['input'][0]['name'] == 'grammar_tool', 'tool name (deny-list) must be left intact'


# ---------------------------------------------------------------------------
# FIX 3 (name-in-JSON under-detection): the gate NER detects a name far better as a BARE value than buried in a
# serialized '{"assignee_name":"Priya McCallum"}' blob. So a tool-argument JSON STRING is PARSED and each inner
# string value is surfaced as its own clean field; redaction writes the placeholder INSIDE the parsed object and
# re-serializes a VALID JSON arguments string. Here the deterministic _swap_all stands in for the NER, but the
# headline is the PLUMBING: the name/email/phone are each their own field, the arguments stays valid JSON, and a
# response echoing the placeholders rehydrates losslessly.
# ---------------------------------------------------------------------------
def test_mcp_call_arguments_json_name_surfaced_per_value_and_roundtrip():
    name = 'Priya McCallum'                 # NER-only; no Tier-0 fallback -- the exact reproduced failing case
    email = 'priya.mccallum@example.com'
    phone = '514-555-0188'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'mcp_call', 'id': 'mc_1', 'server_label': 'crm', 'name': 'assign',
             'arguments': json.dumps({'assignee_name': name, 'email': email, 'phone': phone})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # each JSON string value is its own field (assignee_name + email + phone) -- the NER sees a bare name, not JSON
    assert _swap_all(fields, name, '<PERSON_001>') == 1, 'the bare name value must be its own surfaced field'
    assert _swap_all(fields, email, '<EMAIL_001>') == 1, 'the email value must be its own surfaced field'
    assert _swap_all(fields, phone, '<PHONE_001>') == 1, 'the phone value must be its own surfaced field'

    wire = json.dumps(body, ensure_ascii=False)
    for raw in (name, email, phone):
        assert raw not in wire, f'PRIVACY FAILURE: {raw!r} leaked upstream from mcp_call.arguments JSON'
    # arguments stays valid JSON with every value redacted in place
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert rebuilt == {'assignee_name': '<PERSON_001>', 'email': '<EMAIL_001>', 'phone': '<PHONE_001>'}
    assert body['input'][0]['name'] == 'assign', 'tool name (deny-list) must be left intact'

    # a response echoing the placeholders inside an arguments JSON rehydrates losslessly (JSON-safe value-level)
    resp = {'output': [{'type': 'mcp_call', 'id': 'mc_1', 'name': 'assign',
                        'arguments': json.dumps({'assignee_name': '<PERSON_001>', 'email': '<EMAIL_001>',
                                                 'phone': '<PHONE_001>'})}]}
    ra.rehydrate_responses_response(resp, {'<PERSON_001>': name, '<EMAIL_001>': email, '<PHONE_001>': phone})
    out = json.loads(resp['output'][0]['arguments'])
    assert out == {'assignee_name': name, 'email': email, 'phone': phone}, 'mcp args must rehydrate losslessly'
    assert not _PH_RE.search(json.dumps(resp))


def test_function_call_arguments_json_name_surfaced_per_value():
    """function_call.arguments name-in-JSON: the name value is surfaced as its OWN clean field (not the blob)."""
    name = 'Priya McCallum'
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'call_9', 'name': 'create_ticket',
             'arguments': json.dumps({'assignee_name': name, 'priority': 'high'})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # assignee_name is its own field; 'priority':'high' is also surfaced (a value, harmless under span redaction)
    surfaced = {f.text for f in fields}
    assert name in surfaced, 'the bare name value inside function_call.arguments must be surfaced as its own field'
    assert _swap_all(fields, name, ph) == 1, 'exactly the name-bearing value is redacted'

    wire = json.dumps(body, ensure_ascii=False)
    assert name not in wire, 'PRIVACY FAILURE: a name in function_call.arguments JSON leaked upstream'
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert rebuilt == {'assignee_name': ph, 'priority': 'high'}, 'arguments stays valid JSON, name redacted'


def test_arguments_non_json_falls_back_to_whole_string():
    """If arguments is NOT valid JSON, fall back to whole-string redaction (never drop the field)."""
    name = 'Priya McCallum'
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'c1', 'name': 'note',
             'arguments': f'free-form note about {name}, not json'},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, name, ph) == 1, 'a non-JSON arguments string must fall back to whole-string redaction'
    assert name not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: non-JSON arguments leaked'
    assert body['input'][0]['arguments'] == f'free-form note about {ph}, not json'


def test_arguments_json_value_with_quotes_stays_valid_json():
    """A redacted value re-serializes JSON-safely even when the ORIGINAL value contained quotes/backslashes."""
    tricky = 'O\'Brien "the\\boss"'        # quotes + backslash in the bare value
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'c1', 'name': 'note',
             'arguments': json.dumps({'who': tricky})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, tricky, ph) == 1, 'the tricky value is surfaced as its own field'
    # arguments must still parse as valid JSON after the swap
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert rebuilt == {'who': ph}, 'arguments stays valid JSON after redacting a quote/backslash-bearing value'


def test_tool_definition_description_redacted():
    """body['tools'] tool/function 'description' AND parameter 'description' strings are model-visible free text;
    the deny-list must leave type/name/enum/property-names/required intact."""
    email = 'ops@acme-loans.example'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'hi',
        'tools': [
            {'type': 'function', 'name': 'send_alert',
             'description': f'Send an alert. Escalate to {email} on failure.',
             'parameters': {'type': 'object', 'properties': {
                 'channel': {'type': 'string', 'enum': ['ops', 'oncall'],
                             'description': f'Where to send. Defaults to {email}.'}},
                 'required': ['channel'], 'additionalProperties': False}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 2, 'tool description + param description must both be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a tool/parameter description leaked PII upstream'
    tool = body['tools'][0]
    assert tool['name'] == 'send_alert', 'tool name must be left intact (renaming breaks calls)'
    assert tool['parameters']['type'] == 'object', 'schema "type" must be left intact'
    assert tool['parameters']['properties']['channel']['enum'] == ['ops', 'oncall'], 'enum must be left intact'
    assert tool['parameters']['required'] == ['channel'], 'required list must be left intact'
    assert 'channel' in tool['parameters']['properties'], 'property name must be left intact'


def test_input_file_text_mime_decoded_redacted_and_roundtrip():
    """input_file.file_data with a text mime: base64 in -> decode -> placeholder in the DECODED payload -> rehydrate."""
    email = 'nadia.roy@example.com'
    ph = '<EMAIL_001>'
    raw_text = f'# notes.md\nPrimary contact: {email}\nstatus: open\n'
    b64 = base64.b64encode(raw_text.encode('utf-8')).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_file', 'filename': 'notes.md', 'mime_type': 'text/markdown', 'file_data': b64},
            ]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # the decoded text is surfaced as one redactable field (the base64 string itself is NEVER surfaced raw)
    assert _swap_all(fields, email, ph) == 1, 'decoded text-file content must be surfaced as one field'

    wire_b64 = body['input'][0]['content'][0]['file_data']
    decoded = base64.b64decode(wire_b64).decode('utf-8')
    assert ph in decoded, 'the placeholder must be present in the re-encoded file_data payload'
    assert email not in decoded, 'PRIVACY FAILURE: raw value still present in decoded file_data sent upstream'
    assert email not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: file_data leaked PII upstream'

    # rehydrate the same way: decode -> swap placeholder back -> the local client sees the original file text
    fd = ra.FileDataField(body['input'][0]['content'][0], 'file_data', 'tool_result', '', decoded)
    fd.write(fd.text.replace(ph, email))
    restored = base64.b64decode(body['input'][0]['content'][0]['file_data']).decode('utf-8')
    assert restored == raw_text, 'rehydrated file_data must restore the original decoded text exactly'


def test_input_file_binary_mime_is_documented_passthrough_not_silent():
    """A binary input_file is NOT scanned, but the bypass is a DOCUMENTED note (never a silent pass), and the
    private note marker is popped so it never reaches upstream."""
    png_bytes = b'\x89PNG\r\n\x1a\n\x00\x00binary-not-text'
    b64 = base64.b64encode(png_bytes).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'input_file', 'filename': 'logo.png', 'mime_type': 'image/png', 'file_data': b64},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # no field surfaced for the binary bytes, and the raw base64 is never surfaced as text
    assert all(f.text != b64 for f in fields), 'raw base64 binary must never be surfaced as a redactable string'

    notes = ra.pop_file_passthrough_notes(body)
    assert len(notes) == 1, 'a binary file must produce exactly one passthrough note'
    # the LOG note records only a sanitized extension descriptor, NEVER the raw filename (it could carry PII)
    assert notes[0]['mime'] == 'image/png' and notes[0]['filename'] == '*.png'
    assert notes[0]['reason'] == 'binary-or-undetermined'
    assert '_qc_pii_file_notes' not in body, 'the private note marker must be popped so it never goes upstream'
    assert body['input'][0]['file_data'] == b64, 'binary file_data must pass through unchanged'


# ---------------------------------------------------------------------------
# CONVERGENCE: an UNKNOWN / future item type has its free text redacted by the recursive sweep -- proving the
# extractor does NOT depend on enumerating every type (no whack-a-mole). This is the headline guarantee.
# ---------------------------------------------------------------------------
def test_unknown_future_item_type_redacted_by_recursive_sweep():
    sin = 'SIN 046-454-286'
    ph = '<SIN_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'some_future_call', 'id': 'fut_1', 'call_id': 'c1',
             'payload': f'verify client {sin}',
             'nested': {'deep': {'note': f'second copy {sin}'}}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    touched = _swap_all(fields, sin, ph)
    assert touched == 2, f'an unknown item type must still have ALL its free text surfaced, got {touched}'
    assert sin not in json.dumps(body, ensure_ascii=False), (
        'PRIVACY FAILURE: an un-enumerated future item type leaked PII upstream (whack-a-mole regression)')


# ---------------------------------------------------------------------------
# STRUCTURAL SURVIVAL: identifiers / routing strings / schema STRUCTURAL tokens under deny-list keys are NEVER
# altered by extraction (redacting them would break the request). They must not be surfaced as redactable Fields.
# NOTE (FIX 1): `enum` items and `const` literals are NO LONGER deny-listed -- they are model-picked VALUES that
# may carry PII, so they ARE surfaced for span-based redaction (an ordinary enum like 'fast' never matches a PII
# pattern, so it passes through unchanged regardless). `pattern` (a regex) stays deny-listed. Property NAMES
# (the keys under `properties`) remain structural and unsurfaced.
# ---------------------------------------------------------------------------
def test_structural_keys_not_surfaced():
    body = {
        'model': 'gpt-4.1-mini',
        'service_tier': 'auto',
        'tool_choice': 'auto',
        'input': [
            {'type': 'shell_call', 'id': 'sc_1', 'call_id': 'call_abc', 'item_id': 'item_9',
             'status': 'completed', 'name': 'bash',
             'action': {'type': 'exec', 'commands': ['ls']}},
        ],
        'tools': [
            {'type': 'function', 'name': 'fetch',
             'parameters': {'type': 'object',
                            'properties': {'mode': {'type': 'string', 'enum': ['fast', 'slow']}},
                            'required': ['mode'], 'additionalProperties': False, 'strict': True}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    # 'fast'/'slow' (enum items) are intentionally surfaceable now (FIX 1) and are NOT in this structural set.
    structural = {'gpt-4.1-mini', 'auto', 'shell_call', 'sc_1', 'call_abc', 'item_9', 'completed', 'bash',
                  'exec', 'object', 'function', 'fetch', 'string', 'mode'}
    leaked = surfaced & structural
    assert not leaked, f'structural identifier/enum strings must NOT be surfaced for redaction: {leaked}'
    # the one genuinely free-text value (the command) IS surfaced
    assert 'ls' in surfaced, 'the shell command (free text) must still be surfaced'


# ---------------------------------------------------------------------------
# EXHAUSTIVENESS (all agentic leak paths at once): one synthetic value placed across shell_call.action.commands,
# shell_call_output.stdout, apply_patch_call.operation.diff, code_interpreter_call.code, mcp_call.arguments,
# custom_tool_call.input, a web_search_call.action.query, a computer_call.action.text, a reasoning summary, a
# file_search_call result, a tool description, AND an unknown future type -> ZERO raw survivors in the wire body.
# ---------------------------------------------------------------------------
def test_all_agentic_leak_paths_zero_survivors():
    val = 'sophie.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'shell_call', 'id': 's1', 'action': {'type': 'exec', 'commands': [f'mail {val}']}},
            {'type': 'shell_call_output', 'id': 's2', 'stdout': f'sent to {val}'},
            {'type': 'apply_patch_call', 'id': 'a1',
             'operation': {'type': 'update_file', 'path': 'x.py', 'diff': f'+e = "{val}"'}},
            {'type': 'code_interpreter_call', 'id': 'c1', 'code': f'e="{val}"'},
            {'type': 'mcp_call', 'id': 'm1', 'name': 'send', 'arguments': json.dumps({'to': val})},
            {'type': 'custom_tool_call', 'id': 'ct1', 'name': 'g', 'input': f'for {val}'},
            {'type': 'web_search_call', 'id': 'w1', 'action': {'type': 'search', 'query': f'who is {val}'}},
            {'type': 'computer_call', 'id': 'cc1', 'action': {'type': 'type', 'text': f'typing {val}'}},
            {'type': 'reasoning', 'id': 'r1', 'summary': [{'type': 'summary_text', 'text': f'note {val}'}]},
            {'type': 'file_search_call', 'id': 'f1', 'results': [{'file_id': 'fid', 'text': f'match {val}'}]},
            {'type': 'some_future_call', 'id': 'z1', 'payload': f'future {val}'},
        ],
        'tools': [
            {'type': 'function', 'name': 'alert', 'description': f'escalate to {val}',
             'parameters': {'type': 'object', 'properties': {}, 'required': []}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    _swap_all(fields, val, ph)

    wire = json.dumps(body, ensure_ascii=False)
    assert wire.count(val) == 0, (
        f'PRIVACY FAILURE: {wire.count(val)} raw copies still leak across the agentic surface area')
    assert ph in wire, 'placeholders must be present in the forwarded body'


# ---------------------------------------------------------------------------
# SYMMETRIC REHYDRATION: a response containing agentic items (mcp_call output + shell_call_output) with
# placeholders rehydrates losslessly via the full recursive walk.
# ---------------------------------------------------------------------------
def test_response_agentic_items_rehydrate_recursively():
    val = 'marc-andre.dubois@example.com'
    ph = '<EMAIL_001>'
    resp = {
        'id': 'resp_1',
        'output': [
            {'type': 'mcp_call', 'id': 'm1', 'name': 'lookup', 'output': f'found {ph}'},
            {'type': 'shell_call_output', 'id': 's1', 'stdout': f'wrote {ph}', 'stderr': ''},
            {'type': 'reasoning', 'id': 'r1', 'summary': [{'type': 'summary_text', 'text': f'about {ph}'}]},
        ],
    }
    ra.rehydrate_responses_response(resp, {ph: val})
    assert resp['output'][0]['output'] == f'found {val}'
    assert resp['output'][1]['stdout'] == f'wrote {val}'
    assert resp['output'][2]['summary'][0]['text'] == f'about {val}'
    assert not _PH_RE.search(json.dumps(resp)), 'no placeholder may survive recursive rehydration'


# ===========================================================================
# ROUND 2 -- the four remaining Codex DO-NOT-SHIP findings. Each test pins the exact leak/over-redaction the
# finding describes, so a regression that reopens it fails loudly. 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# FINDING 1 (CRITICAL): top-level `text.format` structured-output json_schema -- the schema's `description`
# strings (root + per-property) are model-visible free text and must be swept; the deny-list must leave the
# schema's type/name/format/enum/property-names/required/strict structural tokens intact.
# ---------------------------------------------------------------------------
def test_text_format_json_schema_descriptions_redacted():
    email = 'ops@acme-loans.example'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'extract the fields',
        'text': {
            'format': {
                'type': 'json_schema',
                'name': 'extraction',
                'strict': True,
                'schema': {
                    'type': 'object',
                    'description': f'Records routed to {email}.',
                    'properties': {
                        'channel': {'type': 'string', 'enum': ['ops', 'oncall'],
                                    'description': f'Defaults to {email}.'},
                    },
                    'required': ['channel'],
                    'additionalProperties': False,
                },
            },
        },
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 2, 'root + property schema descriptions must both be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a text.format json_schema description leaked PII upstream'
    fmt = body['text']['format']
    assert fmt['type'] == 'json_schema', 'format type must be left intact'
    assert fmt['name'] == 'extraction', 'schema name must be left intact'
    assert fmt['strict'] is True, 'strict flag must be left intact'
    assert fmt['schema']['type'] == 'object', 'schema "type" must be left intact'
    assert fmt['schema']['properties']['channel']['enum'] == ['ops', 'oncall'], 'enum must be left intact'
    assert fmt['schema']['required'] == ['channel'], 'required list must be left intact'
    assert 'channel' in fmt['schema']['properties'], 'property name must be left intact'


# ---------------------------------------------------------------------------
# FINDING 2 (HIGH): a `file_data` data URI WITH media-type parameters
# (data:text/plain;charset=utf-8;base64,...) must still be decoded + redacted + re-encoded -- previously it fell
# through to an undecodable-text passthrough and shipped the inline payload unchanged.
# ---------------------------------------------------------------------------
def test_input_file_parameterized_data_uri_decoded_redacted_and_roundtrip():
    email = 'nadia.roy@example.com'
    ph = '<EMAIL_001>'
    raw_text = f'primary contact: {email}\nstatus: open\n'
    b64 = base64.b64encode(raw_text.encode('utf-8')).decode('ascii')
    data_uri = 'data:text/plain;charset=utf-8;base64,' + b64
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_file', 'filename': 'notes.txt', 'file_data': data_uri},  # mime ONLY in the URI
            ]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 1, 'a parameterized-data-URI text file must be surfaced as one field'

    wire_fd = body['input'][0]['content'][0]['file_data']
    assert wire_fd.startswith('data:text/plain;charset=utf-8;base64,'), 'the data-URI prefix must be preserved'
    decoded = base64.b64decode(wire_fd.split(',', 1)[1]).decode('utf-8')
    assert ph in decoded, 'placeholder must be present in the re-encoded parameterized file_data'
    assert email not in decoded, 'PRIVACY FAILURE: raw value still in decoded parameterized file_data'
    assert email not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: parameterized file_data leaked'

    # rehydrate the same way: decode -> swap placeholder back -> the local client sees the original file text
    part = body['input'][0]['content'][0]
    fd = ra.FileDataField(part, 'file_data', 'tool_result', 'data:text/plain;charset=utf-8;base64,', decoded)
    fd.write(fd.text.replace(ph, email))
    restored = base64.b64decode(part['file_data'].split(',', 1)[1]).decode('utf-8')
    assert restored == raw_text, 'rehydrated parameterized file_data must restore the original text exactly'


# ---------------------------------------------------------------------------
# FINDING 3 (MEDIUM, OVER-REDACTION): MCP / file-search ROUTING keys (server_label, server_url,
# vector_store_ids, allowed_tools) select which server/store/tool to call -- they are NOT free text and must
# NEVER be surfaced (a detector firing on one would corrupt the tool configuration).
# ---------------------------------------------------------------------------
def test_mcp_filesearch_routing_keys_not_surfaced():
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'mcp_call', 'id': 'mc_1', 'server_label': 'crm-prod',
             'server_url': 'https://mcp.internal.example/sse', 'name': 'lookup', 'arguments': '{}'},
        ],
        'tools': [
            {'type': 'mcp', 'server_label': 'crm', 'server_url': 'https://mcp.crm.example/sse',
             'allowed_tools': ['lookup', 'create']},
            {'type': 'file_search', 'vector_store_ids': ['vs_abc123', 'vs_def456']},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    routing = {'crm-prod', 'https://mcp.internal.example/sse', 'crm', 'https://mcp.crm.example/sse',
               'lookup', 'create', 'vs_abc123', 'vs_def456'}
    leaked = surfaced & routing
    assert not leaked, f'MCP/file-search routing strings must NOT be surfaced for redaction: {leaked}'
    # and the config survives a redaction pass untouched
    assert body['input'][0]['server_label'] == 'crm-prod'
    assert body['tools'][0]['allowed_tools'] == ['lookup', 'create']
    assert body['tools'][1]['vector_store_ids'] == ['vs_abc123', 'vs_def456']


# ---------------------------------------------------------------------------
# FINDING 4 (MEDIUM, REHYDRATION GAP): streaming events outside output_text / function_call_arguments must also
# rehydrate. Cover (a) a `.done` snapshot carrying part.text (content_part.done), (b) an `error` body,
# (c) a `.delta`-shaped family event (refusal.delta) including a placeholder SPLIT across two fragments,
# (d) a reasoning/mcp delta family -- all by structural shape, no enumerated allow-list.
# ---------------------------------------------------------------------------
def test_stream_content_part_done_rehydrated():
    email = 'luc.bernard@example.com'
    ph = '<EMAIL_001>'
    ev = (b'event: response.content_part.done\n'
          b'data: ' + json.dumps({
              'type': 'response.content_part.done', 'item_id': 'msg_1',
              'output_index': 0, 'content_index': 0,
              'part': {'type': 'output_text', 'text': f'Please reach {ph} now.'}}).encode('utf-8'))
    carry, tool_acc = {}, {}
    res = ra.transform_responses_event(ev, replay={ph: email}, carry=carry, tool_acc=tool_acc).decode('utf-8')
    assert email in res, 'content_part.done part.text must rehydrate'
    assert not _PH_RE.search(res), 'no placeholder may survive in a content_part.done event'


def test_stream_error_body_rehydrated():
    email = 'luc.bernard@example.com'
    ph = '<EMAIL_001>'
    ev = b'data: ' + json.dumps({'type': 'error', 'code': 'server_error',
                                  'message': f'upstream failed handling {ph}'}).encode('utf-8')
    carry, tool_acc = {}, {}
    res = ra.transform_responses_event(ev, replay={ph: email}, carry=carry, tool_acc=tool_acc).decode('utf-8')
    assert email in res, 'an error body must rehydrate placeholders'
    assert 'server_error' in res, 'a structural error code must be left intact'
    assert not _PH_RE.search(res), 'no placeholder may survive in an error event'


def test_stream_refusal_delta_split_placeholder_rehydrated():
    name = 'Genevieve Cliquot-Beaumont'
    ph = '<PERSON_001>'
    replay = {ph: name}
    # split the placeholder across two refusal.delta fragments: "...records for <PERS" | "ON_001>."
    e1 = (b'event: response.refusal.delta\n'
          b'data: ' + json.dumps({'type': 'response.refusal.delta', 'item_id': 'msg_1',
                                   'output_index': 0, 'content_index': 0,
                                   'delta': 'I cannot share records for <PERS'}).encode('utf-8'))
    e2 = (b'event: response.refusal.delta\n'
          b'data: ' + json.dumps({'type': 'response.refusal.delta', 'item_id': 'msg_1',
                                   'output_index': 0, 'content_index': 0,
                                   'delta': 'ON_001>.'}).encode('utf-8'))
    carry, tool_acc = {}, {}
    r1 = ra.transform_responses_event(e1, replay, carry, tool_acc).decode('utf-8')
    r2 = ra.transform_responses_event(e2, replay, carry, tool_acc).decode('utf-8')
    combined = r1 + r2
    assert name in combined, 'a split placeholder in refusal.delta must rehydrate once both fragments arrive'
    assert not _PH_RE.search(combined), 'no full placeholder may survive across split refusal deltas'
    # the partial token must never be emitted on its own (split-safe buffering held it back until completed)
    assert '<PERS' not in r1, 'a partial placeholder must be buffered, not emitted half-rendered'


def test_stream_reasoning_and_mcp_delta_families_rehydrated():
    val = 'Dossier-QX77182'
    ph = '<ACCOUNT_001>'
    replay = {ph: val}
    # free-text delta families (reasoning / code) emit immediately via the generic .delta path. The JSON-argument
    # streams (mcp_call_arguments AND custom_tool_call_input) instead BUFFER + flush JSON-safely at .done, covered by
    # test_stream_mcp_call_arguments_delta_json_safe and test_stream_custom_tool_call_input_delta_json_safe, so they
    # are intentionally NOT in this immediate-emit loop.
    for etype in ('response.reasoning_summary_text.delta', 'response.reasoning_text.delta',
                  'response.code_interpreter_call_code.delta'):
        ev = (b'event: ' + etype.encode('ascii') + b'\n'
              b'data: ' + json.dumps({'type': etype, 'item_id': 'x1',
                                      'output_index': 0, 'content_index': 0,
                                      'delta': f'concerning {ph} here'}).encode('utf-8'))
        carry, tool_acc = {}, {}
        res = ra.transform_responses_event(ev, replay, carry, tool_acc).decode('utf-8')
        assert val in res, f'{etype} delta must rehydrate'
        assert not _PH_RE.search(res), f'no placeholder may survive in a {etype} event'


def test_stream_refusal_done_flushes_tail_and_rehydrates():
    """refusal.done drains the delta-stream buffer for its key AND rehydrates its own snapshot body text.
    The delta stream completes the placeholder cleanly (real streams send the full token before .done), so the
    held tail is benign and the .done body carries the placeholder."""
    name = 'Genevieve Cliquot-Beaumont'
    ph = '<PERSON_001>'
    replay = {ph: name}
    carry, tool_acc = {}, {}
    d = (b'event: response.refusal.delta\n'
         b'data: ' + json.dumps({'type': 'response.refusal.delta', 'item_id': 'msg_1',
                                  'output_index': 0, 'content_index': 0,
                                  'delta': f'first {ph} '}).encode('utf-8'))
    r1 = ra.transform_responses_event(d, replay, carry, tool_acc).decode('utf-8')
    assert name in r1, 'a complete placeholder inside one refusal.delta rehydrates immediately'
    done = (b'event: response.refusal.done\n'
            b'data: ' + json.dumps({'type': 'response.refusal.done', 'item_id': 'msg_1',
                                    'output_index': 0, 'content_index': 0,
                                    'refusal': f'final note about {ph}'}).encode('utf-8'))
    res = ra.transform_responses_event(done, replay, carry, tool_acc).decode('utf-8')
    assert name in res, 'refusal.done body must rehydrate its own placeholder'
    assert carry == {}, 'the auxiliary delta carry must be drained on .done'


# ===========================================================================
# ROUND 3 -- the five remaining Codex DO-NOT-SHIP findings. Each test pins the exact leak / corruption the finding
# describes so a regression that reopens it fails loudly. 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# FINDING 1 (CRITICAL, route-level redaction bypass): `instructions` (and system/developer input content) is
# extracted with kind='system'. The egress redact_body gate only NEURAL-scans kind in
# ('message','tool_result','system') and only forwards-as-skip when NOTHING is a candidate or prose. A system
# field carrying NER-only PII (a synthetic name, no Tier-0 match) must count as PROSE so the gate scans it and
# does not return redaction:skip. This is a gate behavior, so we assert _looks_like_prose + the kind set directly
# against the egress module (imported by absolute path the same way `ra` is, so no heavy deps load at import-time
# unless egress_proxy itself pulls them -- skip cleanly if it does).
# ---------------------------------------------------------------------------
def _try_import_egress():
    """Import appliance/egress_proxy.py by absolute path; return the module or None if its heavy deps are absent
    in this test venv (the prose-gate fix is still covered by the adapter-level extraction tests above)."""
    eg_path = os.path.join(_APPLIANCE, 'egress_proxy.py')
    try:
        spec = importlib.util.spec_from_file_location('egress_proxy_under_test', eg_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def test_system_instructions_surfaced_with_system_kind():
    """The adapter surfaces `instructions` (and system/developer content) with kind='system' so the egress gate
    can prose-scan it. This is the extraction half of the round-3 CRITICAL fix (the gate half is asserted in
    test_egress_prose_gate_includes_system_kind)."""
    sys_prompt = 'You are the dedicated assistant supporting the client Franklin Outerbridge with his files today.'
    body = {'model': 'gpt-test', 'instructions': sys_prompt, 'input': 'hi'}
    fields = ra.extract_text_fields_responses(body)
    instr_fields = [f for f in fields if f.text == sys_prompt]
    assert instr_fields and instr_fields[0].kind == 'system', '`instructions` must be surfaced with kind system'


def test_egress_prose_gate_includes_system_kind():
    """CRITICAL round-3 route-level bypass: the egress redact_body prose predicate must treat kind='system' as
    prose-eligible, else an NER-only name (no Tier-0 match) in `instructions` hits redaction:skip and goes raw
    upstream. Prefer a live import; if the NPU stack is absent in this test venv, source-inspect the predicate so
    the fix is NEVER silently un-asserted (a regression that drops 'system' fails this test either way)."""
    eg = _try_import_egress()
    if eg is not None:
        sys_prompt = 'You are the assistant supporting the client Franklin Outerbridge with all of his files today.'
        assert eg._looks_like_prose(sys_prompt), 'a natural-language system prompt must read as prose'
        prose = 'system' in ('message', 'tool_result', 'system') and eg._looks_like_prose(sys_prompt)
        assert prose, 'system-kind prose must be neural-scan-eligible (else NER-only PII skips redaction)'
        return
    # fall back to source inspection: the prose predicate line must include the 'system' kind
    eg_src = open(os.path.join(_APPLIANCE, 'egress_proxy.py'), encoding='utf-8').read()
    m = re.search(r"prose\s*=\s*f\.kind in \(([^)]*)\)\s*and\s*_looks_like_prose", eg_src)
    assert m, 'could not locate the prose predicate in egress_proxy.redact_body'
    kinds = m.group(1)
    assert "'system'" in kinds or '"system"' in kinds, (
        'CRITICAL: the egress prose gate must include kind=system, else instructions NER-only PII skips redaction')


# ---------------------------------------------------------------------------
# FINDING 2 (HIGH): EXTENSIONLESS text uploads (Dockerfile, Makefile, LICENSE, ...) and unknown-extension files
# with valid UTF-8 content and NO MIME type must be decoded + redacted -- not forwarded raw because the extension
# allow-list missed them. file_data is deny-listed, so the recursive sweep cannot reach it; the decode path must.
# ---------------------------------------------------------------------------
def test_input_file_extensionless_dockerfile_decoded_and_redacted():
    email = 'devops@acme-loans.example'
    ph = '<EMAIL_001>'
    raw_text = f'FROM python:3.12\nLABEL maintainer="{email}"\nRUN pip install .\n'
    b64 = base64.b64encode(raw_text.encode('utf-8')).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'message', 'role': 'user', 'content': [
                # extensionless filename, NO mime_type -> must be decoded by the UTF-8 content backstop
                {'type': 'input_file', 'filename': 'Dockerfile', 'file_data': b64},
            ]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 1, 'an extensionless Dockerfile must be decoded + surfaced as one field'

    wire_b64 = body['input'][0]['content'][0]['file_data']
    decoded = base64.b64decode(wire_b64).decode('utf-8')
    assert ph in decoded and email not in decoded, 'PRIVACY FAILURE: extensionless text file_data not redacted'
    assert email not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: extensionless file_data leaked'


def test_input_file_unknown_extension_valid_utf8_decoded():
    """A file with an UNKNOWN extension, no MIME type, but valid UTF-8 content is decoded by the content backstop."""
    sin = 'SIN 046-454-286'
    ph = '<SIN_001>'
    raw_text = f'client record\n{sin}\n'
    b64 = base64.b64encode(raw_text.encode('utf-8')).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'input_file', 'filename': 'record.unknownext', 'file_data': b64},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, sin, ph) == 1, 'an unknown-extension valid-UTF-8 file must be decoded + surfaced'
    assert sin not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: unknown-extension text file leaked'


def test_input_file_no_mime_binary_bytes_stay_documented_passthrough():
    """A no-MIME upload whose bytes are NOT valid UTF-8 stays a documented passthrough note (the content backstop
    must not mangle genuine binary), and the raw filename is never logged verbatim."""
    png_bytes = b'\x89PNG\r\n\x1a\n\xff\xfe\x00\x01rawbytes'  # not valid UTF-8
    b64 = base64.b64encode(png_bytes).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'input_file', 'filename': 'patient-john-doe-2026.bin', 'file_data': b64},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert all(f.text != b64 for f in fields), 'raw binary base64 must never be surfaced as text'
    notes = ra.pop_file_passthrough_notes(body)
    assert len(notes) == 1 and notes[0]['reason'] == 'binary-or-undetermined'
    assert body['input'][0]['file_data'] == b64, 'binary file_data must pass through unchanged'


# ---------------------------------------------------------------------------
# FINDING 2b / MEDIUM (filename in log): the passthrough note must NOT carry the raw filename (it can itself carry
# PII, e.g. 'patient-john-doe-2026.bin'); only a sanitized extension descriptor reaches the log note.
# ---------------------------------------------------------------------------
def test_passthrough_note_filename_is_sanitized_not_raw():
    png_bytes = b'\x89PNG\r\n\x1a\n\xff\xfe\x00\x01rawbytes'
    b64 = base64.b64encode(png_bytes).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'input_file', 'filename': '/uploads/patient-john-doe-2026.bin',
             'mime_type': 'application/octet-stream', 'file_data': b64},
        ],
    }
    ra.extract_text_fields_responses(body)
    notes = ra.pop_file_passthrough_notes(body)
    assert len(notes) == 1, 'a binary file must produce one passthrough note'
    fn = notes[0]['filename']
    assert 'patient' not in (fn or '') and 'john' not in (fn or '') and 'doe' not in (fn or ''), (
        'PRIVACY FAILURE: a raw PII-bearing filename leaked into the log note')
    assert fn == '*.bin', 'the note must carry only a sanitized extension descriptor'


# ---------------------------------------------------------------------------
# FIX 1 (CRITICAL, enum/const PII literals): a PII value that appears ONLY as a JSON-Schema `const` literal (or an
# `enum` item) is a model-picked VALUE -- it must be SURFACED for span-based redaction, else it is forwarded RAW
# upstream. Redaction is span-based and the response rehydration maps the placeholder back, so const:'<EMAIL_001>'
# round-trips. `pattern` is the ONE deliberate structural exception kept on the deny-list: a pattern value is a
# REGEX and rewriting a substring of it can change its meaning, so it must NEVER be surfaced.
# ---------------------------------------------------------------------------
def test_tool_schema_const_surfaced_pattern_not():
    email = 'ops@acme-loans.example'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'hi',
        'tools': [
            {'type': 'function', 'name': 'route',
             'parameters': {'type': 'object', 'properties': {
                 'dest': {'type': 'string', 'const': email},
                 'channel': {'type': 'string', 'enum': ['ops', email]},
                 'phone': {'type': 'string', 'pattern': r'^\d{3}-\d{3}-\d{4}$'},
             }, 'required': ['dest'], 'additionalProperties': False}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    # the const literal AND the enum items are surfaced (model-picked values); the pattern regex is NOT.
    assert email in surfaced, 'a const literal carrying PII must be surfaced for redaction (FIX 1)'
    assert r'^\d{3}-\d{3}-\d{4}$' not in surfaced, 'a pattern regex must NEVER be surfaced (kept deny-listed)'
    # an ordinary enum item IS surfaced too, but span-based redaction never masks it (no PII pattern matches it),
    # so it passes through unchanged on the wire -- over-surfacing here is safe (the asserts below confirm it).

    # redact: both the const literal and the PII enum item get masked; the pattern regex is left untouched.
    touched = _swap_all(fields, email, ph)
    assert touched == 2, 'the const literal and the PII enum item must both be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a const/enum PII literal leaked RAW upstream'
    props = body['tools'][0]['parameters']['properties']
    assert props['dest']['const'] == ph, 'const literal must round-trip as a placeholder'
    assert props['channel']['enum'] == ['ops', ph], 'the PII enum item is masked; the ordinary one is intact'
    assert props['phone']['pattern'] == r'^\d{3}-\d{3}-\d{4}$', 'pattern regex must be left intact (deny-listed)'

    # a response echoing the const placeholder rehydrates the real value back for the local client
    resp = {'output': [{'type': 'message', 'role': 'assistant',
                        'content': [{'type': 'output_text', 'text': f'Routing to {ph}.'}]}]}
    ra.rehydrate_responses_response(resp, {ph: email})
    assert resp['output'][0]['content'][0]['text'] == f'Routing to {email}.'


# ---------------------------------------------------------------------------
# FINDING 4 (HIGH, streaming JSON corruption): response.mcp_call_arguments.delta fragments form a JSON arguments
# string. They must be BUFFERED and emitted JSON-safely at .done -- not plain-text rehydrated per fragment, which
# would corrupt the JSON when a replay value carries quotes/backslashes. Mirrors function_call_arguments handling.
# ---------------------------------------------------------------------------
def test_stream_mcp_call_arguments_delta_json_safe():
    ph = '<NAME_001>'
    tricky = 'a"b\\c'                      # quotes + backslash: plain-text rehydrate would break the JSON
    replay = {ph: tricky}
    full = json.dumps({'name': ph, 'note': f'see {ph}'})
    cut = len(full) // 2
    events = [
        (b'event: response.mcp_call_arguments.delta\n'
         b'data: ' + json.dumps({'type': 'response.mcp_call_arguments.delta',
                                 'item_id': 'mc_1', 'output_index': 0, 'delta': full[:cut]}).encode('utf-8')),
        (b'event: response.mcp_call_arguments.delta\n'
         b'data: ' + json.dumps({'type': 'response.mcp_call_arguments.delta',
                                 'item_id': 'mc_1', 'output_index': 0, 'delta': full[cut:]}).encode('utf-8')),
        (b'event: response.mcp_call_arguments.done\n'
         b'data: ' + json.dumps({'type': 'response.mcp_call_arguments.done',
                                 'item_id': 'mc_1', 'output_index': 0}).encode('utf-8')),
    ]
    carry, tool_acc = {}, {}
    r1 = ra.transform_responses_event(events[0], replay, carry, tool_acc)
    r2 = ra.transform_responses_event(events[1], replay, carry, tool_acc)
    r3 = ra.transform_responses_event(events[2], replay, carry, tool_acc)
    assert r1 is None and r2 is None, 'mcp_call_arguments delta fragments must be buffered, not emitted raw'
    assert r3 is not None
    payload = json.loads(r3.decode('utf-8').split('data: ', 1)[1])
    args = json.loads(payload['arguments'])   # MUST still be valid JSON after the tricky-value substitution
    assert args['name'] == tricky and args['note'] == f'see {tricky}', 'mcp args must rehydrate JSON-safely'
    assert not _PH_RE.search(r3.decode('utf-8'))


def test_stream_mcp_call_arguments_done_carries_arguments_when_no_delta_buffered():
    """If the upstream sends only an mcp_call_arguments.done (no buffered deltas) with an inline arguments string,
    it is still JSON-safely rehydrated."""
    ph = '<ACCOUNT_001>'
    val = 'Dossier-QX77182'
    ev = (b'event: response.mcp_call_arguments.done\n'
          b'data: ' + json.dumps({'type': 'response.mcp_call_arguments.done', 'item_id': 'mc_2',
                                   'arguments': json.dumps({'case': ph})}).encode('utf-8'))
    carry, tool_acc = {}, {}
    res = ra.transform_responses_event(ev, {ph: val}, carry, tool_acc).decode('utf-8')
    payload = json.loads(res.split('data: ', 1)[1])
    assert json.loads(payload['arguments'])['case'] == val, 'inline mcp arguments at .done must rehydrate'
    assert not _PH_RE.search(res)


# ---------------------------------------------------------------------------
# VERIFY-FAILURE GUARD: prompt.variables carrying a multi-PII string is fully surfaced for redaction (the round-3
# verify failure was a GATE detection gap on one synthetic surname, NOT an adapter extraction gap). This pins that
# the adapter DOES surface the whole variable string so every PII type in it reaches the gate.
# ---------------------------------------------------------------------------
def test_prompt_variables_multi_pii_string_fully_surfaced():
    blob = 'Contact Franklin Outerbridge at franklin@example.com or 514-555-0147.'
    body = {
        'model': 'gpt-test',
        'prompt': {'id': 'pmpt_1', 'variables': {'intro': blob}},
        'input': 'go',
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = [f for f in fields if f.text == blob]
    assert len(surfaced) == 1, 'the whole prompt.variables string must be surfaced as exactly one field'
    assert surfaced[0].kind == 'message', 'a prompt variable maps to kind message'


# ===========================================================================
# ROUND 4 -- the remaining DO-NOT-SHIP findings. Each test pins the exact leak/corruption so a regression that
# reopens it fails loudly. 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# FINDING 1 (HIGH leak): prompt.variables NESTED objects/arrays must be recursively swept. The explicit per-variable
# loop only surfaces top-level string values + a few part shapes; a variable whose value is a nested object or array
# kept its inner strings RAW (they went upstream without the neural gate). The recursive backstop over `prompt` now
# surfaces every nested string value too (deny-list still protects structural keys).
# ---------------------------------------------------------------------------
def test_prompt_variables_nested_object_and_array_swept():
    obj_val = 'sophie.tremblay@example.com'
    arr_val = 'marc-andre.dubois@example.com'
    body = {
        'model': 'gpt-test',
        'prompt': {
            'id': 'pmpt_nest',
            'variables': {
                'ctx': {'deep': {'note': f'reach {obj_val}'}},           # nested object value
                'recipients': [f'cc {arr_val}', 'no-pii-here'],          # nested array value
                'order_id': 'fixed-noPII',
            },
        },
        'input': 'Run it.',
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, obj_val, '<EMAIL_001>') == 1, 'a nested-object prompt variable string must be surfaced'
    assert _swap_all(fields, arr_val, '<EMAIL_002>') == 1, 'a nested-array prompt variable string must be surfaced'

    wire = json.dumps(body, ensure_ascii=False)
    assert obj_val not in wire and arr_val not in wire, (
        'PRIVACY FAILURE: a nested prompt.variables value leaked upstream without passing the gate')
    assert body['prompt']['variables']['order_id'] == 'fixed-noPII', 'a non-PII variable is left intact'


# ---------------------------------------------------------------------------
# FINDING 2 (HIGH leak): a bare `url` (citation/annotation-shaped) is MODEL-VISIBLE free text and must be surfaced
# for span-based redaction; it was globally deny-listed and skipped entirely, bypassing the gate. The ROUTING url
# keys (server_url / image_url / file_url / *_url) MUST stay deny-listed -- redacting one corrupts the request.
# ---------------------------------------------------------------------------
def test_citation_url_surfaced_but_routing_urls_not():
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'message', 'role': 'assistant', 'content': [
                {'type': 'output_text', 'text': 'See source.',
                 'annotations': [
                     {'type': 'url_citation', 'title': 'ref',
                      'url': 'https://host.example/profile?email=nadia.roy@example.com'}]},
                {'type': 'input_image', 'image_url': 'https://cdn.example/x.png'},   # routing: must NOT surface
            ]},
            {'type': 'mcp_call', 'id': 'mc_1', 'server_label': 'crm',
             'server_url': 'https://mcp.internal.example/sse', 'name': 'lookup', 'arguments': '{}'},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert 'https://host.example/profile?email=nadia.roy@example.com' in surfaced, (
        'a citation/annotation bare `url` must be surfaced for span-based redaction (FIX-ROUND-3 HIGH)')
    routing = {'https://cdn.example/x.png', 'https://mcp.internal.example/sse', 'crm'}
    leaked = surfaced & routing
    assert not leaked, f'ROUTING url/label keys must NOT be surfaced (would corrupt the request): {leaked}'

    # span-based redaction over the surfaced citation url masks only the PII substring; the url stays a Field that
    # rewrites in place, so a deterministic swap of the embedded email round-trips like any other free-text field.
    assert _swap_all(fields, 'nadia.roy@example.com', '<EMAIL_001>') == 1, 'the PII in the citation url is redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert 'nadia.roy@example.com' not in wire, 'PRIVACY FAILURE: PII in a citation url leaked upstream'
    assert body['input'][0]['content'][1]['image_url'] == 'https://cdn.example/x.png', 'routing url untouched'
    assert body['input'][1]['server_url'] == 'https://mcp.internal.example/sse', 'routing url untouched'


# ---------------------------------------------------------------------------
# FINDING 3 (MEDIUM leak): top-level `metadata` ({string:string}) is round-tripped and its values can carry PII;
# it was never swept -> forwarded raw. The recursive sweep now surfaces each metadata value for redaction.
# ---------------------------------------------------------------------------
def test_top_level_metadata_values_surfaced_and_redacted():
    email = 'sophie.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'hello',
        'metadata': {'requested_by': f'operator {email}', 'ticket': 'T-1234'},
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 1, 'a PII-bearing metadata value must be surfaced'
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a top-level metadata value leaked upstream'
    assert body['metadata']['ticket'] == 'T-1234', 'a non-PII metadata value is left intact'


# ---------------------------------------------------------------------------
# FINDING 5 (MEDIUM corruption/leak): json.loads collapses DUPLICATE object keys, so the FIRST value of a duplicate
# is invisible to the value collector AND would be silently dropped on re-dump. A duplicate-keyed arguments string
# must fall back to WHOLE-STRING redaction (the full string is scanned span-wise so the first value's PII is still
# masked) and must NOT silently drop a key.
# ---------------------------------------------------------------------------
def test_arguments_duplicate_keys_fall_back_to_whole_string():
    name1 = 'sophie.tremblay@example.com'      # the FIRST (would-be-collapsed) value
    name2 = 'marc-andre.dubois@example.com'    # the surviving value
    ph = '<EMAIL_001>'
    dup_args = '{"assignee": "' + name1 + '", "assignee": "' + name2 + '"}'   # duplicate key on purpose
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'c1', 'name': 'assign', 'arguments': dup_args},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # exactly one WHOLE-STRING field is surfaced for the arguments (not per-value), so the first value is visible
    arg_fields = [f for f in fields if name1 in f.text]
    assert len(arg_fields) == 1, 'a duplicate-keyed arguments string must surface as one whole-string field'
    assert name1 in arg_fields[0].text and name2 in arg_fields[0].text, (
        'whole-string fallback must keep BOTH duplicate values visible to the scanner (no silent collapse)')

    # whole-string redaction masks both PII values; the arguments string is preserved (no key dropped)
    touched = _swap_all(fields, name1, ph) + _swap_all(fields, name2, ph)
    assert touched == 2, 'both duplicate-key values must be redactable via the whole-string field'
    wire = json.dumps(body, ensure_ascii=False)
    assert name1 not in wire and name2 not in wire, (
        'PRIVACY FAILURE: a duplicate-key arguments value leaked (the first value was collapsed away)')


# ===========================================================================
# ROUND 4 / R2 -- the LAST TWO Codex code leaks. Each test pins the exact leak so a regression that reopens it
# fails loudly. 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# LEAK 1 (HIGH): the structural deny-list was over-applied INSIDE user-data payloads. A value under a key that
# merely SHARES a name with a structural key (name / *_id / id / customer_id / ...) inside prompt.variables, top-
# level metadata, or a function_call_output payload was deny-listed and never neural-scanned -> forwarded RAW. The
# deny-list is now CONTEXT-SCOPED: structural in the request envelope + the tool-definition parameters SCHEMA, but
# inside user data EVERY string value is surfaced regardless of key name (routing urls + file_data stay protected,
# being request-breaking in any context). The tool DEFINITION name + schema property/enum keywords stay structural.
# ---------------------------------------------------------------------------
def test_leak1_prompt_variables_structural_named_key_surfaced_and_roundtrip():
    """A prompt.variables entry under a key called 'name' (shares a name with a structural key) holds a person name
    in USER DATA -> it must be surfaced + redacted, not deny-listed."""
    name = 'Genevieve Cliquot-Beaumont'
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'prompt': {'id': 'pmpt_1', 'version': '2', 'variables': {'name': name, 'order_id': 'fixed-noPII'}},
        'input': 'go',
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, name, ph) == 1, "a user-data 'name' variable must be surfaced (not deny-listed)"
    wire = json.dumps(body, ensure_ascii=False)
    assert name not in wire, "PRIVACY FAILURE: a prompt.variables 'name' value leaked (deny-list over-applied)"
    assert body['prompt']['id'] == 'pmpt_1', 'the prompt envelope id stays structural (never redacted)'

    # round-trip: a response echoing the placeholder under a 'name' key rehydrates the real value (blanket swap)
    resp = {'output': [{'type': 'message', 'role': 'assistant',
                        'content': [{'type': 'output_text', 'text': f'Hello {ph}.'}]}]}
    ra.rehydrate_responses_response(resp, {ph: name})
    assert resp['output'][0]['content'][0]['text'] == f'Hello {name}.'
    assert not _PH_RE.search(json.dumps(resp))


def test_leak1_metadata_customer_id_key_surfaced_and_roundtrip():
    """Top-level metadata is USER DATA top-to-bottom: a value under a 'customer_id' key (matches the *_id family)
    holding a PII email must be surfaced + redacted, not skipped by the deny-list."""
    email = 'sophie.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'hi',
        'metadata': {'customer_id': email, 'ticket': 'T-1234'},
    }
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, ph) == 1, "a metadata 'customer_id' value must be surfaced (not deny-listed)"
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, "PRIVACY FAILURE: a metadata 'customer_id' value leaked (deny-list over-applied)"
    assert body['metadata']['ticket'] == 'T-1234', 'a non-PII metadata value is left intact'

    # round-trip: a response metadata echo of the placeholder under 'customer_id' rehydrates the real value
    resp = {'id': 'resp_1', 'metadata': {'customer_id': ph, 'ticket': 'T-1234'}}
    ra.rehydrate_responses_response(resp, {ph: email})
    assert resp['metadata']['customer_id'] == email
    assert not _PH_RE.search(json.dumps(resp))


def test_leak1_function_call_output_dict_id_key_surfaced_and_roundtrip():
    """A function_call_output whose `output` is a DICT carrying PII under an 'id' key (matches the *_id family) is
    USER DATA -> the value must be surfaced + redacted, not deny-listed away."""
    pii = 'jean.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call_output', 'call_id': 'call_1',
             'output': {'id': pii, 'status': 'ok', 'name': pii}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # the 'id' AND 'name' values both carry the PII in user data; both must be surfaced
    assert _swap_all(fields, pii, ph) == 2, "user-data 'id'/'name' values in fco.output must be surfaced"
    wire = json.dumps(body, ensure_ascii=False)
    assert pii not in wire, "PRIVACY FAILURE: a function_call_output dict value leaked (deny-list over-applied)"
    # the call_id ENVELOPE field stays structural -- it was never a candidate
    assert body['input'][0]['call_id'] == 'call_1', 'the call_id envelope field stays structural'

    # round-trip: a response echoing the placeholder under 'id'/'name' in an output dict rehydrates losslessly
    resp = {'output': [{'type': 'function_call_output', 'call_id': 'call_1',
                        'output': {'id': ph, 'status': 'ok', 'name': ph}}]}
    ra.rehydrate_responses_response(resp, {ph: pii})
    assert resp['output'][0]['output']['id'] == pii and resp['output'][0]['output']['name'] == pii
    assert not _PH_RE.search(json.dumps(resp))


def test_leak1_structural_protection_intact():
    """GUARD: the LEAK 1 context-scoping must NOT relax STRUCTURAL protection -- the tool DEFINITION name, the
    json_schema property NAMES, the enum/const KEYWORD keys, and routing ids/urls must STILL never be surfaced
    (redacting them breaks the request). Only the request-breaking error is unsafe; over-redaction in user data is."""
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'shell_call', 'id': 'sc_1', 'call_id': 'call_abc', 'name': 'bash',
             'action': {'type': 'exec', 'commands': ['ls']}},
        ],
        'tools': [
            {'type': 'function', 'name': 'send_alert', 'description': 'Send an alert.',
             'parameters': {'type': 'object',
                            'properties': {'channel': {'type': 'string', 'enum': ['ops', 'oncall']}},
                            'required': ['channel'], 'additionalProperties': False, 'strict': True}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    structural = {'send_alert', 'bash', 'sc_1', 'call_abc', 'shell_call', 'object', 'function',
                  'channel', 'string', 'gpt-test'}
    leaked = surfaced & structural
    assert not leaked, f'STRUCTURAL protection broken -- these must never be surfaced: {leaked}'
    # 'channel' is a property NAME (a schema key) and must NOT be surfaced; the enum VALUES (ops/oncall) MAY be
    # (model-picked values, span-redaction-safe). The tool name 'send_alert' must never be surfaced (renaming
    # breaks calls). The free-text command 'ls' IS surfaced.
    assert 'channel' not in surfaced, 'a json_schema property NAME must stay structural'
    assert 'send_alert' not in surfaced, 'the tool DEFINITION name must stay structural (renaming breaks calls)'
    assert 'ls' in surfaced, 'the genuine free-text command must still be surfaced'
    # and a redaction pass leaves the whole structural surface untouched on the wire
    _swap_all(fields, 'send_alert', '<X_001>')  # no field holds it, so nothing changes
    assert body['tools'][0]['name'] == 'send_alert', 'tool name survives a redaction pass'
    assert body['tools'][0]['parameters']['properties']['channel']['enum'] == ['ops', 'oncall']


# ---------------------------------------------------------------------------
# LEAK 2 (HIGH): JSON argument OBJECT KEYS were never scanned. PII encoded AS a JSON object key (e.g. an email used
# as the key) was forwarded RAW. Object keys are now surfaced for redaction: a PII key is renamed to its placeholder
# and the object re-serialized (JSON-safe). Rehydration is symmetric -- a placeholder appearing in an object KEY is
# restored to the original key.
# ---------------------------------------------------------------------------
def test_leak2_function_call_arguments_object_key_redacted_and_roundtrip():
    email = 'user.synthetic@example.com'        # synthetic email used AS an object key
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'c1', 'name': 'lookup',
             'arguments': json.dumps({email: {'role': 'admin'}, 'plain_key': 'value'})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # the object KEY is surfaced as its own field (not just values)
    assert email in {f.text for f in fields}, 'a PII object KEY in arguments must be surfaced for redaction'
    assert _swap_all(fields, email, ph) == 1, 'the PII object key must be redacted'

    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a raw PII object KEY leaked upstream from function_call.arguments'
    # the forwarded arguments stays VALID JSON with the key replaced by the placeholder
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert ph in rebuilt and 'plain_key' in rebuilt, 'arguments must remain valid JSON with the PII key redacted'
    assert rebuilt[ph] == {'role': 'admin'}, 'the key value is preserved under the redacted key'

    # a response echoing the placeholder-KEY rehydrates back to the ORIGINAL key (symmetric rehydration)
    resp = {'output': [{'type': 'function_call', 'call_id': 'c1', 'name': 'lookup',
                        'arguments': json.dumps({ph: {'role': 'admin'}})}]}
    ra.rehydrate_responses_response(resp, {ph: email})
    out = json.loads(resp['output'][0]['arguments'])
    assert email in out, 'a placeholder object KEY must rehydrate back to the original key'
    assert out[email] == {'role': 'admin'}
    assert not _PH_RE.search(json.dumps(resp))


def test_leak2_object_key_and_value_both_pii_coexist():
    """When an entry's KEY and VALUE both carry PII, redacting both must coexist (the value-field follows the key
    rename via a shared current-key cell) and re-serialize as valid JSON, in either redaction order."""
    email = 'user@example.com'
    phone = '514-555-0199'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call', 'call_id': 'c1', 'name': 'note', 'arguments': json.dumps({email: phone})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    # redact the KEY first, then the VALUE: the value-field must not KeyError on the renamed key
    assert _swap_all(fields, email, '<EMAIL_001>') == 1, 'the PII object key is surfaced + redacted'
    assert _swap_all(fields, phone, '<PHONE_001>') == 1, 'the PII value is surfaced + redacted after the key rename'
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert rebuilt == {'<EMAIL_001>': '<PHONE_001>'}, 'both key and value redacted, JSON still valid'
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire and phone not in wire, 'PRIVACY FAILURE: a key/value PII pair leaked'


def test_leak2_rehydrate_json_string_restores_key_and_value():
    """rehydrate_json_string (the value/stream-level handler) must restore placeholders in object KEYS as well as
    values, JSON-safely -- including an original key that contains quotes/backslashes."""
    ph_k = '<EMAIL_001>'
    ph_v = '<NAME_001>'
    tricky_key = 'a"b\\c@example.com'           # original key with quotes + backslash
    name = 'Priya McCallum'
    args = json.dumps({ph_k: ph_v})
    out = ra.rehydrate_json_string(args, {ph_k: tricky_key, ph_v: name})
    parsed = json.loads(out)                    # MUST still be valid JSON after key + value substitution
    assert tricky_key in parsed, 'a placeholder object KEY must rehydrate (quotes/backslashes re-escaped safely)'
    assert parsed[tricky_key] == name, 'the value must rehydrate too'


# ===========================================================================
# ROUND 4-R2 (the 5 still-blocked findings). Each test pins one fix so a regression reopens it loudly.
# 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# R2 ITEM 1 (HIGH): the recursive USER-DATA walker iterated dict keys only as traversal metadata and never surfaced
# them, so PII encoded AS a dict KEY (an email used as the key of a metadata / prompt.variables /
# function_call_output.output / nested tool-output map) bypassed scanning entirely. Plain-dict object keys in
# user-data scope are now surfaced + redacted (key renamed in place) and rehydrated symmetrically.
# ---------------------------------------------------------------------------
def test_r2_metadata_pii_object_key_surfaced_redacted_and_roundtrip():
    email = 'vip.synthetic@example.com'          # synthetic email used AS a metadata KEY
    ph = '<EMAIL_001>'
    body = {'model': 'gpt-test', 'input': 'go',
            'metadata': {email: 'flagged', 'ticket': 'T-1234'}}
    fields = ra.extract_text_fields_responses(body)
    assert email in {f.text for f in fields}, 'a PII metadata object KEY must be surfaced (not just values)'
    assert _swap_all(fields, email, ph) == 1, 'the PII metadata key must be redacted'

    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a raw PII metadata object KEY leaked upstream'
    assert ph in body['metadata'] and body['metadata'][ph] == 'flagged', 'the value is preserved under the renamed key'
    assert body['metadata']['ticket'] == 'T-1234', 'a non-PII sibling key/value is left intact'

    # symmetric rehydration: a response echoing the placeholder KEY restores the original email key
    resp = {'id': 'resp_1', 'metadata': {ph: 'flagged', 'ticket': 'T-1234'}}
    ra.rehydrate_responses_response(resp, {ph: email})
    assert email in resp['metadata'] and resp['metadata'][email] == 'flagged', 'a placeholder KEY must rehydrate'
    assert not _PH_RE.search(json.dumps(resp))


def test_r2_function_call_output_dict_pii_key_surfaced_and_roundtrip():
    """A function_call_output whose `output` is a DICT keyed by PII (an email key) is user data: the KEY must be
    surfaced + redacted and the placeholder KEY must rehydrate back on the response side."""
    email = 'agent.synthetic@example.com'
    ph = '<EMAIL_001>'
    body = {'model': 'gpt-test', 'input': [
        {'type': 'function_call_output', 'call_id': 'call_1', 'output': {email: 'owner'}},
    ]}
    fields = ra.extract_text_fields_responses(body)
    assert email in {f.text for f in fields}, 'a PII KEY in function_call_output.output dict must be surfaced'
    assert _swap_all(fields, email, ph) == 1, 'the PII output-dict key must be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a raw PII function_call_output.output KEY leaked upstream'

    resp = {'output': [{'type': 'function_call_output', 'call_id': 'call_1', 'output': {ph: 'owner'}}]}
    ra.rehydrate_responses_response(resp, {ph: email})
    assert email in resp['output'][0]['output'], 'a placeholder output-dict KEY must rehydrate back to the email'


def test_r2_prompt_variables_nested_pii_key_surfaced():
    """A prompt.variables value that is a nested dict keyed by PII surfaces the KEY (LEAK 1 round-2 reached only
    string VALUES of nested objects; the KEY itself was still invisible)."""
    email = 'lead.synthetic@example.com'
    body = {'model': 'gpt-test', 'input': 'go',
            'prompt': {'id': 'pmpt_1', 'variables': {'ctx': {email: 'note'}}}}
    fields = ra.extract_text_fields_responses(body)
    assert email in {f.text for f in fields}, 'a PII KEY nested in a prompt.variables object must be surfaced'
    assert _swap_all(fields, email, '<EMAIL_001>') == 1
    assert email not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: a nested prompt.variables KEY leaked'


def test_r2_structural_keys_still_not_surfaced_as_keys():
    """GUARD: object KEYS are surfaced ONLY in user-data scope. A tool DEFINITION name, json_schema PROPERTY names,
    and the enum/const/properties/required KEYWORD keys live in STRUCTURAL scope and must NEVER be surfaced as
    redactable keys (renaming one would corrupt the request schema)."""
    body = {'model': 'gpt-test', 'input': 'go', 'tools': [
        {'type': 'function', 'name': 'send_alert', 'description': 'Send an alert.',
         'parameters': {'type': 'object',
                        'properties': {'channel': {'type': 'string', 'enum': ['ops', 'oncall']},
                                       'recipient': {'type': 'string'}},
                        'required': ['channel']}},
    ]}
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    must_not = {'send_alert', 'channel', 'recipient', 'properties', 'required', 'parameters', 'type', 'enum'}
    leaked = surfaced & must_not
    assert not leaked, f'structural schema KEYS / the tool name must NOT be surfaced as redactable keys: {leaked}'


# ---------------------------------------------------------------------------
# R2 ITEM 2 (MEDIUM): treating every `output`/`outputs` subtree as user-data dropped structural protection for
# nested ROUTING IDs such as file_id, so a detected span inside a valid file_id could corrupt the upstream request.
# Known protocol routing IDs (file_id/container_id/call_id/item_id/response_id/previous_response_id/connector_id)
# stay protected EVEN in user-data scope; an application id (bare `id`, customer_id) remains surfaceable (LEAK 1).
# ---------------------------------------------------------------------------
def test_r2_routing_file_id_protected_inside_user_data_output():
    body = {'model': 'gpt-test', 'input': [
        {'type': 'function_call_output', 'call_id': 'call_1', 'output': {
            'file_id': 'file-AbC123XyZ', 'id': 'rec_007', 'note': 'contact Olivier Tremblay'}},
    ]}
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert 'file-AbC123XyZ' not in surfaced, 'a routing file_id inside user-data output must STAY protected'
    # but an application id and the free-text note ARE surfaced (LEAK 1 user-data behavior preserved)
    assert 'rec_007' in surfaced, "a bare application `id` in user data is surfaceable (not a routing key)"
    assert 'contact Olivier Tremblay' in surfaced, 'free-text user-data values are still surfaced'


def test_r2_routing_id_protected_does_not_regress_leak1_customer_id():
    """LEAK 1 must still hold: a customer_id (NOT a protocol routing id) inside user data is surfaced as PII."""
    email = 'cust.synthetic@example.com'
    body = {'model': 'gpt-test', 'input': 'go', 'metadata': {'customer_id': email, 'ticket': 'T-1'}}
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, email, '<EMAIL_001>') == 1, 'a customer_id value in user data must still be surfaced'


# ---------------------------------------------------------------------------
# R2 ITEM 3 (MEDIUM) -- SUPERSEDED BY FIX-ROUND-4-R3 FIX C: JSON-argument key redaction rebuilt into a plain dict
# without collision handling, so renaming a key to an already-present placeholder key silently dropped one entry. The
# R2 fix avoided the drop by NO-OPPING the rename, but that KEPT THE RAW PII KEY on the wire -- a leak. FIX C now
# disambiguates the colliding placeholder (append a counter) so BOTH guarantees hold: the raw PII key NEVER survives
# AND no sibling entry is dropped. This test pins the FIX C behavior (the old `pii_key in rebuilt` was the leak).
# ---------------------------------------------------------------------------
def test_r2_json_args_key_rename_collision_drops_nothing():
    # two distinct keys; redacting the FIRST to a placeholder that ALREADY exists as the second key would collide.
    pii_key = 'collide.synthetic@example.com'
    body = {'model': 'gpt-test', 'input': [
        {'type': 'function_call', 'call_id': 'c1', 'name': 'm',
         'arguments': json.dumps({pii_key: 'a', '<EMAIL_001>': 'b'})},   # placeholder pre-exists as a sibling key
    ]}
    fields = ra.extract_text_fields_responses(body)
    ra_n = _swap_all(fields, pii_key, '<EMAIL_001>')   # rename pii_key -> a key that already exists
    rebuilt = json.loads(body['input'][0]['arguments'])
    wire = json.dumps(body, ensure_ascii=False)
    # FIX C: the raw PII key must NEVER survive on the wire (the R2 no-op leaked it by keeping the original key).
    assert pii_key not in rebuilt and pii_key not in wire, (
        'PRIVACY FAILURE: the raw PII object KEY survived on a placeholder collision (FIX C regression)')
    # AND no entry may be dropped: both the disambiguated redacted key and the pre-existing sibling survive.
    assert rebuilt['<EMAIL_001>'] == 'b', 'the pre-existing sibling entry must survive (no overwrite)'
    assert len(rebuilt) == 2, f'no entry may be silently dropped on a key-rename collision: {rebuilt}'
    assert '<EMAIL_001>.dup1' in rebuilt and rebuilt['<EMAIL_001>.dup1'] == 'a', (
        'the colliding redacted key is disambiguated (counter appended) so both entries survive')
    assert ra_n == 1


# ---------------------------------------------------------------------------
# R2 ITEM 4 (MEDIUM): response-side rehydrate_json_string used plain json.loads, so DUPLICATE-key arguments from
# upstream collapsed before rehydration and silently dropped earlier values. It now parses with the dup-key reject
# hook and falls back to whole-string text rehydrate, restoring every placeholder without dropping a value.
# ---------------------------------------------------------------------------
def test_r2_rehydrate_json_string_duplicate_keys_no_silent_drop():
    n1, n2 = 'Jane Synthetic', 'John Synthetic'
    replay = {'<NAME_001>': n1, '<NAME_002>': n2}
    dup = '{"assignee": "<NAME_001>", "assignee": "<NAME_002>"}'   # duplicate key from upstream
    out = ra.rehydrate_json_string(dup, replay)
    # BOTH values must survive + rehydrate (plain json.loads would collapse to the last, dropping n1)
    assert n1 in out and n2 in out, 'both duplicate-key values must rehydrate (no silent collapse)'
    assert not _PH_RE.search(out), 'no placeholder may survive'


def test_r2_stream_function_call_args_done_duplicate_keys_no_drop():
    """The streaming .done path uses rehydrate_json_string; a duplicate-key buffered args string must keep both."""
    n1, n2 = 'Amel Synthetic', 'Bilal Synthetic'
    replay = {'<NAME_001>': n1, '<NAME_002>': n2}
    full = '{"assignee": "<NAME_001>", "assignee": "<NAME_002>"}'
    cut = len(full) // 2
    evs = [
        (b'event: response.function_call_arguments.delta\n'
         b'data: ' + json.dumps({'type': 'response.function_call_arguments.delta',
                                 'item_id': 'fc_1', 'delta': full[:cut]}).encode('utf-8')),
        (b'event: response.function_call_arguments.delta\n'
         b'data: ' + json.dumps({'type': 'response.function_call_arguments.delta',
                                 'item_id': 'fc_1', 'delta': full[cut:]}).encode('utf-8')),
        (b'event: response.function_call_arguments.done\n'
         b'data: ' + json.dumps({'type': 'response.function_call_arguments.done',
                                 'item_id': 'fc_1'}).encode('utf-8')),
    ]
    carry, tool_acc = {}, {}
    ra.transform_responses_event(evs[0], replay, carry, tool_acc)
    ra.transform_responses_event(evs[1], replay, carry, tool_acc)
    res = ra.transform_responses_event(evs[2], replay, carry, tool_acc).decode('utf-8')
    assert n1 in res and n2 in res, 'both duplicate-key values must survive streaming rehydration'
    assert not _PH_RE.search(res)


# ---------------------------------------------------------------------------
# R2 ITEM 5 (MEDIUM): custom_tool_call_input.delta fell through to per-fragment PLAIN-TEXT rehydration instead of
# JSON-safe buffering, so a placeholder value containing quotes/backslashes produced INVALID streamed JSON. It now
# buffers per (event-base, item_id) and emits the FULL JSON-safely-rehydrated `input` string only at .done --
# symmetric with the request-side _is_json_args_key treatment of '*input'.
# ---------------------------------------------------------------------------
def test_r2_stream_custom_tool_call_input_delta_json_safe():
    ph = '<NAME_001>'
    tricky = 'a"b\\c'                      # quotes + backslash: plain-text rehydrate would break the JSON
    replay = {ph: tricky}
    full = json.dumps({'name': ph, 'note': f'see {ph}'})
    cut = len(full) // 2
    events = [
        (b'event: response.custom_tool_call_input.delta\n'
         b'data: ' + json.dumps({'type': 'response.custom_tool_call_input.delta',
                                 'item_id': 'ct_1', 'output_index': 0, 'delta': full[:cut]}).encode('utf-8')),
        (b'event: response.custom_tool_call_input.delta\n'
         b'data: ' + json.dumps({'type': 'response.custom_tool_call_input.delta',
                                 'item_id': 'ct_1', 'output_index': 0, 'delta': full[cut:]}).encode('utf-8')),
        (b'event: response.custom_tool_call_input.done\n'
         b'data: ' + json.dumps({'type': 'response.custom_tool_call_input.done',
                                 'item_id': 'ct_1', 'output_index': 0}).encode('utf-8')),
    ]
    carry, tool_acc = {}, {}
    r1 = ra.transform_responses_event(events[0], replay, carry, tool_acc)
    r2 = ra.transform_responses_event(events[1], replay, carry, tool_acc)
    r3 = ra.transform_responses_event(events[2], replay, carry, tool_acc)
    assert r1 is None and r2 is None, 'custom_tool_call_input delta fragments must be BUFFERED, not emitted raw'
    assert r3 is not None
    payload = json.loads(r3.decode('utf-8').split('data: ', 1)[1])
    parsed = json.loads(payload['input'])   # MUST still be valid JSON after the tricky-value substitution
    assert parsed['name'] == tricky and parsed['note'] == f'see {tricky}', 'input must rehydrate JSON-safely'
    assert not _PH_RE.search(r3.decode('utf-8'))


def test_r2_stream_custom_tool_call_input_done_inline_json_safe():
    """If only a .done arrives with an inline `input` string (no buffered deltas), it is still JSON-safely rehydrated
    on the `input` field (not `arguments`)."""
    ph = '<ACCOUNT_001>'
    val = 'Dossier-QX77182'
    ev = (b'event: response.custom_tool_call_input.done\n'
          b'data: ' + json.dumps({'type': 'response.custom_tool_call_input.done', 'item_id': 'ct_2',
                                   'input': json.dumps({'case': ph})}).encode('utf-8'))
    carry, tool_acc = {}, {}
    res = ra.transform_responses_event(ev, {ph: val}, carry, tool_acc).decode('utf-8')
    payload = json.loads(res.split('data: ', 1)[1])
    assert json.loads(payload['input'])['case'] == val, 'inline custom_tool_call_input at .done must rehydrate'
    assert not _PH_RE.search(res)


# ===========================================================================
# ROUND 4-R3 -- the final six Codex adversarial/structural edges. Each test pins the exact over-redaction / leak /
# drop the finding describes so a regression that reopens it fails loudly. 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# FIX A (HIGH :619): scope is decided by STRUCTURAL POSITION, not by rematching a key NAME at arbitrary depth. A
# tool / text.format JSON SCHEMA may legitimately declare a property literally named output / outputs / variables.
# Seeing that NAME inside a schema previously flipped the walk into USER-DATA scope, so the schema's
# type / required / property-name STRUCTURE got treated as user data and risked OVER-REDACTION that corrupts the
# request. Once the walk has entered a tool-definition `parameters` / text.format `schema` subtree it STAYS
# structural for the WHOLE subtree regardless of any property name; user-data scope is entered ONLY at the genuine
# user-data containers at their envelope position.
# ---------------------------------------------------------------------------
def test_fixA_schema_property_named_output_stays_structural():
    body = {
        'model': 'gpt-test',
        'input': 'go',
        'tools': [
            {'type': 'function', 'name': 'build',
             'parameters': {'type': 'object', 'properties': {
                 # a property literally named 'output' (and 'variables'): a SCHEMA property name, NOT a user-data
                 # container. Its nested structure must stay structural -- type/property-names must NOT be surfaced.
                 'output': {'type': 'string', 'description': 'The build output destination.'},
                 'variables': {'type': 'object',
                               'properties': {'mode': {'type': 'string', 'enum': ['fast', 'slow']}},
                               'required': ['mode']},
             }, 'required': ['output'], 'additionalProperties': False}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    # OVER-REDACTION guard: nothing structural inside the output/variables schema properties may be surfaced.
    structural = {'build', 'output', 'variables', 'object', 'string', 'mode', 'fast', 'slow', 'fast', 'function'}
    # 'fast'/'slow' are enum VALUES that ARE surfaceable in schema scope (span-redaction-safe), so exclude them.
    must_not = {'build', 'output', 'variables', 'object', 'string', 'mode', 'function'}
    leaked = surfaced & must_not
    assert not leaked, f'schema structure under an output/variables property must STAY structural: {leaked}'
    # the genuine schema description prose IS still surfaced (it is model-visible free text, not a structural token)
    assert 'The build output destination.' in surfaced, 'a schema description must still be surfaced as free text'
    # a redaction pass leaves the schema structure untouched on the wire (property names + types intact)
    _swap_all(fields, 'output', '<X_001>')   # no field holds the bare 'output' name, so nothing changes
    props = body['tools'][0]['parameters']['properties']
    assert 'output' in props and props['output']['type'] == 'string', 'the output property NAME + type must survive'
    assert 'variables' in props and props['variables']['type'] == 'object', 'the variables property must survive'
    assert props['variables']['properties']['mode']['enum'] == ['fast', 'slow'], 'nested enum must survive'


def test_fixA_genuine_user_data_output_still_surfaced():
    """GUARD: FIX A must NOT break the genuine LEAK 1 behavior. A function_call_output.output dict at its real
    ENVELOPE position is still user data -- a value under an 'id'/'name' key there must STILL be surfaced (the
    schema-position suppression applies only inside an actual tool/text.format schema, not to a real output payload)."""
    pii = 'jean.tremblay@example.com'
    ph = '<EMAIL_001>'
    body = {'model': 'gpt-test', 'input': [
        {'type': 'function_call_output', 'call_id': 'call_1', 'output': {'id': pii, 'name': pii, 'status': 'ok'}},
    ]}
    fields = ra.extract_text_fields_responses(body)
    assert _swap_all(fields, pii, ph) == 2, "user-data output 'id'/'name' values must STILL be surfaced (LEAK 1)"
    assert pii not in json.dumps(body, ensure_ascii=False), 'PRIVACY FAILURE: genuine user-data output leaked'


# ---------------------------------------------------------------------------
# FIX B (HIGH :382): routing-URL protection applies ONLY by structural position. A genuine routing URL (image_url on
# an input_image part, server_url / file_url for mcp/tool routing) stays protected in STRUCTURAL scope. But a *_url
# INSIDE a USER-DATA payload (metadata.profile_url, function_call_output.output.profile_url) is USER CONTENT whose
# value can carry PII and MUST be scanned -- it is no longer protected by the both-scopes request-breaking check.
# ---------------------------------------------------------------------------
def test_fixB_user_data_url_surfaced_routing_url_protected():
    pii = 'nadia.roy@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call_output', 'call_id': 'c1',
             'output': {'profile_url': f'https://crm.example/u?email={pii}', 'status': 'ok'}},
            # genuine routing parts in STRUCTURAL scope -- must STAY protected (redacting one corrupts the request)
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_image', 'image_url': 'https://cdn.example/x.png'}]},
            {'type': 'mcp_call', 'id': 'mc_1', 'server_label': 'crm',
             'server_url': 'https://mcp.internal.example/sse', 'name': 'lookup', 'arguments': '{}'},
        ],
        # top-level metadata is user data top-to-bottom: a *_url value here is user content, scannable.
        'metadata': {'source_url': f'https://intake.example/?e={pii}', 'ticket': 'T-1'},
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    # the two USER-DATA *_url values are surfaced for span-based redaction
    assert f'https://crm.example/u?email={pii}' in surfaced, 'a *_url inside user-data output must be scanned (FIX B)'
    assert f'https://intake.example/?e={pii}' in surfaced, 'a *_url inside top-level metadata must be scanned (FIX B)'
    # the genuine routing URLs / labels stay protected (never surfaced)
    routing = {'https://cdn.example/x.png', 'https://mcp.internal.example/sse', 'crm'}
    assert not (surfaced & routing), f'genuine routing URLs must STAY protected by structural position: {surfaced & routing}'

    # span-based redaction masks only the PII substring in each user-data url; the routing urls are untouched
    assert _swap_all(fields, pii, ph) == 2, 'the PII in both user-data urls must be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert pii not in wire, 'PRIVACY FAILURE: PII in a user-data *_url leaked upstream'
    assert body['input'][1]['content'][0]['image_url'] == 'https://cdn.example/x.png', 'routing image_url untouched'
    assert body['input'][2]['server_url'] == 'https://mcp.internal.example/sse', 'routing server_url untouched'

    # round-trip: a response echoing the placeholder inside a user-data url rehydrates the real value (blanket swap)
    resp = {'output': [{'type': 'function_call_output', 'call_id': 'c1',
                        'output': {'profile_url': f'https://crm.example/u?email={ph}', 'status': 'ok'}}]}
    ra.rehydrate_responses_response(resp, {ph: pii})
    assert resp['output'][0]['output']['profile_url'] == f'https://crm.example/u?email={pii}'
    assert not _PH_RE.search(json.dumps(resp))


# ---------------------------------------------------------------------------
# FIX C (HIGH :165 + :235, MEDIUM :940): a placeholder-key COLLISION must never leave a raw PII key on the wire AND
# must never drop an entry. Cover all three sites: (1) JSON-args key rename (the leaky no-op was already retargeted
# in test_r2_json_args_key_rename_collision_drops_nothing), (2) the in-place user-data dict rename, and (3) the
# RESPONSE-side rehydrate (rehydrate_json_string + rehydrate_responses_response), where two placeholders mapping to
# the same value previously dropped an entry on rebuild.
# ---------------------------------------------------------------------------
def test_fixC_user_data_dict_key_collision_no_raw_key_no_drop():
    """In-place user-data dict (_DictEntry): redacting a PII metadata KEY to a placeholder that ALREADY exists as a
    sibling must NOT keep the raw PII key (the R2 no-op leak) AND must NOT drop the sibling entry."""
    pii_key = 'collide.synthetic@example.com'
    ph = '<EMAIL_001>'
    body = {'model': 'gpt-test', 'input': 'go',
            # the placeholder pre-exists as a sibling KEY in user-data metadata
            'metadata': {pii_key: 'a', ph: 'b'}}
    fields = ra.extract_text_fields_responses(body)
    n = _swap_all(fields, pii_key, ph)   # rename the PII key -> a key that already exists
    assert n == 1, 'the PII metadata key is surfaced + redacted exactly once'
    md = body['metadata']
    wire = json.dumps(body, ensure_ascii=False)
    # (a) the raw PII key must NEVER survive on the wire
    assert pii_key not in md and pii_key not in wire, 'PRIVACY FAILURE: raw PII metadata KEY survived a collision'
    # (b) no entry dropped: both the disambiguated redacted key and the pre-existing sibling survive
    assert md[ph] == 'b', 'the pre-existing sibling entry must survive (no overwrite)'
    assert len(md) == 2, f'no metadata entry may be dropped on a key collision: {md}'
    assert md[f'{ph}.dup1'] == 'a', 'the colliding redacted key is disambiguated so both entries survive'


def test_fixC_response_rehydrate_collision_drops_nothing():
    """RESPONSE side (:940): two DISTINCT placeholders mapping to the SAME rehydrated value previously collapsed to
    one entry on rebuild (a dropped key). rehydrate_json_string AND rehydrate_responses_response must keep both."""
    shared = 'shared.synthetic@example.com'    # two placeholders both rehydrate to this same value
    replay = {'<EMAIL_001>': shared, '<EMAIL_002>': shared}
    # (1) value-level / arguments-string handler
    args = json.dumps({'<EMAIL_001>': 'a', '<EMAIL_002>': 'b'})
    out = ra.rehydrate_json_string(args, replay)
    parsed = json.loads(out)
    assert len(parsed) == 2, f'no entry may be dropped when two placeholder keys rehydrate to one value: {parsed}'
    assert 'a' in parsed.values() and 'b' in parsed.values(), 'both entry values must survive the collision'
    assert not _PH_RE.search(out), 'no placeholder may survive rehydration'

    # (2) full recursive response walk (metadata object keyed by two placeholders -> same value)
    resp = {'id': 'r1', 'metadata': {'<EMAIL_001>': 'a', '<EMAIL_002>': 'b'}}
    ra.rehydrate_responses_response(resp, replay)
    assert len(resp['metadata']) == 2, f'recursive rehydrate must not drop a metadata entry on collision: {resp}'
    assert set(resp['metadata'].values()) == {'a', 'b'}, 'both metadata entry values must survive'
    assert not _PH_RE.search(json.dumps(resp)), 'no placeholder may survive recursive rehydration'


# ---------------------------------------------------------------------------
# FIX D (MEDIUM :322): `name` is globally deny-listed because it is the structural tool/function name. But a file /
# input_file part can use `name` as a FILENAME ALIAS, so a PII filename under `name` leaked while filename/file_name
# are scanned. In file/input_file part context `name` is treated as a filename and SCANNED; it stays deny-listed
# where it is the tool/function structural name.
# ---------------------------------------------------------------------------
def test_fixD_file_part_name_filename_alias_surfaced():
    pii_name = 'patient-genevieve-cliquot.txt'   # a PII filename carried under the `name` alias
    ph = '<FILENAME_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            # an input_file part WITHOUT inline data (referenced by id) carrying a PII filename under `name`
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_file', 'file_id': 'file-abc123', 'name': pii_name}]},
        ],
        'tools': [
            # a tool DEFINITION `name` must STAY deny-listed (renaming it would break calls)
            {'type': 'function', 'name': 'lookup_records', 'description': 'Look up records.',
             'parameters': {'type': 'object', 'properties': {}, 'required': []}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert pii_name in surfaced, 'a PII filename under a file-part `name` ALIAS must be surfaced for scanning (FIX D)'
    assert 'lookup_records' not in surfaced, 'a tool DEFINITION name must STAY deny-listed (renaming breaks calls)'

    assert _swap_all(fields, pii_name, ph) == 1, 'the file-part name-alias filename must be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert pii_name not in wire, 'PRIVACY FAILURE: a PII filename under the `name` alias leaked upstream'
    assert body['tools'][0]['name'] == 'lookup_records', 'the tool name survives a redaction pass (deny-listed)'
    # round-trip: a response echoing the placeholder filename rehydrates the original name (blanket swap)
    resp = {'output': [{'type': 'message', 'role': 'assistant',
                        'content': [{'type': 'output_text', 'text': f'Read {ph}.'}]}]}
    ra.rehydrate_responses_response(resp, {ph: pii_name})
    assert resp['output'][0]['content'][0]['text'] == f'Read {pii_name}.'


def test_fixD_file_part_name_with_inline_text_data_both_surfaced():
    """A file part using `name` as a filename alias AND carrying inline text file_data: BOTH the filename (`name`)
    and the decoded file content are surfaced; the binary-passthrough log note still sanitizes the name."""
    fname_pii = 'contact-marie-gagnon.md'
    body_pii = 'devops@acme-loans.example'
    raw_text = f'maintainer: {body_pii}\n'
    b64 = base64.b64encode(raw_text.encode('utf-8')).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'input_file', 'name': fname_pii, 'mime_type': 'text/markdown', 'file_data': b64},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert fname_pii in surfaced, 'the `name` filename alias must be surfaced even when inline file_data is present'
    # the decoded file content is surfaced as a redactable field too (file_data decode path intact)
    assert _swap_all(fields, body_pii, '<EMAIL_001>') == 1, 'decoded inline file content must still be surfaced'
    assert _swap_all(fields, fname_pii, '<FILENAME_001>') == 1, 'the name-alias filename must still be surfaced'
    wire = json.dumps(body, ensure_ascii=False)
    assert fname_pii not in wire and body_pii not in wire, 'PRIVACY FAILURE: a name-alias or inline-content PII leaked'


# ===========================================================================
# ROUND 4-R3 / R2 -- the four still-blocked Codex findings (prior round blocked). Each test pins the exact
# leak / corruption so a regression that reopens it fails loudly. 100% synthetic data.
# ===========================================================================

# ---------------------------------------------------------------------------
# ITEM 1 (HIGH :410): `file_data` was treated as request-breaking in BOTH scopes via _is_request_breaking_key, so an
# ORDINARY user-data field named `file_data` (metadata.file_data, function_call_output.output.file_data) was skipped
# and never scanned -- even though metadata is explicitly walked as user data. The genuine inline-upload `file_data`
# lives on an input_file / file PART in STRUCTURAL scope (protected by _DENY_KEYS + the _file_part_fields claim), so
# protecting it by key-name in user-data scope was a leak. A user-data `file_data` value is now SURFACED + scanned.
# ---------------------------------------------------------------------------
def test_r3r2_item1_user_data_file_data_value_surfaced_and_roundtrip():
    email = 'nadia.roy@example.com'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'function_call_output', 'call_id': 'c1',
             'output': {'file_data': f'attachment note for {email}', 'status': 'ok'}},
        ],
        # top-level metadata is user data top-to-bottom: a value under a `file_data` key is user content, scannable.
        'metadata': {'file_data': f'metadata note for {email}', 'ticket': 'T-1'},
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert f'attachment note for {email}' in surfaced, 'a user-data output.file_data value must be surfaced (ITEM 1)'
    assert f'metadata note for {email}' in surfaced, 'a user-data metadata.file_data value must be surfaced (ITEM 1)'
    assert _swap_all(fields, email, ph) == 2, 'both user-data file_data values must be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a user-data file_data field leaked upstream (deny-list over-applied)'
    assert body['metadata']['ticket'] == 'T-1', 'a non-PII metadata sibling is left intact'

    # round-trip: a response echoing the placeholder under a user-data file_data key rehydrates the real value
    resp = {'output': [{'type': 'function_call_output', 'call_id': 'c1',
                        'output': {'file_data': f'attachment note for {ph}', 'status': 'ok'}}]}
    ra.rehydrate_responses_response(resp, {ph: email})
    assert resp['output'][0]['output']['file_data'] == f'attachment note for {email}'
    assert not _PH_RE.search(json.dumps(resp))


def test_r3r2_item1_genuine_inline_upload_file_data_still_protected():
    """GUARD: ITEM 1 must NOT regress the inline-upload protection. A GENUINE input_file part with base64 file_data
    is still handled by the dedicated decode path (its raw base64 is NEVER surfaced as free text; only the decoded
    content is), and a binary upload still produces a documented passthrough note rather than a raw-bytes surface."""
    email = 'devops@acme-loans.example'
    ph = '<EMAIL_001>'
    raw_text = f'maintainer: {email}\n'
    b64 = base64.b64encode(raw_text.encode('utf-8')).decode('ascii')
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_file', 'filename': 'notes.md', 'mime_type': 'text/markdown', 'file_data': b64}]},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert all(f.text != b64 for f in fields), 'a genuine inline-upload base64 must NEVER be surfaced raw (ITEM 1 guard)'
    # the decoded content IS surfaced (decode path intact) and redactable
    assert _swap_all(fields, email, ph) == 1, 'the decoded inline-upload content must still be surfaced + redacted'
    decoded = base64.b64decode(body['input'][0]['content'][0]['file_data']).decode('utf-8')
    assert ph in decoded and email not in decoded, 'the placeholder must land in the re-encoded file_data'

    # binary upload still a documented passthrough note, raw base64 never surfaced
    png = base64.b64encode(b'\x89PNG\r\n\x1a\n\xff\xferaw').decode('ascii')
    body2 = {'model': 'gpt-test', 'input': [
        {'type': 'input_file', 'filename': 'logo.png', 'mime_type': 'image/png', 'file_data': png}]}
    f2 = ra.extract_text_fields_responses(body2)
    assert all(f.text != png for f in f2), 'binary inline-upload base64 must never be surfaced as text'
    notes = ra.pop_file_passthrough_notes(body2)
    assert len(notes) == 1 and notes[0]['reason'] == 'binary-or-undetermined', 'binary upload stays a documented note'


# ---------------------------------------------------------------------------
# ITEM 2 (HIGH :695): nested schema LITERALS under enum/const did not enter value scope. A DIRECT string enum/const
# value was surfaced, but an OBJECT/ARRAY literal stayed in structural scope, so nested strings under deny-listed keys
# (name / id / *_url) were skipped -- regressing the enum/const hardening for valid NON-STRING JSON-Schema literals.
# Descending THROUGH an enum/const key now enters value scope, so every nested literal string is surfaced. `pattern`
# (a regex, reached as a SIBLING of enum/const, never through one) stays deny-listed and is never surfaced.
# ---------------------------------------------------------------------------
def test_r3r2_item2_nested_literal_under_const_and_enum_surfaced():
    email = 'ops@acme-loans.example'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'hi',
        'tools': [
            {'type': 'function', 'name': 'route',
             'parameters': {'type': 'object', 'properties': {
                 # const is an OBJECT literal carrying PII under deny-listed keys name + id
                 'dest': {'type': 'object', 'const': {'name': email, 'id': email}},
                 # enum is a LIST of object literals carrying PII under a deny-listed-shaped key
                 'pick': {'type': 'array', 'enum': [{'contact': email}]},
                 # pattern (regex) is a SIBLING and must STAY deny-listed
                 'phone': {'type': 'string', 'pattern': r'^\d{3}-\d{3}-\d{4}$'},
             }, 'required': ['dest'], 'additionalProperties': False}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert email in surfaced, 'a nested string under a const/enum object literal must be surfaced (ITEM 2)'
    assert r'^\d{3}-\d{3}-\d{4}$' not in surfaced, 'a pattern regex must NEVER be surfaced (kept deny-listed)'
    # all three nested-literal copies of the email are redactable; the pattern sibling is untouched
    assert _swap_all(fields, email, ph) == 3, 'every nested const/enum literal string must be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert email not in wire, 'PRIVACY FAILURE: a nested const/enum object-literal PII leaked RAW upstream'
    props = body['tools'][0]['parameters']['properties']
    assert props['dest']['const'] == {'name': ph, 'id': ph}, 'the const object literal redacts in place'
    assert props['pick']['enum'] == [{'contact': ph}], 'the enum object literal redacts in place'
    assert props['phone']['pattern'] == r'^\d{3}-\d{3}-\d{4}$', 'the pattern regex stays intact (deny-listed)'


def test_r3r2_item2_direct_string_const_still_surfaced_property_names_intact():
    """GUARD: ITEM 2 must NOT over-surface. A DIRECT string const/enum is still surfaced (FIX-ROUND-4-R3 behavior),
    and the schema PROPERTY NAMES + type tokens around it stay structural (never surfaced)."""
    email = 'ops@acme-loans.example'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'hi',
        'tools': [
            {'type': 'function', 'name': 'route',
             'parameters': {'type': 'object', 'properties': {
                 'dest': {'type': 'string', 'const': email},
                 'channel': {'type': 'string', 'enum': ['ops', 'oncall']},
             }, 'required': ['dest'], 'additionalProperties': False}},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    surfaced = {f.text for f in fields}
    assert email in surfaced, 'a direct string const literal must still be surfaced'
    must_not = {'route', 'dest', 'channel', 'object', 'string', 'function'}
    assert not (surfaced & must_not), f'schema property names/types must stay structural: {surfaced & must_not}'
    assert _swap_all(fields, email, ph) == 1
    assert body['tools'][0]['parameters']['properties']['channel']['enum'] == ['ops', 'oncall'], 'enum intact'


# ---------------------------------------------------------------------------
# ITEM 3 (MEDIUM :705): a user-data dict KEY was not surfaced when _is_json_args_key(k) matched. _is_json_args_key
# matches any key ending with 'input'/'arguments', so a PII user-data key such as 'x@example.com_input' (an email
# that merely ends in 'input') bypassed key scanning. The json-args slot handling is now gated to STRUCTURAL scope
# (it is a request-envelope mechanism), so in user-data scope such a key is surfaced + redacted like any other key.
# ---------------------------------------------------------------------------
def test_r3r2_item3_user_data_key_ending_in_input_surfaced_and_roundtrip():
    pii_key = 'marie.gagnon@example.com_input'      # a PII email key that ends in 'input'
    ph = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'input': 'go',
        'metadata': {pii_key: 'flagged', 'ticket': 'T-1'},
    }
    fields = ra.extract_text_fields_responses(body)
    assert pii_key in {f.text for f in fields}, "a user-data key ending in 'input' must be surfaced (ITEM 3)"
    assert _swap_all(fields, pii_key, ph) == 1, 'the PII user-data input-suffixed key must be redacted'
    wire = json.dumps(body, ensure_ascii=False)
    assert pii_key not in wire, "PRIVACY FAILURE: a user-data '*_input' key leaked (key-scanning was skipped)"
    assert body['metadata'][ph] == 'flagged', 'the value is preserved under the renamed key'
    assert body['metadata']['ticket'] == 'T-1', 'a non-PII sibling is left intact'

    # symmetric rehydration of the placeholder key
    resp = {'id': 'r1', 'metadata': {ph: 'flagged', 'ticket': 'T-1'}}
    ra.rehydrate_responses_response(resp, {ph: pii_key})
    assert pii_key in resp['metadata'] and resp['metadata'][pii_key] == 'flagged'
    assert not _PH_RE.search(json.dumps(resp))


def test_r3r2_item3_structural_function_call_arguments_still_slot_parsed():
    """GUARD: ITEM 3 gates json-args slot handling to STRUCTURAL scope -- it must NOT regress the envelope path. A
    function_call.arguments / mcp_call.arguments JSON string on an agentic item (structural scope) must STILL be
    parsed value-by-value (the NER sees a bare name) and re-serialize as valid JSON, not be skipped."""
    name = 'Priya McCallum'
    ph = '<PERSON_001>'
    body = {
        'model': 'gpt-test',
        'input': [
            {'type': 'mcp_call', 'id': 'mc_1', 'server_label': 'crm', 'name': 'assign',
             'arguments': json.dumps({'assignee_name': name, 'priority': 'high'})},
        ],
    }
    fields = ra.extract_text_fields_responses(body)
    assert name in {f.text for f in fields}, 'a structural mcp_call.arguments value must still be slot-parsed (ITEM 3 guard)'
    assert _swap_all(fields, name, ph) == 1, 'the name value inside arguments is redacted'
    rebuilt = json.loads(body['input'][0]['arguments'])
    assert rebuilt == {'assignee_name': ph, 'priority': 'high'}, 'arguments stays valid JSON, value redacted in place'


# ---------------------------------------------------------------------------
# ITEM 4 (MEDIUM :1046): duplicate-key JSON RESPONSE arguments fell back to rehydrate_text() (a blind substring
# placeholder swap). That preserves duplicate keys, but it is NOT JSON-safe when a replay VALUE contains quotes or
# backslashes -- the raw chars get spliced into the JSON, producing malformed JSON. The fallback now parses with a
# duplicate-preserving hook and re-serializes every KEY + VALUE via json.dumps, so both entries survive AND the JSON
# stays valid even for tricky replay values. Mirrors the request-side whole-string fallback's no-drop guarantee.
# ---------------------------------------------------------------------------
def test_r3r2_item4_duplicate_key_response_rehydrate_json_safe_for_tricky_value():
    tricky = 'a"b\\c'                               # quotes + backslash: blind rehydrate_text would break the JSON
    clean = 'clean.value'
    replay = {'<NAME_001>': tricky, '<NAME_002>': clean}
    dup = '{"assignee": "<NAME_001>", "assignee": "<NAME_002>"}'   # duplicate key from upstream
    out = ra.rehydrate_json_string(dup, replay)
    # MUST still be valid JSON after the tricky-value substitution (the old blind swap produced malformed JSON)
    parsed = json.loads(out)
    assert isinstance(parsed, dict), 'the duplicate-key rehydration must stay valid JSON for a tricky value'
    # both duplicate keys are preserved in the serialized output (no silent drop)
    assert out.count('"assignee"') == 2, 'both duplicate keys must survive in the rehydrated output (no drop)'
    assert clean in out, 'the clean duplicate value must rehydrate'
    # the tricky value rehydrates to its real chars once JSON-unescaped (the json.loads last-wins gives the 2nd here,
    # but a single-key tricky case below proves the value itself round-trips correctly)
    assert not _PH_RE.search(out), 'no placeholder may survive rehydration'

    # single-key tricky value confirms the rehydrated value itself is correct + JSON-valid
    single = json.dumps({'who': '<NAME_001>'})
    out2 = ra.rehydrate_json_string(single, {'<NAME_001>': tricky})
    assert json.loads(out2) == {'who': tricky}, 'a tricky replay value must rehydrate to the exact value, JSON-safe'


def test_r3r2_item4_duplicate_key_nested_object_stays_json_safe():
    """A duplicate-keyed NESTED object (under a no-duplicate top-level object) must also serialize JSON-safely with a
    tricky replay value -- the duplicate-preserving serializer recurses per value rather than handing the whole dict
    to json.dumps (which cannot serialize the duplicate-preserving wrapper)."""
    tricky = 'x"y\\z'
    replay = {'<NAME_001>': tricky, '<NAME_002>': 'second'}
    nested = '{"outer": {"k": "<NAME_001>", "k": "<NAME_002>"}, "plain": "<NAME_001>"}'
    out = ra.rehydrate_json_string(nested, replay)
    parsed = json.loads(out)   # MUST be valid JSON despite the nested duplicate + tricky value
    assert parsed['plain'] == tricky, 'the no-duplicate sibling value must rehydrate JSON-safely'
    assert isinstance(parsed['outer'], dict), 'the nested duplicate object stays a valid JSON object'
    assert out.count('"k"') == 2, 'both nested duplicate keys must survive (no drop)'
    assert not _PH_RE.search(out), 'no placeholder may survive rehydration'
