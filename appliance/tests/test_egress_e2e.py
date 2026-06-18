"""Always-on end-to-end harness for the egress privacy proxy (egress_proxy.redact_body + rehydrate).

WHY this file exists: redact_body() is the headline always-on LLM filter. Everything that matters about the
product -- the redact<->rehydrate round-trip, the repeated-value sweep that is the core never-leak guarantee
(Finding C), the OpenAI-route parity, and graceful degradation when the NPU is unreachable -- lives in that
one async function plus the two adapters. The deployed regex floor is already covered by test_appliance_floor;
this harness covers the WIRING ABOVE it end to end, with the model network mocked out so it runs offline.

HOW it runs with no heavy deps: .venv-test has pytest only -- no httpx/fastapi/uvicorn/yaml/cryptography and
no pytest-asyncio. So we (1) install tiny in-process stubs for those module names into sys.modules BEFORE
importing egress_proxy (the stubs satisfy only the names egress_proxy touches on the paths we drive -- we never
hit a real socket because _detect_neural is monkeypatched and the FastAPI routes are bypassed in favour of
calling redact_body() directly), and (2) drive the async redact_body via stdlib asyncio.run() instead of a
pytest-asyncio marker. The privacy_gate / secrets_scan / entity_map / openai_adapter modules are the REAL
appliance copies (pure-stdlib regex + a tiny AES shim), so the detection floor and the entity map under test
are the production code, not fakes.

100% SYNTHETIC data. No real PII anywhere. The "neural detector" is a deterministic substring finder so the
test asserts the proxy's PLUMBING (substitute + known-value sweep + rehydrate), not a model's recall.
"""
import os
import re
import sys
import json
import types
import asyncio
import tempfile
import importlib
import importlib.util

import pytest


# ---------------------------------------------------------------------------
# Step 1: stub the heavy third-party deps egress_proxy imports at module top.
# These stubs exist ONLY so the import succeeds and the non-network code paths
# run; we never reach a real HTTP call (the routes are bypassed and the neural
# detector is monkeypatched), so the stubs can be inert. Installed into
# sys.modules so the real packages, if ever present, are not shadowed globally
# beyond this test process.
# ---------------------------------------------------------------------------
def _install_stub(name, module):
    # only stub if the real dependency is genuinely absent in .venv-test; never shadow an installed package
    if importlib.util.find_spec(name) is None:
        sys.modules.setdefault(name, module)


# --- httpx: redact_body opens `async with httpx.AsyncClient(timeout=60) as c`
#     in detection pass 1. We monkeypatch _detect_neural so `c` is never used to
#     reach the network, but the context manager must still enter/exit cleanly.
_httpx = types.ModuleType('httpx')


class _StubAsyncClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):  # pragma: no cover -- never called (neural is mocked)
        raise AssertionError('network egress attempted in an offline test')

    def stream(self, *a, **k):  # pragma: no cover
        raise AssertionError('network egress attempted in an offline test')


_httpx.AsyncClient = _StubAsyncClient
_install_stub('httpx', _httpx)


# --- fastapi + fastapi.responses: only used at import time for the @app.post
#     decorators and Response classes. A no-op app whose .post/.get return the
#     function unchanged is enough; we call redact_body() directly, not via routes.
_fastapi = types.ModuleType('fastapi')


class _StubApp:
    def __init__(self, *a, **k):
        pass

    def post(self, *a, **k):
        return lambda fn: fn

    def get(self, *a, **k):
        return lambda fn: fn


class _StubRequest:  # pragma: no cover -- routes are not exercised
    pass


def _passthrough_response(*a, **k):  # pragma: no cover
    return (a, k)


_fastapi.FastAPI = _StubApp
_fastapi.Request = _StubRequest
_fastapi.Response = _passthrough_response
# capture whether fastapi is genuinely absent BEFORE we install the stub (the stub has no __spec__, which would
# make a later find_spec() raise) -- if absent, stub both fastapi and its .responses submodule together.
_fastapi_absent = importlib.util.find_spec('fastapi') is None
_install_stub('fastapi', _fastapi)
if _fastapi_absent:
    _fastapi_responses = types.ModuleType('fastapi.responses')
    _fastapi_responses.JSONResponse = _passthrough_response
    _fastapi_responses.StreamingResponse = _passthrough_response
    _fastapi_responses.Response = _passthrough_response
    sys.modules.setdefault('fastapi.responses', _fastapi_responses)
    _fastapi.responses = _fastapi_responses

# --- uvicorn: only uvicorn.run() at __main__; never invoked under import.
_uvicorn = types.ModuleType('uvicorn')
_uvicorn.run = lambda *a, **k: None  # pragma: no cover
_install_stub('uvicorn', _uvicorn)

# --- yaml: load_config() calls yaml.safe_load on the config file. We point
#     CONFIG_PATH at a path that does not exist (below) so DEFAULT_CONFIG is used
#     and safe_load is never actually needed, but stub it for safety.
_yaml = types.ModuleType('yaml')
_yaml.safe_load = lambda *a, **k: {}
_install_stub('yaml', _yaml)


# --- cryptography AESGCM: entity_map encrypts the on-disk map at module import
#     (`_AES = AESGCM(_load_key())`). We do not need real crypto for a test -- we
#     need a REVERSIBLE transform so EntityMap.save()/._load() round-trips. This
#     shim is a trivial identity "cipher" (ct == plaintext) that satisfies the
#     (nonce, data, aad) signature. It is test-only and never ships.
def _ensure_crypto_stub():
    if importlib.util.find_spec('cryptography') is not None:
        return
    crypto = types.ModuleType('cryptography')
    hz = types.ModuleType('cryptography.hazmat')
    prim = types.ModuleType('cryptography.hazmat.primitives')
    ciph = types.ModuleType('cryptography.hazmat.primitives.ciphers')
    aead = types.ModuleType('cryptography.hazmat.primitives.ciphers.aead')

    class _StubAESGCM:
        def __init__(self, key):
            self._key = key

        @staticmethod
        def generate_key(bit_length=256):
            return os.urandom(bit_length // 8)

        # identity transform: round-trips so the map persists/reloads; NOT secure -- test only.
        def encrypt(self, nonce, data, aad):
            return bytes(data)

        def decrypt(self, nonce, ct, aad):
            return bytes(ct)

    aead.AESGCM = _StubAESGCM
    ciph.aead = aead
    prim.ciphers = ciph
    hz.primitives = prim
    crypto.hazmat = hz
    for n, mod in [('cryptography', crypto),
                   ('cryptography.hazmat', hz),
                   ('cryptography.hazmat.primitives', prim),
                   ('cryptography.hazmat.primitives.ciphers', ciph),
                   ('cryptography.hazmat.primitives.ciphers.aead', aead)]:
        sys.modules.setdefault(n, mod)


_ensure_crypto_stub()


# ---------------------------------------------------------------------------
# Step 2: route the appliance copies of the NPU stack onto sys.path and isolate
# the encrypted entity map under a throwaway tmp dir (so no run pollutes another
# and we never touch the real ~/.ossredact/maps). Then import the real
# egress_proxy + openai_adapter against the stubs above.
# ---------------------------------------------------------------------------
_APPLIANCE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _APPLIANCE not in sys.path:
    sys.path.insert(0, _APPLIANCE)

_MAPS_TMP = tempfile.mkdtemp(prefix='qcpii-e2e-maps-')
os.environ['GATEWAY_MAPS_DIR'] = _MAPS_TMP
os.environ['GATEWAY_MAP_KEY'] = os.path.join(_MAPS_TMP, '.mapkey')
os.environ['GATEWAY_CONFIG'] = os.path.join(_MAPS_TMP, 'no-such-config.yaml')  # force DEFAULT_CONFIG


# --- Module-name collision fix (the reason these tests used to skip) -------
# The bare names egress_proxy imports (`from privacy_gate import tier0_spans`, plus entity_map / secrets_scan /
# openai_adapter) are NOT unique across this repo: gate/privacy_gate.py ALSO publishes the name `privacy_gate`, but
# exports validated_floor and has NO tier0_spans. Python caches the FIRST `privacy_gate` imported in sys.modules
# and serves it to every later importer (sys.modules is consulted BEFORE sys.path / sys.meta_path). So when pytest
# collected gate/tests first, gate's copy was cached and a plain `import egress_proxy` here bound egress_proxy's
# `from privacy_gate import tier0_spans` to the gate module -> `cannot import name 'tier0_spans'` -> the 5 tests
# skipped. (The mirror hazard: if WE leave the appliance copy cached, a later gate import gets the wrong one.)
#
# Fix (test-side only): for the duration of importing egress_proxy, load the APPLIANCE copies by ABSOLUTE file path
# and pin them into sys.modules under their bare names (evicting any stale gate-sourced entry first), THEN restore
# sys.modules to its prior state. egress_proxy binds the floor functions by name AT its import
# (`from privacy_gate import tier0_spans, ...`) and `import openai_adapter` as a module object, so once it is loaded
# those references are captured -- removing the temporary bare-name pins afterward does not affect egress_proxy, and
# it leaves a clean bare-name slot so a gate test importing later still resolves gate's own copy via its
# `sys.path.insert(0, gate/)`. This makes the import collision-proof in BOTH collection orders, touching only
# sys.modules transiently and never editing any source module or any gate test.
import contextlib  # noqa: E402


@contextlib.contextmanager
def _appliance_modules_pinned(bare_names):
    """Temporarily bind each bare name to its appliance/<name>.py copy (loaded by absolute path), then restore the
    pre-existing sys.modules entries so no cross-suite copy is left cached after egress_proxy is built."""
    saved = {name: sys.modules.get(name) for name in bare_names}
    loaded = {}
    try:
        for name in bare_names:
            path = os.path.join(_APPLIANCE, name + '.py')
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module     # register BEFORE exec so self/peer imports resolve to this copy
            spec.loader.exec_module(module)
            loaded[name] = module
        yield loaded
    finally:
        for name, prev in saved.items():
            if prev is None:
                sys.modules.pop(name, None)   # was absent before -- leave it absent for the next importer
            else:
                sys.modules[name] = prev      # restore whatever (gate copy, etc.) was cached before


try:
    # privacy_gate is the colliding one; entity_map / secrets_scan / openai_adapter / egress_proxy are appliance-only
    # today but loaded by path too so a future same-named gate file cannot shadow them, and so egress_proxy is never
    # served from a stale cache. Order: leaf deps first, egress_proxy last (it imports the others).
    with _appliance_modules_pinned(
            ['privacy_gate', 'entity_map', 'secrets_scan', 'openai_adapter', 'egress_proxy']) as _mods:
        assert hasattr(_mods['privacy_gate'], 'tier0_spans'), (
            'expected the APPLIANCE privacy_gate (tier0_spans) but loaded '
            + repr(getattr(_mods['privacy_gate'], '__file__', None)))
        egress_proxy = _mods['egress_proxy']       # captured before sys.modules is restored on context exit
        openai_adapter = _mods['openai_adapter']
    _IMPORT_ERR = None
except Exception as e:  # pragma: no cover -- surfaces as a clear skip below
    egress_proxy = None
    openai_adapter = None
    _IMPORT_ERR = e

_NEEDS_PROXY = pytest.mark.skipif(
    egress_proxy is None,
    reason=f'egress_proxy could not be imported even with stdlib stubs: {_IMPORT_ERR!r}')


@_NEEDS_PROXY
def test_neural_detect_cache_key_does_not_retain_raw_text():
    raw = 'Client Priya McCallum uses priya.mccallum@example.test'
    key = egress_proxy._detect_cache_key(raw, 0.5)

    assert raw not in repr(key), 'raw request text must not be retained in the neural-cache key'
    assert key == egress_proxy._detect_cache_key(raw, 0.5), 'same text and score should reuse the cache entry'
    assert key != egress_proxy._detect_cache_key(raw + ' extra', 0.5)
    assert key != egress_proxy._detect_cache_key(raw, 0.6)


# ---------------------------------------------------------------------------
# Test doubles + helpers.
# ---------------------------------------------------------------------------
def _make_neural(found):
    """Build an async stand-in for egress_proxy._detect_neural.

    `found` maps a verbatim substring -> label. The stub finds, per call, the FIRST occurrence of each key in
    the field text and emits one span for it (mimicking a model that spots an entity once and may miss later
    repeats -- which is exactly the gap the known-value sweep must close). Returns None to simulate the gate
    being unreachable (degraded mode)."""
    async def _stub(aclient, text, min_score=0.5):
        spans = []
        for needle, label in found.items():
            i = text.find(needle)
            if i != -1:
                spans.append({'start': i, 'end': i + len(needle), 'label': label,
                              'tier': 1, 'conf': 0.95, 'rule': 'npu-stub'})
        return spans
    return _stub


async def _none_neural(aclient, text, min_score=0.5):
    """Degraded-mode double: the NPU gate is unreachable -> _detect_neural returns None."""
    return None


def _run_redact(monkeypatch, body, neural, ctx=None, extract=None):
    """Drive the async redact_body() via stdlib asyncio (no pytest-asyncio dep). Monkeypatches the neural
    detector so no model/HTTP is touched. Returns (meta, replay) and mutates `body` in place."""
    monkeypatch.setattr(egress_proxy, '_detect_neural', neural)
    if ctx is None:
        ctx = {'session': 'sess-' + os.urandom(6).hex(), 'project': 'e2e'}
    if extract is None:
        return asyncio.run(egress_proxy.redact_body(body, ctx))
    return asyncio.run(egress_proxy.redact_body(body, ctx, extract=extract))


_PH_RE = re.compile(r'<[A-Z0-9_]+_\d{3,}>')


def _wire_text(body):
    """The exact bytes that would go upstream: serialize the (mutated) body to one string for raw-leak asserts."""
    return json.dumps(body, ensure_ascii=False)


class _FakeRequest:
    def __init__(self, body, headers=None):
        self._body = json.dumps(body).encode('utf-8')
        self.headers = headers or {}

    async def body(self):
        return self._body


def _json_response_payload(resp):
    """Support both the lightweight test stub and a real FastAPI JSONResponse if the dependency is installed."""
    if isinstance(resp, tuple):
        args, _kwargs = resp
        assert args, 'stubbed JSONResponse must be called with a payload'
        return args[0]
    if hasattr(resp, 'body'):
        raw = resp.body
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8')
        return json.loads(raw)
    raise AssertionError(f'unexpected route response shape: {type(resp)!r}')


def _response_status(resp):
    if isinstance(resp, tuple):
        _args, kwargs = resp
        return kwargs.get('status_code', 200)
    return getattr(resp, 'status_code', None)


def _response_header(resp, name):
    lname = name.lower()
    if isinstance(resp, tuple):
        _args, kwargs = resp
        headers = kwargs.get('headers') or {}
        for k, v in headers.items():
            if k.lower() == lname:
                return v
        return None
    headers = getattr(resp, 'headers', {}) or {}
    return headers.get(name) or headers.get(lname)


def _run_route(route_fn, body, headers=None):
    return _json_response_payload(asyncio.run(route_fn(_FakeRequest(body, headers=headers))))


# ---------------------------------------------------------------------------
# 0. DRYRUN DIAGNOSTICS: the would-be upstream body is safe to return because
#    it is already redacted, but the replay map contains originals and must stay
#    behind the explicit GATEWAY_TEST_EXPOSE_MAP test flag.
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_dryrun_routes_hide_replay_map_unless_test_flag(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'DRYRUN', True)
    monkeypatch.setattr(egress_proxy, 'EXPOSE_MAP', False)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({}))

    cases = [
        ('messages',
         'dryrun.anthropic@example.test',
         {'model': 'claude-test',
          'messages': [{'role': 'user', 'content': 'Email dryrun.anthropic@example.test.'}]},
         {'x-claude-code-session-id': 'dryrun-anthropic-' + os.urandom(4).hex()}),
        ('chat_completions',
         'dryrun.chat@example.test',
         {'model': 'gpt-test',
          'messages': [{'role': 'user', 'content': 'Email dryrun.chat@example.test.'}]},
         {'x-session-id': 'dryrun-chat-' + os.urandom(4).hex()}),
        ('responses',
         'dryrun.responses@example.test',
         {'model': 'gpt-test',
          'input': 'Email dryrun.responses@example.test.'},
         {'x-session-id': 'dryrun-responses-' + os.urandom(4).hex()}),
    ]

    for route_name, email, body, headers in cases:
        payload = _run_route(getattr(egress_proxy, route_name), body, headers=headers)
        assert payload['_dryrun'] is True
        assert '_replay' not in payload, 'dryrun must not expose originals without the explicit test flag'
        wire = json.dumps(payload['upstream_body'], ensure_ascii=False)
        assert email not in wire, f'raw value leaked in dryrun upstream_body for {route_name}'
        assert _PH_RE.search(wire), f'expected a placeholder in dryrun upstream_body for {route_name}'


@_NEEDS_PROXY
def test_dryrun_replay_map_is_explicit_test_opt_in(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'DRYRUN', True)
    monkeypatch.setattr(egress_proxy, 'EXPOSE_MAP', True)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({}))

    email = 'dryrun.exposed@example.test'
    body = {
        'model': 'claude-test',
        'messages': [{'role': 'user', 'content': f'Email {email}.'}],
    }
    payload = _run_route(
        egress_proxy.messages,
        body,
        headers={'x-claude-code-session-id': 'dryrun-exposed-' + os.urandom(4).hex()},
    )

    assert '_replay' in payload, 'GATEWAY_TEST_EXPOSE_MAP must expose replay for diagnostics in dryrun'
    assert email in payload['_replay'].values()


class _FakeUpstreamResponse:
    def __init__(self, status_code, headers, content):
        self.status_code = status_code
        self.headers = headers
        self._content = content
        self.closed = False

    async def aread(self):
        return self._content

    @property
    def content(self):
        return self._content

    def json(self):
        return json.loads(self._content)

    async def aclose(self):
        self.closed = True

    async def aiter_raw(self):  # pragma: no cover -- this regression takes the non-SSE branch
        yield self._content


class _RouteAsyncClient:
    next_response = None
    instances = []

    def __init__(self, *a, **k):
        self.closed = False
        self.request = None
        type(self).instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        await self.aclose()
        return False

    async def aclose(self):
        self.closed = True

    async def post(self, url, content=None, headers=None):
        self.request = {'method': 'POST', 'url': url, 'content': content, 'headers': headers or {}}
        assert self.next_response is not None, 'test did not install a fake upstream response'
        return self.next_response

    def build_request(self, method, url, content=None, headers=None):
        self.request = {'method': method, 'url': url, 'content': content, 'headers': headers or {}}
        return self.request

    async def send(self, req, stream=False):
        assert stream is True, 'streaming route must open upstream in stream mode'
        assert req is self.request, 'expected route to send the built request'
        assert self.next_response is not None, 'test did not install a fake upstream response'
        return self.next_response


@_NEEDS_PROXY
def test_streaming_routes_preserve_upstream_json_error_status(monkeypatch):
    """A streaming upstream JSON error must not be masked as a local 200 text/event-stream response."""
    monkeypatch.setattr(egress_proxy, 'DRYRUN', False)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({}))
    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', _RouteAsyncClient)
    _RouteAsyncClient.instances = []

    cases = [
        ('messages', egress_proxy.messages,
         {'model': 'claude-test', 'stream': True,
          'messages': [{'role': 'user', 'content': 'Email stream.messages@example.test.'}]},
         {'x-claude-code-session-id': 'stream-messages-' + os.urandom(4).hex()},
         'stream.messages@example.test'),
        ('chat', egress_proxy.chat_completions,
         {'model': 'gpt-test', 'stream': True,
          'messages': [{'role': 'user', 'content': 'Email stream.chat@example.test.'}]},
         {'x-session-id': 'stream-chat-' + os.urandom(4).hex()},
         'stream.chat@example.test'),
        ('responses', egress_proxy.responses,
         {'model': 'gpt-test', 'stream': True, 'input': 'Email stream.responses@example.test.'},
         {'x-session-id': 'stream-responses-' + os.urandom(4).hex()},
         'stream.responses@example.test'),
    ]

    for route_name, route_fn, body, headers, email in cases:
        upstream = _FakeUpstreamResponse(
            429,
            {'content-type': 'application/json', 'retry-after': '7',
             'x-request-id': f'req_synthetic_stream_status_{route_name}',
             'set-cookie': 'must-not-forward=1'},
            json.dumps({'error': {'message': 'rate limited while handling <EMAIL_001>'}}).encode('utf-8'),
        )
        _RouteAsyncClient.next_response = upstream

        resp = asyncio.run(route_fn(_FakeRequest(body, headers=headers)))

        payload = _json_response_payload(resp)
        assert _response_status(resp) == 429, f'{route_name} must preserve upstream error status'
        assert payload['error']['message'] == f'rate limited while handling {email}'
        assert _response_header(resp, 'retry-after') == '7', 'retry guidance should survive proxying'
        assert _response_header(resp, 'x-request-id') == f'req_synthetic_stream_status_{route_name}'
        assert _response_header(resp, 'set-cookie') is None, 'upstream cookies must never be forwarded'
        assert upstream.closed, 'non-SSE upstream response must be closed after buffering the error body'
        assert _RouteAsyncClient.instances[-1].closed, 'streaming client must close after non-SSE fallback'


@_NEEDS_PROXY
def test_nonstreaming_routes_preserve_headers_and_rehydrate_json_error(monkeypatch):
    """Non-streaming JSON errors need the same status/header/replay behavior as normal model responses."""
    monkeypatch.setattr(egress_proxy, 'DRYRUN', False)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({}))
    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', _RouteAsyncClient)
    _RouteAsyncClient.instances = []

    cases = [
        ('messages', egress_proxy.messages,
         {'model': 'claude-test',
          'messages': [{'role': 'user', 'content': 'Email nonstream.messages@example.test.'}]},
         {'x-claude-code-session-id': 'nonstream-messages-' + os.urandom(4).hex()},
         'nonstream.messages@example.test'),
        ('chat', egress_proxy.chat_completions,
         {'model': 'gpt-test',
          'messages': [{'role': 'user', 'content': 'Email nonstream.chat@example.test.'}]},
         {'x-session-id': 'nonstream-chat-' + os.urandom(4).hex()},
         'nonstream.chat@example.test'),
        ('responses', egress_proxy.responses,
         {'model': 'gpt-test', 'input': 'Email nonstream.responses@example.test.'},
         {'x-session-id': 'nonstream-responses-' + os.urandom(4).hex()},
         'nonstream.responses@example.test'),
    ]

    for route_name, route_fn, body, headers, email in cases:
        upstream = _FakeUpstreamResponse(
            429,
            {'content-type': 'application/json', 'retry-after': '11',
             'x-request-id': f'req_synthetic_nonstream_status_{route_name}',
             'set-cookie': 'must-not-forward=1'},
            json.dumps({'error': {'message': 'rate limited while handling <EMAIL_001>'}}).encode('utf-8'),
        )
        _RouteAsyncClient.next_response = upstream

        resp = asyncio.run(route_fn(_FakeRequest(body, headers=headers)))

        payload = _json_response_payload(resp)
        assert _response_status(resp) == 429, f'{route_name} must preserve upstream error status'
        assert payload['error']['message'] == f'rate limited while handling {email}'
        assert _response_header(resp, 'retry-after') == '11', 'retry guidance should survive proxying'
        assert _response_header(resp, 'x-request-id') == f'req_synthetic_nonstream_status_{route_name}'
        assert _response_header(resp, 'set-cookie') is None, 'upstream cookies must never be forwarded'
        assert _RouteAsyncClient.instances[-1].closed, 'non-streaming route client must close'


# ---------------------------------------------------------------------------
# 1. ROUND-TRIP: Anthropic /v1/messages body redacts on egress, and the replay
#    map restores the originals in a synthetic upstream response.
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_anthropic_roundtrip_redact_then_rehydrate(monkeypatch):
    email = 'marie.gagnon@example.com'   # synthetic; Tier-0 will catch this on its own
    secret_id = 'Dossier-QX77182'        # synthetic internal ref; ONLY the neural stub "finds" it
    body = {
        'model': 'claude-sonnet-test',
        'system': 'You are a helpful assistant for a fictional credit union.',
        'messages': [
            {'role': 'user', 'content': f'Please email {email} about case {secret_id}.'},
        ],
    }
    neural = _make_neural({secret_id: 'sensitive_account_id'})
    meta, replay = _run_redact(monkeypatch, body, neural)

    wire = _wire_text(body)
    # placeholders present, raw values absent from the forwarded body
    assert _PH_RE.search(wire), f'expected at least one placeholder on the wire, got: {wire}'
    assert email not in wire, 'raw email leaked to upstream body'
    assert secret_id not in wire, 'raw internal ref leaked to upstream body'
    assert meta['redaction'] == 'redacted'
    assert replay, 'replay map must be non-empty when something was redacted'

    # synthetic upstream response that echoes the placeholders -> rehydrate restores originals for local client
    forwarded_user = body['messages'][0]['content']
    resp = {'content': [{'type': 'text', 'text': f'Sure, I will contact {forwarded_user}'}]}
    egress_proxy.rehydrate_anthropic_response(resp, replay)
    restored = resp['content'][0]['text']
    assert email in restored, 'rehydrate must restore the real email for the local client'
    assert secret_id in restored, 'rehydrate must restore the real internal ref for the local client'
    assert not _PH_RE.search(restored), 'no placeholder may survive rehydration in the local-visible text'


# ---------------------------------------------------------------------------
# 2. REPEATED-VALUE SWEEP (Finding C): a value appearing MANY times (same field
#    and across fields) is FULLY masked even when the neural stub finds it ONCE.
#    This is the core always-on never-leak guarantee: zero verbatim survivors.
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_repeated_value_fully_swept_even_if_detected_once(monkeypatch):
    val = 'Dossier-QX77182'   # synthetic; invisible to Tier-0, so the stub is the only "detector"
    n_in_field = 5
    body = {
        'model': 'claude-sonnet-test',
        'system': f'Background record: {val}.',                       # appears in system too (cross-field)
        'messages': [
            {'role': 'user',
             'content': ' '.join([f'ref {val}'] * n_in_field)},        # n_in_field copies in one field
            {'role': 'user',
             'content': f'And again here: {val} -- confirm {val}.'},   # 2 more copies in a second field
        ],
    }
    total_occurrences = n_in_field + 1 + 2   # field1 + system + field2
    neural = _make_neural({val: 'sensitive_account_id'})   # finds FIRST occurrence per field only
    meta, replay = _run_redact(monkeypatch, body, neural)

    wire = _wire_text(body)
    assert val not in wire, (
        f'PRIVACY FAILURE: {total_occurrences - wire.count(val)}/{total_occurrences} occurrences masked; '
        f'{wire.count(val)} verbatim copies of the sensitive value still leak upstream')
    # the value must map to exactly one stable placeholder, and that placeholder is on the wire
    phs = set(_PH_RE.findall(wire))
    assert phs, 'expected the swept value rendered as a placeholder'
    assert val in replay.values(), 'the swept value must be recoverable via the replay map'
    # round-trip still holds for the fully-swept value
    sample = f'Echo: {body["messages"][0]["content"]}'
    assert val in egress_proxy.rehydrate_text(sample, replay)


@_NEEDS_PROXY
def test_response_rehydrate_is_single_pass_for_placeholder_shaped_values():
    replay = {
        '<SECRET_001>': 'tok_<EMAIL_001>_x',
        '<EMAIL_001>': 'alice@example.test',
    }
    sample = 'secret=<SECRET_001> email=<EMAIL_001>'
    expected = 'secret=tok_<EMAIL_001>_x email=alice@example.test'

    for helper in (egress_proxy.rehydrate_text, openai_adapter.rehydrate_text):
        assert helper(sample, replay) == expected

    args = json.dumps({'secret': '<SECRET_001>', 'email': '<EMAIL_001>'})
    for helper in (egress_proxy.rehydrate_json_string, openai_adapter.rehydrate_json_string):
        assert json.loads(helper(args, replay)) == {
            'secret': 'tok_<EMAIL_001>_x',
            'email': 'alice@example.test',
        }


@_NEEDS_PROXY
def test_entity_map_keeps_case_sensitive_credentials_distinct():
    emap = egress_proxy.EntityMap('sess-map-' + os.urandom(6).hex(), 'e2e-map')
    ph1, new1 = emap.placeholder_for('AbC123xy', 'secret')
    ph2, new2 = emap.placeholder_for('abc123xy', 'secret')
    assert new1 and new2
    assert ph1 != ph2
    assert emap.replay()[ph1] == 'AbC123xy'
    assert emap.replay()[ph2] == 'abc123xy'

    email_ph1, _ = emap.placeholder_for('Bob@Example.test', 'email')
    email_ph2, _ = emap.placeholder_for('bob@example.test', 'email')
    assert email_ph1 == email_ph2, 'ordinary PII should keep case-insensitive session stability'


@_NEEDS_PROXY
def test_proxy_known_sweep_uses_exact_case_for_credentials():
    class FakeMap:
        v2p = {
            'AbC123xy': '<SECRET_001>',
            'abc123xy': '<SECRET_002>',
            'Jane Roy': '<PERSON_001>',
        }

    known_re = egress_proxy.build_known_re(FakeMap)
    out, n = egress_proxy.sweep_known('again abc123xy and Jane Roy and JANE ROY', known_re, FakeMap)
    assert out == 'again <SECRET_002> and <PERSON_001> and <PERSON_001>'
    assert n == 3


# ---------------------------------------------------------------------------
# 3. OPENAI ROUTE: same round-trip via the openai_adapter extract + rehydrate.
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_openai_route_roundtrip(monkeypatch):
    email = 'luc.bernard@example.com'    # Tier-0 catches
    secret_id = 'Dossier-QX77182'        # neural stub catches
    body = {
        'model': 'gpt-test',
        'messages': [
            {'role': 'system', 'content': 'You assist a fictional clinic.'},
            {'role': 'user', 'content': f'Send results for {secret_id} to {email}, repeated {secret_id}.'},
        ],
    }
    neural = _make_neural({secret_id: 'sensitive_account_id'})
    meta, replay = _run_redact(monkeypatch, body, neural,
                               ctx={'session': 'sess-oa-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
                               extract=openai_adapter.extract_text_fields_openai)

    wire = _wire_text(body)
    assert _PH_RE.search(wire), 'expected placeholders on the OpenAI-route wire body'
    assert email not in wire, 'raw email leaked on the OpenAI route'
    assert secret_id not in wire, 'raw internal ref (incl. repeat) leaked on the OpenAI route'
    assert meta['redaction'] == 'redacted'

    # synthetic OpenAI chat-completions response echoing the placeholders -> rehydrate restores originals
    forwarded = body['messages'][1]['content']
    resp = {'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': f'Acknowledged: {forwarded}'}}]}
    openai_adapter.rehydrate_openai_response(resp, replay)
    restored = resp['choices'][0]['message']['content']
    assert email in restored and secret_id in restored
    assert not _PH_RE.search(restored), 'no placeholder may survive OpenAI rehydration'


# ---------------------------------------------------------------------------
# 4. DEGRADED MODE: neural returns None -> Tier-0 + the known-value sweep still
#    apply (no crash, still redacts what the deterministic floor + map can).
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_degraded_mode_tier0_and_sweep_still_redact(monkeypatch):
    email = 'nadia.roy@example.com'   # Tier-0 (email regex) catches this with no neural help
    body = {
        'model': 'claude-sonnet-test',
        'system': 'Fictional support assistant.',
        'messages': [
            {'role': 'user', 'content': f'Contact {email} now, then notify {email} again.'},
        ],
    }
    meta, replay = _run_redact(monkeypatch, body, _none_neural)

    wire = _wire_text(body)
    assert meta.get('degraded') is True, 'degraded flag must be set when the gate is unreachable'
    assert meta['redaction'] == 'redacted', 'Tier-0 alone must still redact in degraded mode'
    assert email not in wire, 'degraded mode must not leak a Tier-0-detectable value (incl. its repeat)'
    assert email in replay.values(), 'degraded-mode redactions must remain rehydratable'


# ---------------------------------------------------------------------------
# 4a. FIX-ROUND-3 HIGH (degraded must FAIL CLOSED): post-FIX-2 every non-trivial field is neural-scanned, so a gate
#     outage means an NER-only name with NO Tier-0 fallback would pass upstream RAW. The route gate _degraded_block
#     must REFUSE to forward (return a 503) when meta['degraded'] is set, and must be a no-op when it is not. This
#     applies parity-consistently to all three routes (each calls _degraded_block before forwarding).
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_degraded_route_fails_closed(monkeypatch):
    # FAIL_CLOSED is the default (GATEWAY_FAIL_OPEN unset). Degraded -> a block response; healthy -> None (proceed).
    monkeypatch.setattr(egress_proxy, 'FAIL_CLOSED', True)
    blocked = egress_proxy._degraded_block({'degraded': True, 'redaction': 'scanned-clean'})
    assert blocked is not None, 'a degraded request must be BLOCKED (not forwarded) when fail-closed is on'
    healthy = egress_proxy._degraded_block({'degraded': False, 'redaction': 'redacted'})
    assert healthy is None, 'a healthy (non-degraded) request must proceed (no block)'
    # explicit fail-OPEN override: availability over privacy -> degraded is allowed through (documented opt-in)
    monkeypatch.setattr(egress_proxy, 'FAIL_CLOSED', False)
    assert egress_proxy._degraded_block({'degraded': True}) is None, (
        'GATEWAY_FAIL_OPEN=1 must let a degraded request proceed (Tier-0-only egress)')


@_NEEDS_PROXY
def test_degraded_set_when_ner_only_field_and_gate_down(monkeypatch):
    """An NER-only name (no Tier-0 fallback) in a SHORT field, with the gate unreachable, must mark the request
    degraded -- so the route fails closed rather than forwarding the unmasked name. Pre-fix the field passed raw and
    the route forwarded normally; the degraded flag is the signal _degraded_block trips on."""
    body = {
        'model': 'gpt-test',
        'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': 'Notify Jane Roy.'}]}],
    }
    assert not egress_proxy.cheap_gate('Notify Jane Roy.'), 'guard: the field must have no Tier-0 candidate'
    meta, replay = _run_redact(monkeypatch, body, _none_neural)
    assert meta.get('degraded') is True, 'a scanned field with the gate down must mark the request degraded'
    # and the route gate would refuse to forward this body (still carrying the raw NER-only name)
    assert egress_proxy._degraded_block(meta) is not None, 'a degraded NER-only request must fail closed'


# ---------------------------------------------------------------------------
# 4b. FIX 2 (short non-prose name-only field): a field with NO Tier-0 hit AND below the prose-length bar (a 2-word
#     synthetic NAME in a short tool description / arg value) must STILL be neural-scanned, else the NER-only name
#     passes upstream RAW. The deterministic neural stub finds the name; redact_body must scan the short field and
#     mask it (redaction != 'skip'). Pre-FIX, "t0 or prose" gated the scan and this field skipped -> raw leak.
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_short_nonprose_name_only_field_is_neural_scanned(monkeypatch):
    name = 'Jane Roy'   # synthetic NER-only name: no email/phone, invisible to Tier-0, below the prose word bar
    # a SHORT tool description -- not prose-length, no Tier-0 candidate -- carrying only the name.
    body = {
        'model': 'gpt-test',
        'messages': [
            {'role': 'user', 'content': [
                {'type': 'text', 'text': 'Notify Jane Roy.'},   # short; < PROSE_MIN_WORDS, no Tier-0 hit
            ]},
        ],
    }
    # sanity: the field is genuinely NOT prose and has NO Tier-0 candidate, so only FIX 2 (scan every field) catches it
    assert not egress_proxy._looks_like_prose('Notify Jane Roy.'), 'guard: the field must be sub-prose-length'
    assert not egress_proxy.cheap_gate('Notify Jane Roy.'), 'guard: the field must have no Tier-0 candidate'

    neural = _make_neural({name: 'person'})
    meta, replay = _run_redact(monkeypatch, body, neural)

    wire = _wire_text(body)
    assert meta['redaction'] != 'skip', 'FIX 2: a short name-only field must be scanned, not skipped'
    assert name not in wire, 'PRIVACY FAILURE: an NER-only name in a short non-prose field leaked upstream raw'
    assert _PH_RE.search(wire), 'the name must be masked to a placeholder on the wire'
    assert name in replay.values(), 'the redacted name must remain rehydratable'


# ---------------------------------------------------------------------------
# 5. ADAPTER PURITY: openai_adapter extract -> (manual placeholder swap) ->
#    rehydrate is lossless on a synthetic payload, with NO network and NO proxy.
#    This pins the pure-function contract the route relies on.
# ---------------------------------------------------------------------------
@_NEEDS_PROXY
def test_openai_adapter_extract_rehydrate_lossless():
    original = 'sophie.tremblay@example.com'
    placeholder = '<EMAIL_001>'
    body = {
        'model': 'gpt-test',
        'messages': [
            {'role': 'system', 'content': 'Fictional assistant.'},
            {'role': 'user', 'content': [
                {'type': 'text', 'text': f'Write to {original} please.'},
                {'type': 'image_url', 'image_url': {'url': 'https://example.test/x.png'}},  # never touched
            ]},
            {'role': 'tool', 'content': f'lookup done for {original}'},
        ],
    }
    # extract returns IN-PLACE handles onto the redactable strings -> swap to a placeholder via .write()
    fields = openai_adapter.extract_text_fields_openai(body)
    swapped = 0
    for f in fields:
        if original in f.text:
            f.write(f.text.replace(original, placeholder))
            swapped += 1
    assert swapped == 2, 'extractor must surface the two text fields containing the value (text-part + tool)'
    assert body['messages'][1]['content'][1]['type'] == 'image_url', 'non-text parts must be left intact'

    # rehydrate the same body back via the response helper contract (value-level, JSON-safe)
    replay = {placeholder: original}
    rehydrated_user = openai_adapter._rehydrate_json(body['messages'][1]['content'], replay)
    assert rehydrated_user[0]['text'] == f'Write to {original} please.', 'lossless round-trip on the text part'
    assert rehydrated_user[1] == body['messages'][1]['content'][1], 'image part unchanged through rehydrate'

    # JSON-string tool-args rehydration is lossless even when the value contains quotes/backslashes
    tricky = 'a"b\\c'
    args_json = json.dumps({'note': f'see {placeholder}', 'raw': placeholder})
    out = openai_adapter.rehydrate_json_string(args_json, {placeholder: tricky})
    parsed = json.loads(out)   # must still be valid JSON after substitution
    assert parsed['raw'] == tricky and parsed['note'] == f'see {tricky}'


@_NEEDS_PROXY
def test_anthropic_and_openai_json_rehydrate_restore_keys_and_duplicates():
    key_ph = '<EMAIL_001>'
    val_ph1 = '<PERSON_001>'
    val_ph2 = '<PERSON_002>'
    email = 'sophie.tremblay@example.com'
    replay = {key_ph: email, val_ph1: 'Alice Tremblay', val_ph2: 'Bob Roy'}

    keyed = json.dumps({key_ph: val_ph1})
    for helper in (egress_proxy.rehydrate_json_string, openai_adapter.rehydrate_json_string):
        out = helper(keyed, replay)
        parsed = json.loads(out)
        assert parsed[email] == 'Alice Tremblay', 'placeholder object keys must rehydrate'

    dup = '{"assignee":"<PERSON_001>","assignee":"<PERSON_002>"}'
    for helper in (egress_proxy.rehydrate_json_string, openai_adapter.rehydrate_json_string):
        out = helper(dup, replay)
        assert 'Alice Tremblay' in out and 'Bob Roy' in out, 'duplicate-key JSON must not drop a value'
        json.loads(out)


@_NEEDS_PROXY
def test_openai_stream_split_multi_underscore_placeholder_rehydrates():
    """OpenAI chat streams can split a gate-form placeholder with internal underscores across deltas."""
    value = 'Dossier-QX77182'
    placeholder = '<SENSITIVE_ACCOUNT_ID_001>'
    replay = {placeholder: value}
    carry, tool_acc = {}, {}

    e1 = b'data: ' + json.dumps({
        'choices': [{'index': 0, 'delta': {'content': 'Case <SENSITIVE_ACCOUNT'}}],
    }).encode('utf-8')
    e2 = b'data: ' + json.dumps({
        'choices': [{'index': 0, 'delta': {'content': '_ID_001> ready.'}}],
    }).encode('utf-8')

    r1 = openai_adapter.transform_openai_event(e1, replay, carry, tool_acc).decode('utf-8')
    r2 = openai_adapter.transform_openai_event(e2, replay, carry, tool_acc).decode('utf-8')
    combined = r1 + r2

    assert '<SENSITIVE_ACCOUNT' not in r1, 'partial multi-underscore placeholder must be buffered'
    assert value in combined, 'split multi-underscore placeholder must rehydrate once complete'
    assert not _PH_RE.search(combined), 'no full placeholder may survive OpenAI stream rehydration'


# ---------------------------------------------------------------------------
# Carrier-wrap booster (plan 026 option A): a RARE name in a bare structural value scores zero
# from the model (no prose to cue it) and has NO Tier-0 floor -> it would leak. The booster
# re-scans the value inside a prose carrier and maps the verdict back. These drive redact_body
# end to end with the model mocked, so they assert the WIRING, not a real model's recall.
# ---------------------------------------------------------------------------
def _name_only_in_carrier(names):
    """Model double matching the MEASURED behaviour: a rare name scores ZERO as a bare value but
    fires once wrapped in the prose carrier. Emits a person span only when the name appears inside
    a longer carrier text (text.strip() != the bare name)."""
    async def _stub(aclient, text, min_score=0.5):
        spans = []
        for nm in names:
            i = text.find(nm)
            if i != -1 and text.strip() != nm:   # bare value -> miss; carrier-wrapped -> hit
                spans.append({'start': i, 'end': i + len(nm), 'label': 'person',
                              'tier': 1, 'conf': 0.99, 'rule': 'npu-stub'})
        return spans
    return _stub


@_NEEDS_PROXY
def test_carrier_booster_recovers_bare_structural_name(monkeypatch):
    name = 'Priya McCallum'   # synthetic rare name; NO Tier-0 floor for person names
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': name}]}
    meta, replay = _run_redact(monkeypatch, body, _name_only_in_carrier([name]))
    wire = _wire_text(body)
    assert name not in wire, 'bare rare name leaked -- carrier booster did not fire'
    assert _PH_RE.search(wire), 'expected a placeholder for the recovered name'
    assert meta['redaction'] == 'redacted'
    assert meta.get('by_rule', {}).get('gpu:carrier', 0) >= 1, 'recovered span should be tagged gpu:carrier'


@_NEEDS_PROXY
def test_bare_name_leaks_when_model_misses_even_the_carrier(monkeypatch):
    # CONTROL: a model that finds the name in NEITHER bare nor carrier form -> the name leaks
    # (Tier-0 has no name floor). Proves (a) the test name is truly NER-only, and (b) the booster
    # only ever helps; it never invents a redaction the model didn't make. This residual is the
    # retrain-augment track (plan 026 option B), not closable client-side.
    name = 'Priya McCallum'
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': name}]}
    _run_redact(monkeypatch, body, _make_neural({}))   # finds nothing, ever
    assert name in _wire_text(body), 'expected the NER-only name to remain when the model never finds it'


@_NEEDS_PROXY
def test_carrier_booster_does_not_fire_on_non_name_short_value(monkeypatch):
    # a short non-name value that is name-shaped lexically ("active") must not be mangled: the model
    # returns no person for it even carrier-wrapped (measured 0 FP), so it passes through untouched.
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': 'active'}]}
    meta, replay = _run_redact(monkeypatch, body, _name_only_in_carrier(['Priya McCallum']))
    assert 'active' in _wire_text(body), 'a non-name short value must not be redacted by the booster'
    assert meta['redaction'] in ('scanned-clean', 'skip')
