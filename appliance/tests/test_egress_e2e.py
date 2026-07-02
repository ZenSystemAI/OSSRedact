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


# httpx exception hierarchy the proxy references to classify gate failures (TransportError = unreachable ->
# fail over / degrade; HTTPStatusError = a reachable gate returned 4xx/5xx -> a real fault, not an outage).
class _StubHTTPError(Exception):
    pass


class _StubTransportError(_StubHTTPError):
    pass


class _StubConnectError(_StubTransportError):
    pass


class _StubHTTPStatusError(_StubHTTPError):
    pass


_httpx.HTTPError = _StubHTTPError
_httpx.TransportError = _StubTransportError
_httpx.ConnectError = _StubConnectError
_httpx.HTTPStatusError = _StubHTTPStatusError
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
    # privacy_gate is the colliding one; entity_map / secrets_scan / adapters / egress_proxy are appliance-only
    # today but loaded by path too so a future same-named gate file cannot shadow them, and so egress_proxy is never
    # served from a stale cache. Order: leaf deps first, egress_proxy last (it imports the others).
    with _appliance_modules_pinned(
            ['privacy_gate', 'entity_map', 'secrets_scan', 'responses_adapter', 'openai_adapter',
             'egress_proxy']) as _mods:
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


@_NEEDS_PROXY
def test_redact_body_accepts_injected_detector_without_httpx_client(monkeypatch):
    class NoHttpxClient:
        def __init__(self, *a, **k):
            raise AssertionError('redact_body should not construct httpx when detector is injected')

    async def detector(text, min_score=0.5):
        needle = 'Jane Proof'
        i = text.find(needle)
        if i == -1:
            return []
        return [{'start': i, 'end': i + len(needle), 'label': 'person',
                 'tier': 1, 'conf': 0.95, 'rule': 'injected'}]

    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', NoHttpxClient)
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': 'Notify Jane Proof.'}]}
    ctx = {'session': 'injected-detector-' + os.urandom(4).hex(), 'project': 'e2e'}

    meta, replay = asyncio.run(egress_proxy.redact_body(body, ctx, detector=detector))

    wire = _wire_text(body)
    assert meta['redaction'] == 'redacted'
    assert 'Jane Proof' not in wire
    assert '<PERSON_001>' in wire
    assert replay['<PERSON_001>'] == 'Jane Proof'


@_NEEDS_PROXY
def test_scannable_request_loads_entity_map_once(monkeypatch):
    """perf-lock: on the COMMON path (a request carrying scannable text) redact_body must NOT pre-load the
    session map merely to compute the empty-body fast-path -- that read is consulted only when there are zero
    scannable fields. So a scannable request constructs EntityMap exactly ONCE (the authoritative pass-2 load
    under the lock), not twice. Regression guard for the dropped redundant load+decrypt of the whole map."""
    class NoHttpxClient:
        def __init__(self, *a, **k):
            raise AssertionError('redact_body should not construct httpx when a detector is injected')
    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', NoHttpxClient)

    real_map = egress_proxy.EntityMap
    count = {'n': 0}

    class CountingEntityMap(real_map):
        def __init__(self, *a, **k):
            count['n'] += 1
            super().__init__(*a, **k)
    monkeypatch.setattr(egress_proxy, 'EntityMap', CountingEntityMap)

    async def detector(text, min_score=0.5):
        i = text.find('Jane Proof')
        return [] if i == -1 else [{'start': i, 'end': i + 10, 'label': 'person',
                                    'tier': 1, 'conf': 0.95, 'rule': 'inj'}]

    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': 'Notify Jane Proof.'}]}
    ctx = {'session': 'perf-once-' + os.urandom(4).hex(), 'project': 'e2e'}
    meta, _ = asyncio.run(egress_proxy.redact_body(body, ctx, detector=detector))
    assert meta['redaction'] == 'redacted'
    assert count['n'] == 1, f'scannable path should load the entity map exactly once, got {count["n"]}'


@_NEEDS_PROXY
def test_concurrent_redact_body_same_session_keeps_placeholders_stable(monkeypatch):
    """Plan 033 Task A, LIVE-PATH guard (the committed interprocess-lock test drives map_file_lock directly;
    this drives redact_body() itself under concurrency). Claude Code fires PARALLEL requests in one session
    (parallel tool calls / subagents). redact_body builds a FRESH EntityMap per call, so without the
    inter-process map lock two concurrent load->mint->save cycles can mint DIVERGENT placeholders for the
    same value -- which makes the next turn redact the cached prefix to different bytes, so the upstream
    prompt cache misses every turn and token usage 'inflates'. Assert the shared value resolves to ONE
    placeholder across all concurrent requests (cache-stable bytes) and per-request values never cross."""
    class NoHttpxClient:
        def __init__(self, *a, **k):
            raise AssertionError('redact_body must not construct httpx when a detector is injected')
    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', NoHttpxClient)

    N = 8
    shared = 'jane.doe@example.test'   # present in EVERY concurrent request

    async def detector(text, min_score=0.5):
        spans = []
        for needle, label in [(shared, 'email')] + [(f'val-{i}', 'person') for i in range(N)]:
            j = 0
            while (k := text.find(needle, j)) != -1:
                spans.append({'start': k, 'end': k + len(needle), 'label': label,
                              'tier': 1, 'conf': 0.95, 'rule': 'inj'})
                j = k + len(needle)
        return spans

    session = 'concurrent-' + os.urandom(4).hex()
    bodies = [{'model': 'claude-test',
               'messages': [{'role': 'user', 'content': f'Email {shared} about val-{i}.'}]}
              for i in range(N)]

    async def drive():
        return await asyncio.gather(*[
            egress_proxy.redact_body(b, {'session': session, 'project': 'e2e'}, detector=detector)
            for b in bodies])
    results = asyncio.run(drive())

    shared_phs = set()
    for i, ((meta, replay), b) in enumerate(zip(results, bodies)):
        wire = _wire_text(b)
        assert shared not in wire, f'shared value leaked to wire in req {i}'
        assert f'val-{i}' not in wire, f'per-request value leaked to wire in req {i}'
        inv = {v: ph for ph, v in replay.items()}
        shared_phs.add(inv[shared])
        # no cross-flow bleed: req i's person placeholder rehydrates to ITS OWN value, not another req's
        assert inv[f'val-{i}'] != inv[shared]
        assert replay[inv[f'val-{i}']] == f'val-{i}'

    # the cache-stability invariant: one stable placeholder for the shared value across ALL concurrent reqs
    assert len(shared_phs) == 1, f'divergent placeholders for the shared value across reqs: {shared_phs}'

    # persisted map is consistent: one placeholder per distinct value, every value rehydratable
    reloaded = egress_proxy.EntityMap(session, 'e2e')
    expected = {shared, *(f'val-{i}' for i in range(N))}
    assert set(reloaded.v2p) == expected
    assert len(set(reloaded.v2p.values())) == len(expected)
    rep = reloaded.replay()
    assert all(rep[reloaded.v2p[v]] == v for v in expected)


@_NEEDS_PROXY
def test_replay_scoped_to_outbound_body_no_cross_client_bleed(monkeypatch):
    """Replay-scoping guard. Two DIFFERENT header-less clients that share a system prompt hash to the SAME
    session map (derive_session falls to 'sys-'+hash(system)). The per-request replay must NOT expose one
    client's PII to the other: it is scoped to placeholders actually present in THIS request's outbound body,
    so a client that sent no PII gets an empty replay even though the shared map holds the other's value."""
    async def detector(text, min_score=0.5):
        needle = 'alice.private@example.test'
        i = text.find(needle)
        return ([{'start': i, 'end': i + len(needle), 'label': 'email', 'tier': 1, 'conf': 0.95, 'rule': 'inj'}]
                if i != -1 else [])

    sysprompt = 'You are a helpful assistant. Be concise.'
    def body(user_text):
        return {'model': 'x', 'system': sysprompt, 'messages': [{'role': 'user', 'content': user_text}]}

    # both clients omit the session header -> identical sys-hash session -> ONE shared map file
    assert egress_proxy.derive_session('', sysprompt) == egress_proxy.derive_session('', sysprompt)
    ctx = lambda: {'session': '', 'project': 'e2e-bleed'}

    bA = body('Email alice.private@example.test about the bug.')   # client A sends real PII
    _, replayA = asyncio.run(egress_proxy.redact_body(bA, ctx(), detector=detector))
    assert 'alice.private@example.test' in replayA.values()        # A still rehydrates its OWN value

    bB = body('What is the capital of France?')                    # client B (different) sends NO PII
    metaB, replayB = asyncio.run(egress_proxy.redact_body(bB, ctx(), detector=detector))

    # the breach the fix closes: B's replay must not carry A's value, and a response that happens to carry
    # A's placeholder must NOT rehydrate to A's PII inside B's turn (it stays raw -- fail-safe, never a leak)
    assert 'alice.private@example.test' not in replayB.values()
    ph = next(iter(replayA))
    assert egress_proxy.rehydrate_text(f'see {ph} please', replayB) == f'see {ph} please'


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


@_NEEDS_PROXY
def test_dryrun_wire_redacts_and_local_rehydrate_restores(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'DRYRUN', True)
    monkeypatch.setattr(egress_proxy, 'EXPOSE_MAP', True)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({'Alice Proof': 'person'}))

    name = 'Alice Proof'
    email = 'proof.alice@example.test'
    body = {
        'model': 'claude-test',
        'messages': [{'role': 'user', 'content': f'Prepare a note for {name} at {email}.'}],
    }

    payload = _run_route(
        egress_proxy.messages,
        body,
        headers={'x-claude-code-session-id': 'dryrun-wire-proof-' + os.urandom(4).hex()},
    )

    wire = json.dumps(payload['upstream_body'], ensure_ascii=False)
    assert name not in wire, 'raw synthetic name leaked in the would-be upstream body'
    assert email not in wire, 'raw synthetic email leaked in the would-be upstream body'
    assert '<PERSON_' in wire and '<EMAIL_' in wire

    replay = payload['_replay']
    name_ph = next(ph for ph, value in replay.items() if value == name)
    email_ph = next(ph for ph, value in replay.items() if value == email)
    upstream_resp = {'content': [{'type': 'text', 'text': f'Sent to {name_ph} using {email_ph}.'}]}

    egress_proxy.rehydrate_anthropic_response(upstream_resp, replay)

    restored = upstream_resp['content'][0]['text']
    assert name in restored
    assert email in restored
    assert not _PH_RE.search(restored), 'local-visible text must not retain placeholders after rehydration'


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


@_NEEDS_PROXY
def test_count_tokens_dryrun_redacts(monkeypatch):
    """B2: the count_tokens pre-flight must redact its body like /v1/messages (it carries the same content)."""
    monkeypatch.setattr(egress_proxy, 'DRYRUN', True)
    monkeypatch.setattr(egress_proxy, 'EXPOSE_MAP', False)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({}))

    email = 'count.tokens@example.test'
    body = {'model': 'claude-test',
            'messages': [{'role': 'user', 'content': f'How many tokens is {email}?'}]}
    payload = _run_route(egress_proxy.messages_count_tokens, body,
                         headers={'x-claude-code-session-id': 'ct-dry-' + os.urandom(4).hex()})

    assert payload['_dryrun'] is True
    wire = json.dumps(payload['upstream_body'], ensure_ascii=False)
    assert email not in wire, 'raw email leaked in count_tokens dryrun upstream_body'
    assert _PH_RE.search(wire), 'expected a placeholder in the count_tokens dryrun upstream_body'


@_NEEDS_PROXY
def test_count_tokens_redacts_then_forwards_count_verbatim(monkeypatch):
    """B2: count_tokens redacts the body, forwards to ANTHROPIC /v1/messages/count_tokens, and returns the
    upstream {input_tokens: N} verbatim (no rehydration -- the count carries no PII)."""
    monkeypatch.setattr(egress_proxy, 'DRYRUN', False)
    monkeypatch.setattr(egress_proxy, '_detect_neural', _make_neural({'Alice Proof': 'person'}))
    monkeypatch.setattr(egress_proxy.httpx, 'AsyncClient', _RouteAsyncClient)
    _RouteAsyncClient.instances = []
    _RouteAsyncClient.next_response = _FakeUpstreamResponse(
        200, {'content-type': 'application/json'}, json.dumps({'input_tokens': 1234}).encode('utf-8'))

    name, email = 'Alice Proof', 'proof.alice@example.test'
    body = {'model': 'claude-test',
            'messages': [{'role': 'user', 'content': f'Count tokens for {name} at {email}.'}]}
    resp = asyncio.run(egress_proxy.messages_count_tokens(
        _FakeRequest(body, headers={'x-claude-code-session-id': 'ct-fwd-' + os.urandom(4).hex()})))

    # returned verbatim count
    assert _json_response_payload(resp) == {'input_tokens': 1234}
    assert _response_status(resp) == 200
    # forwarded to the count_tokens endpoint with a REDACTED body
    inst = _RouteAsyncClient.instances[-1]
    assert inst.request['url'] == egress_proxy.ANTHROPIC_UPSTREAM + '/v1/messages/count_tokens'
    fwd = inst.request['content']
    assert name not in fwd and email not in fwd, 'raw PII forwarded to the count_tokens endpoint'
    assert _PH_RE.search(fwd), 'expected placeholders in the forwarded count_tokens body'
    assert inst.closed, 'count_tokens client must close'


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

    # TOOL-ARG single-pass: a NON-FLOOR token still rehydrates (Half A); its restored value carrying
    # placeholder-shaped text must not be rescanned either.
    nf_replay = {'<PERSON_001>': 'tok_<EMAIL_001>_x', '<EMAIL_001>': 'alice@example.test'}
    nf_args = json.dumps({'name': '<PERSON_001>', 'email': '<EMAIL_001>'})
    for helper in (egress_proxy.rehydrate_json_string, openai_adapter.rehydrate_json_string):
        assert json.loads(helper(nf_args, nf_replay)) == {
            'name': 'tok_<EMAIL_001>_x',
            'email': 'alice@example.test',
        }
    # B5: a FLOOR/secret token is WITHHELD from executed tool args -> stays the inert literal.
    f_args = json.dumps({'secret': '<SECRET_001>'})
    for helper in (egress_proxy.rehydrate_json_string, openai_adapter.rehydrate_json_string):
        assert json.loads(helper(f_args, replay)) == {'secret': '<SECRET_001>'}


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

    person_ph1, new_person_1 = emap.placeholder_for('Nadia', 'person')
    person_ph2, new_person_2 = emap.placeholder_for('nadia', 'person')
    assert new_person_1 and new_person_2
    assert person_ph1 != person_ph2
    assert emap.replay()[person_ph1] == 'Nadia'
    assert emap.replay()[person_ph2] == 'nadia'


@_NEEDS_PROXY
def test_proxy_known_sweep_uses_exact_case_for_credentials_and_people():
    class FakeMap:
        v2p = {
            'AbC123xy': '<SECRET_001>',
            'abc123xy': '<SECRET_002>',
            'Jane Roy': '<PERSON_001>',
        }

    known_re = egress_proxy.build_known_re(FakeMap)
    out, n = egress_proxy.sweep_known('again abc123xy and Jane Roy and JANE ROY', known_re, FakeMap)
    assert out == 'again <SECRET_002> and <PERSON_001> and JANE ROY'
    assert n == 2


@_NEEDS_PROXY
def test_proxy_person_sweep_preserves_lowercase_paths_and_usernames():
    class FakeMap:
        v2p = {'Nadia': '<PERSON_001>'}

        @staticmethod
        def replay():
            return {'<PERSON_001>': 'Nadia'}

    known_re = egress_proxy.build_known_re(FakeMap)
    text = "I'm <PERSON_001>; open /home/nadia/dev/x and log in as nadia."
    out, n = egress_proxy.sweep_known(text, known_re, FakeMap)
    assert n == 0
    assert '/home/nadia/dev/x' in out
    assert 'as nadia' in out
    assert egress_proxy.rehydrate_text(out, FakeMap.replay()) == "I'm Nadia; open /home/nadia/dev/x and log in as nadia."


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


@_NEEDS_PROXY
def test_anthropic_assistant_tool_use_history_redacted_on_next_request(monkeypatch):
    """A prior assistant tool_use input is rehydrated locally, then sent back as conversation history.
    The next outbound pass must redact that model-visible history before forwarding upstream."""
    name = 'Alice Proof'
    email = 'history.alice@example.test'
    body = {
        'model': 'claude-test',
        'messages': [
            {'role': 'assistant', 'content': [
                {'type': 'tool_use', 'id': 'toolu_1', 'name': 'lookup_case',
                 'input': {'recipient': name, email: {'role': 'owner'}}},
            ]},
            {'role': 'user', 'content': 'Continue.'},
        ],
    }
    neural = _make_neural({name: 'person'})
    meta, replay = _run_redact(monkeypatch, body, neural)

    wire = _wire_text(body)
    assert meta['redaction'] == 'redacted'
    assert name not in wire, 'PRIVACY FAILURE: prior Anthropic tool_use input value leaked upstream raw'
    assert email not in wire, 'PRIVACY FAILURE: prior Anthropic tool_use input key leaked upstream raw'
    assert '<PERSON_' in wire and '<EMAIL_' in wire
    assert name in replay.values() and email in replay.values()
    assert body['messages'][0]['content'][0]['name'] == 'lookup_case', 'tool routing name must stay structural'


@_NEEDS_PROXY
def test_openai_assistant_tool_call_history_redacted_on_next_request(monkeypatch):
    """OpenAI chat history can include assistant tool_calls. After response rehydration those arguments contain
    originals locally, so the next request must parse/redact the JSON arguments before forwarding."""
    name = 'Alice Proof'
    email = 'history.openai@example.test'
    body = {
        'model': 'gpt-test',
        'messages': [
            {'role': 'assistant', 'tool_calls': [
                {'id': 'call_1', 'type': 'function',
                 'function': {'name': 'lookup_case',
                              'arguments': json.dumps({'assignee': name, email: {'role': 'owner'}})}},
            ]},
            {'role': 'user', 'content': 'Continue.'},
        ],
    }
    neural = _make_neural({name: 'person'})
    meta, replay = _run_redact(
        monkeypatch, body, neural,
        ctx={'session': 'sess-oa-history-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
        extract=openai_adapter.extract_text_fields_openai)

    wire = _wire_text(body)
    assert meta['redaction'] == 'redacted'
    assert name not in wire, 'PRIVACY FAILURE: prior OpenAI tool_call argument value leaked upstream raw'
    assert email not in wire, 'PRIVACY FAILURE: prior OpenAI tool_call argument key leaked upstream raw'
    args = json.loads(body['messages'][0]['tool_calls'][0]['function']['arguments'])
    assert any(isinstance(v, str) and v.startswith('<PERSON_') for v in args.values()), (
        'tool_call argument value should be redacted inside valid JSON')
    assert any(k.startswith('<EMAIL_') for k in args), 'tool_call argument key should be redacted inside valid JSON'
    assert body['messages'][0]['tool_calls'][0]['function']['name'] == 'lookup_case', 'function name must stay structural'
    assert name in replay.values() and email in replay.values()


@_NEEDS_PROXY
def test_native_numeric_tool_arguments_are_redacted_and_rehydrate(monkeypatch):
    """A1 regression: native JSON numbers in tool/function arguments are scan-only strings and write back
    as placeholder strings on a hit, never raw numeric PII."""
    ssn_num = 46454286
    card_num = 4111111111111111

    anth = {
        'model': 'claude-test',
        'messages': [{'role': 'assistant', 'content': [
            {'type': 'tool_use', 'id': 'toolu_1', 'name': 'lookup_case',
             'input': {'ssn': ssn_num, 'card': card_num, 'ok': True, 'none': None}},
        ]}],
    }
    meta, replay = _run_redact(monkeypatch, anth, _make_neural({}))
    wire = _wire_text(anth)
    assert meta['redaction'] == 'redacted'
    assert str(ssn_num) not in wire and str(card_num) not in wire
    tool_input = anth['messages'][0]['content'][0]['input']
    assert isinstance(tool_input['ssn'], str) and tool_input['ssn'].startswith('<')
    assert isinstance(tool_input['card'], str) and tool_input['card'].startswith('<')
    restored = {'content': [{'type': 'tool_use', 'input': dict(tool_input)}]}
    egress_proxy.rehydrate_anthropic_response(restored, replay)
    # B5 Half A: ssn (government_id) and card (payment_card) are FLOOR/secret-class, and this is a tool_use.input
    # (an EXECUTED tool argument), so they are WITHHELD from rehydration -> the inert placeholder stays literal,
    # the real numeric PII never reappears in an executed argument. (request-side redaction above is unchanged.)
    out_ssn = restored['content'][0]['input']['ssn']
    out_card = restored['content'][0]['input']['card']
    assert out_ssn.startswith('<') and str(ssn_num) not in out_ssn
    assert out_card.startswith('<') and str(card_num) not in out_card
    assert restored['content'][0]['input']['ok'] is True
    assert restored['content'][0]['input']['none'] is None

    tool_result = {
        'model': 'claude-test',
        'messages': [{'role': 'user', 'content': [
            {'type': 'tool_result', 'tool_use_id': 'toolu_1',
             'content': {'ssn': ssn_num, 'card': card_num}},
        ]}],
    }
    meta, replay = _run_redact(monkeypatch, tool_result, _make_neural({}))
    wire = _wire_text(tool_result)
    assert meta['redaction'] == 'redacted'
    assert str(ssn_num) not in wire and str(card_num) not in wire
    restored = {'content': [{'type': 'text', 'text': json.dumps(tool_result['messages'][0]['content'][0]['content'])}]}
    egress_proxy.rehydrate_anthropic_response(restored, replay)
    assert str(ssn_num) in restored['content'][0]['text']
    assert str(card_num) in restored['content'][0]['text']

    openai_body = {
        'model': 'gpt-test',
        'messages': [{'role': 'assistant', 'tool_calls': [
            {'id': 'call_1', 'type': 'function',
             'function': {'name': 'lookup_case', 'arguments': {'ssn': ssn_num, 'card': card_num}}},
        ]}],
    }
    meta, replay = _run_redact(
        monkeypatch, openai_body, _make_neural({}),
        ctx={'session': 'sess-native-num-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
        extract=openai_adapter.extract_text_fields_openai)
    wire = _wire_text(openai_body)
    assert meta['redaction'] == 'redacted'
    assert str(ssn_num) not in wire and str(card_num) not in wire
    args = openai_body['messages'][0]['tool_calls'][0]['function']['arguments']
    assert isinstance(args['ssn'], str) and args['ssn'].startswith('<')
    resp = {'choices': [{'message': {'tool_calls': [{'function': {'arguments': args}}]}}]}
    openai_adapter.rehydrate_openai_response(resp, replay)
    out_args = resp['choices'][0]['message']['tool_calls'][0]['function']['arguments']
    # B5: FLOOR ssn/card are WITHHELD from the executed tool_calls.arguments (native dict form here, reached via
    # the _is_json_args_key key rule) -> stay the inert placeholder, never the raw number.
    assert out_args['ssn'].startswith('<') and str(ssn_num) not in out_args['ssn']
    assert out_args['card'].startswith('<') and str(card_num) not in out_args['card']

    responses_body = {
        'model': 'gpt-test',
        'input': [{'type': 'function_call', 'call_id': 'call_2', 'name': 'lookup_case',
                   'arguments': {'ssn': ssn_num, 'card': card_num}}],
    }
    meta, replay = _run_redact(
        monkeypatch, responses_body, _make_neural({}),
        ctx={'session': 'sess-resp-native-num-' + os.urandom(6).hex(), 'project': 'e2e-resp'},
        extract=egress_proxy.responses_adapter.extract_text_fields_responses)
    wire = _wire_text(responses_body)
    assert meta['redaction'] == 'redacted'
    assert str(ssn_num) not in wire and str(card_num) not in wire
    resp_args = responses_body['input'][0]['arguments']
    restored_resp = {'output': [{'type': 'function_call', 'arguments': resp_args}]}
    egress_proxy.responses_adapter.rehydrate_responses_response(restored_resp, replay)
    # B5: FLOOR ssn/card withheld from the executed function_call.arguments -> stay the inert placeholder.
    out_resp = restored_resp['output'][0]['arguments']
    assert out_resp['ssn'].startswith('<') and str(ssn_num) not in out_resp['ssn']
    assert out_resp['card'].startswith('<') and str(card_num) not in out_resp['card']


@_NEEDS_PROXY
def test_anthropic_document_text_blocks_are_scanned(monkeypatch):
    email = 'document.text@example.test'
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': [
        {'type': 'document', 'source': {'type': 'text', 'media_type': 'text/plain',
                                        'data': f'Contact {email}.'}},
    ]}]}

    meta, replay = _run_redact(monkeypatch, body, _make_neural({}))

    wire = _wire_text(body)
    assert meta['redaction'] == 'redacted'
    assert email not in wire
    assert email in replay.values()
    assert '<EMAIL_' in wire


@_NEEDS_PROXY
def test_tool_schema_descriptions_are_scanned_without_rewriting_tool_names(monkeypatch):
    email = 'schema.owner@example.test'
    anth = {
        'model': 'claude-test',
        'tools': [{'name': 'lookup_case', 'description': f'Use for {email}.',
                   'input_schema': {'type': 'object', 'properties': {'case_id': {'type': 'string'}}}}],
        'messages': [{'role': 'user', 'content': 'Continue.'}],
    }
    meta, replay = _run_redact(monkeypatch, anth, _make_neural({}))
    wire = _wire_text(anth)
    assert meta['redaction'] == 'redacted'
    assert email not in wire
    assert anth['tools'][0]['name'] == 'lookup_case'
    assert email in replay.values()

    openai_body = {
        'model': 'gpt-test',
        'tools': [{'type': 'function', 'function': {
            'name': 'lookup_case',
            'description': f'Use for {email}.',
            'parameters': {'type': 'object', 'properties': {'case_id': {'type': 'string'}}},
        }}],
        'messages': [{'role': 'user', 'content': 'Continue.'}],
    }
    meta, replay = _run_redact(
        monkeypatch, openai_body, _make_neural({}),
        ctx={'session': 'sess-schema-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
        extract=openai_adapter.extract_text_fields_openai)
    wire = _wire_text(openai_body)
    assert meta['redaction'] == 'redacted'
    assert email not in wire
    assert openai_body['tools'][0]['function']['name'] == 'lookup_case'
    assert email in replay.values()


def test_tool_schema_numeric_constraints_not_corrupted(monkeypatch):
    # Regression for the LIVE 400 ("tools.N.input_schema ... must match JSON Schema draft 2020-12"): the A1
    # numeric scanning must NOT reach into a tool/function SCHEMA and rewrite a numeric constraint
    # (default/minimum/maximum/enum) into a placeholder string. Schema STRING descriptions stay scanned; only
    # numerics in schema scope are exempt (in_schema guard + 'input_schema' as a schema-entry key).
    def _schema():
        return {'type': 'object',
                'properties': {'limit': {'type': 'integer', 'default': 100000000, 'maximum': 99999999, 'minimum': 1},
                               'codes': {'type': 'integer', 'enum': [46454286, 581653612]}},
                'required': ['limit']}
    anth = {'model': 'claude-test',
            'tools': [{'name': 'lookup', 'description': 'Search the ledger.', 'input_schema': _schema()}],
            'messages': [{'role': 'user', 'content': 'Continue.'}]}
    _run_redact(monkeypatch, anth, _make_neural({}))
    assert anth['tools'][0]['input_schema'] == _schema()   # numeric constraints + numeric enum untouched

    openai_body = {'model': 'gpt-test',
                   'tools': [{'type': 'function', 'function': {
                       'name': 'lookup', 'description': 'Search.', 'parameters': _schema()}}],
                   'messages': [{'role': 'user', 'content': 'Continue.'}]}
    _run_redact(monkeypatch, openai_body, _make_neural({}),
                ctx={'session': 'sess-num-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
                extract=openai_adapter.extract_text_fields_openai)
    assert openai_body['tools'][0]['function']['parameters'] == _schema()


def test_openai_metadata_redacted_parity_with_responses(monkeypatch):
    """Adapter-parity leak (leak-hunt): top-level `metadata` (the Chat Completions free-form developer map of
    up to 16 string pairs) was forwarded RAW on /v1/chat/completions while the Responses path redacted it. A
    PII value in metadata must now be redacted on the OpenAI path too -- parity with the Responses adapter."""
    body = {'model': 'gpt-test',
            'messages': [{'role': 'user', 'content': 'Continue.'}],
            'metadata': {'requested_by': 'marie.gagnon@example.com', 'note': 'flagged by Jean Tremblay'}}
    _run_redact(monkeypatch, body, _make_neural({'Jean Tremblay': 'person'}),
                ctx={'session': 'sess-md-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
                extract=openai_adapter.extract_text_fields_openai)
    wire = _wire_text(body)
    assert 'marie.gagnon@example.com' not in wire, 'metadata email must be redacted on the openai chat path'
    assert 'Jean Tremblay' not in wire, 'metadata person must be redacted on the openai chat path'


def test_openai_message_name_field_redacted_but_function_name_preserved(monkeypatch):
    """Leak-hunt #1: the optional participant `name` on a user/assistant message is free-form metadata that can
    carry PII -- it was forwarded RAW to api.openai.com. It must now be scanned. But `name` on a role:function /
    role:tool message is the tool IDENTIFIER the API routes on and MUST pass through verbatim (never redacted)."""
    body = {'model': 'gpt-test',
            'messages': [
                {'role': 'user', 'name': 'Jean Tremblay', 'content': 'Please look up my order.'},
                {'role': 'function', 'name': 'get_order_status', 'content': 'status: shipped'},
            ]}
    _run_redact(monkeypatch, body, _make_neural({'Jean Tremblay': 'person'}),
                ctx={'session': 'sess-nm-' + os.urandom(6).hex(), 'project': 'e2e-oa'},
                extract=openai_adapter.extract_text_fields_openai)
    wire = _wire_text(body)
    assert 'Jean Tremblay' not in wire, 'participant name on a user message must be redacted'
    assert body['messages'][1]['name'] == 'get_order_status', 'function-role name is a routing id, never redacted'


# --- adapter-leak-hunt confirmed gaps (verified against the real API schemas) ---
def test_anthropic_thinking_block_opaque_passthrough(monkeypatch):
    """Extended-thinking blocks are CRYPTOGRAPHICALLY BOUND: `signature` is a MAC over the `thinking` content, and a
    multi-turn client must re-send the block VERBATIM. Redacting the thinking desyncs content<->signature (Anthropic
    400s) AND mutates a block inside the cached prefix -> the whole prompt re-caches every turn (the operator's
    "context maxed / 5h usage climbs fast" symptom). The model only ever saw REDACTED input, so its thinking carries
    placeholders, never real PII -- nothing to protect. So a thinking block is OPAQUE PASSTHROUGH: never redacted.
    A model-mentioned entity INSIDE the thinking (here 'Acme Corp') must survive untouched -- redacting it is exactly
    what diverged the bytes turn-to-turn before. Real PII in a SIBLING user message is STILL redacted."""
    thinking_text = 'The user <PERSON_NAME_001> asked about org Acme Corp and path /etc/hosts.'
    body = {'model': 'claude-x', 'messages': [
        {'role': 'assistant', 'content': [
            {'type': 'thinking', 'thinking': thinking_text, 'signature': 'sig-abc-123'},
            {'type': 'text', 'text': 'noted'}]},
        {'role': 'user', 'content': 'Also email nadia.roy@example.com please.'}]}
    # The detector would tag 'Acme Corp' as an org IF the thinking were surfaced -- it must never be called on it.
    _run_redact(monkeypatch, body, _make_neural({'nadia.roy@example.com': 'email', 'Acme Corp': 'organization'}))
    tb = body['messages'][0]['content'][0]
    assert tb['thinking'] == thinking_text, 'thinking text must pass through byte-for-byte (signature would desync)'
    assert tb['signature'] == 'sig-abc-123', 'thinking signature must be untouched'
    assert 'Acme Corp' in _wire_text(body), 'a model-mentioned entity inside thinking must NOT be redacted'
    assert 'nadia.roy@example.com' not in body['messages'][1]['content'], 'a real user-message email is still redacted'


def test_anthropic_thinking_block_not_rehydrated_on_response():
    """Response rehydration must NOT touch a thinking block. Rehydrating its placeholders into real values would
    inject real PII into a SIGNED block, which then (a) is forwarded upstream verbatim next turn (the gate no longer
    redacts thinking) AND (b) desyncs the signature. So thinking/signature pass through the response unchanged; only
    the user-visible text + tool_use inputs are rehydrated."""
    replay = {'<EMAIL_001>': 'nadia.roy@example.com'}
    resp = {'type': 'message', 'content': [
        {'type': 'thinking', 'thinking': 'emailing <EMAIL_001> now', 'signature': 'sig-xyz'},
        {'type': 'redacted_thinking', 'data': 'opaque<EMAIL_001>blob'},
        {'type': 'text', 'text': 'I emailed <EMAIL_001>.'},
        # a coincidental tool-arg sub-object literally tagged type:thinking but with NO signature is NOT a real
        # thinking block -> the structural guard must still rehydrate it (placeholder -> real value for the tool).
        {'type': 'tool_use', 'name': 'send', 'input': {'type': 'thinking', 'to': '<EMAIL_001>'}}]}
    egress_proxy.rehydrate_anthropic_response(resp, replay)
    assert resp['content'][0]['thinking'] == 'emailing <EMAIL_001> now', 'thinking placeholders must NOT be rehydrated'
    assert resp['content'][0]['signature'] == 'sig-xyz', 'signature untouched'
    assert resp['content'][1]['data'] == 'opaque<EMAIL_001>blob', 'redacted_thinking data must NOT be rehydrated'
    assert resp['content'][2]['text'] == 'I emailed nadia.roy@example.com.', 'user-visible text IS rehydrated'
    assert resp['content'][3]['input']['to'] == 'nadia.roy@example.com', 'signature-less type:thinking sub-object IS rehydrated'


def test_concurrent_detection_deterministic_minting(monkeypatch):
    """Concurrent per-field detection must not change placeholder NUMBERING. Pass-2 mints in field order, which the
    concurrent path preserves (asyncio.gather returns in submission order; detected_fields is reassembled in fi
    order). A serial run (GATEWAY_DETECT_CONCURRENCY=1) and a concurrent run (8) over the same body MUST produce
    byte-identical redacted bodies AND replay maps -- otherwise the redacted prefix diverges turn-to-turn and busts
    the upstream prompt cache (the exact failure class this whole change set is closing)."""
    def build():
        return {'model': 'claude-x', 'messages': [
            {'role': 'user', 'content': [
                {'type': 'text', 'text': f'msg {i}: email person{i}@example.com re Client Name{i}'}
                for i in range(12)]}]}
    found = {f'person{i}@example.com': 'email' for i in range(12)}
    found.update({f'Client Name{i}': 'person' for i in range(12)})
    base = _make_neural(found)

    # Concurrency stub that REVERSES completion order vs submission order: field i sleeps (12-i)ms, so the LAST
    # field finishes FIRST. If the code reassembled detected_fields by completion order (a real bug), placeholder
    # numbering would invert and the bytes would differ from the serial run -> this test fails loudly. It passes
    # only because gather + fi-order reassembly keeps minting deterministic.
    async def _reordering_neural(aclient, text, min_score=0.5):
        m = re.search(r'msg (\d+):', text)
        if m:
            await asyncio.sleep((12 - int(m.group(1))) * 0.001)
        return await base(aclient, text, min_score)

    monkeypatch.setattr(egress_proxy, 'DETECT_CONCURRENCY', 1)
    b1 = build()
    _m1, r1 = _run_redact(monkeypatch, b1, base, ctx={'session': 'det-serial-' + os.urandom(6).hex(), 'project': 'e2e'})

    monkeypatch.setattr(egress_proxy, 'DETECT_CONCURRENCY', 8)
    b2 = build()
    _m2, r2 = _run_redact(monkeypatch, b2, _reordering_neural, ctx={'session': 'det-conc-' + os.urandom(6).hex(), 'project': 'e2e'})

    assert _wire_text(b1) == _wire_text(b2), 'serial vs concurrent detection must produce identical redacted bytes'
    assert r1 == r2, 'serial vs concurrent detection must produce identical replay maps'
    assert 'person0@example.com' not in _wire_text(b1) and '<EMAIL_' in _wire_text(b1), 'sanity: redaction happened'


def test_anthropic_top_level_metadata_redacted(monkeypatch):
    """Leak-hunt: Anthropic top-level metadata (e.g. user_id) was forwarded RAW -- parity with the OpenAI path."""
    body = {'model': 'claude-x', 'messages': [{'role': 'user', 'content': 'hi'}],
            'metadata': {'user_id': 'contact nadia.roy@example.com'}}
    _run_redact(monkeypatch, body, _make_neural({}))
    assert 'nadia.roy@example.com' not in _wire_text(body), 'PII in top-level metadata must be redacted'


def test_anthropic_server_tool_use_input_redacted(monkeypatch):
    body = {'model': 'claude-x', 'messages': [{'role': 'assistant', 'content': [
        {'type': 'server_tool_use', 'id': 'srv_1', 'name': 'web_search',
         'input': {'query': 'records for nadia.roy@example.com'}}]}]}
    _run_redact(monkeypatch, body, _make_neural({}))
    assert 'nadia.roy@example.com' not in _wire_text(body), 'PII in a server_tool_use query must be redacted'


def test_openai_response_format_schema_literal_redacted(monkeypatch):
    body = {'model': 'gpt', 'messages': [{'role': 'user', 'content': 'go'}],
            'response_format': {'type': 'json_schema', 'json_schema': {'name': 'r', 'schema': {
                'type': 'object', 'properties': {'note': {'type': 'string', 'description': 'flag nadia.roy@example.com'}}}}}}
    _run_redact(monkeypatch, body, _make_neural({}), extract=openai_adapter.extract_text_fields_openai)
    assert 'nadia.roy@example.com' not in _wire_text(body), 'PII in a response_format json_schema literal must be redacted'


def test_openai_user_field_redacted(monkeypatch):
    body = {'model': 'gpt', 'messages': [{'role': 'user', 'content': 'go'}], 'user': 'nadia.roy@example.com'}
    _run_redact(monkeypatch, body, _make_neural({}), extract=openai_adapter.extract_text_fields_openai)
    assert 'nadia.roy@example.com' not in _wire_text(body), 'a PII-shaped top-level user id must be redacted'


def test_openai_prediction_content_redacted(monkeypatch):
    body = {'model': 'gpt', 'messages': [{'role': 'user', 'content': 'go'}],
            'prediction': {'type': 'content', 'content': 'draft reply to nadia.roy@example.com'}}
    _run_redact(monkeypatch, body, _make_neural({}), extract=openai_adapter.extract_text_fields_openai)
    assert 'nadia.roy@example.com' not in _wire_text(body), 'PII in prediction.content must be redacted'


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
def test_healthz_sanitizes_gate_url(monkeypatch):
    monkeypatch.setattr(
        egress_proxy,
        'GATE_URL',
        'http://user:secret@127.0.0.1:8001/tokens/raw-secret/detect?token=raw#frag',
    )

    payload = egress_proxy.healthz()

    assert payload['gate'] == 'http://127.0.0.1:8001'
    assert 'secret' not in json.dumps(payload, ensure_ascii=False)
    assert 'token=raw' not in json.dumps(payload, ensure_ascii=False)
    assert 'raw-secret' not in json.dumps(payload, ensure_ascii=False)


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


@_NEEDS_PROXY
def test_carrier_gate_error_marks_degraded(monkeypatch):
    """A8 regression: carrier scan None is a gate error, not the same as no person found."""
    name = 'Priya McCallum'
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': name}]}

    async def carrier_down(aclient, text, min_score=0.5):
        if text.startswith('The customer is '):
            return None
        return []

    meta, replay = _run_redact(monkeypatch, body, carrier_down)

    assert meta.get('degraded') is True
    assert egress_proxy._degraded_block(meta) is not None
    assert name in _wire_text(body)
    assert replay == {}


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
def test_nonstreaming_route_rehydrate_is_single_pass_for_placeholder_shaped_values():
    replay = {'<SECRET_001>': 'tok_<EMAIL_001>_x', '<EMAIL_001>': 'alice@example.test'}
    upstream = _FakeUpstreamResponse(
        200,
        {'content-type': 'application/json'},
        json.dumps({'content': [{'type': 'text', 'text': 'secret=<SECRET_001> email=<EMAIL_001>'}]}).encode('utf-8'),
    )

    resp = egress_proxy._finalize_upstream_response(upstream, replay, egress_proxy.rehydrate_anthropic_response)
    payload = _json_response_payload(resp)

    assert payload['content'][0]['text'] == 'secret=tok_<EMAIL_001>_x email=alice@example.test'


@_NEEDS_PROXY
def test_map_eviction_of_current_body_placeholder_is_reported(monkeypatch):
    monkeypatch.setitem(egress_proxy.EntityMap.placeholder_for.__globals__, 'MAX_ENTITIES', 1)
    body = {
        'model': 'claude-test',
        'messages': [{'role': 'user', 'content': 'Email first.eviction@example.test and second.eviction@example.test.'}],
    }

    meta, replay = _run_redact(
        monkeypatch, body, _make_neural({}),
        ctx={'session': 'sess-evict-' + os.urandom(6).hex(), 'project': 'e2e-evict'})

    wire = _wire_text(body)
    assert 'first.eviction@example.test' not in wire
    assert 'second.eviction@example.test' not in wire
    assert meta.get('map_evicted_present_count') == 1
    assert meta.get('map_evicted_present') == ['<EMAIL_001>']
    assert '<EMAIL_001>' not in replay
    assert replay.get('<EMAIL_002>') == 'second.eviction@example.test'


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


def test_anthropic_stream_split_placeholder_rehydrates():
    """Anthropic streaming -- the path Claude Code (the primary client) uses -- can split a multi-underscore
    placeholder across content_block text deltas. The partial must be held until complete, then the full value
    rehydrates, and no placeholder (full OR the distinctive partial) may survive on the wire to the user."""
    value = 'Dossier-QX77182'
    replay = {'<SENSITIVE_ACCOUNT_ID_001>': value}
    carry, block_type, json_acc = {}, {}, {}

    def ev(obj):
        return b'event: ' + obj['type'].encode('utf-8') + b'\ndata: ' + json.dumps(obj).encode('utf-8')

    events = [
        ev({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text'}}),
        ev({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'Case <SENSITIVE_ACCOUNT'}}),
        ev({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': '_ID_001> is ready.'}}),
        ev({'type': 'content_block_stop', 'index': 0}),
    ]
    outs = []
    for e in events:
        r = egress_proxy._transform_event(e, replay, carry, block_type, json_acc)
        outs.append(r.decode('utf-8') if r else '')
    combined = ''.join(outs)

    assert '<SENSITIVE_ACCOUNT' not in outs[1], 'partial placeholder in the first delta must be buffered, not emitted raw'
    assert value in combined, 'split placeholder must rehydrate once complete'
    assert '<SENSITIVE' not in combined, 'no placeholder (full or partial) may survive Anthropic stream rehydration'


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


# ---------------------------------------------------------------------------
# Allowlist (the do-not-redact dictionary): user-declared known-safe values pass through verbatim, but
# SECRETS are never allowlist-exempt (ALWAYS_REDACT stays non-negotiable).
# ---------------------------------------------------------------------------
def test_allowlist_passes_user_values_through_but_never_secrets(monkeypatch):
    import allowlist as al
    # the user declared their own email + a token safe; the gate must never exempt a SECRET label though.
    monkeypatch.setattr(egress_proxy, 'current_allowlist',
                        lambda: al.build_allow_set(['alex@example.com', 'hunter2']))

    async def neural(client, text, min_score=0.5):
        spans = []
        for val, lab in [('hunter2', 'password'), ('Jane Doe', 'person')]:
            i = text.find(val)
            if i >= 0:
                spans.append({'start': i, 'end': i + len(val), 'label': lab, 'tier': 1, 'conf': 0.95,
                              'rule': 'neural'})
        return spans

    body = {'model': 'claude-test', 'messages': [
        {'role': 'user', 'content': 'Email alex@example.com, password hunter2, signed Jane Doe.'}]}
    meta, replay = _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    # allowlisted, non-secret -> passes through verbatim (never minted)
    assert 'alex@example.com' in wire, 'an allowlisted email must pass through un-redacted'
    # allowlisted BUT a secret label -> still redacted (the floor stays non-negotiable)
    assert 'hunter2' not in wire, 'a SECRET must be redacted even when allowlisted'
    # not allowlisted -> normal redaction still happens
    assert 'Jane Doe' not in wire, 'a non-allowlisted name must still be redacted'
    assert _PH_RE.search(wire), 'placeholders present for the redacted values'


def test_allowlisted_name_in_path_not_case_mangled(monkeypatch):
    """The case-mangle fix via allowlist: an allowlisted lowercase name in a file path is never redacted,
    so it is never swept onto a capitalized person placeholder -> the path round-trips unchanged."""
    import allowlist as al
    monkeypatch.setattr(egress_proxy, 'current_allowlist', lambda: al.build_allow_set(['alex']))

    async def neural(client, text, min_score=0.5):
        # the model flags the capitalized prose name as person; the lowercase path token must NOT be minted
        spans = []
        i = text.find('Alex')
        if i >= 0:
            spans.append({'start': i, 'end': i + 4, 'label': 'person', 'tier': 1, 'conf': 0.9, 'rule': 'neural'})
        return spans

    body = {'model': 'claude-test', 'messages': [
        {'role': 'user', 'content': "I'm Alex; open /home/alex/dev/x"}]}
    _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    assert '/home/alex/dev/x' in wire, 'allowlisted name keeps the lowercase path intact (no /home/Alex)'
    assert 'Alex' in wire, 'the allowlisted prose name also passes through'


def test_allowlist_never_exempts_the_hard_floor(monkeypatch):
    """Defense-in-depth: even if a user puts a real payment card / IBAN value in their allowlist, the hard
    deterministic floor (FLOOR_NEVER_EXEMPT = credentials + card/account/government/tax/DOB) STILL redacts
    it. The allowlist is for soft identifiers (name / email / file paths) only -- a user must not be able to
    wave real money/identity values past the firewall, deliberately or by accident."""
    import allowlist as al
    card = '4111111111111111'        # Luhn-valid synthetic Visa test number
    iban = 'GB82WEST12345698765432'  # RFC mod-97-valid example IBAN
    # the user (mistakenly or maliciously) tries to allowlist a real card + IBAN alongside their own email
    monkeypatch.setattr(egress_proxy, 'current_allowlist',
                        lambda: al.build_allow_set([card, iban, 'alex@example.com']))

    async def neural(client, text, min_score=0.5):
        return []  # floor-only: card + IBAN are Tier-0 deterministic, need no neural pass

    body = {'model': 'claude-test', 'messages': [
        {'role': 'user', 'content': f'card {card} iban {iban} email alex@example.com'}]}
    _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    assert card not in wire, 'an allowlisted payment card MUST still be redacted (hard floor, non-exemptable)'
    assert iban not in wire, 'an allowlisted IBAN MUST still be redacted (hard floor, non-exemptable)'
    assert 'alex@example.com' in wire, 'a soft identifier (email) the user allowlisted still passes through'


def test_merge_relabel_cannot_strip_the_floor_via_allowlist(monkeypatch):
    """ADVERSARIAL regression (floor-stickiness, 2026-06-20 audit): the model over-tags a real payment card
    as a HIGHER-confidence 'person'. Pre-fix, merge_spans relabeled the card cluster to person (0.99 > 0.97
    card floor), and the label-based allowlist drop then forwarded the RAW card when the user had allowlisted
    that exact value. Floor-sticky merge keeps the payment_card label, so the allowlist can never exempt it."""
    import allowlist as al
    card = '4111111111111111'  # Luhn-valid synthetic Visa
    monkeypatch.setattr(egress_proxy, 'current_allowlist', lambda: al.build_allow_set([card]))

    async def neural(client, text, min_score=0.5):
        i = text.find(card)
        return ([{'start': i, 'end': i + len(card), 'label': 'person', 'tier': 2, 'conf': 0.99, 'rule': 'gpu'}]
                if i >= 0 else [])

    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': f'card on file {card} thanks'}]}
    _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    assert card not in wire, 'a card relabeled person by a higher-conf overlap MUST still redact (floor sticky)'


def test_merge_relabel_cannot_strip_the_floor_under_off_mode(monkeypatch, tmp_path):
    """Same merge-relabel attack, no allowlist, under mode=off: 'off' is a soft-PII escape hatch, but the
    deterministic floor must still redact. Pre-fix the card-tagged-person passed as soft PII under off."""
    p = tmp_path / 'mode'
    p.write_text('off\n')
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(p))
    card = '4111111111111111'

    async def neural(client, text, min_score=0.5):
        i = text.find(card)
        return ([{'start': i, 'end': i + len(card), 'label': 'person', 'tier': 2, 'conf': 0.99, 'rule': 'gpu'}]
                if i >= 0 else [])

    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': f'card {card} please'}]}
    _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    assert card not in wire, 'under off mode a card mis-tagged person MUST still redact (floor sticky + policy floor)'


def test_denylist_redacts_a_term_the_model_misses(monkeypatch):
    """The always-redact dictionary catches a user term (a project codename) the neural model never flags."""
    import denylist as dl
    monkeypatch.setattr(egress_proxy, 'current_denylist', lambda: dl.compile_denylist(['Project Bluebird']))

    async def neural(client, text, min_score=0.5):
        return []   # model misses the codename entirely

    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': 'ship Project Bluebird tonight'}]}
    _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    assert 'Project Bluebird' not in wire, 'a declared always-redact term MUST redact even if the model misses it'
    assert '<CUSTOM_' in wire, 'the denylist hit mints a <CUSTOM_n> placeholder'


def test_denylist_redacts_under_off_mode(monkeypatch, tmp_path):
    """Always-redact terms are force-redacted even when mode is 'off' (off is a soft-PII escape hatch; a
    user-declared must-redact term is not soft and must not be releasable)."""
    import denylist as dl
    monkeypatch.setattr(egress_proxy, 'current_denylist', lambda: dl.compile_denylist(['Bluebird']))
    mf = tmp_path / 'mode'
    mf.write_text('off\n')
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(mf))

    async def neural(client, text, min_score=0.5):
        return []

    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': 'the Bluebird launch'}]}
    _run_redact(monkeypatch, body, neural)
    assert 'Bluebird' not in _wire_text(body), 'a denylist term must redact even under off mode'


def test_denylist_wins_over_allowlist(monkeypatch):
    """If the same term is in BOTH lists, ALWAYS-redact WINS (denylist is injected after the allowlist filter)."""
    import denylist as dl
    import allowlist as al
    monkeypatch.setattr(egress_proxy, 'current_denylist', lambda: dl.compile_denylist(['Falcon']))
    monkeypatch.setattr(egress_proxy, 'current_allowlist', lambda: al.build_allow_set(['Falcon']))

    async def neural(client, text, min_score=0.5):
        return []

    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': 'codename Falcon ready'}]}
    _run_redact(monkeypatch, body, neural)
    assert 'Falcon' not in _wire_text(body), 'a term in both lists must be redacted (always-redact wins)'


def test_egress_redacts_real_secret_shapes_floor_only(monkeypatch):
    """End-to-end through the proxy: real-shaped API keys in a plain message body AND a tool_result are
    caught by the deterministic secret floor and never reach the wire -- with the neural model contributing
    NOTHING. Proves the always-on secret floor (egress_proxy line: tier0 + secret_spans) stands alone."""
    akia = 'AKIA' + 'IOSFODNN7EXAMPLE'              # synthetic AWS access key shape
    antk = 'sk-ant-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'   # synthetic anthropic key shape

    async def neural(client, text, min_score=0.5):
        return []  # the model finds nothing; the floor alone must redact both secrets

    body = {'model': 'claude-test', 'messages': [
        {'role': 'user', 'content': f'deploy with {akia}'},
        {'role': 'user', 'content': [{'type': 'tool_result', 'content': f'env had {antk} set'}]}]}
    _run_redact(monkeypatch, body, neural)
    wire = _wire_text(body)
    assert akia not in wire, 'an AWS access key must be redacted by the always-on secret floor'
    assert antk not in wire, 'an anthropic key in a tool_result must be redacted by the secret floor'
    assert _PH_RE.search(wire), 'placeholders present for the redacted secrets'


@_NEEDS_PROXY
@_NEEDS_PROXY
def test_rc3_mode_toggle_takes_effect_on_frozen_and_swept_value(monkeypatch, tmp_path):
    """RC3: a config change (mode toggle) must take effect on content the gate ALREADY saw this session. Turn 1
    (privacy) mints an org and FREEZES the field. Turn 2 re-sends the SAME text under 'off' mode: the freeze must
    INVALIDATE (the config fingerprint in the key changed) AND the cross-turn sweep must NOT replay the org
    placeholder (the policy-aware veto), so the org passes through. Without the freeze-key cfg dimension OR the
    sweep veto, the stale privacy redaction would replay -- the 'mode toggle feels dead' bug. Turn 3 (still off)
    is the regression guard: config UNCHANGED must stay byte-identical (the freeze still hits, no spurious bust)."""
    mode_file = tmp_path / 'mode'
    monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(mode_file))
    al = tmp_path / 'allow'; al.write_text(''); monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(al))
    dl = tmp_path / 'deny'; dl.write_text(''); monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(dl))
    monkeypatch.setattr(egress_proxy, 'FREEZE_PREFIX', True)

    async def detector(text, min_score=0.5):
        return [{'start': m.start(1), 'end': m.end(1), 'label': 'organization', 'tier': 1, 'conf': 0.95, 'rule': 'cue'}
                for m in re.finditer(r'vendor:\s+(\S+)', text)]

    SYS = 'Our billing runs through vendor: Acme today.'
    session = 'rc3-' + os.urandom(6).hex()

    def turn():
        body = {'model': 'claude-test', 'system': SYS, 'messages': [{'role': 'user', 'content': 'Hi.'}]}
        asyncio.run(egress_proxy.redact_body(body, {'session': session, 'project': 'e2e'}, detector=detector))
        return body['system']

    mode_file.write_text('privacy')
    t1 = turn()
    assert 'Acme' not in t1, f'turn-1 privacy mode must redact the org, got {t1!r}'

    mode_file.write_text('off')
    t2 = turn()
    assert t2 == SYS, f'toggling to off must un-mask the org on the re-sent field (mode took effect), got {t2!r}'

    t3 = turn()   # config UNCHANGED (still off)
    assert t3 == t2, f'a config-stable turn must stay byte-identical (freeze still hits, no spurious cache-bust): {t3!r}'


def test_prompt_cache_freeze_keeps_prefix_bytes_stable_across_turns(monkeypatch):
    """Headline prompt-cache fix. A re-sent system prefix must redact to BYTE-IDENTICAL output every turn, even
    after the entity map grows -- otherwise Anthropic re-processes the whole prefix every turn (the operator's
    "context balloons one shot / 5h usage climbs fast" symptom). The pass-3 known-value sweep applies the WHOLE
    (growing) map to every field, so a value first minted on a LATER turn would retroactively redact the SAME
    system text and shift its bytes. The freeze memo (redact once, replay verbatim) prevents that. We drive the
    real divergence and assert BOTH directions: freeze ON -> prefix stable; freeze OFF -> prefix diverges (so the
    test provably exercises the bug, and the freeze is what fixes it)."""

    # Detector tags the token after a 'codename:' cue as an organization. The cue lets a value be UNKNOWN in the
    # system prefix on turn 1 (no cue there) yet minted from a tail message on turn 2 -- the exact shape that makes
    # the growing sweep retroactively rewrite the prefix.
    async def detector(text, min_score=0.5):
        return [{'start': m.start(1), 'end': m.end(1), 'label': 'organization',
                 'tier': 1, 'conf': 0.95, 'rule': 'cue'}
                for m in re.finditer(r'codename:\s+(\S+)', text)]

    # Turn-1 system carries 'Falcon' RAW (no cue) plus a cued 'Tango' so turn 1 redacts something and PERSISTS the
    # map (stabilising its generation for the freeze key). The system text is identical on both turns.
    SYS = 'The Falcon dashboard is owned by codename: Tango today.'

    def run_two_turns():
        session = 'freeze-' + os.urandom(6).hex()
        body1 = {'model': 'claude-test', 'system': SYS,
                 'messages': [{'role': 'user', 'content': 'Kickoff.'}]}
        asyncio.run(egress_proxy.redact_body(body1, {'session': session, 'project': 'e2e'}, detector=detector))
        sys_t1 = body1['system']
        # Turn 2: SAME system, plus a NEW tail message that first introduces 'Falcon' under the cue -> minted.
        body2 = {'model': 'claude-test', 'system': SYS,
                 'messages': [{'role': 'user', 'content': 'Kickoff.'},
                              {'role': 'assistant', 'content': 'Ack.'},
                              {'role': 'user', 'content': 'New: codename: Falcon goes live.'}]}
        _m, replay2 = asyncio.run(
            egress_proxy.redact_body(body2, {'session': session, 'project': 'e2e'}, detector=detector))
        return sys_t1, body2['system'], body2['messages'][-1]['content'], replay2

    # freeze ON (default): prefix byte-stable; the NEW tail is still redacted + rehydratable.
    monkeypatch.setattr(egress_proxy, 'FREEZE_PREFIX', True)
    s1, s2, tail, replay = run_two_turns()
    assert 'Falcon' in s1, 'turn-1 system should carry Falcon RAW (no cue there, not yet a known value)'
    assert s2 == s1, ('FROZEN prefix must be byte-identical across turns or the Anthropic prompt cache busts:'
                      f'\n  t1={s1!r}\n  t2={s2!r}')
    assert 'Falcon' not in tail, 'the NEW tail message must still be redacted (freeze only covers re-sent text)'
    assert any(v == 'Falcon' for v in replay.values()), 'Falcon must still rehydrate from the tail mint'

    # freeze OFF: the growing sweep rewrites the SAME prefix -> divergence (the bug the fix prevents).
    monkeypatch.setattr(egress_proxy, 'FREEZE_PREFIX', False)
    s1b, s2b, _tail, _r = run_two_turns()
    assert 'Falcon' in s1b
    assert s2b != s1b, ('control: with freeze OFF the sweep should retroactively redact Falcon in the re-sent '
                        'prefix, proving this test exercises the real divergence')
    assert 'Falcon' not in s2b, 'freeze-off path should have swept Falcon out of the prefix on turn 2'


# --- file_path over-redaction precision (GATEWAY_PATH_POLICY) -----------------------------------------------
# The gate NER tags the WHOLE absolute path as file_path (verified live against the GPU gate :8001). These tests mock that
# behaviour with an injected detector and assert the appliance narrows it to the home-dir username only.
def _path_detector():
    async def detector(text, min_score=0.5):
        return [{'start': m.start(), 'end': m.end(), 'label': 'file_path', 'tier': 1, 'conf': 0.99, 'rule': 'npu'}
                for m in re.finditer(r'/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*', text)]
    return detector


def _redact_with_path_detector(session, content):
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': content}]}
    meta, replay = asyncio.run(
        egress_proxy.redact_body(body, {'session': session, 'project': 'e2e'}, detector=_path_detector()))
    return body['messages'][0]['content'], meta, replay


@_NEEDS_PROXY
def test_filepath_narrowed_to_home_username_linux(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    out, _meta, replay = _redact_with_path_detector('p-' + os.urandom(4).hex(), 'Edit /home/alex/dev/app.py now.')
    assert out == 'Edit /home/<FILEPATH_001>/dev/app.py now.', out
    assert replay['<FILEPATH_001>'] == 'alex', 'username must round-trip to EXACT case (no /home/Alex mangle)'


@_NEEDS_PROXY
def test_filepath_narrowed_to_home_username_mac(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    out, _m, replay = _redact_with_path_detector('p-' + os.urandom(4).hex(), 'Open /Users/alex/Projects/x.ts here.')
    assert out == 'Open /Users/<FILEPATH_001>/Projects/x.ts here.', out
    assert replay['<FILEPATH_001>'] == 'alex'


@_NEEDS_PROXY
def test_filepath_without_home_username_passes_through(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    for path_text in ('The file /etc/nginx/nginx.conf controls it.',
                      'Asset /assets/img/logo.svg is referenced.',
                      'Logs at /var/log/app/output.log on the box.'):
        out, _m, _r = _redact_with_path_detector('p-' + os.urandom(4).hex(), path_text)
        assert out == path_text, f'a non-PII path must pass through verbatim, got {out!r}'


@_NEEDS_PROXY
def test_filepath_narrowing_preserves_surrounding_html(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    out, _m, _r = _redact_with_path_detector(
        'p-' + os.urandom(4).hex(), '<img src="/home/alex/pics/avatar.png" alt="profile"/>')
    assert out == '<img src="/home/<FILEPATH_001>/pics/avatar.png" alt="profile"/>', out


@_NEEDS_PROXY
def test_filepath_narrowing_keeps_other_pii_in_same_field(monkeypatch):
    """No-leak guard: narrowing a file_path span must not suppress a co-located span (email here, caught by the
    Tier-0 floor). The username AND the email both redact; only the non-PII path structure passes through."""
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    out, _m, replay = _redact_with_path_detector(
        'p-' + os.urandom(4).hex(), 'Edit /home/alex/app.py and ping jordan.castellano@example.test')
    assert 'alex' not in out and 'jordan.castellano@example.test' not in out, out
    assert '/app.py' in out, 'non-username path structure must survive'
    assert set(replay.values()) >= {'alex', 'jordan.castellano@example.test'}, replay


@_NEEDS_PROXY
def test_path_policy_passthrough_drops_every_filepath(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'passthrough')
    out, _m, _r = _redact_with_path_detector('p-' + os.urandom(4).hex(), 'Edit /home/alex/dev/app.py now.')
    assert out == 'Edit /home/alex/dev/app.py now.', 'passthrough must forward the whole path verbatim'


@_NEEDS_PROXY
def test_path_policy_full_keeps_legacy_whole_path_span(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'full')
    out, _m, replay = _redact_with_path_detector('p-' + os.urandom(4).hex(), 'Edit /home/alex/dev/app.py now.')
    assert '/home/alex/dev/app.py' not in out and '<FILEPATH_001>' in out, out
    assert replay['<FILEPATH_001>'] == '/home/alex/dev/app.py'


@_NEEDS_PROXY
def test_narrow_path_span_vetoes_echoed_placeholder_username(monkeypatch):
    """RC4 remint guard at the narrower. When a placeholder leaked to chat in a prior turn and is echoed back
    at the home-username offset (/home/<FILEPATH_001>/...), the NER may tag the whole path as file_path again.
    Narrowing must NOT target the placeholder -- doing so reminted <FILEPATH_005> over <FILEPATH_001>, which
    single-pass rehydrate cannot unwind, leaking a raw token to the local chat and breaking file ops. The span
    is dropped (already redacted); a real-username path in the SAME batch still narrows normally."""
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    text = 'Edit /home/<FILEPATH_001>/dev/app.py and /home/alex/x.py'
    p1, p1e = text.index('/home/<'), text.index('/dev/app.py') + len('/dev/app.py')
    p2 = text.index('/home/alex')
    spans = [
        {'start': p1, 'end': p1e, 'label': 'file_path', 'tier': 1, 'conf': 0.99},
        {'start': p2, 'end': p2 + len('/home/alex/x.py'), 'label': 'file_path', 'tier': 1, 'conf': 0.99},
    ]
    out = egress_proxy._narrow_path_spans(spans, text)
    narrowed = [text[s['start']:s['end']] for s in out]
    assert '<FILEPATH_001>' not in narrowed, 'must not narrow onto an existing placeholder (no remint)'
    assert narrowed == ['alex'], f'only the real-username path narrows, got {narrowed!r}'


# --- red-team must-fixes (workflow redteam-path-narrowing): username-variant leaks + sweep pollution ----------
def _abs_path_detector():
    """Tag unix, Windows-drive, and tilde absolute paths as one file_path span each (as the GPU-gate NER does)."""
    async def detector(text, min_score=0.5):
        return [{'start': m.start(), 'end': m.end(), 'label': 'file_path', 'tier': 1, 'conf': 0.99, 'rule': 'npu'}
                for m in re.finditer(r'(?:[A-Za-z]:\\[^\s]+|/[A-Za-z0-9._\-/]*[A-Za-z0-9._\-]|~[^\s]+)', text)]
    return detector


@_NEEDS_PROXY
@pytest.mark.parametrize('content,raw', [
    ('Open /users/alex/dev/app.py', 'alex'),          # lowercase macOS canonical
    ('Edit /HOME/alex/dev/app.py', 'alex'),           # uppercase HOME
    ('Path /home//alex/dev/app.py', 'alex'),          # double-slash join artifact
    (r'Read C:\Users\alex\proj\app.py', 'alex'),      # Windows drive form
    ('Config in ~alex/.bashrc today', 'alex'),        # tilde home
])
def test_home_username_variants_do_not_leak(monkeypatch, content, raw):
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': content}]}
    meta, replay = asyncio.run(
        egress_proxy.redact_body(body, {'session': 'v-' + os.urandom(4).hex(), 'project': 'e2e'},
                                 detector=_abs_path_detector()))
    out = body['messages'][0]['content']
    assert raw not in out, f'home-dir username leaked raw for {content!r}: {out!r}'
    assert raw in replay.values(), f'username must be minted+rehydratable, replay={replay}'


@_NEEDS_PROXY
def test_filepath_username_not_swept_into_flags_or_prose(monkeypatch):
    """Fix B: a short/common home-dir username (build) is redacted at its path site ONLY -- it must not be swept
    body-wide into the CLI flag --build, the prose word in 'test suite', or an unrelated /tmp/test directory."""
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')
    content = 'Read /home/build/app.py then run --build; the test suite writes /tmp/test/out'
    body = {'model': 'claude-test', 'messages': [{'role': 'user', 'content': content}]}
    _m, replay = asyncio.run(
        egress_proxy.redact_body(body, {'session': 'v-' + os.urandom(4).hex(), 'project': 'e2e'},
                                 detector=_abs_path_detector()))
    out = body['messages'][0]['content']
    assert out == 'Read /home/<FILEPATH_001>/app.py then run --build; the test suite writes /tmp/test/out', out
    assert replay == {'<FILEPATH_001>': 'build'}


@_NEEDS_PROXY
def test_path_username_colliding_with_person_does_not_leak(monkeypatch):
    """Red-team round-2 blocker: a lowercase home-dir username ('mason') that EXACTLY collides with an NER-tagged
    lowercase person, with the path field processed FIRST and a third UNTAGGED recurrence, must not leak. The path
    mint claims the value (placeholder_for is value-keyed); keep_values keeps it in the sweep because it was also
    tagged a person this request, so the bare recurrence is caught."""
    monkeypatch.setattr(egress_proxy, 'PATH_POLICY', 'username')

    async def detector(text, min_score=0.5):
        out = [{'start': m.start(), 'end': m.end(), 'label': 'file_path', 'tier': 1, 'conf': 0.99, 'rule': 'npu'}
               for m in re.finditer(r'/[A-Za-z0-9._\-/]*[A-Za-z0-9._\-]', text)]
        if 'Engineer mason' in text:          # tag 'mason' as a person ONLY in this sentence (msg1)
            j = text.index('mason')
            out.append({'start': j, 'end': j + 5, 'label': 'person', 'tier': 1, 'conf': 0.99, 'rule': 'npu'})
        return out

    body = {'model': 'm', 'messages': [
        {'role': 'user', 'content': 'Patch lives at /home/mason/src/fix.py'},   # path FIRST -> mints 'mason' file_path
        {'role': 'user', 'content': 'Engineer mason reviewed the change.'},      # person tag (same request)
        {'role': 'user', 'content': 'mason will deploy it tonight.'}]}           # bare untagged recurrence
    asyncio.run(egress_proxy.redact_body(body, {'session': 'col-' + os.urandom(4).hex(), 'project': 'e2e'},
                                         detector=detector))
    assert 'mason' not in body['messages'][2]['content'], \
        f'colliding name leaked in untagged recurrence: {body["messages"][2]["content"]!r}'


# ---------------------------------------------------------------------------
# GATE FALLBACK (availability): a remote-primary outage degrades to the local
# CPU gate instead of failing every request closed. Connection-level failures
# fail over; a reachable gate returning an HTTP error does NOT (real fault).
# ---------------------------------------------------------------------------
def _fallback_detect_against(fail_primary_with):
    """Build a fake _detect_against that raises `fail_primary_with` for the primary GATE_URL and returns a marker
    span for the fallback URL, so a test can assert which gate produced the result."""
    async def _da(aclient, gate_url, text, min_score):
        if gate_url == egress_proxy.GATE_URL:
            raise fail_primary_with
        return [{'start': 0, 'end': 4, 'label': 'person', 'tier': 1, 'conf': 0.9, 'rule': 'fallback-gate'}]
    return _da


def test_gate_fallback_used_when_primary_unreachable(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'GATE_URL', 'http://primary:8001')
    monkeypatch.setattr(egress_proxy, 'GATE_FALLBACK_URL', 'http://127.0.0.1:8001')
    monkeypatch.setattr(egress_proxy, '_DETECT_CACHE', egress_proxy.OrderedDict())
    monkeypatch.setattr(egress_proxy, '_detect_against',
                        _fallback_detect_against(egress_proxy.httpx.ConnectError('primary down')))
    spans = asyncio.run(egress_proxy._detect_neural(None, 'Jean lives here', 0.5))
    assert spans is not None and len(spans) == 1
    assert spans[0]['rule'] == 'fallback-gate', 'a connection-level primary failure must fail over to the fallback gate'


def test_is_connection_error_classifies_only_transport_failures():
    """The failover trigger: only httpx.TransportError (unreachable) counts; an HTTPStatusError (reachable gate,
    HTTP error) or any other exception is a real fault, not an outage."""
    assert egress_proxy._is_connection_error(egress_proxy.httpx.ConnectError('down')) is True
    assert egress_proxy._is_connection_error(ValueError('x')) is False
    # HTTPStatusError is a sibling of TransportError under HTTPError, so it is NOT a connection error.
    assert not issubclass(egress_proxy.httpx.HTTPStatusError, egress_proxy.httpx.TransportError)


def test_gate_fallback_not_used_on_non_transport_error(monkeypatch):
    """A reachable gate returning 4xx/5xx (or any non-transport fault) is a real error, not an outage -- do NOT
    paper over it by retrying elsewhere; degrade (return None) so fail-closed kicks in. Uses a stand-in
    non-transport exception; the branch is identical for HTTPStatusError (asserted non-transport above)."""
    monkeypatch.setattr(egress_proxy, 'GATE_URL', 'http://primary:8001')
    monkeypatch.setattr(egress_proxy, 'GATE_FALLBACK_URL', 'http://127.0.0.1:8001')
    monkeypatch.setattr(egress_proxy, '_DETECT_CACHE', egress_proxy.OrderedDict())
    monkeypatch.setattr(egress_proxy, '_detect_against',
                        _fallback_detect_against(ValueError('gate returned 500')))
    spans = asyncio.run(egress_proxy._detect_neural(None, 'Jean lives here', 0.5))
    assert spans is None, 'a non-transport error from a reachable gate must NOT trigger failover'


def test_gate_no_fallback_returns_none_when_unset(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'GATE_URL', 'http://primary:8001')
    monkeypatch.setattr(egress_proxy, 'GATE_FALLBACK_URL', '')
    monkeypatch.setattr(egress_proxy, '_DETECT_CACHE', egress_proxy.OrderedDict())
    monkeypatch.setattr(egress_proxy, '_detect_against',
                        _fallback_detect_against(egress_proxy.httpx.ConnectError('primary down')))
    spans = asyncio.run(egress_proxy._detect_neural(None, 'Jean lives here', 0.5))
    assert spans is None, 'with no fallback configured, an unreachable primary degrades (None), not crashes'


def test_gate_fallback_ignored_when_same_as_primary(monkeypatch):
    """A fallback identical to the primary is not a real second gate -- do not retry the same dead URL."""
    monkeypatch.setattr(egress_proxy, 'GATE_URL', 'http://127.0.0.1:8001')
    monkeypatch.setattr(egress_proxy, 'GATE_FALLBACK_URL', 'http://127.0.0.1:8001')
    monkeypatch.setattr(egress_proxy, '_DETECT_CACHE', egress_proxy.OrderedDict())
    calls = []

    async def _da(aclient, gate_url, text, min_score):
        calls.append(gate_url)
        raise egress_proxy.httpx.ConnectError('down')

    monkeypatch.setattr(egress_proxy, '_detect_against', _da)
    spans = asyncio.run(egress_proxy._detect_neural(None, 'x', 0.5))
    assert spans is None and calls == ['http://127.0.0.1:8001'], 'identical fallback must not double-call the dead gate'


# ---------------------------------------------------------------------------
# BODY-SIZE CAP: reject oversized bodies (413) before the detector fan-out,
# via Content-Length pre-check and a post-read backstop.
# ---------------------------------------------------------------------------
def test_body_cap_rejects_oversized_by_content_length(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'MAX_BODY_BYTES', 1000)
    req = _FakeRequest({'x': 'y'}, headers={'content-length': '5000'})
    _body, err = asyncio.run(egress_proxy._read_json_body(req))
    assert _body is None and _response_status(err) == 413, 'oversized Content-Length must 413 before the body is read'


def test_body_cap_rejects_oversized_after_read(monkeypatch):
    """No/again-lying Content-Length: the post-read length check is the backstop."""
    monkeypatch.setattr(egress_proxy, 'MAX_BODY_BYTES', 50)
    req = _FakeRequest({'blob': 'A' * 500})   # no content-length header on the fake request
    _body, err = asyncio.run(egress_proxy._read_json_body(req))
    assert _body is None and _response_status(err) == 413, 'oversized actual body must 413 even without a Content-Length'


def test_body_cap_allows_normal_body_and_flags_bad_json(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'MAX_BODY_BYTES', 32 * 1024 * 1024)
    ok, err = asyncio.run(egress_proxy._read_json_body(_FakeRequest({'model': 'm', 'messages': []})))
    assert err is None and ok == {'model': 'm', 'messages': []}

    class _BadReq:
        headers = {}
        async def body(self):
            return b'{not json'
    body2, err2 = asyncio.run(egress_proxy._read_json_body(_BadReq()))
    assert body2 is None and _response_status(err2) == 400, 'malformed JSON must 400'


# ---------------------------------------------------------------------------
# CORS MIDDLEWARE: the control route runs EXACTLY once, even if response-header
# mutation throws (regression: the old except re-invoked call_next -> a mutating
# write could double-execute).
# ---------------------------------------------------------------------------
class _CorsReq:
    def __init__(self, path, method='POST', origin=None):
        self.url = types.SimpleNamespace(path=path)
        self.method = method
        self.headers = {'origin': origin} if origin else {}


class _RaisingHeaders(dict):
    def __setitem__(self, k, v):
        raise RuntimeError('header assignment blew up after the route already ran')


def test_cors_middleware_runs_route_once_even_if_header_mutation_fails(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'CONTROL_CORS_ORIGINS', frozenset({'http://console'}))
    count = {'n': 0}

    async def call_next(_request):
        count['n'] += 1
        return types.SimpleNamespace(headers=_RaisingHeaders())   # header set will raise

    resp = asyncio.run(egress_proxy._control_cors(_CorsReq('/api/settings', origin='http://console'), call_next))
    assert count['n'] == 1, 'the (state-mutating) control route must execute exactly once even when header set fails'
    assert resp is not None


def test_cors_preflight_answered_without_running_route(monkeypatch):
    monkeypatch.setattr(egress_proxy, 'CONTROL_CORS_ORIGINS', frozenset({'http://console'}))
    count = {'n': 0}

    async def call_next(_request):
        count['n'] += 1
        return types.SimpleNamespace(headers={})

    resp = asyncio.run(egress_proxy._control_cors(_CorsReq('/api/allowlist', method='OPTIONS', origin='http://console'), call_next))
    assert count['n'] == 0, 'a preflight OPTIONS must be answered by the middleware, never forwarded to the route'
    assert _response_status(resp) == 204


def test_cors_non_control_path_forwarded_untouched(monkeypatch):
    count = {'n': 0}

    async def call_next(_request):
        count['n'] += 1
        return types.SimpleNamespace(headers={})

    asyncio.run(egress_proxy._control_cors(_CorsReq('/v1/messages'), call_next))
    assert count['n'] == 1, 'a non-control route is forwarded exactly once with no CORS handling'
