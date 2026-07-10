"""Phase 4 -- gate bind/auth policy contract (GATE_TOKEN).

Independently deployable gate services (CPU, GPU, deploy CPU mirror, appliance NPU) must share one
HTTP policy:

  * Exact loopback bind hosts ``127.0.0.1``, ``::1``, ``localhost`` stay unauthenticated.
  * Any other bind fails startup unless ``GATE_TOKEN`` is configured, and that check runs BEFORE
    model initialization.
  * On a non-loopback service, ``POST /detect`` and ``POST /redact`` require a constant-time match
    of header ``X-OSSRedact-Gate-Token`` and must reject without invoking detection.
  * ``GET /healthz`` stays unauthenticated and value-free (no mapping / original values / token).
  * ``deploy/gate_service_cpu.py`` remains byte-identical to ``gate/gate_service_cpu.py``.
  * NPU (``appliance/gate_service.py``) stays standalone: it may import a local twin
    ``appliance/gate_http_policy.py`` but must not import from the gate package/path.
  * ``gate_http_policy.py`` is byte-identical across gate/, deploy/, and appliance/.

Import seam (proposed production helper -- pure stdlib, no FastAPI, no model load)::

    # gate/gate_http_policy.py  (mirrored byte-identical at deploy/ and appliance/)
    GATE_TOKEN_ENV = 'GATE_TOKEN'
    GATE_TOKEN_HEADER = 'X-OSSRedact-Gate-Token'

    def is_loopback_host(host: str | None) -> bool: ...
    def gate_token_required(host: str | None) -> bool: ...
    def require_gate_token_configured(host: str | None, token: str | None = None) -> str: ...
    def authorize_gate_request(
        presented: str | None,
        configured: str | None,
        *,
        bind_host: str | None,
    ) -> bool: ...

CPU + GPU import ``gate/gate_http_policy.py`` and call
``require_gate_token_configured(HOST, os.environ.get(...))`` before constructing PrivacyGate /
loading weights. Deploy keeps a byte-identical policy copy next to its CPU service. NPU imports the
local twin ``appliance/gate_http_policy.py`` so its tree does not depend on ``gate/``.

Synthetic inputs only. No models, network, or private data.
Run: .venv-test/bin/python -m pytest gate/tests/test_gate_http_policy.py gate/tests/test_deploy_gate_service_sync.py -v
"""
from __future__ import annotations

import ast
import hmac
import importlib
import re
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
GATE_DIR = ROOT / 'gate'
DEPLOY_DIR = ROOT / 'deploy'
APPLIANCE_DIR = ROOT / 'appliance'
DEPLOY_CPU = DEPLOY_DIR / 'gate_service_cpu.py'
GATE_CPU = GATE_DIR / 'gate_service_cpu.py'
GATE_GPU = GATE_DIR / 'gate_service_gpu.py'
APPLIANCE_NPU = APPLIANCE_DIR / 'gate_service.py'

POLICY_MODULE = 'gate_http_policy'
POLICY_PATH = GATE_DIR / f'{POLICY_MODULE}.py'
DEPLOY_POLICY_PATH = DEPLOY_DIR / f'{POLICY_MODULE}.py'
APPLIANCE_POLICY_PATH = APPLIANCE_DIR / f'{POLICY_MODULE}.py'

# Distinct from GATEWAY_GATE_TOKEN (egress outbound) and control-token (X-OSSRedact-Control-Token).
EXPECTED_TOKEN_ENV = 'GATE_TOKEN'
EXPECTED_TOKEN_HEADER = 'X-OSSRedact-Gate-Token'
EXPECTED_HEADER_LOOKUP = 'x-ossredact-gate-token'  # Starlette lowercases

LOOPBACK_HOSTS = ('127.0.0.1', '::1', 'localhost')
NONLOOPBACK_HOSTS = (
    '0.0.0.0',
    '::',
    '192.0.2.24',
    '192.168.1.10',
    '10.0.0.5',
    'example.local',
    'Localhost',  # case-sensitive exact match only
    '127.0.0.1 ',  # exact, no incidental trim requirement in the contract
)

SERVICE_FILES = {
    'gate_cpu': GATE_CPU,
    'gate_gpu': GATE_GPU,
    'deploy_cpu': DEPLOY_CPU,
    'appliance_npu': APPLIANCE_NPU,
}


def _load_policy():
    """Import the pure policy helper without importing any gate_service_*.py (those load models)."""
    if str(GATE_DIR) not in sys.path:
        sys.path.insert(0, str(GATE_DIR))
    if not POLICY_PATH.is_file():
        pytest.fail(
            f'proposed pure policy module missing: {POLICY_PATH.relative_to(ROOT)} '
            f'(GATE_TOKEN bind/auth helper required before model init)'
        )
    # Drop a stale module so each test sees the on-disk file.
    sys.modules.pop(POLICY_MODULE, None)
    try:
        return importlib.import_module(POLICY_MODULE)
    except Exception as exc:  # noqa: BLE001 -- surface import failures as contract reds
        pytest.fail(f'failed to import {POLICY_MODULE} from {POLICY_PATH}: {exc!r}')


def _read(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def _source_before_model_init(src: str) -> str:
    """Text that must host the startup token check: everything before first model/warmup construct."""
    markers = (
        'PrivacyGate(',
        'OVTier(',
        'NPUTier(',
        'GPUTier(',
        'gate.detect(',
        'gate.npu',
        "print(f'loading",
        'print(f"loading',
        "print('loading",
        'print("loading',
    )
    cut = len(src)
    for marker in markers:
        idx = src.find(marker)
        if idx != -1:
            cut = min(cut, idx)
    return src[:cut]


# ---------------------------------------------------------------------------
# Pure policy API
# ---------------------------------------------------------------------------
class TestLoopbackHostDetermination:
    def test_exact_loopback_hosts_are_unauthenticated_binds(self):
        policy = _load_policy()
        for host in LOOPBACK_HOSTS:
            assert policy.is_loopback_host(host) is True, host
            assert policy.gate_token_required(host) is False, host

    def test_nonloopback_hosts_require_token(self):
        policy = _load_policy()
        for host in NONLOOPBACK_HOSTS:
            assert policy.is_loopback_host(host) is False, host
            assert policy.gate_token_required(host) is True, host

    def test_empty_and_none_host_are_not_loopback(self):
        policy = _load_policy()
        assert policy.is_loopback_host('') is False
        assert policy.is_loopback_host(None) is False
        assert policy.gate_token_required('') is True
        assert policy.gate_token_required(None) is True


class TestStartupTokenConfiguration:
    def test_loopback_starts_without_token(self):
        policy = _load_policy()
        for host in LOOPBACK_HOSTS:
            # Empty / missing token is fine on loopback; return value is the (possibly empty) token.
            assert policy.require_gate_token_configured(host, '') == ''
            out = policy.require_gate_token_configured(host, None)
            assert out in ('', None) or out == ''

    def test_nonloopback_missing_token_exits_before_model(self):
        policy = _load_policy()
        for host in ('0.0.0.0', '192.0.2.24', '198.51.100.10'):
            with pytest.raises(SystemExit) as ei:
                policy.require_gate_token_configured(host, '')
            assert ei.value.code not in (0, None)
            with pytest.raises(SystemExit):
                policy.require_gate_token_configured(host, None)
            with pytest.raises(SystemExit):
                policy.require_gate_token_configured(host, '   ')  # whitespace-only is not configured

    def test_nonloopback_with_token_returns_token(self):
        policy = _load_policy()
        token = 'synth-gate-token-aa11'
        out = policy.require_gate_token_configured('0.0.0.0', token)
        assert out == token

    def test_require_reads_gate_token_env_when_token_arg_omitted(self, monkeypatch):
        policy = _load_policy()
        monkeypatch.delenv(EXPECTED_TOKEN_ENV, raising=False)
        with pytest.raises(SystemExit):
            policy.require_gate_token_configured('0.0.0.0')
        monkeypatch.setenv(EXPECTED_TOKEN_ENV, 'from-env-token-bb22')
        assert policy.require_gate_token_configured('0.0.0.0') == 'from-env-token-bb22'
        # Loopback still fine with env unset.
        monkeypatch.delenv(EXPECTED_TOKEN_ENV, raising=False)
        policy.require_gate_token_configured('127.0.0.1')


class TestAuthorizeDetectRedact:
    def test_loopback_bind_allows_missing_and_wrong_headers(self):
        policy = _load_policy()
        for host in LOOPBACK_HOSTS:
            assert policy.authorize_gate_request(None, 'secret', bind_host=host) is True
            assert policy.authorize_gate_request('', 'secret', bind_host=host) is True
            assert policy.authorize_gate_request('wrong', 'secret', bind_host=host) is True

    def test_nonloopback_requires_matching_header(self):
        policy = _load_policy()
        token = 'synth-gate-token-cc33'
        host = '0.0.0.0'
        assert policy.authorize_gate_request(token, token, bind_host=host) is True
        assert policy.authorize_gate_request(None, token, bind_host=host) is False
        assert policy.authorize_gate_request('', token, bind_host=host) is False
        assert policy.authorize_gate_request('nope', token, bind_host=host) is False
        assert policy.authorize_gate_request(token, '', bind_host=host) is False
        assert policy.authorize_gate_request(token, None, bind_host=host) is False

    def test_authorize_uses_hmac_compare_digest(self, monkeypatch):
        policy = _load_policy()
        calls = []

        def _spy(a, b):
            calls.append((a, b))
            return hmac.compare_digest(a, b)

        if hasattr(policy, 'hmac'):
            monkeypatch.setattr(policy.hmac, 'compare_digest', _spy)
        monkeypatch.setattr(hmac, 'compare_digest', _spy)
        if hasattr(policy, 'compare_digest'):
            monkeypatch.setattr(policy, 'compare_digest', _spy)

        token = 'synth-gate-token-dd44'
        result = policy.authorize_gate_request(token, token, bind_host='10.0.0.8')
        src = POLICY_PATH.read_text(encoding='utf-8')
        assert 'compare_digest' in src, 'authorize must use hmac.compare_digest (constant-time)'
        assert result is True

    def test_length_mismatched_token_is_rejected_without_raising(self):
        policy = _load_policy()
        # hmac.compare_digest must not raise on length mismatch; auth simply fails closed.
        assert policy.authorize_gate_request('x', 'synth-gate-token-ee55', bind_host='0.0.0.0') is False
        assert policy.authorize_gate_request('synth-gate-token-ee55', 'x', bind_host='0.0.0.0') is False

    def test_unauthorized_path_does_not_need_detection_callable(self):
        """Auth decision is pure: False means the service must return 401/403 without detect/redact."""
        policy = _load_policy()
        assert policy.authorize_gate_request('bad', 'good', bind_host='0.0.0.0') is False


class TestPolicyConstants:
    def test_env_and_header_names_are_gate_token_not_control_or_gateway(self):
        policy = _load_policy()
        env_name = getattr(policy, 'GATE_TOKEN_ENV', None) or getattr(policy, 'TOKEN_ENV', None)
        header_name = getattr(policy, 'GATE_TOKEN_HEADER', None) or getattr(policy, 'TOKEN_HEADER', None)
        assert env_name == EXPECTED_TOKEN_ENV
        assert header_name == EXPECTED_TOKEN_HEADER
        # Preserve distinct semantics from egress outbound + remote-control tokens.
        assert env_name != 'GATEWAY_GATE_TOKEN'
        assert env_name != 'GATEWAY_CONTROL_TOKEN'
        assert 'Control-Token' not in header_name
        assert header_name != 'X-OSSRedact-Control-Token'


# ---------------------------------------------------------------------------
# Service wiring contract (source-level; no model import)
# ---------------------------------------------------------------------------
def _assert_startup_guard_before_model(label: str, path: Path):
    src = _read(path)
    pre = _source_before_model_init(src)
    assert EXPECTED_TOKEN_ENV in src, (
        f'{label}: service source never mentions {EXPECTED_TOKEN_ENV}; '
        f'nonloopback binds are currently unprotected'
    )
    assert 'require_gate_token_configured' in src or (
        'GATE_TOKEN' in pre and ('SystemExit' in pre or 'sys.exit' in pre)
    ), (
        f'{label}: GATE_TOKEN must be enforced at startup before model init '
        f'(require_gate_token_configured or equivalent SystemExit)'
    )
    # The guard text itself must appear before model construction markers.
    assert EXPECTED_TOKEN_ENV in pre or 'require_gate_token_configured' in pre, (
        f'{label}: token startup check must run BEFORE model/PrivacyGate initialization'
    )


def _assert_detect_redact_authorize(label: str, path: Path):
    src = _read(path)
    assert EXPECTED_TOKEN_HEADER in src or EXPECTED_HEADER_LOOKUP in src, (
        f'{label}: /detect and /redact must check header {EXPECTED_TOKEN_HEADER}; '
        f'currently exposed without gate auth'
    )
    assert 'authorize_gate_request' in src or 'compare_digest' in src, (
        f'{label}: detect/redact auth must constant-time compare the gate token'
    )
    for route in ("'/detect'", '"/detect"', "'/redact'", '"/redact"'):
        assert route in src, f'{label}: missing route marker {route}'


def _assert_healthz_unauthenticated(label: str, path: Path):
    src = _read(path)
    assert '/healthz' in src, f'{label}: missing /healthz'
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        pytest.fail(f'{label}: cannot parse for healthz audit: {exc}')
    health_fns = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == 'healthz'
    ]
    assert health_fns, f'{label}: no healthz() function found'
    for fn in health_fns:
        body_src = ast.get_source_segment(src, fn) or ''
        assert EXPECTED_HEADER_LOOKUP not in body_src.lower().replace('_', '-'), (
            f'{label}: healthz must not require {EXPECTED_TOKEN_HEADER}'
        )
        assert 'authorize_gate_request' not in body_src, (
            f'{label}: healthz must remain unauthenticated'
        )
        assert 'mapping' not in body_src, f'{label}: healthz must stay value-free (no mapping)'
        assert 'redacted_text' not in body_src, f'{label}: healthz must stay value-free'


class TestServiceSourceContract:
    @pytest.mark.parametrize('label,path', [
        ('gate_cpu', GATE_CPU),
        ('gate_gpu', GATE_GPU),
        ('deploy_cpu', DEPLOY_CPU),
        ('appliance_npu', APPLIANCE_NPU),
    ])
    def test_startup_requires_gate_token_on_nonloopback_before_model(self, label, path):
        assert path.is_file(), path
        _assert_startup_guard_before_model(label, path)

    @pytest.mark.parametrize('label,path', [
        ('gate_cpu', GATE_CPU),
        ('gate_gpu', GATE_GPU),
        ('deploy_cpu', DEPLOY_CPU),
        ('appliance_npu', APPLIANCE_NPU),
    ])
    def test_detect_and_redact_require_gate_token_header(self, label, path):
        _assert_detect_redact_authorize(label, path)

    @pytest.mark.parametrize('label,path', [
        ('gate_cpu', GATE_CPU),
        ('gate_gpu', GATE_GPU),
        ('deploy_cpu', DEPLOY_CPU),
        ('appliance_npu', APPLIANCE_NPU),
    ])
    def test_healthz_unauthenticated_and_value_free(self, label, path):
        _assert_healthz_unauthenticated(label, path)

    def test_cpu_and_gpu_import_shared_policy_module(self):
        for label, path in (('gate_cpu', GATE_CPU), ('gate_gpu', GATE_GPU)):
            src = _read(path)
            assert (
                'gate_http_policy' in src
                or 'from gate_http_policy import' in src
                or 'import gate_http_policy' in src
            ), f'{label} must import shared {POLICY_MODULE} (not a one-off inline only)'

    def test_npu_uses_local_policy_not_gate_package(self):
        """NPU may import appliance/gate_http_policy.py; it must not depend on gate/."""
        src = _read(APPLIANCE_NPU)
        # Forbid gate-package / gate-path imports (standalone appliance layout).
        assert 'from gate.' not in src and 'import gate.' not in src, (
            'appliance NPU must not import the gate package'
        )
        assert 'gate/gate_http_policy' not in src and 'gate.gate_http_policy' not in src, (
            'appliance NPU must not import gate/gate_http_policy.py by path or package'
        )
        # Reject sys.path inserts that point at the repo gate/ tree for policy resolution.
        assert not re.search(r"""sys\.path\.(?:insert|append)\([^)]*['"][^'"]*gate['"]""", src), (
            'appliance NPU must not put gate/ on sys.path to reach the gate-local policy'
        )
        # Local twin is allowed and expected once wired.
        has_local_policy = (
            'gate_http_policy' in src
            or 'is_loopback_host' in src
            or 'require_gate_token' in src
            or EXPECTED_TOKEN_ENV in src
        )
        assert has_local_policy, (
            'appliance NPU must host/import a local gate_http_policy twin '
            f'({APPLIANCE_POLICY_PATH.relative_to(ROOT)}) without gate/ imports'
        )

    def test_gate_deploy_appliance_policy_modules_are_byte_identical(self):
        """Shared policy helpers must not drift across the three deployable trees."""
        paths = (POLICY_PATH, DEPLOY_POLICY_PATH, APPLIANCE_POLICY_PATH)
        missing = [p.relative_to(ROOT).as_posix() for p in paths if not p.is_file()]
        assert not missing, (
            'gate_http_policy.py must exist in gate/, deploy/, and appliance/ '
            f'(missing: {", ".join(missing)})'
        )
        gate_bytes = POLICY_PATH.read_bytes()
        deploy_bytes = DEPLOY_POLICY_PATH.read_bytes()
        appliance_bytes = APPLIANCE_POLICY_PATH.read_bytes()
        assert deploy_bytes == gate_bytes, (
            'deploy/gate_http_policy.py must be byte-identical to gate/gate_http_policy.py'
        )
        assert appliance_bytes == gate_bytes, (
            'appliance/gate_http_policy.py must be byte-identical to gate/gate_http_policy.py'
        )

    def test_deploy_cpu_byte_identical_to_gate_cpu(self):
        assert DEPLOY_CPU.read_bytes() == GATE_CPU.read_bytes(), (
            'deploy/gate_service_cpu.py must remain byte-identical to gate/gate_service_cpu.py '
            'after GATE_TOKEN policy wiring'
        )

    def test_default_bind_hosts_are_loopback(self):
        # Safe default remains loopback; nonloopback is an explicit operator opt-in.
        for label, path in SERVICE_FILES.items():
            src = _read(path)
            assert "127.0.0.1" in src, f'{label}: default bind should remain loopback 127.0.0.1'


class TestMiniAppAuthShortCircuit:
    """Integration-shaped seam using the pure helper: unauthorized requests never call detection."""

    def test_detect_and_redact_reject_without_calling_detection(self):
        policy = _load_policy()

        detect_calls = {'n': 0}
        redact_calls = {'n': 0}
        bind_host = '0.0.0.0'
        configured = 'synth-gate-token-ff66'
        # Startup policy must accept this configuration.
        assert policy.require_gate_token_configured(bind_host, configured) == configured

        app = FastAPI()

        def _check(request: Request):
            presented = request.headers.get(EXPECTED_HEADER_LOOKUP)
            if not policy.authorize_gate_request(presented, configured, bind_host=bind_host):
                raise HTTPException(status_code=401, detail='unauthorized')

        @app.post('/detect')
        def detect(request: Request):
            _check(request)
            detect_calls['n'] += 1
            return {'spans': [], 'elapsed_ms': 0}

        @app.post('/redact')
        def redact(request: Request):
            _check(request)
            redact_calls['n'] += 1
            return {'redacted_text': 'x', 'mapping': {}, 'stats': {}}

        @app.get('/healthz')
        def healthz():
            return {'status': 'ok', 'model': 'synthetic', 'uptime_s': 0}

        client = TestClient(app)
        # Missing / wrong token: auth failure, detection never runs.
        r = client.post('/detect', json={'text': 'synthetic Jean Tremblay'})
        assert r.status_code == 401
        r = client.post('/detect', json={'text': 'synthetic'}, headers={EXPECTED_HEADER_LOOKUP: 'wrong'})
        assert r.status_code == 401
        r = client.post('/redact', json={'text': 'synthetic'})
        assert r.status_code == 401
        assert detect_calls['n'] == 0
        assert redact_calls['n'] == 0

        # Correct token: handlers run.
        headers = {EXPECTED_HEADER_LOOKUP: configured}
        assert client.post('/detect', json={'text': 'synthetic'}, headers=headers).status_code == 200
        assert client.post('/redact', json={'text': 'synthetic'}, headers=headers).status_code == 200
        assert detect_calls['n'] == 1
        assert redact_calls['n'] == 1

        # healthz stays open and value-free.
        h = client.get('/healthz')
        assert h.status_code == 200
        body = h.json()
        assert body['status'] == 'ok'
        assert 'mapping' not in body
        assert 'redacted_text' not in body
        assert configured not in h.text
