"""Plan/OAuth routing tests (2026-06-21): the egress proxy must forward the genuine CLIENT FINGERPRINT headers
verbatim so a Max/Codex *plan* (OAuth) request looks like the official client it actually is, and must detect the
Codex ChatGPT-plan path on more than one fragile header. Locks the fix for the "blocked on the plan but fine with
an API key" symptom (Anthropic subscription enforcement keys on user-agent / x-app / x-stainless-* fingerprint).

Torch-free, no network: exercises the pure header-forwarding + plan-detection helpers directly.
Run: .venv-test/bin/python -m pytest appliance/tests/test_plan_routing_headers.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy as ep          # noqa: E402
import responses_adapter as ra     # noqa: E402
import openai_adapter as oa        # noqa: E402


class _FakeHeaders:
    """Lowercased, case-insensitive-enough stand-in for Starlette Headers (items() + get())."""
    def __init__(self, d):
        self._d = {k.lower(): v for k, v in d.items()}

    def items(self):
        return self._d.items()

    def get(self, k, default=None):
        return self._d.get(k.lower(), default)


class _FakeReq:
    def __init__(self, headers):
        self.headers = _FakeHeaders(headers)


# --- the genuine Claude Code request fingerprint (Max/Pro OAuth) ---
_CLAUDE_CODE_HEADERS = {
    'authorization': 'Bearer oauth-token', 'anthropic-version': '2023-06-01',
    'anthropic-beta': 'oauth-2025-04-20', 'content-type': 'application/json',
    'user-agent': 'claude-cli/1.2.3 (external, cli)', 'x-app': 'cli',
    'x-stainless-lang': 'js', 'x-stainless-os': 'Linux', 'x-stainless-runtime': 'node',
    'x-stainless-package-version': '0.40.0',
    'cookie': 'do-not-forward', 'x-evil': 'nope', 'host': 'localhost:8011',
}


def test_anthropic_forwards_claude_code_fingerprint():
    fwd = {k.lower(): v for k, v in ep.fwd_headers(_FakeReq(_CLAUDE_CODE_HEADERS)).items()}
    # the OAuth fingerprint Anthropic's enforcement keys on MUST survive verbatim
    assert fwd.get('user-agent') == 'claude-cli/1.2.3 (external, cli)', 'real Claude Code UA must forward (not python-httpx)'
    assert fwd.get('x-app') == 'cli'
    for h in ('x-stainless-lang', 'x-stainless-os', 'x-stainless-runtime', 'x-stainless-package-version'):
        assert h in fwd, f'{h} (Stainless fingerprint) must forward'
    # auth + version + beta still forwarded
    for h in ('authorization', 'anthropic-version', 'anthropic-beta'):
        assert h in fwd
    # non-fingerprint / hop-by-hop headers still stripped (cookie philosophy unchanged)
    assert 'cookie' not in fwd and 'x-evil' not in fwd and 'host' not in fwd


def test_anthropic_stainless_prefix_only_matches_family():
    # a header that merely contains "stainless" but is not the x-stainless-* family is NOT forwarded
    fwd = {k.lower() for k in ep.fwd_headers(_FakeReq({'authorization': 'Bearer t', 'my-stainless-thing': 'x'}))}
    assert 'my-stainless-thing' not in fwd


def test_responses_forwards_codex_fingerprint_and_plan_identity():
    headers = {
        'authorization': 'Bearer oauth', 'content-type': 'application/json',
        'chatgpt-account-id': 'acct-uuid', 'originator': 'codex_cli_rs', 'session_id': 'sess-1',
        'openai-beta': 'responses=experimental', 'openai-sentinel-token': 'sent-xyz',
        'codex-version': '0.9.0', 'user-agent': 'codex_cli_rs/0.9.0',
        'x-stainless-lang': 'rust',
        'cookie': 'nope', 'x-evil': 'nope',
    }
    fwd = {k.lower(): v for k, v in ra.fwd_headers_responses(_FakeReq(headers)).items()}
    # plan identity the ChatGPT backend needs
    for h in ('authorization', 'chatgpt-account-id', 'originator', 'session_id', 'openai-beta', 'openai-sentinel-token'):
        assert h in fwd, f'{h} must forward for the Codex plan path'
    # NEW: the genuine Codex UA must forward (chatgpt.com WAF inspects it) + stainless family
    assert fwd.get('user-agent') == 'codex_cli_rs/0.9.0', 'real Codex UA must forward (not python-httpx)'
    assert 'x-stainless-lang' in fwd
    # arbitrary headers still stripped
    assert 'cookie' not in fwd and 'x-evil' not in fwd


def test_openai_chat_forwards_user_agent():
    fwd = {k.lower(): v for k, v in oa.fwd_headers_openai(
        _FakeReq({'authorization': 'Bearer t', 'user-agent': 'my-client/1', 'x-stainless-lang': 'py', 'cookie': 'no'})).items()}
    assert fwd.get('user-agent') == 'my-client/1'
    assert 'x-stainless-lang' in fwd
    assert 'cookie' not in fwd


# --- multi-signal Codex plan detection (replaces the fragile single-header discriminator) ---
def test_plan_detect_account_id():
    assert ep.is_codex_plan_request(_FakeHeaders({'chatgpt-account-id': 'acct', 'authorization': 'Bearer oauth'}))


def test_plan_detect_originator_only():
    # a plan request that dropped chatgpt-account-id but kept originator must STILL route to the ChatGPT backend
    assert ep.is_codex_plan_request(_FakeHeaders({'originator': 'codex_cli_rs', 'authorization': 'Bearer oauth'}))


def test_plan_detect_sentinel_only():
    assert ep.is_codex_plan_request(_FakeHeaders({'openai-sentinel-token': 'sent', 'authorization': 'Bearer oauth'}))


def test_plan_detect_api_key_is_not_plan():
    # a genuine Platform API-key request carries none of the plan markers -> must route to api.openai.com
    assert not ep.is_codex_plan_request(_FakeHeaders({'authorization': 'Bearer sk-platform-key', 'content-type': 'application/json'}))


def test_plan_detect_originator_case_insensitive():
    assert ep.is_codex_plan_request(_FakeHeaders({'originator': 'Codex_CLI_RS'}))
