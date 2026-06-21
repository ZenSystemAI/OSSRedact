"""Tests for client compatibility profiles.

The profiles contain setup snippets only. They must stay synthetic and must not
include credential values.
"""
import importlib.util
import os


def _load_adapter():
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'client_compat_adapter.py'))
    spec = importlib.util.spec_from_file_location('client_compat_adapter_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_codex_plan_profile_is_default_no_per_use_path():
    adapter = _load_adapter()

    profile = adapter.recommended_codex_profile(want_included_chatgpt_plan=True)

    assert profile.client_id == 'codex_chatgpt_plan_responses_proxy'
    assert profile.uses_included_codex_plan
    assert not profile.uses_platform_api_key_billing
    assert profile.gateway_route == adapter.ROUTE_OPENAI_RESPONSES
    assert 'requires_openai_auth = true' in profile.setup_snippet
    assert 'wire_api = "responses"' in profile.setup_snippet
    assert 'env_key' not in profile.setup_snippet
    assert 'OPENAI_API_KEY' not in profile.setup_snippet
    assert 'CODEX_API_KEY' not in profile.setup_snippet


def test_codex_api_key_profile_is_explicitly_separate():
    adapter = _load_adapter()

    plan_profile = adapter.recommended_codex_profile(want_included_chatgpt_plan=True, allow_platform_api_key=True)
    api_profile = adapter.recommended_codex_profile(want_included_chatgpt_plan=False, allow_platform_api_key=True)

    assert plan_profile.client_id != api_profile.client_id
    assert api_profile.uses_platform_api_key_billing
    assert 'standard API billing' in api_profile.setup_snippet


def test_opencode_openai_profile_targets_chat_completions_base_url():
    adapter = _load_adapter()

    profile = adapter.get_profile('opencode_openai_compatible')

    assert profile.gateway_route == adapter.ROUTE_OPENAI_CHAT
    assert '"npm": "@ai-sdk/openai-compatible"' in profile.setup_snippet
    assert '"baseURL": "http://127.0.0.1:8011/v1"' in profile.setup_snippet


def test_opencode_anthropic_profile_targets_proxy_root():
    adapter = _load_adapter()

    profile = adapter.get_profile('opencode_anthropic_messages')

    assert profile.gateway_route == adapter.ROUTE_ANTHROPIC_MESSAGES
    assert '"npm": "@ai-sdk/anthropic"' in profile.setup_snippet
    assert '"baseURL": "http://127.0.0.1:8011"' in profile.setup_snippet
    assert '"baseURL": "http://127.0.0.1:8011/v1"' not in profile.setup_snippet


def test_hermes_profiles_cover_direct_custom_and_oauth_proxy_chain():
    adapter = _load_adapter()

    custom = adapter.get_profile('hermes_custom_openai_chat')
    oauth = adapter.get_profile('hermes_oauth_local_proxy_upstream')

    assert custom.gateway_route == adapter.ROUTE_OPENAI_CHAT
    assert 'provider: custom' in custom.setup_snippet
    assert 'api_mode: chat_completions' in custom.setup_snippet

    assert oauth.billing_mode == adapter.BILLING_HERMES_OAUTH
    assert 'hermes proxy start --provider nous' in oauth.setup_snippet
    assert 'GATEWAY_OPENAI_UPSTREAM=http://127.0.0.1:8645' in oauth.setup_snippet
    assert 'base_url: http://127.0.0.1:8011/v1' in oauth.setup_snippet


def test_pi_and_omp_profiles_use_installed_provider_schema_names():
    adapter = _load_adapter()

    pi = adapter.get_profile('pi_models_json_openai_chat')
    omp = adapter.get_profile('omp_models_yaml_openai_chat')

    assert pi.config_scope == '~/.pi/agent/models.json'
    assert '"baseUrl": "http://127.0.0.1:8011/v1"' in pi.setup_snippet
    assert '"api": "openai-completions"' in pi.setup_snippet
    assert '"apiKey": "OSSREDACT_UPSTREAM_API_KEY"' in pi.setup_snippet

    assert 'baseUrl: http://127.0.0.1:8011/v1' in omp.setup_snippet
    assert 'api: openai-completions' in omp.setup_snippet
    assert 'apiKey: OSSREDACT_UPSTREAM_API_KEY' in omp.setup_snippet


def test_gateway_v1_is_not_double_suffixed():
    adapter = _load_adapter()

    profile = adapter.get_profile('opencode_openai_compatible', gateway='http://127.0.0.1:8011/v1')

    assert profile.setup_snippet.count('http://127.0.0.1:8011/v1') == 1
    assert 'http://127.0.0.1:8011/v1/v1' not in profile.setup_snippet


def test_profiles_can_be_found_by_client_family():
    adapter = _load_adapter()

    codex = adapter.profiles_for_client('codex')
    hermes = adapter.profiles_for_client('hermes')
    opencode = adapter.profiles_for_client('opencode')

    assert {p.client_id for p in codex} >= {
        'codex_chatgpt_plan_responses_proxy',
        'codex_api_key_responses_proxy',
        'codex_app_server_bridge_spike',
    }
    assert {p.client_id for p in hermes} >= {
        'hermes_custom_openai_chat',
        'hermes_oauth_local_proxy_upstream',
    }
    assert {p.client_id for p in opencode} >= {
        'opencode_openai_compatible',
        'opencode_anthropic_messages',
    }


def test_setup_snippets_do_not_contain_secret_values():
    adapter = _load_adapter()

    combined = '\n'.join(profile.setup_snippet for profile in adapter.all_profiles())

    forbidden_fragments = (
        'sk-',
        'sess-',
        'Bearer ',
        'CODEX_ACCESS_TOKEN=',
        'OPENAI_API_KEY=',
        'ANTHROPIC_API_KEY=',
    )
    for fragment in forbidden_fragments:
        assert fragment not in combined
