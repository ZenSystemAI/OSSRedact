#!/usr/bin/env python3
"""Client compatibility profiles for the OSSRedact egress gateway.

This module is a pure, testable compatibility matrix. It does not read client
auth stores, inspect config files, open sockets, or proxy traffic. It records
the concrete setup shapes that let coding-agent clients route through
OSSRedact while keeping each client's own auth and billing path explicit.

The most important distinction is Codex:

* Codex with a Platform API key is already covered by `/v1/responses`.
* Codex with a ChatGPT/Codex plan must keep Codex-managed OpenAI auth. The
  recommended route uses a user-level provider with `requires_openai_auth`.
* If that redirect does not preserve the desired subscription path in a real
  login, the next path is an app-server bridge, not guessing private payloads.
"""
from dataclasses import dataclass
import json
from typing import Tuple


DEFAULT_GATEWAY_ORIGIN = "http://127.0.0.1:8011"
DEFAULT_HERMES_PROXY_ORIGIN = "http://127.0.0.1:8645"

ROUTE_ANTHROPIC_MESSAGES = "/v1/messages"
ROUTE_OPENAI_CHAT = "/v1/chat/completions"
ROUTE_OPENAI_RESPONSES = "/v1/responses"

BILLING_CHATGPT_PLAN = "chatgpt_plan"
BILLING_PLATFORM_API_KEY = "platform_api_key"
BILLING_CLIENT_PROVIDER = "client_provider_auth"
BILLING_HERMES_OAUTH = "hermes_oauth_proxy"

STATUS_SUPPORTED = "supported"
STATUS_EXISTING = "existing"
STATUS_PREFERRED = "preferred"
STATUS_SPIKE = "fixture_gated_spike"
STATUS_REPO_DOCUMENTED = "repo_documented"

DOC_OPENAI_CODEX_AUTH = "https://developers.openai.com/codex/auth"
DOC_OPENAI_CODEX_CONFIG = "https://developers.openai.com/codex/config-advanced"
DOC_OPENAI_CODEX_APP_SERVER = "https://developers.openai.com/codex/app-server"
DOC_OPENCODE_PROVIDERS = "https://opencode.ai/docs/providers/"
DOC_PI_MODELS = "local:@mariozechner/pi-coding-agent/docs/models.md"
DOC_OMP_MODELS_SCHEMA = "local:@oh-my-pi/pi-coding-agent/src/config/models-config-schema.ts"
DOC_HERMES_RUNTIME = "local:hermes_cli/runtime_provider.py"
DOC_HERMES_PROXY_HELP = "local:hermes proxy --help"


@dataclass(frozen=True)
class ClientCompatibilityProfile:
    client_id: str
    client_name: str
    status: str
    billing_mode: str
    auth_model: str
    gateway_route: str
    upstream_route: str
    config_scope: str
    setup_snippet: str
    verification: str
    notes: Tuple[str, ...]
    evidence: Tuple[str, ...]

    @property
    def uses_included_codex_plan(self):
        return self.billing_mode == BILLING_CHATGPT_PLAN

    @property
    def uses_platform_api_key_billing(self):
        return self.billing_mode == BILLING_PLATFORM_API_KEY


def gateway_origin(gateway=DEFAULT_GATEWAY_ORIGIN):
    return gateway.rstrip("/")


def gateway_v1(gateway=DEFAULT_GATEWAY_ORIGIN):
    base = gateway_origin(gateway)
    if base.endswith("/v1"):
        return base
    return base + "/v1"


def _json_snippet(obj):
    return json.dumps(obj, indent=2, sort_keys=False)


def _codex_plan_snippet(gateway):
    return """# User-level ~/.codex/config.toml only.
# Project .codex/config.toml cannot redirect credentials or providers.
model_provider = "ossredact_chatgpt_plan"

[model_providers.ossredact_chatgpt_plan]
name = "OSSRedact ChatGPT-plan bridge"
base_url = "{base_url}"
wire_api = "responses"
requires_openai_auth = true
""".format(base_url=gateway_v1(gateway))


def _codex_api_key_snippet(gateway):
    return """# User-level ~/.codex/config.toml only.
# Existing Platform API-key path. This uses standard API billing.
openai_base_url = "{base_url}"
""".format(base_url=gateway_v1(gateway))


def _opencode_openai_snippet(gateway):
    return _json_snippet({
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            "ossredact": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "OSSRedact proxy",
                "options": {
                    "baseURL": gateway_v1(gateway),
                },
                "models": {
                    "your-model-id": {
                        "name": "Your Model",
                    },
                },
            },
        },
    })


def _opencode_anthropic_snippet(gateway):
    return _json_snippet({
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            "ossredact-anthropic": {
                "npm": "@ai-sdk/anthropic",
                "name": "OSSRedact Anthropic proxy",
                "options": {
                    "baseURL": gateway_origin(gateway),
                },
                "models": {
                    "your-claude-model-id": {
                        "name": "Your Claude Model",
                    },
                },
            },
        },
    })


def _pi_models_json_snippet(gateway, api="openai-completions"):
    return _json_snippet({
        "providers": {
            "ossredact": {
                "baseUrl": gateway_v1(gateway) if api != "anthropic-messages" else gateway_origin(gateway),
                "api": api,
                "apiKey": "OSSREDACT_UPSTREAM_API_KEY",
                "models": [
                    {
                        "id": "your-model-id",
                        "name": "Your Model",
                    },
                ],
            },
        },
    })


def _omp_models_yaml_snippet(gateway, api="openai-completions"):
    base_url = gateway_v1(gateway) if api != "anthropic-messages" else gateway_origin(gateway)
    return """providers:
  ossredact:
    baseUrl: {base_url}
    api: {api}
    apiKey: OSSREDACT_UPSTREAM_API_KEY
    models:
      - id: your-model-id
        name: Your Model
""".format(base_url=base_url, api=api)


def _hermes_custom_snippet(gateway, api_mode="chat_completions"):
    return """# ~/.hermes/config.yaml
model:
  provider: custom
  model: your-model-id
  base_url: {base_url}
  api_mode: {api_mode}
  api_key: OSSREDACT_UPSTREAM_API_KEY
""".format(base_url=gateway_v1(gateway), api_mode=api_mode)


def _hermes_oauth_proxy_snippet(gateway, hermes_proxy):
    return """# Terminal 1: start Hermes' OAuth-backed OpenAI-compatible proxy.
hermes proxy start --provider nous --host 127.0.0.1 --port 8645

# Terminal 2: run OSSRedact in front of that local proxy.
export GATEWAY_OPENAI_UPSTREAM={hermes_proxy}
export GATEWAY_PORT=8011

# Point OpenAI-compatible clients at OSSRedact, not directly at Hermes.
base_url: {gateway_v1}
""".format(hermes_proxy=hermes_proxy.rstrip("/"), gateway_v1=gateway_v1(gateway))


def all_profiles(
    gateway=DEFAULT_GATEWAY_ORIGIN,
    hermes_proxy=DEFAULT_HERMES_PROXY_ORIGIN,
):
    """Return compatibility profiles for the named clients in the repo docs."""

    return (
        ClientCompatibilityProfile(
            client_id="codex_chatgpt_plan_responses_proxy",
            client_name="Codex CLI with ChatGPT/Codex plan",
            status=STATUS_PREFERRED,
            billing_mode=BILLING_CHATGPT_PLAN,
            auth_model="Codex ChatGPT sign-in or CODEX_ACCESS_TOKEN; OSSRedact never reads token stores",
            gateway_route=ROUTE_OPENAI_RESPONSES,
            upstream_route=ROUTE_OPENAI_RESPONSES,
            config_scope="user ~/.codex/config.toml",
            setup_snippet=_codex_plan_snippet(gateway),
            verification="Run a logged-in synthetic Codex prompt and confirm [egress:responses] redaction logs.",
            notes=(
                "This is the no-per-use Codex path the user asked for.",
                "Do not set CODEX_API_KEY, OPENAI_API_KEY, or env_key for this profile.",
                "Project .codex/config.toml cannot set provider or base URL redirects.",
                "If a real logged-in run does not route through this provider, use the app-server spike path.",
            ),
            evidence=(DOC_OPENAI_CODEX_AUTH, DOC_OPENAI_CODEX_CONFIG),
        ),
        ClientCompatibilityProfile(
            client_id="codex_api_key_responses_proxy",
            client_name="Codex CLI with Platform API key",
            status=STATUS_EXISTING,
            billing_mode=BILLING_PLATFORM_API_KEY,
            auth_model="Platform API key",
            gateway_route=ROUTE_OPENAI_RESPONSES,
            upstream_route=ROUTE_OPENAI_RESPONSES,
            config_scope="user ~/.codex/config.toml",
            setup_snippet=_codex_api_key_snippet(gateway),
            verification="Existing egress /v1/responses tests cover this path.",
            notes=(
                "This path is useful but not the requested no-per-use Codex plan answer.",
                "Keep it explicit so plan usage cannot silently fall back to API billing.",
            ),
            evidence=(DOC_OPENAI_CODEX_AUTH, DOC_OPENAI_CODEX_CONFIG),
        ),
        ClientCompatibilityProfile(
            client_id="codex_app_server_bridge_spike",
            client_name="Codex app-server bridge",
            status=STATUS_SPIKE,
            billing_mode=BILLING_CHATGPT_PLAN,
            auth_model="Codex app-server inherits local Codex auth",
            gateway_route="JSON-RPC app-server thread/turn text fields",
            upstream_route="Codex-controlled model dispatch",
            config_scope="generated Codex app-server schemas plus fixture tests",
            setup_snippet="""# Spike only. Generate schemas from the installed Codex version first.
codex app-server generate-json-schema --out ./schemas
codex app-server --listen ws://127.0.0.1:4500
""",
            verification="Not complete until schema-backed synthetic fixtures prove text-field interception.",
            notes=(
                "Use this only if the ChatGPT-plan provider redirect cannot preserve plan auth.",
                "Do not guess private ChatGPT backend envelopes.",
            ),
            evidence=(DOC_OPENAI_CODEX_APP_SERVER, DOC_OPENAI_CODEX_AUTH),
        ),
        ClientCompatibilityProfile(
            client_id="opencode_openai_compatible",
            client_name="opencode OpenAI-compatible provider",
            status=STATUS_SUPPORTED,
            billing_mode=BILLING_CLIENT_PROVIDER,
            auth_model="opencode provider credential from /connect or provider options",
            gateway_route=ROUTE_OPENAI_CHAT,
            upstream_route=ROUTE_OPENAI_CHAT,
            config_scope="opencode.json",
            setup_snippet=_opencode_openai_snippet(gateway),
            verification="Send a synthetic prompt and confirm [egress:openai] redaction logs.",
            notes=(
                "OpenCode documents baseURL customization and @ai-sdk/openai-compatible local providers.",
                "Use this for Chat Completions models. For Responses models, choose an OpenAI adapter that emits /responses.",
            ),
            evidence=(DOC_OPENCODE_PROVIDERS,),
        ),
        ClientCompatibilityProfile(
            client_id="opencode_anthropic_messages",
            client_name="opencode Anthropic provider",
            status=STATUS_SUPPORTED,
            billing_mode=BILLING_CLIENT_PROVIDER,
            auth_model="opencode provider credential from /connect or provider options",
            gateway_route=ROUTE_ANTHROPIC_MESSAGES,
            upstream_route=ROUTE_ANTHROPIC_MESSAGES,
            config_scope="opencode.json",
            setup_snippet=_opencode_anthropic_snippet(gateway),
            verification="Send a synthetic prompt and confirm [egress] redaction logs.",
            notes=(
                "The Anthropic adapter should point at the proxy root, not /v1.",
                "Do not use third-party subscription plugins that violate provider terms.",
            ),
            evidence=(DOC_OPENCODE_PROVIDERS,),
        ),
        ClientCompatibilityProfile(
            client_id="hermes_custom_openai_chat",
            client_name="Hermes custom OpenAI-compatible endpoint",
            status=STATUS_SUPPORTED,
            billing_mode=BILLING_CLIENT_PROVIDER,
            auth_model="Hermes custom provider api_key or environment variable",
            gateway_route=ROUTE_OPENAI_CHAT,
            upstream_route=ROUTE_OPENAI_CHAT,
            config_scope="~/.hermes/config.yaml",
            setup_snippet=_hermes_custom_snippet(gateway),
            verification="Run a synthetic Hermes prompt and confirm [egress:openai] redaction logs.",
            notes=(
                "Hermes supports model.base_url and explicit model.api_mode.",
                "Use api_mode: codex_responses to land on /v1/responses instead.",
            ),
            evidence=(DOC_HERMES_RUNTIME,),
        ),
        ClientCompatibilityProfile(
            client_id="hermes_oauth_local_proxy_upstream",
            client_name="Hermes OAuth proxy as OSSRedact upstream",
            status=STATUS_SUPPORTED,
            billing_mode=BILLING_HERMES_OAUTH,
            auth_model="Hermes proxy attaches OAuth credentials to upstream requests",
            gateway_route=ROUTE_OPENAI_CHAT,
            upstream_route=ROUTE_OPENAI_CHAT,
            config_scope="GATEWAY_OPENAI_UPSTREAM plus hermes proxy start",
            setup_snippet=_hermes_oauth_proxy_snippet(gateway, hermes_proxy),
            verification="Start Hermes proxy, run OSSRedact dry-run off, then confirm both proxies see one synthetic request.",
            notes=(
                "This preserves OAuth-provider billing while OSSRedact remains the client-facing redaction gate.",
                "Clients should point at OSSRedact; OSSRedact points upstream at Hermes' local proxy.",
            ),
            evidence=(DOC_HERMES_PROXY_HELP,),
        ),
        ClientCompatibilityProfile(
            client_id="pi_models_json_openai_chat",
            client_name="Pi custom provider",
            status=STATUS_SUPPORTED,
            billing_mode=BILLING_CLIENT_PROVIDER,
            auth_model="Pi models.json apiKey or existing provider auth",
            gateway_route=ROUTE_OPENAI_CHAT,
            upstream_route=ROUTE_OPENAI_CHAT,
            config_scope="~/.pi/agent/models.json",
            setup_snippet=_pi_models_json_snippet(gateway),
            verification="Select the configured model in pi and confirm [egress:openai] redaction logs.",
            notes=(
                "Pi custom models require baseUrl, api, apiKey, and models for non-built-in providers.",
                "Set api to anthropic-messages and baseUrl to the proxy root for /v1/messages.",
            ),
            evidence=(DOC_PI_MODELS,),
        ),
        ClientCompatibilityProfile(
            client_id="omp_models_yaml_openai_chat",
            client_name="Oh My Pi / omp custom provider",
            status=STATUS_SUPPORTED,
            billing_mode=BILLING_CLIENT_PROVIDER,
            auth_model="omp provider apiKey or auth gateway",
            gateway_route=ROUTE_OPENAI_CHAT,
            upstream_route=ROUTE_OPENAI_CHAT,
            config_scope="~/.omp config/model provider YAML",
            setup_snippet=_omp_models_yaml_snippet(gateway),
            verification="Select the configured model in omp and confirm [egress:openai] redaction logs.",
            notes=(
                "Installed omp schema accepts openai-completions, openai-responses, openai-codex-responses, and anthropic-messages.",
                "Use anthropic-messages with the proxy root when routing /v1/messages.",
            ),
            evidence=(DOC_OMP_MODELS_SCHEMA,),
        ),
    )


def get_profile(client_id, gateway=DEFAULT_GATEWAY_ORIGIN, hermes_proxy=DEFAULT_HERMES_PROXY_ORIGIN):
    for profile in all_profiles(gateway, hermes_proxy):
        if profile.client_id == client_id:
            return profile
    raise KeyError(client_id)


def profiles_for_client(client_name, gateway=DEFAULT_GATEWAY_ORIGIN, hermes_proxy=DEFAULT_HERMES_PROXY_ORIGIN):
    needle = client_name.strip().lower()
    return tuple(
        profile for profile in all_profiles(gateway, hermes_proxy)
        if needle in profile.client_id.lower() or needle in profile.client_name.lower()
    )


def recommended_codex_profile(
    want_included_chatgpt_plan=True,
    allow_platform_api_key=False,
    require_app_server=False,
    gateway=DEFAULT_GATEWAY_ORIGIN,
):
    if require_app_server:
        return get_profile("codex_app_server_bridge_spike", gateway)
    if want_included_chatgpt_plan:
        return get_profile("codex_chatgpt_plan_responses_proxy", gateway)
    if allow_platform_api_key:
        return get_profile("codex_api_key_responses_proxy", gateway)
    raise ValueError("No Codex profile matches the requested billing constraints")


def render_setup(client_id, gateway=DEFAULT_GATEWAY_ORIGIN, hermes_proxy=DEFAULT_HERMES_PROXY_ORIGIN):
    return get_profile(client_id, gateway, hermes_proxy).setup_snippet
