# Security Policy

OSSRedact is a privacy tool: it sits between your local tooling and a cloud LLM and redacts PII and secrets
on the way out. Security reports are taken seriously -- a redaction bug can mean private data reaching a
third party.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the affected version/commit, and a minimal reproduction if you have one.

We aim to acknowledge a report within a few days and to work with you on a fix and coordinated disclosure.
Credit is given to reporters who want it.

If you cannot use GitHub's private reporting, open a regular issue that says only *"security issue, please
contact me privately"* (no details) and a maintainer will reach out.

## What to report

High-value reports for a redaction firewall include:

- **Redaction bypasses** -- an input shape (request body, content-block type, encoding, structured field) where a PII value or secret reaches the upstream body unredacted.
- **Deterministic-rule bypasses** -- a value that matches a shipped checksum, shape, contextual-cue, or recognized-secret rule but is forwarded in cleartext in a mode where that deterministic span must redact.
- **Rehydration leaks** -- a placeholder map exposed beyond the intended local/session boundary, or cross-session/cross-tenant rehydration.
- **Control-surface exposure** -- an off-device peer reaching a default-local control-plane route, bypassing header-only control-token checks, reading the live PII feed without authorization, or causing a state change without the CSRF header.
- **Remote-boundary confusion** -- a configuration in which `GATEWAY_CONTROL_TOKEN` is presented as protection for `/v1/*` relay routes, a gate token can be bypassed, or a reachable gate authentication error incorrectly triggers transport fallback.

## Scope and threat model (be honest about what this is)

OSSRedact reduces accidental egress of private data; it is **not** a guarantee of zero leakage.

- The **deterministic Tier-0 floor** is provenance-gated. It uses recognized secret patterns and filtered entropy, checksum validation, constrained shapes, and contextual cues. It is strongest when a concrete rule matches, not a promise that every opaque secret, identifier, or model label is covered.
- The deterministic `account_number` floor requires a recognized account cue and a shaped same-line value. Generic structured digit runs can be marked `sensitive_account_id`; neither behavior means every account or reference number is known.
- The **NER model** raises coverage but recall is below 100%. `organization` and `address` have **no** deterministic Tier-0 floor and remain model-owned categories. Their synthetic held-out results are measurements, not hard guarantees.
- Opaque Anthropic thinking blocks and OpenAI encrypted reasoning content must be forwarded byte-for-byte and are not re-scanned. The gateway does not independently prove they contain only placeholders; client-injected real data in such content can pass through.
- The default desktop and headless CPU routes run detection locally on-device. A deliberately configured remote gate is a separate detector-transport boundary and needs its own protected transport.
- The gate-served `/` and `/console` stay loopback-only. Control-plane routes are loopback-only by default, but `GATEWAY_CONTROL_TOKEN` can opt remote control in through the `X-OSSRedact-Control-Token` header, including fetch-based SSE. Remote use requires authenticated encrypted transport; the token is not URL-authentication and does not protect `/v1/*` relay traffic.
- Out of scope: the security of the upstream LLM provider, the OS/account the proxy runs under, and the security of network interfaces or remote transports an operator deliberately exposes.

See [README.md](README.md#limitations) and [QUICKSTART.md](QUICKSTART.md#5-gate-egress-and-control-tokens) for the operational limits and remote-boundary setup.

## Supported versions

OSSRedact is pre-1.0 and ships from `main`. Security fixes land on `main`; please report against the latest
commit.
