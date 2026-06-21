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

- **Redaction bypasses** -- an input shape (request body, content-block type, encoding, structured field)
  where a PII value or secret reaches the upstream body unredacted.
- **Floor bypasses** -- any way a deterministic-floor category (secrets/API keys, payment cards, IBANs,
  bank accounts, government/tax IDs, date of birth) is forwarded in the clear, in *any* mode including `off`.
- **Rehydration leaks** -- a placeholder map exposed beyond the local machine, or cross-session/cross-tenant
  rehydration.
- **Control-surface exposure** -- the local console / settings / allowlist API reachable from off-host.

## Scope and threat model (be honest about what this is)

OSSRedact reduces accidental egress of private data; it is **not** a guarantee of zero leakage.

- The **deterministic Tier-0 floor** (regex + Luhn + entropy for secrets, cards, IBANs, government IDs,
  emails, IPs, file paths) is the hard, model-independent layer and is the strongest guarantee.
- The **NER model** raises coverage on top of the floor but recall is below 100%. `organization` and
  `address` have **no** Tier-0 floor and depend entirely on the model.
- Detection runs **locally**; no detection call leaves the machine. The control console and settings/allowlist
  APIs are **loopback-only**.
- Out of scope: the security of the upstream LLM provider, the OS/account the proxy runs under, and
  network interfaces you deliberately expose (`GATEWAY_HOST`).

See the README's *Limitations* section for the documented gaps.

## Supported versions

OSSRedact is pre-1.0 and ships from `main`. Security fixes land on `main`; please report against the latest
commit.
