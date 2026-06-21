# Contributing to OSSRedact

Thanks for your interest. OSSRedact is a local PII/secret redaction firewall; correctness of the redaction
path is the top priority, so changes there come with tests.

## Project layout

| Path | What it is |
|------|------------|
| `appliance/` | the egress proxy (`:8011`): field extraction, redact/rehydrate, SSE streaming, entity map, secrets floor, the console + settings/allowlist APIs |
| `gate/` | the NER gate service + the deterministic Tier-0 floor (`privacy_gate.py`) |
| `packages/redaction-core/` | the shared TypeScript core (Tier-0 detector, span/placeholder logic) -- published as `@ossredact/core` |
| `workbench/` | the desktop app: React document-redaction workbench + Firewall console, wrapped as a Tauri tray app |
| `training/`, `validation/` | model training + held-out evaluation |
| `deploy/` | systemd units + drift checks |

## Dev setup

**Python (appliance + gate):**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-test.txt   # torch-free test deps (incl. the FastAPI TestClient stack)
# Run the two domains in SEPARATE invocations: gate/ and appliance/ both ship a module named privacy_gate,
# so one interpreter collides on sys.modules['privacy_gate']. This is exactly what CI does.
python -m pytest gate/tests training/gen/tests training/tests/test_labeling.py validation/test_parity_check.py
python -m pytest appliance/tests
```

**TypeScript (core + workbench):**

```bash
cd packages/redaction-core && npm ci && npm run build && npm test
cd ../../workbench         && npm ci && npm run build && npm test
```

**The desktop app (optional, Tauri):** see `workbench/src-tauri/icons/README` and run `npm run app:dev`
(needs the Rust toolchain + your platform's webview deps).

## Before opening a PR

- **Tests pass:** the suites above are green. Add tests for any change to the redaction/floor path.
- **No em dashes:** the repo uses `--`, not the em-dash character (CI enforces this -- `git grep $'\u2014'`
  must be empty).
- **No real data:** examples, fixtures, and docs use synthetic values (e.g. `user@example.com`,
  `4111 1111 1111 1111`, RFC-5737 IPs). Never commit real PII, credentials, or internal infrastructure.
- **Redaction is fail-closed:** if you touch the proxy, preserve the prime directive -- on any uncertainty the
  body must not be forwarded unredacted. The deterministic floor must never be disableable.

## Commit + PR style

- Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) with a scope where it helps.
- Keep PRs focused. Describe what changed and how you verified it; link any issue.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
