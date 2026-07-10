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

**Python (gate, training, validation, deployment contracts, and appliance):**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-test.txt
# Keep these in separate interpreter processes: gate/ and appliance/ both ship privacy_gate.py,
# and a combined run can cache the wrong module in sys.modules.
python -m pytest gate/tests training/gen/tests training/tests validation deploy/test_public_boundary.py deploy/test_repository_profiles.py deploy/test_install_units.py -v
python -m pytest appliance/tests -v
```

**TypeScript (core + workbench):**

```bash
( cd packages/redaction-core && npm ci && npm run build && npm test )
( cd workbench && npm ci && npm run build && npm test )
```

**Tauri shell (Rust):**

```bash
cargo test --manifest-path workbench/src-tauri/Cargo.toml
```

**The desktop app (optional, Tauri):** see `workbench/src-tauri/icons/README` and run `npm run app:dev`
(needs the Rust toolchain + your platform's webview deps).

## Before opening a PR

- **Tests pass:** the suites above are green. Add tests for any change to the redaction/floor path.
- **Public-boundary or hook changes:** run `python -m pytest deploy/test_public_boundary.py -v`, `bash -n deploy/pre-push-guard.sh`, and `bash -n deploy/install-git-hooks.sh`. `bash deploy/install-git-hooks.sh` is opt-in per clone, not a CI prerequisite.
- **Frozen CPU runtime lock changes:** run `python -m pip install pip-audit==2.10.1`, then `python -m pip_audit -r deploy/requirements-gate-cpu.lock --strict`.
- **Real model promotion:** `validation/` discovery includes `validation/test_run_v12_gates.py`, a hermetic shell-mechanics test with synthetic stubs, not a model, dataset, or log evaluation. Only a real V12 promotion is stop-gated: after `training/train_v12_local.sh`, run `validation/run_v12_gates.sh` against the candidate and promote only if every strict bar passes; fixture drift or a failed bar blocks promotion.
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
