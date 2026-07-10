<!-- Thanks for contributing to OSSRedact. Keep PRs focused; describe what changed and how you verified it. -->

## What & why

<!-- One or two sentences: what does this change, and why? Link any related issue. -->

## How verified

<!-- Run applicable commands from the repository root and record their results. -->

- [ ] `( cd packages/redaction-core && npm ci && npm run build && npm test )` passes
- [ ] `( cd workbench && npm ci && npm run build && npm test )` passes
- [ ] `python -m pytest gate/tests training/gen/tests training/tests validation deploy/test_public_boundary.py deploy/test_repository_profiles.py deploy/test_install_units.py -v` passes
- [ ] `python -m pytest appliance/tests -v` passes in a separate interpreter process from the preceding Python command
- [ ] `cargo test --manifest-path workbench/src-tauri/Cargo.toml` passes

## Checklist

- [ ] Added/updated tests for any change to the redaction or floor path
- [ ] If public-boundary or hook files changed: `python -m pytest deploy/test_public_boundary.py -v`, `bash -n deploy/pre-push-guard.sh`, and `bash -n deploy/install-git-hooks.sh` pass. `bash deploy/install-git-hooks.sh` is opt-in per clone, not a CI prerequisite.
- [ ] If `deploy/requirements-gate-cpu.lock` changed: `python -m pip install pip-audit==2.10.1 && python -m pip_audit -r deploy/requirements-gate-cpu.lock --strict` passes.
- [ ] If this is a real model promotion: after `training/train_v12_local.sh`, the stop-gated V12 `validation/run_v12_gates.sh` procedure ran against the candidate and every strict bar passed. Fixture drift or a failed bar blocks promotion. `validation/test_run_v12_gates.py` is a hermetic shell-mechanics test only, not a real model evaluation.
- [ ] No em dashes (`git grep $'\u2014'` is empty -- use `--`)
- [ ] No real PII / credentials / internal infrastructure (synthetic values only)
- [ ] Redaction stays **fail-closed**; the deterministic floor stays un-disableable
- [ ] Docs updated if behavior or install steps changed
