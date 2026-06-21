<!-- Thanks for contributing to OSSRedact. Keep PRs focused; describe what changed and how you verified it. -->

## What & why

<!-- One or two sentences: what does this change, and why? Link any related issue. -->

## How verified

<!-- The commands you ran and what you saw. -->

- [ ] `pytest appliance gate` passes
- [ ] `npm test` passes in `packages/redaction-core` and `workbench`
- [ ] `npm run build` passes in `workbench` (and `redaction-core`)

## Checklist

- [ ] Added/updated tests for any change to the redaction or floor path
- [ ] No em dashes (`git grep $'\u2014'` is empty -- use `--`)
- [ ] No real PII / credentials / internal infrastructure (synthetic values only)
- [ ] Redaction stays **fail-closed**; the deterministic floor stays un-disableable
- [ ] Docs updated if behavior or install steps changed
