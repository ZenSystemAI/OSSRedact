# HuggingFace model cards

HF-ready model cards for the two published OSSRedact detection models. Each folder is a drop-in upload: its
`README.md` (the card, with HF YAML frontmatter) plus the chart PNGs it embeds.

| Folder | HF repo | Tier | Revision |
|--------|---------|------|----------|
| `ossredact-pii-large/` | `ZenSystemAI/ossredact-pii-large` | GPU / large (full precision) | `v11r9c` |
| `ossredact-pii-base/`  | `ZenSystemAI/ossredact-pii-base`  | CPU INT8 ONNX / in-browser   | `v11r9c` |

## Uploading

Upload each folder's `README.md` + chart PNGs alongside the weights, e.g.:

```bash
huggingface-cli upload ZenSystemAI/ossredact-pii-large model-cards/ossredact-pii-large/ . --repo-type model
huggingface-cli upload ZenSystemAI/ossredact-pii-base  model-cards/ossredact-pii-base/  . --repo-type model
```

The charts are bundled in each folder (rather than linked to the GitHub repo) so they render on HF regardless
of GitHub repo visibility. The large-tier numbers are sourced from `validation/RESULT-v11.md`; the base-tier
figures are the `v11r9c` re-eval (`eval_labelaware.py` + `bar_check_v11.py` on `datasets/pii-heldout-v11r5`),
not the stale v11r5 base rows in `RESULT-v11.md`. Numbers are kept in sync with the root `MODEL_CARD.md`.
