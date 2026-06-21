---
license: mit
language:
  - fr
  - en
library_name: transformers.js
pipeline_tag: token-classification
base_model: FacebookAI/xlm-roberta-base
tags:
  - pii
  - redaction
  - privacy
  - ner
  - token-classification
  - french
  - quebec
  - onnx
  - int8
  - gdpr
  - law-25
---

# OSSRedact PII NER -- xlm-roberta-base (CPU / in-browser tier)

![OSSRedact PII (base) -- in-browser bilingual FR/EN PII + secrets detection](banner.png)

**A bilingual (French-Québec + English) PII / secrets token-classifier**, dynamic-INT8 ONNX -- the always-on
detection model behind [OSSRedact](https://github.com/ZenSystemAI/OSSRedact), a local privacy gateway that
redacts private data before it reaches a cloud LLM and rehydrates it on the reply.

Shipping revision: **`v11r9c`** (carries the cumulative organization/address augmentation; address recall is now
~0.93 on this tier). The higher-capacity tier is
[`ZenSystemAI/ossredact-pii-large`](https://huggingface.co/ZenSystemAI/ossredact-pii-large).

![OSSRedact vs Microsoft Presidio on Québec FR/EN PII](fig5_vs_presidio.png)

![Recall by tier](fig1_recall_by_tier.png)

*OSSRedact recall vs Microsoft Presidio (historical v6/v7 sets), and recall by tier. The base model nearly
matches the large model on recall (trailing by ~1 point on overall recall) at roughly 4x lower latency -- which
is why it is the always-on tier.*

## What it is

A `xlm-roberta-base` token classifier fine-tuned to tag **20 PII / secret entity types** in realistic French-
Québec and English documents, exported to **dynamic-INT8 ONNX (~277 MB)** for CPU (onnxruntime) and **in-browser**
(transformers.js / onnxruntime-web) inference. The carded numbers below are the fp32 `v11r9c` reference; the
shipped artifact is the **per-channel dynamic INT8** export (WASM-native). v11r9c's org/address augmentation
sharpened the boundaries, so the INT8 lands at pii_argmax 0.967 (cosine 0.997, faithful) -- the parity bar is
0.965 for this reason: ~62% of the token-flips are on floor-protected types the deterministic Tier-0 layer
redacts regardless of the model, and person (the highest-frequency no-floor type) is barely affected.
It is the always-on detection tier of OSSRedact; in production it
runs **inside** the OSSRedact gateway alongside a deterministic Tier-0 floor. Detection runs **locally** -- no
call leaves the machine; in the browser, the document never leaves the page.

The bilingual Québec-French focus is the differentiator: general English-first PII detectors miss FR structure
(NEQ, RAMQ, SIN, FR letterhead, accented ALL-CAPS names).

## Labels (20)

`account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`,
`iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`,
`secret`, `sensitive_account_id`, `tax_id`, `username` (41 BIO label ids).

## Intended use

- **Primary:** the always-on detection tier inside the OSSRedact gateway (CPU), and the in-browser redaction
  workbench (transformers.js).
- **Also:** on-device / edge PII detection where a ~277 MB INT8 model and CPU latency matter.

> **Use it with a deterministic floor.** As a standalone NER model, recall is below 100%. On this base tier
> `address` recall is now ~0.93 (no longer weak), but `organization` coverage may still trail the large tier --
> use the [large tier](https://huggingface.co/ZenSystemAI/ossredact-pii-large) when organization recall matters.
> OSSRedact's hard guarantee for the catastrophic categories (secrets, cards via Luhn, IBANs, government IDs,
> emails, IPs, file paths) comes from a Tier-0 floor that runs *independently* of this model.

### Quick start (browser, transformers.js)

```js
import { pipeline } from '@huggingface/transformers'
// dtype:'int8' loads onnx/model_int8.onnx -- this repo ships INT8 only (the WASM-native browser format)
const ner = await pipeline('token-classification', 'ZenSystemAI/ossredact-pii-base', { dtype: 'int8' })
const out = await ner('Contactez Marie-Eve Tremblay au 514-555-0188; NAS 046 454 286.')
// out: [{ entity, score, word, start, end }, ...]  -- the document never leaves the page
```

### Quick start (Python, onnxruntime via optimum)

```python
from optimum.onnxruntime import ORTModelForTokenClassification
from transformers import AutoTokenizer, pipeline

tok = AutoTokenizer.from_pretrained("ZenSystemAI/ossredact-pii-base")
# the repo ships INT8 only (model.int8.onnx at the root); name it explicitly
model = ORTModelForTokenClassification.from_pretrained("ZenSystemAI/ossredact-pii-base", file_name="model.int8.onnx")
ner = pipeline("token-classification", model=model, tokenizer=tok)
print(ner("Reçu de la Caisse Desjardins; IBAN GB82 WEST 1234 5698 7654 32."))
```

## Training data

A **100% synthetic** French-Québec + English corpus (bank statements, financing forms, email threads, CSV
exports, `.env` files, code, KYC/tax/SAAQ/RAMQ documents). Every name, SIN, account, card, and secret is
fabricated. It deliberately includes adversarial cases (ALL-CAPS, NBSP-separated IDs, mixed FR/EN, long unbroken
lines, look-alike decoys). Same corpus and recipe as the large tier; this is the `v11r9c` revision, trained on the
cumulative corpus including the organization/address augmentation.

## Evaluation

Synthetic held-out corpus (7,498 rows, 0 train overlap). Privacy metric = full-stack catastrophic DETECTION
recall; `clean_fp` = over-redaction on no-PII rows.

| tier | catastrophic full-stack DETECTION | all-label recall | precision | clean_fp |
|------|-----------------------------------|------------------|-----------|----------|
| **CPU / base (v11r9c)** | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 |

The base model nearly matches the large model on overall recall (trailing by ~1 point: 0.9777 vs 0.9882) at
~4x lower latency -- the reason it is the always-on tier. `address` recall is now ~0.93 here vs 0.95 on large;
`organization` coverage may still trail the large tier, so use the
[large tier](https://huggingface.co/ZenSystemAI/ossredact-pii-large) when organization recall matters.

Training recipe: `xlm-roberta-base` (277 M), batch size 8, learning rate 2e-5, max length 512, 3 epochs,
`metric_for_best_model=cat_f1`. Figures above are the fp32 `v11r9c` reference; the shipped artifact is the
per-channel dynamic-INT8 ONNX (~277 MB), pii_argmax 0.967 vs fp32 (parity bar 0.965 -- see the model card's
INT8 note and validation/RESULT-base-int8-parity-v11r9c.md).

## Limitations

- Trained and validated entirely on **synthetic Québec** data; broader real-world domains are future work.
- **French and English only** by design.
- On this base tier, **`organization` coverage may still trail the large tier** (`address` recall is now ~0.93,
  no longer weak) -- use the large tier when organization recall matters, and in all cases pair with OSSRedact's
  deterministic floor for the catastrophic categories.
- Identifier coverage targets **Canadian / Québec** formats. Foreign formats (US ZIP, Brazilian CPF) are not
  specifically targeted.
- Recall is below 100%; this model is one layer of a redaction system, not a standalone guarantee.

## License & links

MIT. Part of [OSSRedact](https://github.com/ZenSystemAI/OSSRedact) by ZenSystemAI. The version label `v11rN`
is the weight revision (an HF revision tag), not part of the repo id.
