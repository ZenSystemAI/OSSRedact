---
license: mit
language:
  - fr
  - en
library_name: transformers
pipeline_tag: token-classification
base_model: FacebookAI/xlm-roberta-large
tags:
  - pii
  - redaction
  - privacy
  - ner
  - token-classification
  - french
  - quebec
  - gdpr
  - law-25
---

# OSSRedact PII NER -- xlm-roberta-large (GPU tier)

![OSSRedact PII (large) -- bilingual FR/EN PII + secrets detection, on-device](banner.png)

**A bilingual (French-Québec + English) PII / secrets token-classifier** -- the high-capacity detection model
behind [OSSRedact](https://github.com/ZenSystemAI/OSSRedact), a local privacy gateway that redacts private data
before it reaches a cloud LLM and rehydrates it on the reply.

Shipping revision: **`v11r9c`**. The smaller always-on tier is
[`ZenSystemAI/ossredact-pii-base`](https://huggingface.co/ZenSystemAI/ossredact-pii-base) (dynamic-INT8 ONNX, also the
in-browser tier).

![v11r9c closes the organization + address leak](fig_v11r9c_org_address.png)

![OSSRedact vs Microsoft Presidio on Québec FR/EN PII](fig5_vs_presidio.png)

*Top: the v11r9c gain on the synthetic held-out corpus. Bottom: a historical (v6/v7) recall comparison vs
Microsoft Presidio on Québec FR/EN PII -- OSSRedact wins recall by 17-23 points with far fewer false positives.*

## What it is

A `xlm-roberta-large` token classifier fine-tuned to tag **20 PII / secret entity types** in realistic French-
Québec and English documents. It is the GPU/large detection tier of OSSRedact; in production it runs **inside**
the OSSRedact gateway, which pairs it with a deterministic Tier-0 floor (regex + Luhn + entropy) and AES-GCM
session rehydration. The model runs **locally on-device** -- no detection call leaves the machine.

The bilingual Québec-French focus is the differentiator: general English-first PII detectors miss FR structure
(NEQ, RAMQ, SIN, FR letterhead, accented ALL-CAPS names).

## Labels (20)

`account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`,
`iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`,
`secret`, `sensitive_account_id`, `tax_id`, `username` (41 BIO label ids).

## Intended use

- **Primary:** the detection tier inside the OSSRedact gateway (redact-on-egress / rehydrate-on-response for
  cloud LLM traffic), or any local PII-redaction pipeline.
- **Also:** document de-identification, DLP, privacy review of FR/EN text.

> **Use it with a deterministic floor.** As a standalone NER model, recall is below 100% and `organization`
> and `address` have **no** fallback. OSSRedact gets its hard guarantee from a Tier-0 floor (secrets, payment
> cards via Luhn, IBANs, government IDs, emails, IPs, file paths) that runs *independently* of this model. Do
> not rely on the model alone for the catastrophic categories.

### Quick start

```python
from transformers import AutoTokenizer, AutoModelForTokenClassification
import torch

tok = AutoTokenizer.from_pretrained("ZenSystemAI/ossredact-pii-large", revision="v11r9c")
model = AutoModelForTokenClassification.from_pretrained("ZenSystemAI/ossredact-pii-large", revision="v11r9c").eval()

text = "Contactez Marie-Eve Tremblay au 514-555-0188; NAS 046 454 286."
enc = tok(text, return_offsets_mapping=True, return_tensors="pt")
offsets = enc.pop("offset_mapping")[0].tolist()
with torch.no_grad():
    pred = model(**enc).logits[0].argmax(-1).tolist()
for (s, e), p in zip(offsets, pred):
    lab = model.config.id2label[p]
    if s != e and lab != "O":
        print(f"{text[s:e]!r:24} -> {lab}")
```

## Training data

A **100% synthetic** French-Québec + English corpus (bank statements, financing forms, email threads, CSV
exports, `.env` files, code, KYC/tax/SAAQ/RAMQ documents). Every name, SIN, account, card, and secret is
fabricated, so the corpus can be regenerated and re-run anywhere with no real-data exposure. It deliberately
includes adversarial cases (ALL-CAPS, NBSP-separated IDs, mixed FR/EN, long unbroken lines, look-alike decoys,
names glued into code identifiers). The corpus is cumulative across the v11 error-mining rounds (base + the
structural-name and organization/address augmentations).

## Evaluation

Measured on a synthetic held-out corpus (7,498 rows, 0 train overlap, unseen document structures). The privacy
metric is **full-stack catastrophic DETECTION recall** -- any detected span is redacted regardless of which
label it gets, so an intra-catastrophic mislabel is a redaction, not a leak. `clean_fp` is over-redaction count
on no-PII rows.

| tier | catastrophic full-stack DETECTION | all-label recall | precision | clean_fp |
|------|-----------------------------------|------------------|-----------|----------|
| **GPU / large (v11r9c)** | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 |

All-label F1 0.9742. Of the 13 catastrophic categories, email / iban / secret / password / file_path / tax_id /
card_expiry / card_cvv / government_id / postal_code / date_of_birth / ip_address / payment_card all detect at
**1.000**; `person` 0.9946 (precision 0.9999), `sensitive_account_id` 0.9993. **Organization 1.00, address
0.95** (v11r9c closed the structural-form leak the prior revision had: organization ~0.10 -> 1.00, address
~0.60 -> 0.95). FR is not weaker than EN. The cost of the org/address fix is more over-redaction on digit-ID-
shaped tokens (clean_fp 12 -> 34) -- the safe failure direction (over-redaction never leaks).

Training recipe: batch size 8, learning rate 2e-5, max length 512, 3 epochs, `metric_for_best_model=cat_f1`
(checkpoint maximizes recall on the catastrophic-leak labels). 559 M params.

## Limitations

- Trained and validated entirely on **synthetic Québec** data; broader real-world domains are future work.
- **French and English only** by design.
- `organization` and `address` have **no deterministic floor** -- they rely entirely on this model (well-covered
  on the synthetic corpus, but model-dependent, not a hard guarantee).
- Identifier coverage targets **Canadian / Québec** formats (SIN, RAMQ, NEQ, postal codes). Foreign formats
  (US ZIP, Brazilian CPF) are not specifically targeted.
- Full names glued into code identifiers (camelCase / snake_case) are under-detected.
- Recall is below 100%; use within OSSRedact's deterministic floor for the catastrophic categories.

## License & links

MIT. Part of [OSSRedact](https://github.com/ZenSystemAI/OSSRedact) by ZenSystemAI. The version label `v11rN`
is the weight revision (an HF revision tag), not part of the repo id.
