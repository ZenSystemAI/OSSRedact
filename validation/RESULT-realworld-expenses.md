# Real-document validation -- expense receipts/invoices

> **PII-free report.** Aggregate counts only: no values, no filenames. The corpus is REAL personal data
> (a private set of expense receipts/invoices, 2025-2026). Raw extracted text and per-document offset maps
> stay in a gitignored, out-of-repo work area (`~/expenses-eval/`, never committed). Reproduce with
> `validation/realworld_expenses.py` (Python floor + secrets) and the TS twin runner.

## Why this run exists

The synthetic corpus (`generate_corpus.py`) proves recall on *generated* PII. It cannot surface
distribution shift -- real layouts, real extraction noise, and real number shapes that collide with our
detectors. This run pushes 88 real documents (988,098 characters of `pdftotext -layout` output) through
the **always-on deterministic layers** and the **client-side TS Tier-0** twin. The neural tier (names,
addresses, merchants) is GPU-resident and is **not** exercised here; it is the separate headline run.

## 1. Deterministic floor (`validated_floor`) + secrets -- the never-leak backstop

| Label | Count |
|-------|-------|
| government_id (9-digit Luhn) | 85 |
| email | 72 |
| payment_card (15/16-digit Luhn) | 5 |
| **total** | **162** |

- **Self-leak check: 0 leaks** across all catastrophic categories (email, government_id, payment_card,
  iban, sensitive_account_id, secret). Every value the floor flags is absent, verbatim, from the redacted
  output. The never-leak property holds on real text.
- **76 / 88 docs (86%)** had at least one deterministic hit (the rest are image-heavy or text-sparse).
- Email parity with the TS twin is exact (72 = 72).

### Finding A -- `government_id` is mostly the Canadian Business Number, not a SIN (precision bug)

The floor's 9-digit + Luhn rule (`_SIN_CAND_RE`) is meant to catch the SIN. But the **Canadian Business
Number (BN)** is also 9 digits and **Luhn-valid by construction**, and it is printed publicly on every
Quebec/Canada invoice as the GST/HST and QST registration number. Classifying the 85 hits by context:

| Class | Count | Verdict |
|-------|-------|---------|
| Followed by a BN program-account suffix (`RT`/`RP`/`RC`+4 digits, e.g. `...RT0001`) | 40 | **Definitive BN** -- a SIN is never suffixed this way |
| Business-tax word cue adjacent (GST/HST/TPS/TVQ/QST) but no suffix | 26 | Near-certain BN |
| Bare 9-digit, no cue | 19 | Genuinely ambiguous |
| **Genuine SIN cue (NAS/SIN/assurance sociale) adjacent** | **0** | -- |

So ~78% of `government_id` hits on real expense docs are **merchant Business Numbers** -- public data,
not personal PII. Two harms: (1) **over-redaction** of public merchant tax numbers (degrades the
redact -> LLM -> rehydrate utility), and (2) **mislabeling** a business tax id as a personal `government_id`
(a Law 25 audit-accuracy problem). The synthetic corpus never exposed this because it does not inject BNs
as decoys.

**Fix applied (this branch):** a structural peek-ahead. When a 9-digit Luhn candidate is immediately
followed by a BN program-account suffix `(RT|RP|RC|RZ|RM|RR|RG)\s?\d{4}`, the floor does **not** emit it
as `government_id`. This is format-exact (consistent with the floor's "checksum/format-exact only"
doctrine), removes the 40 definitive BN false positives, and carries **zero SIN-leak risk** (a SIN cannot
be followed by an `RT0001` program account). Mirrored in the TS twin (`tier0.ts`).
The 26 cue-only and 19 bare cases are deliberately left as `government_id` (safe over-redaction; the
neural tier owns the precision call). Whether to also demote the 26 tax-cued cases is flagged for
operator + Codex review (it trades a sliver of never-leak guarantee for precision).

**Confirmed after the fix (re-run on the same corpus):** floor `government_id` 85 -> **45** (the 40
program-account BNs removed), self-leak check still **0**; TS twin `government_id` 119 -> **89**. All other
labels and email parity (72 = 72) unchanged. Gate-floor + appliance suites pass; workbench suite 110/110.

## 2. Client-side TS Tier-0 twin (`tier0Spans`) -- the no-model workbench detector

Run standalone on the same text (this is what the no-install workbench / hosted demo uses when "deep
detect" is off):

| Label | Count |
|-------|-------|
| sensitive_account_id | 3372 |
| phone_number | 2825 |
| sensitive_date | 604 |
| postal_code | 174 |
| government_id | 119 |
| payment_card | 23 |
| email | 72 |
| **total** | **7189** |

Spans/doc: median **15**, mean **82**, max **536**.

### Finding B -- the no-model client detector over-redacts numeric content on real invoices

`sensitive_account_id` (the 7-19 digit catch-all) and `phone_number` (any 3-3-4 grouping) dominate. On
invoices these are mostly **non-PII**: line-item codes, order/tracking numbers, quantities, SKUs, and
per-page repeated merchant phone/fax. Only ~1% of the account-id and phone hits sit next to a currency
amount, so the plan-014/022 amount-bleed guard is working (amounts are not being swallowed) -- the issue
is breadth, not the amount bug. A document blacked out at 82 spans average (one at 536) is poor utility
and a weak demo.

This is the **deliberate precision/recall trade** of a model-free detector: high recall (safe-error
over-redaction) at the cost of precision. It is **not a regression** and is not changed on this branch.
Recommendation for launch: keep the high-recall floor as the safety net, but in the workbench/demo (a)
make clear this is the no-model pass and (b) surface "enable deep detect (neural) to refine" -- the model
is what turns 82 noisy spans into the precise PII set. Tracked as a launch finding for operator decision;
no recall-cutting change should ship without sign-off.

## 3. Neural tier -- full P620 GPU gate (floor + xlm-roberta-large v11r5)

Operator-approved run of the live model gate (`qc-pii/pii-gpu-xlmr-large-v11r5`, fp16/CUDA) over all 88
docs via `/redact` (33s, 0 errors). Reproduce: `python3 validation/realworld_neural.py`. PII stays in
memory; only PII-free aggregates persist.

| Label | Count | | Label | Count |
|-------|-------|-|-------|-------|
| phone_number | 2769 | | postal_code | 159 |
| sensitive_date | 604 | | email | 94 |
| person | 372 | | address | 88 |
| account_number | 353 | | government_id | 40 |
| tax_id | 187 | | organization | 16 |
| sensitive_account_id | 161 | | username | 15 |
| payment_card | 13 | | iban | 9 |
| file_path | 3 | | date_of_birth | 1 |

**4884 spans across all 88 docs.** What the neural tier adds over the deterministic floor:
- **Model-owned PII the floor cannot get**: person 372, address 88, organization 16, username 15,
  date_of_birth 1 -- the dominant real-document categories. This is the end-to-end protection the floor
  alone (162 spans, 3 categories) cannot provide.
- **Finding A confirmed by the model itself**: `tax_id` 187 vs `government_id` 40. The model labels Business
  Numbers as `tax_id` and SINs as `government_id`. The floor fix on this branch aligns the deterministic
  backstop with that distinction (it no longer mislabels BNs as `government_id`).
- **iban 9**: the model flagged 9 IBANs the deterministic floor caught 0 of -- exactly the F14 gap (IBAN was
  model-only on the live gate). The F14 patch on this branch adds the mod-97 IBAN floor as a backstop.
  (Follow-up: spot-check whether those 9 are real IBANs vs model false positives.)

### Finding C (HIGH) -- repeated values leak the redacted output (positional redaction)

Round-trip self-leak: across the 88 docs, **20 redacted values survived verbatim in the gate's OWN
redacted output** (19 email + 1 tax_id), concentrated in 5 long / multi-page docs. Diagnosed mechanism
(PII-free occurrence counts): `duplicate_partial_miss` -- the same value repeats many times (per-page
footers, repeated headers, line items) and the gate masks only the **detected span positions**, not every
occurrence of the value. Worst case: one email occurred **51 times and 33 survived** (only 18 masked). The
gate `/redact` does positional replacement (`appliance/gate_service.py:91-101`); any occurrence the
detector misses on a long document survives. This is invisible on the synthetic corpus (single-occurrence
values) and is a direct hit on the "no data exposed" promise for real multi-page documents.

**Fix -- workbench DONE on this branch; gate-side still gated.** The fix is to mask EVERY verbatim
occurrence of each ALREADY-DETECTED value ("sweep known values"). The naive version is fragile (a 7-digit
account value is a substring of an 8-digit number; a name is a substring of a longer word), so the sweep is
**token-boundary-aware** (`(?<!TOK)value(?!TOK)`, `TOK = [\p{L}\p{N}\p{M}_]`), runs only on the literal gaps
between placeholders (never rewrites a placeholder), and uses a single combined-alternation pass so an
earlier replacement cannot cascade into a later one. Implemented in the workbench `sweepKnownValues` +
wired into `redactedText` and the batch text export; **Codex 5.5 xhigh reviewed it across 3 rounds** (it
caught a placeholder-corruption bug and a same-pass cascade bug -- both fixed) -> SHIP. The workbench
office/xlsx/PDF exports were already safe (fail-closed verify). **REMAINING (operator-gated):** the same
boundary-aware sweep (or a fail-closed re-scan) must be added to the live gate `/redact` and redeployed --
that is where the measured leak lives. Tracked as LAUNCH-CHECKLIST item 1b.

## 4. What is NOT covered here

- **Image/scanned pages** -- text extraction sees no PII inside rasterized regions; the workbench's manual
  region-box flow (PageView) covers those, and is out of scope for a text-layer harness.

## Reproduce

```bash
# extract (out-of-repo, gitignored): pdftotext -layout each PDF to ~/expenses-eval/text/exp_NNN.layout.txt
python3 validation/realworld_expenses.py            # floor + secrets, writes per-doc offsets + auto summary
node --experimental-strip-types ~/expenses-eval/run_tier0.ts   # TS twin
python3 validation/realworld_neural.py              # full P620 GPU gate (floor + neural), PII-free aggregates
```
