# Comprehensive firewall stress test -- v11r6 + cue backstop (tuning-round spec)

> Measured 2026-06-18 through the **egress firewall** (the real surface: broad Tier-0 floor + deterministic
> secrets + neural gate + carrier-wrap + cue backstop), 52 cases x real-world agent-traffic forms (FR/EN:
> prose, JSON, CSV, headers, signatures, logs, file dumps). Leak metric is privacy-true: is the sensitive
> VALUE covered by ANY span (redacted), regardless of label. 100% synthetic values.

## Result: 39 COVERED / 3 PARTIAL / 10 LEAK -- and every miss is in TWO categories

| category | covered/partial/leak | verdict |
|---|---|---|
| email, payment_card, gov_id (SIN), iban, account, uuid, dob | all covered | deterministic floor solid |
| phone (paren / +1 / dotted), ip (v4), postal (incl. glued lowercase) | all covered | broad Tier-0 regex solid |
| secret (AWS / sk-ant / ghp / JWT / password) | all covered | deterministic secrets layer solid |
| person (bare, ALLCAPS, mailbox, headers, git, JSON, prose, title, initials) | 10/10 covered | model + cue backstop solid |
| **organization** | **1 / 1 / 8** | **BROKEN -- primary v11r7 target** |
| **address** | **4 / 2 / 2** | weak on EN / PO-box / directional / rural |

Note: a raw `/detect` probe (narrow gate floor only) over-reported phone/ip/postal/secret as leaks; the egress's
broad floor + secrets heal those. The genuine model gap is the **no-floor free-form categories** only.

## Tuning targets (feed `training/gen/augment_v11r7.py`)
**organization (highest priority -- 8/10 leak):**
- prose "je travaille chez {org}" / institutions: Hydro-Québec, Revenu Québec, SAAQ (acronym), Desjardins...
- corporate suffixes: `{name} inc./Ltd./Ltée/SENC/& Associés` (Béland & Associés inc. -> only "Béland" caught, as person)
- JSON `"company":"{org}"`, signature-block trailing org, "We signed with {org}", second org in a two-org sentence
- surname-based firm names get mistagged person -> include them labeled organization

**address (EN + structural forms):**
- EN abbreviations: `200 King St W` (St/Ave/Blvd/Rd + W/E/N/S) -> total miss
- PO box / `Case postale 6204`
- directional suffix dropped (`...René-Lévesque Ouest` -> "Ouest" leaks)
- rural route `601 rang Sainte-Catherine` -> mistagged person

**person:** already 25/25 via the deterministic cue backstop (`gate/privacy_gate.py cue_name_spans`); retrain to
harden the model itself on mailbox/header/git-author forms so it does not rely solely on the heuristic.

## Out of scope for retrain (already solid / deterministic)
phone, ip, postal, email, card, sin, iban, account, uuid, dob, secrets -- regex/checksum/entropy floor; do not
need NER changes. Keep them in the corpus as-is to preserve the measured 0-FP precision.
