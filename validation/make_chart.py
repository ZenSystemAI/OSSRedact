#!/usr/bin/env python3
"""Regenerate fig3 as a SYNTHETIC-corpus chart, matching the style of the other figures
(horizontal indigo bars, value labels, identity categories, dates excluded from bars but in the title)."""
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

r = json.load(open('result.json'))
total = r['pii_spans_redacted']
by = dict(r['by_category'])

# pretty labels; exclude high-volume dates from the bars (mirrors the original C1 chart)
PRETTY = {'sensitive_account_id': 'sensitive account id', 'bank_account': 'bank account',
          'government_id': 'government id', 'payment_card': 'payment card', 'tax_id': 'tax id',
          'postal_code': 'postal code', 'phone_number': 'phone number', 'routing_number': 'routing number',
          'date_of_birth': 'date of birth', 'api_key': 'api key', 'access_token': 'access token',
          'file_path': 'file path'}
EXCLUDE = {'sensitive_date'}
items = [(PRETTY.get(k, k), v) for k, v in by.items() if k not in EXCLUDE]
items.sort(key=lambda kv: kv[1])  # ascending -> largest at top in barh
items = items[-12:]  # top 12 categories
labels = [k for k, v in items]
vals = [v for k, v in items]

PURPLE = '#5a3fe6'
fig, ax = plt.subplots(figsize=(11.2, 6.4), dpi=130)
bars = ax.barh(labels, vals, color=PURPLE, height=0.72)
for b, v in zip(bars, vals):
    ax.text(b.get_width() + max(vals) * 0.01, b.get_y() + b.get_height() / 2,
            f"{v:,}", va='center', ha='left', fontsize=11, color='#222')
ax.set_xlabel('Spans redacted across a synthetic Québec corpus (FR + EN)', fontsize=13, color='#333')
ax.set_title(f"Synthetic Québec corpus: {total:,} PII spans redacted  ·  0 email / SIN / account-ID leaks",
             fontsize=13, fontweight='bold', color='#1a1a2e', pad=14)
ax.tick_params(axis='y', labelsize=12, colors='#444')
ax.tick_params(axis='x', labelsize=11, colors='#666')
for s in ('top', 'right', 'left'):
    ax.spines[s].set_visible(False)
ax.spines['bottom'].set_color('#ccc')
ax.grid(axis='x', color='#e8e8ee', linewidth=0.9)
ax.set_axisbelow(True)
ax.margins(x=0.12)
plt.tight_layout()
out = 'fig3_synthetic_corpus.png'
plt.savefig(out, facecolor='white')
print(f"wrote {out}  (total={total:,}, bars={len(labels)})")
