#!/usr/bin/env python3
"""Regenerate the README benchmark charts with OSSRedact branding + the brand teal palette.

fig5 (vs Presidio) and fig1 (recall by tier) were originally rendered with a pre-rebrand
title/legend and an indigo palette. This rebuilds both from the published figures (README.md /
MODEL-RESULTS.md, the historical v6/v7 sets) so the public charts read "OSSRedact" and match the
ZenSystem teal. White facecolor, no top/right spines, light grid, value labels -- same visual register
as the existing figures. Output dir defaults to ./charts (override with argv[1]).
"""
import sys, os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else 'charts'
os.makedirs(OUT, exist_ok=True)

# ZenSystem brand palette (readable on white; labels stay dark and off-bar)
TEAL = '#3AAE9F'        # OSSRedact / always-on base tier
TEAL_DEEP = '#1F7A6E'   # GPU large tier
GREY = '#64748B'        # comparison / Presidio
GREY_LT = '#9AA6B2'     # distilbert tier
INK = '#1a1a2e'

plt.rcParams['font.family'] = 'DejaVu Sans'


def _style(ax):
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    ax.spines['left'].set_color('#ccc')
    ax.spines['bottom'].set_color('#ccc')
    ax.grid(axis='y', color='#e8e8ee', linewidth=0.9)
    ax.set_axisbelow(True)


# ---- fig5: OSSRedact vs Microsoft Presidio (Quebec FR/EN PII) ----
sets = ['ALL-CAPS gate', 'v6 val', 'canonical']
ours = [0.955, 0.990, 0.986]
presidio = [0.779, 0.759, 0.798]
x = np.arange(len(sets))
w = 0.38
fig, ax = plt.subplots(figsize=(10.5, 6.0), dpi=130)
b1 = ax.bar(x - w / 2, ours, w, label='OSSRedact (FR/EN)', color=TEAL)
b2 = ax.bar(x + w / 2, presidio, w, label='Microsoft Presidio (EN+FR lg)', color=GREY)
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.012, f"{b.get_height():.3f}",
                ha='center', va='bottom', fontsize=11, color='#222')
ax.set_ylim(0, 1.12)
ax.set_yticks(np.arange(0, 1.01, 0.2))
ax.set_ylabel('Recall (leak prevention)', fontsize=13, color='#333')
ax.set_xticks(x); ax.set_xticklabels(sets, fontsize=12, color='#444')
ax.set_title('OSSRedact vs Microsoft Presidio: Québec FR/EN PII',
             fontsize=15, fontweight='bold', color=INK, pad=14)
ax.legend(loc='upper center', ncol=2, frameon=False, fontsize=12, bbox_to_anchor=(0.5, 1.0))
_style(ax)
plt.tight_layout()
plt.savefig(os.path.join(OUT, 'fig5_vs_presidio.png'), facecolor='white')
plt.close(fig)

# ---- fig1: OSSRedact recall by tier (FR/EN, leak-prevention metric) ----
groups = ['ALL-CAPS gate', 'tabular test', 'v6 val', 'canonical']
distil = [0.923, 0.938, 0.978, 0.987]
base = [0.955, 0.968, 0.990, 0.986]
large = [0.955, 0.968, 0.990, 0.986]
x = np.arange(len(groups))
w = 0.26
fig, ax = plt.subplots(figsize=(11.5, 6.0), dpi=130)
series = [('CPU distilbert', distil, GREY_LT), ('NPU xlm-r-base', base, TEAL),
          ('GPU xlm-r-large', large, TEAL_DEEP)]
for i, (lab, vals, col) in enumerate(series):
    bars = ax.bar(x + (i - 1) * w, vals, w, label=lab, color=col)
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.0012, f"{b.get_height():.3f}",
                ha='center', va='bottom', fontsize=9.5, color='#333')
ax.set_ylim(0.88, 1.00)
ax.set_ylabel('Recall (leak prevention)', fontsize=13, color='#333')
ax.set_xticks(x); ax.set_xticklabels(groups, fontsize=12, color='#444')
ax.set_title('OSSRedact recall by tier: FR/EN, leak-prevention metric',
             fontsize=15, fontweight='bold', color=INK, pad=14)
ax.legend(loc='lower center', ncol=3, frameon=False, fontsize=12, bbox_to_anchor=(0.5, -0.16))
_style(ax)
plt.tight_layout()
plt.savefig(os.path.join(OUT, 'fig1_recall_by_tier.png'), facecolor='white', bbox_inches='tight')
plt.close(fig)

print(f"wrote fig5_vs_presidio.png + fig1_recall_by_tier.png to {OUT}/")
