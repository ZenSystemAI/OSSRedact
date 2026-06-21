#!/usr/bin/env python3
"""v11r9c headline chart: closing the organization + address firewall leak.

The prior shipped model (v11r5/v11r6) leaked organizations and addresses in structural forms (org recall ~0.10,
address ~0.60) -- the last detection gap. v11r9c closes it (org 1.00, address 0.95 on the synthetic held-out
corpus) while *improving* sensitive_account_id recall. The honest cost is more over-redaction on digit-ID-shaped
tokens (clean false-positives 12 -> 34) -- the SAFE failure direction (over-redaction never leaks). This figure
is the launch visual for that trade. Brand palette matches make_charts_branded.py. Output dir defaults to ./charts.
"""
import sys, os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else 'charts'
os.makedirs(OUT, exist_ok=True)

TEAL = '#3AAE9F'
TEAL_DEEP = '#1F7A6E'
GREY = '#9AA6B2'
INK = '#1a1a2e'
plt.rcParams['font.family'] = 'DejaVu Sans'


def _style(ax):
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    ax.spines['left'].set_color('#ccc')
    ax.spines['bottom'].set_color('#ccc')
    ax.grid(axis='y', color='#e8e8ee', linewidth=0.9)
    ax.set_axisbelow(True)


# Recall (leak prevention) on the structural-form synthetic held-out corpus.
cats = ['Organization', 'Address']
prior = [0.10, 0.60]    # v11r5 / v11r6 -- the firewall gap
v11r9c = [1.00, 0.95]   # v11r9c -- closed
x = np.arange(len(cats))
w = 0.38

fig, ax = plt.subplots(figsize=(10.5, 6.2), dpi=130)
b1 = ax.bar(x - w / 2, prior, w, label='Prior model (v11r5/r6)', color=GREY)
b2 = ax.bar(x + w / 2, v11r9c, w, label='v11r9c (shipping)', color=TEAL_DEEP)
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.015, f"{b.get_height():.2f}",
                ha='center', va='bottom', fontsize=12, color='#222')
# leak arrows
for i in range(len(cats)):
    ax.annotate('', xy=(x[i] + w / 2, v11r9c[i] - 0.02), xytext=(x[i] - w / 2, prior[i] + 0.06),
                arrowprops=dict(arrowstyle='-|>', color=TEAL, lw=1.6, alpha=0.7))
ax.set_ylim(0, 1.18)
ax.set_yticks(np.arange(0, 1.01, 0.2))
ax.set_ylabel('Recall  (leak prevention)', fontsize=13, color='#333')
ax.set_xticks(x); ax.set_xticklabels(cats, fontsize=13, color='#444')
ax.set_title('OSSRedact v11r9c: closing the organization + address leak',
             fontsize=15, fontweight='bold', color=INK, pad=16)
ax.legend(loc='upper right', ncol=2, frameon=False, fontsize=12, bbox_to_anchor=(1.0, 1.04))
ax.text(0.5, -0.155,
        'Synthetic held-out corpus. Cost of the gain: clean false-positives 12 -> 34 '
        '-- more over-redaction on ID-shaped numbers, the safe direction (over-redaction never leaks).',
        transform=ax.transAxes, ha='center', va='top', fontsize=10.5, color='#666')
_style(ax)
plt.tight_layout()
plt.savefig(os.path.join(OUT, 'fig_v11r9c_org_address.png'), facecolor='white', bbox_inches='tight')
plt.close(fig)
print(f"wrote fig_v11r9c_org_address.png to {OUT}/")
