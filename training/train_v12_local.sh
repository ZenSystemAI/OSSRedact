#!/usr/bin/env bash
# Turnkey v12 fine-tune on the 5090 (plan 048): openai/privacy-filter base + public-data blend.
# Idempotent phases; each skips if its output exists. Re-run after any interruption.
#
#   [1] venv deps          [4] build stage-1/stage-2 mixes
#   [2] cache base model   [5] dry-run alignment check
#   [3] convert public data (network; ~1.4M rows streamed -- the long prep step)
#   [6] stage-1 train (broad)   [7] stage-2 train (adaptation, from stage-1 weights)
#
# VRAM: 1.5B full-FT bf16 + AdamW is UNVERIFIED on 32G until the first smoke; if step [6] OOMs,
# lower --bs and raise --accum (same effective batch), or fall back to GB10 (plan 048 §GPU).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$REPO/.venv-train"
PY="$VENV/bin/python"
BASE="openai/privacy-filter"
CONV="$REPO/datasets/public-cache/converted"
S1_DATA="$REPO/datasets/pii-merged-v12-stage1"
S2_DATA="$REPO/datasets/pii-merged-v12-stage2"
S1_OUT="$REPO/models/pii-gpu-opf-v12-stage1"
S2_OUT="$REPO/models/pii-gpu-opf-v12"
OURS="$REPO/datasets/pii-merged-v11r9c"
HOLDOUT="telecom_bill,insurance"   # generator-holdout = the v12 generalization gate (plan 048)
LOG="$REPO/training/v12-train.local.log"

echo "[1/7] deps in $VENV"
"$PY" -c "import torch, transformers, seqeval, datasets, accelerate" 2>/dev/null || \
  uv pip install --python "$PY" --index-strategy unsafe-best-match \
    --extra-index-url https://download.pytorch.org/whl/cu128 \
    torch "transformers>=5" seqeval numpy accelerate datasets huggingface_hub

echo "[2/7] cache base $BASE"
"$PY" - <<PY
from transformers import AutoTokenizer, AutoModelForTokenClassification
AutoTokenizer.from_pretrained("$BASE")
AutoModelForTokenClassification.from_pretrained("$BASE", num_labels=2, ignore_mismatched_sizes=True)
print("base cached")
PY

echo "[3/7] convert public datasets -> $CONV (skips existing)"
mkdir -p "$CONV"
declare -A SPLITS=( [ai4privacy]="train validation" [nemotron]="train test" \
                    [gretel]="train validation" [privy]="train validation" )
for src in ai4privacy nemotron gretel privy; do
  for split in ${SPLITS[$src]}; do
    out="$CONV/$src-$split.jsonl"
    if [ ! -s "$out" ]; then
      echo "  converting $src/$split (full split -- the 1M-row source takes a while)"
      "$PY" "$REPO/training/ingest/convert_public.py" --source "$src" --split "$split" --out "$out"
    fi
  done
done

echo "[4/7] build mixes"
[ -s "$S1_DATA/train.jsonl" ] || "$PY" "$REPO/training/ingest/build_mix_v12.py" --stage 1 \
    --public-dir "$CONV" --ours "$OURS" --out "$S1_DATA" --holdout-generators "$HOLDOUT"
[ -s "$S2_DATA/train.jsonl" ] || "$PY" "$REPO/training/ingest/build_mix_v12.py" --stage 2 \
    --public-dir "$CONV" --ours "$OURS" --out "$S2_DATA" --holdout-generators "$HOLDOUT"

echo "[5/7] dry-run alignment check (tokenizer offsets vs char labels)"
"$PY" "$REPO/training/train_suite.py" --base "$BASE" --data "$S1_DATA" --out /tmp/v12-dryrun --dry-run

if ! "$PY" -c "import torch; assert torch.cuda.is_available()" 2>/dev/null; then
  echo "CUDA not available -- prep done, reboot/driver-fix then re-run to train."; exit 0
fi

# Config from the 2026-07-04 timing matrix on the 5090 (20-step smoke each, same 32-row effective batch):
#   grad-ckpt on, bs8/accum4, 0 workers : 7.3 s/step  (76h/stage-1 -- the naive config)
#   no ckpt,     bs8/accum4, 0 workers : 5.6 s/step   (ckpt unneeded: bs16 peaks ~17G of 32G)
#   no ckpt,     bs16/accum2, 4 workers: 2.9 s/step   (<-- shipped; dataloader starvation was the rest)
#   no ckpt,     bs32/accum1           : OOM at 28.5G
echo "[6/7] stage-1 train (broad mix) -> $S1_OUT"
[ -s "$S1_OUT/model.safetensors" ] || \
  "$PY" "$REPO/training/train_suite.py" --base "$BASE" --data "$S1_DATA" --out "$S1_OUT" \
      --epochs 2 --bs 16 --accum 2 --workers 4 --lr 2e-5 --max-len 512 --bf16 --resume 2>&1 | tee -a "$LOG"

echo "[7/7] stage-2 train (adaptation, ours+wire-shaped) -> $S2_OUT"
[ -s "$S2_OUT/model.safetensors" ] || \
  "$PY" "$REPO/training/train_suite.py" --base "$S1_OUT" --data "$S2_DATA" --out "$S2_OUT" \
      --epochs 2 --bs 16 --accum 2 --workers 4 --lr 8e-6 --max-len 512 --bf16 --resume 2>&1 | tee -a "$LOG"

echo "DONE. Acceptance gates next (plan 048 §gates):"
echo "  GATE_DIR=gate GPU_GATE_MODEL=$S2_OUT GPU_GATE_VAL=datasets/pii-heldout-v11r5/test.jsonl \\"
echo "    GATE_DEVICE=cuda $PY validation/eval_labelaware.py"
echo "  + firewall stress + credential fuzz + $S1_DATA/generator_holdout.jsonl"
