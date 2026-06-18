#!/usr/bin/env bash
# Turnkey local fine-tune of v11r6 on the 5090 (plan 026 option B).
# Idempotent: builds the venv + caches the base model (GPU-independent prep), then trains IF CUDA is up.
# If CUDA is down (driver/library mismatch -> needs a reboot to load the matching kernel module), it does
# the prep and stops with instructions. Re-run after reboot to train (prep is cached -> fast).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$REPO/.venv-train"
OUT="$REPO/models/pii-gpu-xlmr-large-v11r6"
DATA="$REPO/datasets/pii-merged-v11r6"
LOG="$REPO/training/v11r6-train.local.log"

echo "[1/4] venv ($VENV) with torch cu128 (Blackwell sm_120) + transformers + seqeval"
if [ ! -x "$VENV/bin/python" ]; then
  uv venv --python 3.12 "$VENV"
fi
# torch cu128 supports the 5090 (sm_120); transformers/seqeval/accelerate for train_suite.py
"$VENV/bin/python" -c "import torch" 2>/dev/null || \
  uv pip install --python "$VENV/bin/python" --index-strategy unsafe-best-match \
    --extra-index-url https://download.pytorch.org/whl/cu128 torch
"$VENV/bin/python" -c "import transformers,seqeval,numpy,accelerate" 2>/dev/null || \
  uv pip install --python "$VENV/bin/python" "transformers>=4.44" seqeval numpy accelerate

echo "[2/4] cache base model FacebookAI/xlm-roberta-large"
"$VENV/bin/python" - <<'PY'
from transformers import AutoTokenizer, AutoModelForTokenClassification
AutoTokenizer.from_pretrained("FacebookAI/xlm-roberta-large")
AutoModelForTokenClassification.from_pretrained("FacebookAI/xlm-roberta-large", num_labels=2, ignore_mismatched_sizes=True)
print("base model cached")
PY

echo "[3/4] CUDA check"
if ! "$VENV/bin/python" -c "import torch,sys; sys.exit(0 if torch.cuda.is_available() else 1)" 2>/dev/null; then
  echo
  echo ">>> PREP DONE, but CUDA is NOT available (driver/library mismatch)."
  echo ">>> REBOOT this workstation to load the matching nvidia kernel module, then re-run:"
  echo ">>>   bash $REPO/training/train_v11r6_local.sh"
  exit 3
fi
echo "CUDA OK: $("$VENV/bin/python" -c 'import torch;print(torch.cuda.get_device_name(0))')"

echo "[4/4] train (5090, bs 16, lr 2e-5, max-len 512, 3 epochs) -> $OUT"
mkdir -p "$(dirname "$OUT")"
nohup "$VENV/bin/python" "$REPO/training/train_suite.py" \
  --base FacebookAI/xlm-roberta-large \
  --data "$DATA" \
  --out "$OUT" \
  --bs 16 --lr 2e-5 --max-len 512 --epochs 3 \
  > "$LOG" 2>&1 </dev/null &
echo "TRAINING LAUNCHED pid=$! ; tail -f $LOG"
