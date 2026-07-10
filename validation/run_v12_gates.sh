#!/usr/bin/env bash
# v12 acceptance gates (plan 048): run AFTER training/train_v12_local.sh completes.
# One command; writes per-gate JSON next to /tmp and prints the bar-check verdicts.
#
#   gate 1  v11r5 heldout (7,498 rows)   -- must meet/beat v11r9c: 0.9954 catastrophic detection,
#                                           clean_fp not materially worse than 34/7498
#   gate 2  generator holdout (2,231)    -- telecom_bill+insurance never seen in ANY training form:
#                                           the memorization referendum (v11r5 failed its analogue at 0.10 org)
#   gate 3  firewall-stress org/address  -- the documented v11r6 leak forms (validation/stress_orgaddr_heldout.jsonl)
#   gate 4  floor + mode suites          -- model-independent, must stay green after any gate-code change
#
# MODEL defaults to the finished stage-2 output; pass another dir as $1 (e.g. the stage-1 epoch-1
# weights for an early CPU probe: GATE_DEVICE=cpu GPU_GATE_DTYPE=float32 $0 models/pii-gpu-opf-v12-stage1-ep1).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${1:-$REPO/models/pii-gpu-opf-v12}"
PY="$REPO/.venv-train/bin/python"
DEV="${GATE_DEVICE:-cuda}"
# MoE base is bf16-trained: never eval it in fp16 (GPUTier default). float32 on CPU.
DTYPE="${GPU_GATE_DTYPE:-$([ "$DEV" = cuda ] && echo bfloat16 || echo float32)}"
STRESS_FIXTURE="$REPO/validation/stress_orgaddr_heldout.jsonl"
STRESS_FIXTURE_SNAPSHOT="$(mktemp)"
trap 'rm -f "$STRESS_FIXTURE_SNAPSHOT"' EXIT
cp "$STRESS_FIXTURE" "$STRESS_FIXTURE_SNAPSHOT"

"$PY" "$REPO/validation/build_stress_heldout.py"
if ! cmp -s "$STRESS_FIXTURE" "$STRESS_FIXTURE_SNAPSHOT"; then
  echo "stress fixture drifted after regeneration" >&2
  exit 1
fi
rm -f "$STRESS_FIXTURE_SNAPSHOT"


run_eval() { # name val_jsonl
  echo "=== gate: $1 ($2)"
  GATE_DIR="$REPO/gate" GPU_GATE_MODEL="$MODEL" GATE_DEVICE="$DEV" GPU_GATE_DTYPE="$DTYPE" \
  GPU_GATE_VAL="$2" GPU_GATE_OUT="/tmp/v12-gate-$1.json" \
    "$PY" "$REPO/validation/eval_labelaware.py" | tail -20
}

run_eval heldout-v11r5      "$REPO/datasets/pii-heldout-v11r5/test.jsonl"
run_eval generator-holdout  "$REPO/datasets/pii-merged-v12-stage1/generator_holdout.jsonl"
run_eval stress-orgaddr     "$REPO/validation/stress_orgaddr_heldout.jsonl"

echo "=== gate: bar check (headline numbers vs v11r9c)"
for gate in heldout-v11r5 generator-holdout stress-orgaddr; do
  "$PY" "$REPO/validation/bar_check_v11.py" "/tmp/v12-gate-$gate.json"
done

echo "=== gate: floor + mode suites (model-independent)"
GATEWAY_ALLOWLIST_FILE=/dev/null GATEWAY_DENYLIST_FILE=/dev/null GATEWAY_MODE_FILE=/dev/null \
  "$REPO/.venv-test/bin/python" -m pytest "$REPO/appliance/tests/test_floor_diet.py" \
  "$REPO/appliance/tests/test_floor_label_parity.py" "$REPO/gate/tests" -q | tail -2
