#!/usr/bin/env bash
# Drift check: the deployed gate-service files on the GPU host vs the version-controlled copies in gate/.
# The gate at the install dir is edited live, so it can silently diverge from the repo (that is how the
# F14 IBAN-floor regression happened). Run from the repo root; needs SSH access to the gate host.
#   GATE_HOST=<gpu-host> GATE_REMOTE_DIR=ossredact-gate deploy/check-gate-drift.sh
# Exit 0 = in sync; non-zero = drift (reconcile before relying on the deployed gate).
set -uo pipefail

HOST="${GATE_HOST:-gate-host}"
REMOTE_DIR="${GATE_REMOTE_DIR:-ossredact-gate}"
FILES=(gate_service_gpu.py gate_service_cpu.py privacy_gate.py)

drift=0
for f in "${FILES[@]}"; do
  remote=$(ssh "$HOST" "md5sum ~/$REMOTE_DIR/$f 2>/dev/null" | awk '{print $1}')
  local=$(md5sum "gate/$f" 2>/dev/null | awk '{print $1}')
  if [ -z "$remote" ]; then
    printf 'MISSING  %-22s (not on %s:~/%s)\n' "$f" "$HOST" "$REMOTE_DIR"; drift=1
  elif [ -z "$local" ]; then
    printf 'MISSING  %-22s (not in repo gate/)\n' "$f"; drift=1
  elif [ "$remote" = "$local" ]; then
    printf 'ok       %-22s %s\n' "$f" "$local"
  else
    printf 'DRIFT    %-22s host=%s repo=%s\n' "$f" "$remote" "$local"; drift=1
  fi
done

if [ "$drift" -eq 0 ]; then
  echo "gate in sync with repo"
else
  echo "GATE DRIFT DETECTED -- reconcile gate/ <-> $HOST:~/$REMOTE_DIR (redeploy the repo copy, or pull host changes back)"
fi
exit "$drift"
