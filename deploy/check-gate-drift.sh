#!/usr/bin/env bash
# Drift check: the deployed redaction files on a REMOTE gate host vs the version-controlled copies in this repo.
# A remote gate host holds an rsync copy (not a git checkout), so it can silently diverge from the repo -- that is
# how the F14 IBAN-floor regression happened. md5 is the only available signal (a non-git copy has no HEAD to diff;
# deploying the host as a real `git` checkout so `git rev-parse HEAD` could be compared would be strictly better).
#
# SCOPE: check the files the target host actually RUNS. A remote GPU/CPU gate host runs ONLY the gate/ detect
# service (gate_service_{gpu,cpu}.py, which import gate/privacy_gate.py); it does NOT run the appliance egress
# proxy. The egress proxy runs on the WORKSTATION off the repo working tree directly (ExecStart points at
# ~/dev/ossredact/appliance/egress_proxy.py), so it CANNOT drift from the repo -- there is nothing to check for it
# remotely. Override GATE_FILES to audit a host that also carries appliance copies.
#
# The remote mirrors the repo layout under a base dir (gate hosts hold the copy at ~/dev/ossredact), so the SAME
# repo-relative path is compared on both sides.
#
#   # GPU gate host (set GATE_HOST to its ssh host/alias):
#   GATE_HOST=gpu-gate deploy/check-gate-drift.sh
#   # CPU gate host with a different remote layout:
#   GATE_HOST=cpu-gate GATE_REMOTE_BASE=ossredact GATE_FILES="gate_service_cpu.py privacy_gate.py" deploy/check-gate-drift.sh
#
# Exit 0 = in sync; non-zero = drift or an unreachable/missing file (reconcile before relying on that gate).
set -uo pipefail

HOST="${GATE_HOST:?set GATE_HOST to the ssh host/alias of the gate box}"
REMOTE_BASE="${GATE_REMOTE_BASE:-dev/ossredact}"
# Repo-relative paths. Default = the gate DETECT-SERVICE files a remote gate host runs; their bytes decide what PII
# that gate catches. (appliance/* is the workstation egress proxy, which runs the working tree -> cannot drift.)
if [ -n "${GATE_FILES:-}" ]; then
  # shellcheck disable=SC2206
  FILES=(${GATE_FILES})
else
  FILES=(
    gate/gate_service_gpu.py
    gate/gate_service_cpu.py
    gate/privacy_gate.py
  )
fi

echo "drift check: $HOST:~/$REMOTE_BASE  <->  repo $(pwd)"
drift=0
for f in "${FILES[@]}"; do
  remote=$(ssh "$HOST" "md5sum ~/$REMOTE_BASE/$f 2>/dev/null" | awk '{print $1}')
  local=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
  if [ -z "$local" ]; then
    printf 'MISSING  %-32s (not in repo)\n' "$f"; drift=1
  elif [ -z "$remote" ]; then
    printf 'MISSING  %-32s (not on %s:~/%s)\n' "$f" "$HOST" "$REMOTE_BASE"; drift=1
  elif [ "$remote" = "$local" ]; then
    printf 'ok       %-32s %s\n' "$f" "$local"
  else
    printf 'DRIFT    %-32s host=%s repo=%s\n' "$f" "$remote" "$local"; drift=1
  fi
done

if [ "$drift" -eq 0 ]; then
  echo "gate in sync with repo"
else
  echo "GATE DRIFT DETECTED -- reconcile repo <-> $HOST:~/$REMOTE_BASE (redeploy the repo copy, or pull host changes back)"
fi
exit "$drift"
