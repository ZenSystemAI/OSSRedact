#!/usr/bin/env bash
#
# Install the OSSRedact pre-push guard into THIS clone's hooks directory. Idempotent; re-run after
# pulling guard updates (it copies the current deploy/pre-push-guard.sh into the active hook).
#
# Also repairs a stale `core.hooksPath`: a repository move/rename can leave a local override pointing
# at a directory that no longer exists, which silently disables ALL git hooks. If the configured hooks
# dir is missing, the local override is dropped so git falls back to .git/hooks.
#
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

guard="$repo_root/deploy/pre-push-guard.sh"
[ -f "$guard" ] || { echo "ERROR: $guard not found" >&2; exit 1; }

hooks_dir="$(git rev-parse --git-path hooks)"
if [ ! -d "$hooks_dir" ]; then
  stale="$(git config --local --get core.hooksPath || true)"
  if [ -n "$stale" ]; then
    echo "core.hooksPath is stale ($stale does not exist) -- removing the local override"
    git config --local --unset core.hooksPath
  fi
  hooks_dir="$(git rev-parse --git-path hooks)"
fi
mkdir -p "$hooks_dir"

hook="$hooks_dir/pre-push"
# Self-contained copy so the hook works regardless of which branch (or none) is checked out at push
# time -- a wrapper sourcing the working tree would fail-closed if the pushed branch lacks the guard.
cp "$guard" "$hook"
chmod +x "$hook"

echo "installed pre-push guard -> $hook"
echo "source of truth          -> $guard"
echo "active hooks dir         -> $(cd "$hooks_dir" && pwd)"
