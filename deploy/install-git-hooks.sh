#!/usr/bin/env bash
#
# Install the OSSRedact pre-push guard and its public-boundary helper into THIS clone's hooks
# directory. Idempotent; re-run after pulling guard updates.
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
helper="$repo_root/deploy/public_boundary.py"
[ -f "$helper" ] || { echo "ERROR: $helper not found" >&2; exit 1; }

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
installed_helper="$hooks_dir/public_boundary.py"
# Copy the helper before the hook so a failed helper copy cannot leave a new guard without it.
cp "$helper" "$installed_helper"
# Self-contained copies work regardless of which branch (or none) is checked out at push time.
cp "$guard" "$hook"
chmod +x "$hook"

echo "installed pre-push guard -> $hook"
echo "installed public-boundary helper -> $installed_helper"
echo "source of truth          -> $guard"
echo "active hooks dir         -> $(cd "$hooks_dir" && pwd)"
