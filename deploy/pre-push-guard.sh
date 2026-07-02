#!/usr/bin/env bash
#
# OSSRedact pre-push guard -- protect the PUBLIC origin from accidental disclosure.
#
# `origin` (https://github.com/ZenSystemAI/OSSRedact.git) is WORLD-READABLE, including the FULL
# history of any pushed ref. Only a clean local `main` is push-safe (== origin/main). `master` and
# every advisor/* | feat/* | worktree-* branch embed dev-only paths (plans/, AGENTS.md, ...) as
# recoverable blobs in their history, so pushing any of them -- or `git push --all` / `--mirror` --
# would permanently leak them.
#
# This guard ABORTS a push to the public repo when EITHER:
#   RULE 1  the push is anything other than local main -> origin refs/heads/main, OR
#   RULE 2  the pushed ref's tip tree OR the commits being added touch a dev-only path
#           (plans/, AGENTS.md, .agents/, extension/, *PRELAUNCH-AUDIT*).
# Over-blocking is the safe error. Non-origin remotes are not guarded.
#
# Installed into <repo>/.git/hooks/pre-push by deploy/install-git-hooks.sh (a self-contained copy,
# so it works on any checkout). Git invokes it with:
#   $1 = remote name   $2 = remote URL   stdin = "<local ref> <local sha> <remote ref> <remote sha>" lines
#
set -euo pipefail

remote_name="${1:-}"
remote_url="${2:-}"
ZERO='0000000000000000000000000000000000000000'

# Public-repo identity: match by URL (any host/protocol) OR the conventional remote name `origin`
# (defence in depth -- origin IS the public repo in this clone). A future private mirror is not matched.
is_public=0
printf '%s' "$remote_url" | grep -qiE 'ZenSystemAI/OSSRedact' && is_public=1
[ "$remote_name" = "origin" ] && is_public=1
[ "$is_public" -eq 1 ] || exit 0

# Dev-only paths that must NEVER reach the public repo (matched against tracked path names).
FORBIDDEN_RE='(^|/)(plans/|AGENTS\.md|\.agents/|extension/)|PRELAUNCH-AUDIT'

abort() {
  {
    echo ""
    echo "  ###############################################################"
    echo "  # PRE-PUSH BLOCKED -- $*"
    echo "  # origin is PUBLIC. Only a clean local 'main' is push-safe."
    echo "  # If you are CERTAIN this is safe: git push --no-verify"
    echo "  ###############################################################"
    echo ""
  } >&2
  exit 1
}

# `|| [ -n ... ]` processes a final line that lacks a trailing newline (git always terminates its
# lines, but a security guard must not fail-open on a missing newline).
while read -r local_ref local_sha remote_ref remote_sha || [ -n "${local_ref:-}" ]; do
  [ -z "${local_ref:-}" ] && continue
  # Deleting a remote ref (local all-zero) carries no content -- harmless.
  [ "$local_sha" = "$ZERO" ] && continue

  # RULE 1: only local main -> origin/main.
  if [ "$local_ref" != "refs/heads/main" ] || [ "$remote_ref" != "refs/heads/main" ]; then
    abort "attempted ${local_ref} -> ${remote_ref} (only main -> main allowed)"
  fi

  # RULE 2: scan the pushed content. Tip tree is always scanned; the added commits are scanned over
  # the delta (remote_sha..local_sha), or the full reachable history for a brand-new ref.
  if [ "$remote_sha" = "$ZERO" ]; then
    range="$local_sha"
  else
    range="${remote_sha}..${local_sha}"
  fi
  hits="$(
    {
      git ls-tree -r --name-only "$local_sha" 2>/dev/null || true
      git log --name-only --pretty=format: "$range" 2>/dev/null || true
    } | grep -iE "$FORBIDDEN_RE" | sort -u || true
  )"
  if [ -n "$hits" ]; then
    echo "$hits" | sed 's/^/  dev-only path in push: /' >&2
    abort "ref ${local_ref} carries dev-only paths that must not be public"
  fi

  # RULE 3: content scan -- an internal TAILNET address (100.64/10 CGNAT, e.g. a deploy/*.service
  # `Environment=..._HOST=100.65.x.x` line) must never reach the public tree even inside an otherwise
  # shippable file. RFC1918 (192.168./10./172.16-31.) is intentionally NOT scanned: those are textbook
  # example IPs used throughout the tests and docs (127.0.0.1, 192.168.1.100, 10.0.0.5), so flagging them
  # would false-positive the guard into being --no-verify'd. CGNAT 100.64-127.x is never a public example.
  tailnet_re='(^|[^0-9])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'
  ip_hits="$(git grep -I -nE "$tailnet_re" "$local_sha" -- . 2>/dev/null | sort -u || true)"
  if [ -n "$ip_hits" ]; then
    echo "$ip_hits" | sed 's/^/  tailnet IP in push: /' >&2
    abort "ref ${local_ref} carries internal tailnet (100.64/10) addresses in file content"
  fi
done

exit 0
