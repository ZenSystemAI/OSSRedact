#!/usr/bin/env bash
#
# OSSRedact pre-push guard -- enforce public and private repository boundaries.
#
# The only permitted remote identity pairs are:
# * origin + https://github.com/ZenSystemAI/OSSRedact.git -> public
# * origin/private + https://github.com/ZenSystemAI/OSSRedact-dev.git -> private
# Every other remote identity is rejected before ref or content checks.
#
# This guard aborts a push when the remote identity is unrecognized, when a ref
# violates its profile, or when the tip tree or added commits violate that
# profile's path boundary.
#
# Installed with public_boundary.py into <repo>/.git/hooks by deploy/install-git-hooks.sh. The
# hook resolves its sibling helper, so it works on any checkout.
#   $1 = remote name   $2 = remote URL   stdin = "<local ref> <local sha> <remote ref> <remote sha>" lines
#
set -euo pipefail

remote_name="${1:-}"
remote_url="${2:-}"
ZERO='0000000000000000000000000000000000000000'

# Tag annotations are not part of a commit tree, so release tags need explicit
# content checks in addition to the path boundary.
TAILNET_RE='(^|[^0-9])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)'

abort() {
  {
    echo ""
    echo "  ###############################################################"
    echo "  # PRE-PUSH BLOCKED -- $*"
    echo "  # Repository boundary enforcement is fail-closed."
    echo "  # If you are CERTAIN this is safe: git push --no-verify"
    echo "  ###############################################################"
    echo ""
  } >&2
  exit 1
}

# A remote name or URL alone is not enough to select a permissive profile.
case "${remote_name}:${remote_url}" in
  origin:https://github.com/ZenSystemAI/OSSRedact.git)
    profile="public"
    ;;
  origin:https://github.com/ZenSystemAI/OSSRedact-dev.git|private:https://github.com/ZenSystemAI/OSSRedact-dev.git)
    profile="private"
    ;;
  *)
    abort "remote identity is not an approved repository profile"
    ;;
esac
# The installer copies the helper beside this hook. Never depend on the currently checked-out tree.
hook_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
boundary_helper="$hook_dir/public_boundary.py"

if [ ! -f "$boundary_helper" ]; then
  abort "public-boundary helper is missing beside this hook"
fi
if ! command -v python3 >/dev/null 2>&1; then
  abort "python3 is required to enforce the repository path boundary"
fi

# `|| [ -n ... ]` processes a final line that lacks a trailing newline (git always terminates its
# lines, but a security guard must not fail-open on a missing newline).
is_tag_ref() {
  case "$1" in
    refs/tags/*) return 0 ;;
    *) return 1 ;;
  esac
}

tailnet_text_is_clean() {
  local candidate="$1"
  local -a scan_status
  set +e
  printf '%s\n' "$candidate" | grep -E "$TAILNET_RE" >/dev/null 2>&1
  scan_status=("${PIPESTATUS[@]}")
  set -e
  case "${scan_status[0]}:${scan_status[1]}" in
    0:1) return 0 ;;
    *) return 1 ;;
  esac
}

tailnet_object_is_clean() {
  local object_type="$1"
  local object="$2"
  local -a scan_status
  set +e
  git cat-file "$object_type" "$object" 2>/dev/null | grep -E "$TAILNET_RE" >/dev/null 2>&1
  scan_status=("${PIPESTATUS[@]}")
  set -e
  case "${scan_status[0]}:${scan_status[1]}" in
    0:1) return 0 ;;
    *) return 1 ;;
  esac
}

if ! git_dir="$(git rev-parse --git-dir 2>/dev/null)"; then
  abort "local marker directory could not be resolved"
fi
[ -n "$git_dir" ] || abort "local marker directory could not be resolved"
local_markers="$git_dir/ossredact-guard-local"
if [ -e "$local_markers" ] && [ ! -f "$local_markers" ]; then
  abort "local marker configuration is not a regular file"
fi
if [ -f "$local_markers" ] && [ ! -r "$local_markers" ]; then
  abort "local marker configuration cannot be read"
fi

scan_local_marker_text() {
  local candidate="$1"
  local marker_re
  local -a scan_status
  [ -f "$local_markers" ] || return 0
  while IFS= read -r marker_re || [ -n "${marker_re:-}" ]; do
    [ -z "${marker_re:-}" ] && continue
    case "$marker_re" in \#*) continue ;; esac
    set +e
    printf '%s\n' "$candidate" | grep -E "$marker_re" >/dev/null 2>&1
    scan_status=("${PIPESTATUS[@]}")
    set -e
    case "${scan_status[0]}:${scan_status[1]}" in
      0:1) ;;
      *) return 1 ;;
    esac
  done < "$local_markers"
}

scan_local_marker_object() {
  local object_type="$1"
  local object="$2"
  local marker_re
  local -a scan_status
  [ -f "$local_markers" ] || return 0
  while IFS= read -r marker_re || [ -n "${marker_re:-}" ]; do
    [ -z "${marker_re:-}" ] && continue
    case "$marker_re" in \#*) continue ;; esac
    set +e
    git cat-file "$object_type" "$object" 2>/dev/null | grep -E "$marker_re" >/dev/null 2>&1
    scan_status=("${PIPESTATUS[@]}")
    set -e
    case "${scan_status[0]}:${scan_status[1]}" in
      0:1) ;;
      *) return 1 ;;
    esac
  done < "$local_markers"
}

scan_local_marker_tree() {
  local treeish="$1"
  local marker_re
  local -a scan_status
  [ -f "$local_markers" ] || return 0
  while IFS= read -r marker_re || [ -n "${marker_re:-}" ]; do
    [ -z "${marker_re:-}" ] && continue
    case "$marker_re" in \#*) continue ;; esac
    set +e
    git ls-tree -r -z --name-only "$treeish" 2>/dev/null | grep -zqE "$marker_re" >/dev/null 2>&1
    scan_status=("${PIPESTATUS[@]}")
    set -e
    case "${scan_status[0]}:${scan_status[1]}" in
      0:1) ;;
      *) return 1 ;;
    esac
    set +e
    git grep -a -qE "$marker_re" "$treeish" -- . >/dev/null 2>&1
    scan_status=("$?")
    set -e
    case "${scan_status[0]}" in
      1) ;;
      *) return 1 ;;
    esac
  done < "$local_markers"
}

while read -r local_ref local_sha remote_ref remote_sha || [ -n "${local_ref:-}" ]; do
  [ -z "${local_ref:-}" ] && continue
  # Deleting a remote ref (local all-zero) carries no content -- harmless.
  [ "$local_sha" = "$ZERO" ] && continue

  if is_tag_ref "$local_ref" || is_tag_ref "$remote_ref"; then
    if ! is_tag_ref "$local_ref" || ! is_tag_ref "$remote_ref"; then
      abort "tag updates must use tag references"
    fi
    for tag_ref in "$local_ref" "$remote_ref"; do
      if ! printf '%s\n' "$tag_ref" | python3 "$boundary_helper" --text --profile "$profile" >/dev/null 2>&1; then
        abort "tag reference violates the repository boundary"
      fi
      if [ "$profile" = "public" ] && ! tailnet_text_is_clean "$tag_ref"; then
        abort "public tag reference carries an internal tailnet address"
      fi
      if ! scan_local_marker_text "$tag_ref"; then
        abort "tag reference matches a local marker rule"
      fi
    done

    if ! tag_type="$(git cat-file -t "$local_sha" 2>/dev/null)"; then
      abort "tag object type could not be inspected"
    fi
    case "$tag_type" in
      tag)
        if ! tag_commit="$(git rev-parse --verify --quiet "${local_sha}^{commit}")"; then
          abort "tag does not point at a commit"
        fi
        if [ "$profile" = "public" ]; then
          if ! git cat-file tag "$local_sha" 2>/dev/null | python3 "$boundary_helper" --text --profile public >/dev/null 2>&1; then
            abort "tag annotation violates the repository boundary"
          fi
          if ! tailnet_object_is_clean tag "$local_sha"; then
            abort "tag annotation carries an internal tailnet address"
          fi
        elif ! git cat-file tag "$local_sha" 2>/dev/null | python3 "$boundary_helper" --text --profile private >/dev/null 2>&1; then
          abort "tag annotation violates the repository boundary"
        fi
        ;;
      commit)
        tag_commit="$local_sha"
        ;;
      *)
        abort "tag has an unsupported object type"
        ;;
    esac

    if ! git cat-file commit "$tag_commit" 2>/dev/null | python3 "$boundary_helper" --text --profile "$profile" >/dev/null 2>&1; then
      abort "tag target metadata violates the repository boundary"
    fi
    if [ "$profile" = "public" ] && ! tailnet_object_is_clean commit "$tag_commit"; then
      abort "tag target metadata carries an internal tailnet address"
    fi
    if [ "$profile" = "public" ]; then
      if ! public_main="$(git ls-remote "$remote_name" refs/heads/main 2>/dev/null | cut -f1)"; then
        abort "public main could not be resolved"
      fi
      [ -n "$public_main" ] || abort "public main could not be resolved"
      if ! git merge-base --is-ancestor "$tag_commit" "$public_main" 2>/dev/null; then
        abort "tag target is not reachable from public main"
      fi
    fi
    if ! git ls-tree -r -z --name-only "$tag_commit" 2>/dev/null | python3 "$boundary_helper" --stdin0 --profile "$profile" >/dev/null 2>&1; then
      abort "tag target tree carries paths outside the selected path boundary"
    fi
    if ! scan_local_marker_object "$tag_type" "$local_sha"; then
      abort "tag object matches a local marker rule"
    fi
    if [ "$tag_type" = "tag" ] && ! scan_local_marker_object commit "$tag_commit"; then
      abort "tag target metadata matches a local marker rule"
    fi
    if ! scan_local_marker_tree "$tag_commit"; then
      abort "tag target tree matches a local marker rule"
    fi
    continue
  fi

  # RULE 1: public accepts only main -> main. Private review refs may not involve main.
  if [ "$profile" = "public" ] && { [ "$local_ref" != "refs/heads/main" ] || [ "$remote_ref" != "refs/heads/main" ]; }; then
    abort "unsupported public ref update (only main -> main, or a tag on an already-public commit)"
  fi
  if [ "$profile" = "private" ] && { [ "$local_ref" = "refs/heads/main" ] || [ "$remote_ref" = "refs/heads/main" ]; }; then
    abort "private review profile does not accept refs/heads/main"
  fi

  # RULE 2: scan each pushed path against the selected repository boundary. The tip tree is always scanned;
  # added commits are scanned as complete trees from rev-list, including roots and merge commits.
  # NUL framing preserves unusual file names without git log's commit separators.
  if [ "$remote_sha" = "$ZERO" ]; then
    range="$local_sha"
  else
    range="${remote_sha}..${local_sha}"
  fi
  if ! git ls-tree -r -z --name-only "$local_sha" 2>/dev/null | python3 "$boundary_helper" --stdin0 --profile "$profile" >/dev/null 2>&1; then
    abort "ref carries paths outside the selected path boundary"
  fi
  if ! scan_local_marker_tree "$local_sha"; then
    abort "ref matches a local marker rule"
  fi

  if ! git rev-list "$range" | while IFS= read -r commit; do
    [ -z "${commit:-}" ] && continue
    if ! git ls-tree -r -z --name-only "$commit" 2>/dev/null | python3 "$boundary_helper" --stdin0 --profile "$profile" >/dev/null 2>&1; then
      abort "added commit tree carries paths outside the selected path boundary"
    fi
    if ! scan_local_marker_tree "$commit"; then
      abort "added commit tree matches a local marker rule"
    fi
    if ! git cat-file commit "$commit" 2>/dev/null | python3 "$boundary_helper" --text --profile "$profile" >/dev/null 2>&1; then
      abort "added commit metadata violates the selected repository boundary"
    fi
    if ! scan_local_marker_object commit "$commit"; then
      abort "added commit metadata matches a local marker rule"
    fi

    if [ "$profile" = "public" ]; then
      if ! tailnet_object_is_clean commit "$commit"; then
        abort "added commit metadata carries an internal tailnet address"
      fi

      set +e
      git grep -I -qE "$TAILNET_RE" "$commit" -- . >/dev/null 2>&1
      content_scan_status=$?
      set -e
      case "$content_scan_status" in
        0) abort "ref carries internal tailnet (100.64/10) addresses in file content" ;;
        1) ;;
        *) abort "added commit tree could not be scanned for internal tailnet addresses" ;;
      esac
    fi
  done; then
    abort "added commit history could not be scanned"
  fi
done

exit 0
