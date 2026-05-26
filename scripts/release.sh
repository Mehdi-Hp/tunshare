#!/usr/bin/env bash
# Orchestrates a tunshare tagged release.
#
# What it does:
#   1. Validates preconditions (on main, clean tree, in sync with origin).
#   2. Validates the requested X.Y.Z version (semver-shaped, not already
#      taken locally or on the remote, strictly newer than the latest tag).
#   3. Bumps Cargo.toml, refreshes Cargo.lock, and stamps CHANGELOG.md
#      ([Unreleased] -> [X.Y.Z] - YYYY-MM-DD, new empty [Unreleased],
#      updated compare links).
#   4. Shows the plan (diff + commits since last tag).
#   5. With --push/--confirm, commits the bump, pushes main, creates an
#      annotated tag, and pushes it. Pushing the tag triggers
#      .github/workflows/release.yml.
#
# By design, running without --push or --confirm is a dry-run: it prints
# the plan, leaves the bump unstaged in the working tree (so you can
# inspect), and exits. Re-running with --push/--confirm reuses the same
# bump.
#
# Usage:
#   scripts/release.sh --version 0.2.0
#   scripts/release.sh --version 0.2.0 --confirm
#   scripts/release.sh --version 0.2.0 --push --watch
#
# Flags:
#   --version X.Y.Z   required, semver-shaped (no leading "v", no pre-release)
#   --push            commit bump, push main, tag, push tag (default: dry-run)
#   --confirm         like --push, but prompt interactively before mutating
#   --watch           after pushing, run `gh run watch` on the release workflow
#   --remote NAME     git remote (default: origin)

set -euo pipefail

VERSION=""
DO_PUSH=0
DO_CONFIRM=0
DO_WATCH=0
REMOTE="origin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?--version requires X.Y.Z}"; shift 2 ;;
    --push)    DO_PUSH=1; shift ;;
    --confirm) DO_CONFIRM=1; shift ;;
    --watch)   DO_WATCH=1; shift ;;
    --remote)  REMOTE="${2:?--remote requires a name}"; shift 2 ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "release.sh: unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$DO_PUSH" -eq 1 && "$DO_CONFIRM" -eq 1 ]]; then
  echo "release.sh: pass --push or --confirm, not both" >&2
  exit 2
fi
WILL_PUSH=$(( DO_PUSH | DO_CONFIRM ))

if [[ -z "$VERSION" ]]; then
  echo "release.sh: --version X.Y.Z is required" >&2
  exit 2
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release.sh: '$VERSION' is not X.Y.Z-shaped (pre-release tags aren't supported)" >&2
  exit 2
fi

TAG="v$VERSION"

# Resolve repo root so the script works from any cwd.
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# --- Preconditions --------------------------------------------------------

HEAD_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo "")"
if [[ "$HEAD_BRANCH" != "main" ]]; then
  echo "release.sh: must be on 'main' (currently on '$HEAD_BRANCH')" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "release.sh: working tree is dirty — commit or stash first" >&2
  git status --short >&2
  exit 1
fi

git fetch "$REMOTE" main --quiet

REMOTE_HEAD="$(git rev-parse "$REMOTE/main" 2>/dev/null || echo "")"
if [[ -z "$REMOTE_HEAD" ]]; then
  echo "release.sh: '$REMOTE/main' not found — is the remote configured?" >&2
  exit 1
fi

LOCAL_HEAD="$(git rev-parse HEAD)"
if [[ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]]; then
  BEHIND="$(git rev-list --count HEAD.."$REMOTE/main")"
  if [[ "$BEHIND" -gt 0 ]]; then
    echo "release.sh: local main is behind $REMOTE/main by $BEHIND commit(s) — pull first" >&2
    exit 1
  fi
  AHEAD="$(git rev-list --count "$REMOTE/main"..HEAD)"
  echo "release.sh: local main is $AHEAD commit(s) ahead of $REMOTE/main — push or reset first" >&2
  exit 1
fi

if git rev-parse "refs/tags/$TAG" >/dev/null 2>&1; then
  echo "release.sh: tag '$TAG' already exists locally" >&2
  exit 1
fi
if git ls-remote --tags --exit-code "$REMOTE" "refs/tags/$TAG" >/dev/null 2>&1; then
  echo "release.sh: tag '$TAG' already exists on $REMOTE" >&2
  exit 1
fi

# Strict monotonic check against the highest existing X.Y.Z tag. The git
# `--list` arg is a shell glob (not a regex), so it can't exclude
# pre-release suffixes like `-dev1` — filter with grep to keep only strict
# vX.Y.Z. Pre-releases are intentionally ignored: they're not part of the
# stable line, and `sort -V` orders them as "newer than" their release,
# which would block the actual release.
LAST_TAG="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --merged "$REMOTE/main" --sort=-version:refname \
  | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)"
if [[ -n "$LAST_TAG" ]]; then
  PREV="${LAST_TAG#v}"
  HIGHER="$(printf '%s\n%s\n' "$PREV" "$VERSION" | sort -V | tail -1)"
  if [[ "$HIGHER" != "$VERSION" || "$PREV" == "$VERSION" ]]; then
    echo "release.sh: '$VERSION' is not strictly newer than last tag '$LAST_TAG'" >&2
    exit 1
  fi
fi

# --- Bump version files ---------------------------------------------------

# Cargo.toml: only the [package] version. Match the literal line under the
# [package] table; refuse if exactly one match isn't found.
CARGO_TOML="Cargo.toml"
if ! grep -q '^version = "[0-9][0-9.]*"$' "$CARGO_TOML"; then
  echo "release.sh: couldn't find 'version = \"X.Y.Z\"' in $CARGO_TOML" >&2
  exit 1
fi
# Use a portable in-place edit: write to tmp, move into place.
awk -v v="$VERSION" '
  BEGIN { done = 0 }
  /^version = "[0-9][0-9.]*"$/ && !done { print "version = \"" v "\""; done = 1; next }
  { print }
' "$CARGO_TOML" > "$CARGO_TOML.tmp"
mv "$CARGO_TOML.tmp" "$CARGO_TOML"

# Cargo.lock: refresh via cargo so the [[package]] entry for tunshare is in
# sync. `cargo check` is a metadata-only call for an own-package version
# bump — no dep resolution, no network. If deps were edited too, this also
# fixes the lockfile up correctly (whereas --offline would fail confusingly).
cargo check --quiet

# CHANGELOG.md: rename [Unreleased] to [X.Y.Z] - YYYY-MM-DD, add a new empty
# [Unreleased] section above it, and fix compare links at the bottom.
CHANGELOG="CHANGELOG.md"
TODAY="$(date +%Y-%m-%d)"
if ! grep -q '^## \[Unreleased\]' "$CHANGELOG"; then
  echo "release.sh: $CHANGELOG has no '## [Unreleased]' section" >&2
  exit 1
fi

awk -v ver="$VERSION" -v today="$TODAY" '
  /^## \[Unreleased\]/ && !done_top {
    print "## [Unreleased]"
    print ""
    print "## [" ver "] - " today
    done_top = 1
    next
  }
  /^\[Unreleased\]: / && !done_links {
    print "[Unreleased]: https://github.com/kumamaki/tunshare/compare/v" ver "...HEAD"
    print "[" ver "]: https://github.com/kumamaki/tunshare/releases/tag/v" ver
    done_links = 1
    next
  }
  { print }
' "$CHANGELOG" > "$CHANGELOG.tmp"
mv "$CHANGELOG.tmp" "$CHANGELOG"

# --- Plan -----------------------------------------------------------------

TAG_MSG_FILE="$(mktemp)"
trap 'rm -f "$TAG_MSG_FILE"' EXIT
{
  echo "tunshare $VERSION"
  echo
  if [[ -n "$LAST_TAG" ]]; then
    echo "Changes since $LAST_TAG:"
    # Include the bump commit we're about to create.
    git --no-pager log --pretty='- %s' "$LAST_TAG"..HEAD
    echo "- chore: release v$VERSION"
  else
    echo "Initial release."
  fi
} > "$TAG_MSG_FILE"

echo "Release plan"
echo "  version : $VERSION"
echo "  tag     : $TAG"
echo "  remote  : $REMOTE"
echo "  prev tag: ${LAST_TAG:-<none>}"
echo
echo "Version-bump diff:"
git --no-pager diff --stat
echo
echo "Tag annotation:"
sed 's/^/  /' "$TAG_MSG_FILE"
echo

if [[ "$WILL_PUSH" -ne 1 ]]; then
  echo "Dry-run only. The bump is in your working tree (uncommitted) — inspect or 'git checkout .' to undo."
  echo "Re-run with --push to commit + tag + push, or --confirm to prompt."
  exit 0
fi

if [[ "$DO_CONFIRM" -eq 1 ]]; then
  read -r -p "Commit bump, push main, tag $TAG, and push tag? [y/N] " reply </dev/tty
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "release.sh: aborted (bump left in working tree)" >&2; exit 1 ;;
  esac
fi

# --- Execute --------------------------------------------------------------

echo "Committing version bump..."
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: release v$VERSION"

echo "Pushing to $REMOTE/main..."
git push "$REMOTE" main

TAG_TARGET="$(git rev-parse HEAD)"

echo "Creating annotated tag $TAG at $TAG_TARGET..."
git tag -a "$TAG" -F "$TAG_MSG_FILE" "$TAG_TARGET"

echo "Pushing $TAG to $REMOTE..."
git push "$REMOTE" "$TAG"

echo
echo "Tag pushed. The release workflow should now be running:"
echo "  https://github.com/kumamaki/tunshare/actions/workflows/release.yml"
echo

if [[ "$DO_WATCH" -eq 1 ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "release.sh: --watch requires the 'gh' CLI" >&2
    exit 0
  fi
  RUN_ID=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    RUN_ID="$(gh run list --workflow release.yml --branch "$TAG" --limit 1 --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
    [[ -n "$RUN_ID" ]] && break
    sleep 2
  done
  if [[ -n "$RUN_ID" ]]; then
    gh run watch "$RUN_ID" --exit-status
  else
    echo "release.sh: couldn't locate the workflow run for $TAG after 20s; check the Actions tab manually." >&2
  fi
fi
