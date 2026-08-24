# tunshare task runner. Run `just` with no args to see all recipes.

# Optional local recipes (gitignored). Use for personal workflows like
# pushing builds to a specific host — anything that shouldn't be committed.
import? 'justfile.local'

# Show the recipe list.
default:
    @just --list

# Build the debug binary.
build:
    cargo build

# Build and run with sudo. Always rebuilds — no stale-binary trap.
run: build
    sudo ./target/debug/tunshare

# Live sharing inspect. Always rebuilds, then sudo like `just run`.
# Flags go after `--` so just does not swallow them:
#   just status
#   just status -- --check digikala.com
status *args: build
    sudo ./target/debug/tunshare status {{args}}

# Run clippy.
lint:
    cargo clippy --all-targets

# Run tests.
test:
    cargo test

# Format code.
fmt:
    cargo fmt

# Full pre-commit check: fmt, lint, test, build.
check:
    cargo fmt -- --check
    cargo clippy --all-targets
    cargo test
    cargo build

# Clean build artifacts.
clean:
    cargo clean

# === Release ================================================================

# Delegates to scripts/release.sh, which validates preconditions (clean tree,
# in sync with origin, monotonic version), bumps Cargo.{toml,lock} +
# CHANGELOG.md, commits, tags origin/main, and pushes — which triggers
# .github/workflows/release.yml (build, GitHub release, Homebrew tap update).
#
# For a dry-run preview without prompting:
#   ./scripts/release.sh --version 1.2.3                    # prints plan, leaves bump in worktree
#   ./scripts/release.sh --version 1.2.3 --confirm --watch  # prompt, ship, watch CI
#
# Bump v* tag (major|minor|patch), confirm, then push to trigger the release.
ship kind:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ kind }}" in
      major|minor|patch) ;;
      *) echo "usage: just ship <major|minor|patch>" >&2; exit 2 ;;
    esac
    git fetch origin main --quiet
    # Restrict to strict vX.Y.Z (the --list arg is a glob; can't reject -dev1 suffixes there).
    latest="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --merged origin/main --sort=-version:refname \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
    latest="${latest:-v0.0.0}"
    IFS=. read -r major minor patch <<< "${latest#v}"
    case "{{ kind }}" in
      major) major=$((major+1)); minor=0; patch=0 ;;
      minor) minor=$((minor+1)); patch=0 ;;
      patch) patch=$((patch+1)) ;;
    esac
    next="${major}.${minor}.${patch}"
    echo "==> bumping {{ kind }}: ${latest} → v${next}"
    echo
    ./scripts/release.sh --version "${next}" --confirm
    open https://github.com/kumamaki/tunshare/actions
