# tunshare task runner. Run `just` with no args to see all recipes.

# Show the recipe list.
default:
    @just --list

# Build the debug binary.
build:
    cargo build

# Build and run with sudo. Always rebuilds — no stale-binary trap.
run: build
    sudo ./target/debug/tunshare

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
