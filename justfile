# VPN Share - Task Runner

# Set PATH to include cargo
export PATH := env_var("HOME") + "/.cargo/bin:" + env_var("PATH")

# Default recipe: show available commands
default:
    @echo "Available commands: build, build-release, dev, run, run-release, lint, test, fmt, check, clean"
    @echo "Run 'just --list' for details"

# Build debug version
build:
    cargo build

# Build release version
build-release:
    cargo build --release

# Run in development mode (debug build)
dev:
    cargo run

# Run release version (requires sudo)
run:
    sudo ./target/release/tunshare

# Build and run release version
run-release: build-release
    sudo ./target/release/tunshare

# Run clippy linter
lint:
    cargo clippy --all-targets

# Run tests
test:
    cargo test

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt -- --check

# Clean build artifacts
clean:
    cargo clean

# Full check: format, lint, test, build
check: fmt-check lint test build
