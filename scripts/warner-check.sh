#!/usr/bin/env bash
set -euo pipefail
echo "== fmt =="
cargo fmt --all

echo "== test =="
cargo test

echo "== clippy =="
cargo clippy --all-features -- -D warnings
