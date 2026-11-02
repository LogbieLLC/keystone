#!/usr/bin/env bash
# Prepares the pinned ubuntu:26.04 CI container (PRD NFR-01): distribution packages for
# GTK4, libadwaita, OpenSSL 3 and PC/SC, plus the exact Rust toolchain from
# rust-toolchain.toml installed with the distribution's rustup.
# Usage: scripts/ci-setup.sh [extra apt packages ...]
set -euo pipefail
cd "$(dirname "$0")/.."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  ca-certificates git curl build-essential pkg-config \
  libgtk-4-dev libadwaita-1-dev libssl-dev libpcsclite-dev \
  openssl perl python3 rustup "$@"
# actions/checkout runs as another user than the container's root.
git config --global --add safe.directory "$PWD"
channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
rustup toolchain install "$channel" --profile minimal \
  --component rustfmt --component clippy --component llvm-tools-preview
rustup default "$channel"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
fi
rustc --version
cargo --version
openssl version
