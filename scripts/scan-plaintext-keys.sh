#!/usr/bin/env bash
# Plaintext private-key scanner (PRD SEC-04, TESTING.md section 1).
# Fails if any file under the given paths contains an unencrypted private key, as a PEM
# label or as DER-encoded PKCS#8/PKCS#1 key material, in text or binary files.
# Encrypted PKCS#8 ("BEGIN ENCRYPTED PRIVATE KEY") is allowed.
# Usage: scripts/scan-plaintext-keys.sh <path> [<path> ...]
set -euo pipefail
if [[ $# -eq 0 ]]; then
  echo "usage: $0 <path> [<path> ...]" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
cargo run --quiet -p keystone-testkit --example scan_plaintext_keys -- "$@"
