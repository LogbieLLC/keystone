#!/usr/bin/env bash
# Plaintext private-key scanner (PRD SEC-04, TESTING.md section 1).
# Fails if any file under the given paths contains an unencrypted private-key PEM
# marker. Encrypted PKCS#8 ("BEGIN ENCRYPTED PRIVATE KEY") is allowed.
# Usage: scripts/scan-plaintext-keys.sh <path> [<path> ...]
set -euo pipefail
if [[ $# -eq 0 ]]; then
  echo "usage: $0 <path> [<path> ...]" >&2
  exit 2
fi
# "ENCRYPTED PRIVATE KEY" (PKCS#8) is the only allowed private-key PEM label.
hits=$(grep -rIlE -- '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' "$@" 2>/dev/null || true)
if [[ -n "$hits" ]]; then
  echo "PLAINTEXT PRIVATE KEY FOUND (SEC-04):" >&2
  echo "$hits" >&2
  exit 1
fi
echo "No plaintext private-key markers found in: $*"
