#!/usr/bin/env bash
# Enforces the code-safety boundaries of PRD SEC-18 / SECURITY.md SECP-06:
#   1. `unsafe` code exists only in keystone-core/src/crypto/ffi.rs.
#   2. Every other Rust source file has #![forbid(unsafe_code)]. Exempt: the parents
#      of ffi.rs, because `forbid` cannot be relaxed for a child module. The crate root
#      keystone-core/src/lib.rs must #![deny(unsafe_code)] instead, and
#      crypto/mod.rs may hold only module declarations and re-exports.
#   3. Every OpenSSL call (`openssl::` / `openssl_sys::`) is inside keystone-core/src/crypto/.
#   4. No networking API is used anywhere (PRD HR-1, SEC-03, SECP-07).
# Exit code 0 = all rules hold.
set -euo pipefail
cd "$(dirname "$0")/.."

FFI="keystone-core/src/crypto/ffi.rs"
CRYPTO_MOD="keystone-core/src/crypto/mod.rs"
CORE_ROOT="keystone-core/src/lib.rs"
failures=0
fail() { echo "BOUNDARY VIOLATION: $*" >&2; failures=$((failures + 1)); }

mapfile -t sources < <(git ls-files --cached --others --exclude-standard -- '*.rs' | grep -v '^fuzz/' | sort)

for file in "${sources[@]}"; do
  [[ -f "$file" ]] || continue
  # Rule 1: no `unsafe` keyword outside the FFI module (comments mentioning the word are allowed).
  if [[ "$file" != "$FFI" ]]; then
    if grep -nE '^[^/]*\bunsafe\b' "$file" | grep -vE 'unsafe_code' >/dev/null; then
      fail "$file uses 'unsafe' outside $FFI"
    fi
    if grep -nE 'allow\(\s*unsafe_code\s*\)' "$file" >/dev/null && [[ "$file" != "$CRYPTO_MOD" ]]; then
      fail "$file allows unsafe_code; only $CRYPTO_MOD may allow it, for $FFI only"
    fi
  fi
  # Rule 2: #![forbid(unsafe_code)] in every file except ffi.rs and its two parents
  # (crypto/mod.rs and the crate root, which instead denies unsafe_code crate-wide).
  if [[ "$file" == "$CORE_ROOT" ]]; then
    grep -qE '^#!\[deny\(unsafe_code\)\]' "$file" || fail "$file must deny unsafe_code crate-wide"
  elif [[ "$file" != "$FFI" && "$file" != "$CRYPTO_MOD" ]]; then
    if ! grep -qE '^#!\[forbid\(unsafe_code\)\]' "$file"; then
      fail "$file is missing #![forbid(unsafe_code)]"
    fi
  fi
  # Rule 3: OpenSSL only inside the crypto module.
  if [[ "$file" != keystone-core/src/crypto/* ]]; then
    if grep -nE '\b(openssl|openssl_sys)::' "$file" >/dev/null; then
      fail "$file calls OpenSSL outside keystone-core/src/crypto/"
    fi
  fi
  # Rule 4: no networking APIs.
  if grep -nE '\bstd::net\b|\bTcpStream\b|\bUdpSocket\b|\bTcpListener\b|rustix::net\b' "$file" >/dev/null; then
    fail "$file uses a networking API (HR-1)"
  fi
done

# crypto/mod.rs may contain only comments, attributes, mod and use lines.
if grep -nvE '^\s*(//.*)?$|^\s*#\[allow\(unsafe_code\)\]\s*$|^\s*(pub(\(crate\))? )?mod [a-z_0-9]+;\s*$|^\s*pub use [^;]+;\s*$' "$CRYPTO_MOD" >/dev/null; then
  fail "$CRYPTO_MOD must contain only module declarations and re-exports"
fi
# Only the ffi declaration may carry the allow attribute.
if [[ $(grep -cE 'allow\(unsafe_code\)' "$CRYPTO_MOD") -ne 1 ]] || ! grep -A1 -E 'allow\(unsafe_code\)' "$CRYPTO_MOD" | grep -qE '^\s*mod ffi;'; then
  fail "$CRYPTO_MOD must allow unsafe_code exactly once, on 'mod ffi;'"
fi
# Each unsafe block in the FFI module needs a SAFETY comment just above it.
if [[ -f "$FFI" ]]; then
  while IFS=: read -r line _; do
    start=$((line > 3 ? line - 3 : 1))
    if ! sed -n "${start},${line}p" "$FFI" | grep -q 'SAFETY:'; then
      fail "$FFI:$line unsafe block without a // SAFETY: comment in the 3 lines above"
    fi
  done < <(grep -nE '^\s*(pub(\(crate\))? )?unsafe \{|[=(] *unsafe \{|^\s*unsafe \{' "$FFI" || true)
fi

if [[ $failures -gt 0 ]]; then
  echo "$failures boundary violation(s)." >&2
  exit 1
fi
echo "Boundaries OK: unsafe only in $FFI, OpenSSL only in keystone-core/src/crypto/, no networking APIs."
