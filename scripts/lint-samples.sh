#!/usr/bin/env bash
# RFC 5280 lint of every certificate and CRL Keystone produces (PRD FR-10 AC4, SEC-13;
# docs/adr/0002-rfc5280-lint-tools.md).
#   certificates: zlint (RFC 5280 / RFC 5480 / RFC 5891 rules only; CA/B Forum web-PKI
#                 rules do not apply to a private CA)
#   CRLs:         pkilint lint_crl, PKIX profile
# Usage: scripts/lint-samples.sh <samples dir>
# Requires `zlint` and `lint_crl` on PATH (CI installs the pinned versions).
set -euo pipefail
if [[ $# -ne 1 || ! -d "$1" ]]; then
  echo "usage: $0 <samples dir produced by: cargo run -p keystone-testkit --example generate_samples -- DIR>" >&2
  exit 2
fi
samples="$1"
failures=0

mapfile -t certs < <(find "$samples" -type f -name '*.crt' | sort)
mapfile -t crls < <(find "$samples" -type f -name '*.crl' | sort)
if [[ ${#certs[@]} -eq 0 || ${#crls[@]} -eq 0 ]]; then
  echo "no certificates or CRLs found in $samples" >&2
  exit 1
fi

for cert in "${certs[@]}"; do
  findings=$(zlint -includeSources RFC5280,RFC5480,RFC5891 "$cert" | python3 -c '
import json, sys
results = json.load(sys.stdin)
bad = sorted(name + ": " + str(r.get("details", "")) for name, r in results.items()
             if r.get("result") in ("error", "warn", "fatal"))
passed = sum(1 for r in results.values() if r.get("result") == "pass")
if passed == 0:
    bad.append("no lint passed - is the certificate readable?")
print("\n".join(bad))
')
  if [[ -n "$findings" ]]; then
    echo "LINT FAIL (zlint) $cert:" >&2
    echo "$findings" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  else
    echo "lint ok (zlint RFC 5280): $cert"
  fi
done

for crl in "${crls[@]}"; do
  if output=$(lint_crl lint -t CRL -p PKIX -s WARNING "$crl" 2>&1) && [[ -z "${output//[[:space:]]/}" ]]; then
    echo "lint ok (pkilint PKIX CRL): $crl"
  else
    echo "LINT FAIL (pkilint) $crl:" >&2
    echo "$output" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  fi
done

if [[ $failures -gt 0 ]]; then
  echo "$failures file(s) failed the RFC 5280 lint." >&2
  exit 1
fi
echo "RFC 5280 lint passed: ${#certs[@]} certificates, ${#crls[@]} CRLs."
