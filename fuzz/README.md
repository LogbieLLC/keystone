# Keystone fuzz targets (PRD SEC-08)

Four named targets, one per parser family, each run briefly on every pull request and for
a long time nightly in CI:

| Target | Parses |
| --- | --- |
| `pem_pkcs8` | PEM and encrypted PKCS#8, including decryption (`decrypt_key_pem`), and PEM certificate bundles |
| `cert_crl` | Certificates and CRLs, DER and PEM |
| `audit_journal` | The audit log and operation-journal entries |
| `issuance_record` | Issuance-record files, plus drive identity and binary-hash records |

This folder is a separate Cargo workspace with its own `Cargo.lock` and the pinned nightly
toolchain in `rust-toolchain.toml`; it is never part of the application.

```bash
cd fuzz
cargo fuzz run -O cert_crl corpus/cert_crl seeds/cert_crl -- -max_total_time=60
```

Every crash or hang becomes a regression test in `keystone-core` and its input is added to
`seeds/<target>/` (TESTING.md TEST-13).
