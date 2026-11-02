# Keystone fuzz targets (PRD SEC-08)

Named targets, one per parser family, each run briefly on every pull request in CI; the
first four also run for a long time nightly:

| Target | Parses |
| --- | --- |
| `pem_pkcs8` | PEM and encrypted PKCS#8, including decryption (`decrypt_key_pem`), and PEM certificate bundles |
| `cert_crl` | Certificates and CRLs, DER and PEM |
| `audit_journal` | The audit log and operation-journal entries |
| `issuance_record` | Issuance-record files, plus drive identity and binary-hash records |
| `pkcs8_key_decode` | The plaintext PKCS#8 `PrivateKeyInfo` that decryption hands to the RSA key decoder, without the key derivation in front of it |

`pkcs8_key_decode` calls `keystone_core::crypto::pkcs8::fuzz_decode_private_key_info`, which
is compiled only with `--cfg fuzzing` (set by `cargo fuzz`) and never with the `production`
feature.

Seeds that reach the key decoder:
- `seeds/pem_pkcs8/valid-scrypt.pem` and `valid-pbkdf2.pem`: synthetic RSA 2,048 keys from
  `keystone-testkit`, encrypted by Keystone with the target's passphrase
  `keystone fuzz passphrase` (master and sub-intermediate parameters).
- `seeds/pkcs8_key_decode/textbook-rsa.der` (the textbook p = 61, q = 53 example) and
  `rsa2048-shape.der` (the field sizes of an RSA 2,048 key filled with fixed pseudo-random
  numbers): unencrypted `PrivateKeyInfo` structures that are not usable keys.
- `seeds/pkcs8_key_decode/lsan-first-signature.der`: the first finding of the target, a
  LeakSanitizer report that was not a Keystone leak. The target then also signed with the
  decoded key; the first signature creates OpenSSL's random generator (for RSA blinding),
  whose context lives in the secure heap, which LeakSanitizer does not scan, so everything
  the generator owns looked leaked. Creating the generator before fuzzing did not help
  (the leak check reports it whenever it runs), so the target no longer signs. Signing
  with a malformed decrypted key is therefore not fuzzed.

This folder is a separate Cargo workspace with its own `Cargo.lock` and the pinned nightly
toolchain in `rust-toolchain.toml`; it is never part of the application.

```bash
cd fuzz
cargo fuzz run -O cert_crl corpus/cert_crl seeds/cert_crl -- -max_total_time=60
```

Every crash or hang becomes a regression test in `keystone-core` and its input is added to
`seeds/<target>/` (TESTING.md TEST-13).
