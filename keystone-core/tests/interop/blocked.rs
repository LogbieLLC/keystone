//! Tests that need StarnetAuth features that do not exist yet (PRD section 12).
//! They are compiled only with `--features blocked-tests` for the separate
//! "blocked tests" report job and always fail with `BLOCKED:` (TESTING.md
//! TEST-10). They are never counted as passing.
#![forbid(unsafe_code)]

#[cfg(feature = "blocked-tests")]
#[test]
fn fr13_ac5_crl_download_from_starnetauth() {
    // Covers: FR-13 AC5
    panic!(
        "BLOCKED: FR-13 AC5 needs `openssl verify -crl_check_all -crl_download` against CRLs \
         hosted by a StarnetAuth test instance; StarnetAuth CRL hosting (OQ-2) has not shipped. \
         The same two scenarios run with local CRL files in crl_cli.rs."
    );
}

#[cfg(feature = "blocked-tests")]
#[test]
fn fr09_ac3_starnetauth_encrypted_key_import() {
    // Covers: FR-09 AC3
    panic!(
        "BLOCKED: FR-09 AC3 needs StarnetAuth's encrypted-key import \
         (POST /api/v1/pki/ca/import with an encrypted PKCS#8 key and passphrase, OQ-1), \
         which has not shipped."
    );
}
