//! Errors from the crypto module.
#![forbid(unsafe_code)]

/// A failure inside the crypto module.
///
/// No variant ever carries secret material (key bytes, passphrases, PINs).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// OpenSSL reported an error. The text never contains secret material.
    #[error("OpenSSL operation failed: {0}")]
    OpenSsl(String),
    /// The secure random source failed.
    #[error("the operating system's secure random source failed")]
    Random,
    /// Memory for a secret could not be allocated and locked into RAM (SEC-07).
    #[error("could not lock memory for a secret; raise the memory-lock limit (RLIMIT_MEMLOCK)")]
    LockedMemory,
    /// A secret buffer would have to grow beyond its fixed capacity.
    #[error("secret is longer than its fixed buffer allows")]
    SecretCapacity,
    /// The operator cancelled the operation (FR-16). Nothing was produced.
    #[error("the operation was cancelled; nothing was produced")]
    Cancelled,
    /// The requested RSA key size is not one Keystone generates.
    #[error("unsupported RSA key size {bits}; Keystone uses 2,048 to 8,192 bits in steps of 1,024")]
    UnsupportedKeySize {
        /// The requested size.
        bits: u32,
    },
    /// The key is not an RSA key with the expected properties.
    #[error("unsupported key: {0}")]
    UnsupportedKey(String),
    /// Decryption failed: the passphrase is wrong or the file is damaged (FR-04 AC3).
    /// Nothing was decrypted and no partial output exists.
    #[error(
        "the passphrase is wrong or the key file is damaged; nothing was decrypted (check the words and try again)"
    )]
    WrongPassphrase,
    /// An empty passphrase was given. Keystone never encrypts with an empty passphrase.
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    /// A file or value is larger than the strict input limit (SEC-08).
    #[error("{what} is too large: {actual} bytes, the limit is {limit} bytes")]
    InputTooLarge {
        /// What was being read.
        what: &'static str,
        /// The limit from `crate::limits`.
        limit: usize,
        /// The actual size.
        actual: usize,
    },
    /// A PEM file is malformed or has an unexpected label.
    #[error("invalid PEM: {0}")]
    Pem(String),
    /// A DER structure (certificate, CRL, key) could not be parsed.
    #[error("invalid DER encoding: {0}")]
    Der(String),
    /// An encrypted key file uses other encryption parameters than the two sets
    /// Keystone writes (SEC-08). Refused before any key derivation runs, so a file
    /// with a raised KDF cost cannot hang decryption.
    #[error(
        "the key file uses encryption parameters Keystone does not write ({0}); Keystone reads only PBES2 with scrypt (N = 16384, r = 8, p = 1) or PBKDF2-HMAC-SHA256 (600,000 iterations), each with AES-256-CBC and a 16-byte salt and IV"
    )]
    UnsupportedKeyEncryption(String),
    /// A private key file is not encrypted. Keystone refuses plaintext keys (SEC-04).
    #[error("the key file is not encrypted; Keystone accepts only encrypted PKCS#8 keys")]
    NotEncrypted,
    /// A signature did not verify against the expected public key.
    #[error("signature verification failed: {0}")]
    BadSignature(String),
    /// Certificate chain verification failed.
    #[error(
        "certificate chain verification failed at depth {depth}: {reason} (OpenSSL error {code})"
    )]
    ChainInvalid {
        /// OpenSSL `X509_V_ERR_*` code.
        code: i32,
        /// Depth of the failing certificate (0 = leaf).
        depth: u32,
        /// OpenSSL's text for the code.
        reason: String,
    },
}

impl CryptoError {
    /// OpenSSL's `X509_V_ERR_CERT_REVOKED`.
    pub const X509_V_ERR_CERT_REVOKED: i32 = 23;

    /// True when chain verification failed because the certificate at `depth`
    /// is revoked (FR-13 AC5 wording: "certificate revoked" at that depth).
    pub fn is_revoked_at(&self, depth: u32) -> bool {
        matches!(
            self,
            CryptoError::ChainInvalid { code, depth: d, .. }
                if *code == Self::X509_V_ERR_CERT_REVOKED && *d == depth
        )
    }
}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(stack: openssl::error::ErrorStack) -> Self {
        CryptoError::OpenSsl(stack.to_string())
    }
}
