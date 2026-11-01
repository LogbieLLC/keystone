//! Top-level error type. Each module has its own typed error; this enum wraps them
//! so the GUI can show one clear message per failure (G3).
#![forbid(unsafe_code)]

/// Result alias used across the core crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Any failure in the core crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error(transparent)]
    Passphrase(#[from] crate::passphrase::PassphraseError),
    #[error(transparent)]
    Profile(#[from] crate::profile::ProfileError),
    #[error(transparent)]
    Cert(#[from] crate::cert::CertError),
    #[error(transparent)]
    Crl(#[from] crate::crl::CrlError),
    #[error(transparent)]
    Token(#[from] crate::token::TokenError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Clock(#[from] crate::clock::ClockError),
    #[error(transparent)]
    Hardening(#[from] crate::hardening::HardeningError),
    #[error(transparent)]
    Ops(#[from] crate::ops::OpsError),
}
