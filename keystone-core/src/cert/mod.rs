//! Certificate building, signing and parsing (FR-02, FR-07, FR-08, FR-09, FR-10,
//! FR-18, FR-21).
//!
//! - [`issue_ca_certificate`] builds a TBSCertificate exactly per the fixed profile,
//!   signs it through a [`Sha384Signer`] and verifies the result with OpenSSL.
//! - [`parse_certificate_der`] / [`parse_certificate_pem`] read certificates with
//!   strict size limits (SEC-08).
//! - [`chain_pem`] writes the chain file in the order sub, main, master (FR-09 AC1).
#![forbid(unsafe_code)]

mod chain;
pub mod encode;
mod issue;
mod parse;
mod signer;

pub use chain::chain_pem;
pub use issue::{
    CaCertificateRequest, IssuedCertificate, Issuer, MAX_SERIAL_ATTEMPTS, PlannedSerial,
    issue_ca_certificate, plan_serial,
};
pub use parse::{
    BasicConstraintsInfo, CertificateInfo, ConstraintName, KeyUsageInfo, NameConstraintsInfo,
    parse_certificate_der, parse_certificate_pem,
};
pub use signer::{Sha384Signer, SignError, SoftwareSigner};

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// An operator input broke a profile rule.
    #[error(transparent)]
    Profile(#[from] crate::profile::ProfileError),
    /// A crypto operation failed (including size limits and signature checks).
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// The key does not have the size the profile fixes for this level.
    #[error("a {level} key must be RSA {expected} bits, not {actual}")]
    WrongKeySize {
        /// Level display name.
        level: &'static str,
        /// Profile key size.
        expected: u32,
        /// Actual key size.
        actual: u32,
    },
    /// The key's public exponent is not 65537.
    #[error("the public exponent must be 65537, not {0}")]
    WrongExponent(u64),
    /// The request does not fit the hierarchy (wrong issuer, missing choice, ...).
    #[error("{0}")]
    Request(String),
    /// The validity was planned for another level than the certificate's (FR-10 AC3).
    #[error(
        "the validity was planned for a {}, not for a {}",
        .planned.display_name(),
        .level.display_name()
    )]
    ValidityPlannedForOtherLevel {
        /// The level the validity was planned for.
        planned: crate::model::CaLevel,
        /// The level of the certificate being issued.
        level: crate::model::CaLevel,
    },
    /// The subject name equals the issuer's name (FR-10 AC3).
    #[error("the subject name must differ from the issuer's name")]
    SubjectEqualsIssuer,
    /// The certificate would start before its issuer (FR-10 AC1).
    #[error(
        "the certificate would start at {not_before}, before its issuer ({issuer_not_before}); check the clock"
    )]
    StartsBeforeIssuer {
        /// Planned notBefore (RFC 3339).
        not_before: String,
        /// The issuer's notBefore (RFC 3339).
        issuer_not_before: String,
    },
    /// The signer's key is not the issuer's key.
    #[error("the signing key does not belong to the issuer certificate")]
    SignerKeyMismatch,
    /// No unused serial number was found (FR-10 AC2).
    #[error("could not find an unused serial number")]
    SerialSpaceExhausted,
    /// DER encoding failed.
    #[error("certificate encoding failed: {0}")]
    Encoding(String),
    /// A certificate could not be parsed.
    #[error("certificate could not be read: {0}")]
    Parse(String),
    /// Certificates are not a valid chain in the expected order.
    #[error("invalid chain: {0}")]
    ChainOrder(String),
}
