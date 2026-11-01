//! Certificate and CRL verification with OpenSSL, and DER/PEM conversion
//! (FR-07 AC5, FR-09 AC2, FR-13, SEC-13, SEC-23).
#![forbid(unsafe_code)]

use openssl::pkey::PKey;
use openssl::x509::{X509, X509Crl};
use time::OffsetDateTime;

use super::CryptoError;
use super::ffi::{self, ChainInput, ChainOutcome};
use super::pem;
use crate::limits::{MAX_CERT_DER_BYTES, MAX_CRL_BYTES, MAX_PEM_BYTES};

/// Whether chain verification checks revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationCheck {
    /// No CRL check.
    None,
    /// A CRL is required and checked for every certificate in the chain, like
    /// `openssl verify -crl_check_all`.
    CrlCheckAll,
}

/// Options for [`verify_chain`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// The time at which the chain must be valid.
    pub at: OffsetDateTime,
    /// Revocation checking.
    pub revocation: RevocationCheck,
    /// OpenSSL's RFC 5280 strict mode (`-x509_strict`).
    pub strict: bool,
}

impl VerifyOptions {
    /// Plain verification at `at`, no CRL check, strict RFC 5280 checks on.
    pub fn at(at: OffsetDateTime) -> Self {
        VerifyOptions {
            at,
            revocation: RevocationCheck::None,
            strict: true,
        }
    }
}

fn check_len(what: &'static str, len: usize, limit: usize) -> Result<(), CryptoError> {
    if len > limit {
        return Err(CryptoError::InputTooLarge {
            what,
            limit,
            actual: len,
        });
    }
    Ok(())
}

/// Verifies `leaf` up to one of `trusted` with OpenSSL's `X509_verify_cert`, using
/// `untrusted` as intermediates and, with [`RevocationCheck::CrlCheckAll`], `crls`.
///
/// Every input is DER. A failed verification is [`CryptoError::ChainInvalid`] with
/// OpenSSL's code and the failing depth (0 = leaf).
pub fn verify_chain(
    leaf: &[u8],
    untrusted: &[&[u8]],
    trusted: &[&[u8]],
    crls: &[&[u8]],
    options: &VerifyOptions,
) -> Result<(), CryptoError> {
    for der in std::iter::once(&leaf).chain(untrusted).chain(trusted) {
        check_len("certificate", der.len(), MAX_CERT_DER_BYTES)?;
    }
    for der in crls {
        check_len("CRL", der.len(), MAX_CRL_BYTES)?;
    }
    let input = ChainInput {
        leaf,
        untrusted,
        trusted,
        crls: match options.revocation {
            RevocationCheck::None => &[],
            RevocationCheck::CrlCheckAll => crls,
        },
        crl_check_all: options.revocation == RevocationCheck::CrlCheckAll,
        strict: options.strict,
        at_unix: options.at.unix_timestamp(),
    };
    match ffi::verify_chain(&input)? {
        ChainOutcome::Valid => Ok(()),
        ChainOutcome::Invalid {
            code,
            depth,
            reason,
        } => Err(CryptoError::ChainInvalid {
            code,
            depth: u32::try_from(depth).unwrap_or(0),
            reason,
        }),
    }
}

fn issuer_key(issuer_spki_der: &[u8]) -> Result<PKey<openssl::pkey::Public>, CryptoError> {
    check_len("public key", issuer_spki_der.len(), MAX_CERT_DER_BYTES)?;
    PKey::public_key_from_der(issuer_spki_der)
        .map_err(|e| CryptoError::Der(format!("public key: {e}")))
}

/// Verifies a certificate's signature with the issuer's public key (DER SPKI).
pub fn verify_certificate_signature(
    cert_der: &[u8],
    issuer_spki_der: &[u8],
) -> Result<(), CryptoError> {
    check_len("certificate", cert_der.len(), MAX_CERT_DER_BYTES)?;
    let cert =
        X509::from_der(cert_der).map_err(|e| CryptoError::Der(format!("certificate: {e}")))?;
    let key = issuer_key(issuer_spki_der)?;
    match cert.verify(&key) {
        Ok(true) => Ok(()),
        _ => Err(CryptoError::BadSignature(
            "the certificate signature does not verify with the issuer's public key".into(),
        )),
    }
}

/// Verifies a CRL's signature with the issuer's public key (DER SPKI).
pub fn verify_crl_signature(crl_der: &[u8], issuer_spki_der: &[u8]) -> Result<(), CryptoError> {
    check_len("CRL", crl_der.len(), MAX_CRL_BYTES)?;
    let crl = X509Crl::from_der(crl_der).map_err(|e| CryptoError::Der(format!("CRL: {e}")))?;
    let key = issuer_key(issuer_spki_der)?;
    match crl.verify(&key) {
        Ok(true) => Ok(()),
        _ => Err(CryptoError::BadSignature(
            "the CRL signature does not verify with the issuer's public key".into(),
        )),
    }
}

/// DER certificate to PEM (`CERTIFICATE`).
pub fn certificate_der_to_pem(der: &[u8]) -> Result<String, CryptoError> {
    check_len("certificate", der.len(), MAX_CERT_DER_BYTES)?;
    Ok(pem::encode(pem::LABEL_CERTIFICATE, der))
}

/// One PEM certificate to DER.
pub fn certificate_pem_to_der(text: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len("certificate PEM file", text.len(), MAX_PEM_BYTES)?;
    let der = pem::decode_one(text, pem::LABEL_CERTIFICATE, MAX_PEM_BYTES)?;
    check_len("certificate", der.len(), MAX_CERT_DER_BYTES)?;
    Ok(der)
}

/// One or more PEM certificates (a chain file) to DER, in file order.
pub fn certificates_pem_to_der(text: &[u8]) -> Result<Vec<Vec<u8>>, CryptoError> {
    check_len("certificate PEM file", text.len(), MAX_PEM_BYTES)?;
    let all = pem::decode_all(text, pem::LABEL_CERTIFICATE, MAX_PEM_BYTES)?;
    for der in &all {
        check_len("certificate", der.len(), MAX_CERT_DER_BYTES)?;
    }
    Ok(all)
}

/// DER CRL to PEM (`X509 CRL`).
pub fn crl_der_to_pem(der: &[u8]) -> Result<String, CryptoError> {
    check_len("CRL", der.len(), MAX_CRL_BYTES)?;
    Ok(pem::encode(pem::LABEL_CRL, der))
}

/// PEM CRL to DER.
pub fn crl_pem_to_der(text: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_len("CRL file", text.len(), MAX_CRL_BYTES)?;
    pem::decode_one(text, pem::LABEL_CRL, MAX_CRL_BYTES)
}
