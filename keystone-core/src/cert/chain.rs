//! Chain files (FR-09 AC1).
#![forbid(unsafe_code)]

use super::CertError;
use super::parse::{CertificateInfo, parse_certificate_der};
use crate::crypto::verify::{certificate_der_to_pem, verify_certificate_signature};
use crate::model::CaLevel;

fn check_link(
    child: &CertificateInfo,
    child_der: &[u8],
    issuer: &CertificateInfo,
) -> Result<(), CertError> {
    if child.issuer_der != issuer.subject_der {
        return Err(CertError::ChainOrder(format!(
            "{} was not issued by {}",
            child.subject, issuer.subject
        )));
    }
    if child.authority_key_id.is_none() || child.authority_key_id != issuer.subject_key_id {
        return Err(CertError::ChainOrder(format!(
            "the key identifiers of {} and {} do not match",
            child.subject, issuer.subject
        )));
    }
    verify_certificate_signature(child_der, &issuer.spki_der)?;
    Ok(())
}

/// Builds `<name>-chain.pem`: the sub-intermediate, the main intermediate and the
/// master, in that order (FR-09 AC1). Each link is checked (issuer name, key
/// identifiers, signature verified with OpenSSL) and each certificate must have
/// the structure of its level.
pub fn chain_pem(sub_der: &[u8], main_der: &[u8], master_der: &[u8]) -> Result<String, CertError> {
    let sub = parse_certificate_der(sub_der)?;
    let main = parse_certificate_der(main_der)?;
    let master = parse_certificate_der(master_der)?;
    for (info, level) in [
        (&sub, CaLevel::SubIntermediate),
        (&main, CaLevel::MainIntermediate),
        (&master, CaLevel::Master),
    ] {
        if info.ca_level() != Some(level) {
            return Err(CertError::ChainOrder(format!(
                "{} is not a {} certificate",
                info.subject,
                level.display_name()
            )));
        }
    }
    check_link(&sub, sub_der, &main)?;
    check_link(&main, main_der, &master)?;
    verify_certificate_signature(master_der, &master.spki_der)?;
    let mut out = certificate_der_to_pem(sub_der)?;
    out.push_str(&certificate_der_to_pem(main_der)?);
    out.push_str(&certificate_der_to_pem(master_der)?);
    Ok(out)
}
