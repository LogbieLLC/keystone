//! Strict PEM (RFC 7468) encoding and decoding.
//!
//! Decoding accepts only the expected label, standard base64 in lines, LF or CRLF
//! line endings, and nothing but whitespace outside the blocks. Headers (as in legacy
//! `Proc-Type` keys) and non-canonical base64 are rejected. The caller checks the
//! file size against `crate::limits` first (SEC-08); these functions check it again.
#![forbid(unsafe_code)]

use super::CryptoError;

/// PEM label of a certificate.
pub const LABEL_CERTIFICATE: &str = "CERTIFICATE";
/// PEM label of a CRL.
pub const LABEL_CRL: &str = "X509 CRL";
/// PEM label of an encrypted PKCS#8 private key, the only private-key form
/// Keystone writes or reads (SEC-04).
pub const LABEL_ENCRYPTED_PRIVATE_KEY: &str = "ENCRYPTED PRIVATE KEY";

const LINE_WIDTH: usize = 64;

/// Encodes `der` as one PEM block with 64-character lines and a final newline.
pub fn encode(label: &str, der: &[u8]) -> String {
    let body = openssl::base64::encode_block(der);
    let mut out =
        String::with_capacity(body.len() + body.len() / LINE_WIDTH + 2 * label.len() + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in body.as_bytes().chunks(LINE_WIDTH) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Decodes exactly one PEM block with `label`; anything else in `text` except
/// whitespace is an error.
pub fn decode_one(text: &[u8], label: &str, max_bytes: usize) -> Result<Vec<u8>, CryptoError> {
    let mut blocks = decode_all(text, label, max_bytes)?;
    if blocks.len() != 1 {
        return Err(CryptoError::Pem(format!(
            "expected exactly one {label} block, found {}",
            blocks.len()
        )));
    }
    Ok(blocks.remove(0))
}

/// Decodes one or more consecutive PEM blocks, all with `label`.
pub fn decode_all(text: &[u8], label: &str, max_bytes: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
    if text.len() > max_bytes {
        return Err(CryptoError::InputTooLarge {
            what: "PEM file",
            limit: max_bytes,
            actual: text.len(),
        });
    }
    let text = std::str::from_utf8(text)
        .map_err(|_| CryptoError::Pem("the file is not text (UTF-8)".into()))?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut body: Option<String> = None;
    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        match body.as_mut() {
            None => {
                if line.trim().is_empty() {
                    continue;
                }
                if line == begin {
                    body = Some(String::new());
                } else if line.starts_with("-----BEGIN ") {
                    return Err(CryptoError::Pem(format!(
                        "unexpected block {line:?}; expected {begin:?}"
                    )));
                } else {
                    return Err(CryptoError::Pem("text outside a PEM block".into()));
                }
            }
            Some(current) => {
                if line == end {
                    let encoded = std::mem::take(current);
                    body = None;
                    blocks.push(decode_base64(&encoded)?);
                } else if line.starts_with("-----") {
                    return Err(CryptoError::Pem(format!(
                        "unexpected line {line:?} in a {label} block"
                    )));
                } else if line.contains(':') {
                    return Err(CryptoError::Pem("PEM headers are not accepted".into()));
                } else {
                    current.push_str(line);
                }
            }
        }
    }
    if body.is_some() {
        return Err(CryptoError::Pem(format!("missing {end:?}")));
    }
    if blocks.is_empty() {
        return Err(CryptoError::Pem(format!("no {begin:?} block found")));
    }
    Ok(blocks)
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(4) {
        return Err(CryptoError::Pem("base64 body has an invalid length".into()));
    }
    let valid = encoded
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    if !valid {
        return Err(CryptoError::Pem(
            "base64 body contains invalid characters".into(),
        ));
    }
    let decoded = openssl::base64::decode_block(encoded)
        .map_err(|_| CryptoError::Pem("base64 body could not be decoded".into()))?;
    // Canonical form only: re-encoding must give back exactly the input.
    if openssl::base64::encode_block(&decoded) != encoded {
        return Err(CryptoError::Pem("base64 body is not canonical".into()));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trip_and_line_width() {
        let der: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let pem = encode(LABEL_CERTIFICATE, &der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(
            pem.lines()
                .all(|line| line.len() <= 64 || line.starts_with("-----"))
        );
        assert_eq!(
            decode_one(pem.as_bytes(), LABEL_CERTIFICATE, 1 << 20).unwrap(),
            der
        );
        let crlf = pem.replace('\n', "\r\n");
        assert_eq!(
            decode_one(crlf.as_bytes(), LABEL_CERTIFICATE, 1 << 20).unwrap(),
            der
        );
    }

    #[test]
    fn sec08_pem_rejects_wrong_label_extra_text_headers_and_size() {
        // Covers: SEC-08
        let pem = encode(LABEL_CERTIFICATE, b"abc");
        assert!(decode_one(pem.as_bytes(), LABEL_CRL, 1 << 20).is_err());
        let with_text = format!("hello\n{pem}");
        assert!(decode_one(with_text.as_bytes(), LABEL_CERTIFICATE, 1 << 20).is_err());
        let with_header = pem.replace("-----\n", "-----\nProc-Type: 4,ENCRYPTED\n");
        assert!(decode_one(with_header.as_bytes(), LABEL_CERTIFICATE, 1 << 20).is_err());
        assert!(matches!(
            decode_one(pem.as_bytes(), LABEL_CERTIFICATE, 10),
            Err(CryptoError::InputTooLarge { .. })
        ));
        let truncated = &pem[..pem.len() - 10];
        assert!(decode_one(truncated.as_bytes(), LABEL_CERTIFICATE, 1 << 20).is_err());
        let two = format!("{pem}{pem}");
        assert!(decode_one(two.as_bytes(), LABEL_CERTIFICATE, 1 << 20).is_err());
        assert_eq!(
            decode_all(two.as_bytes(), LABEL_CERTIFICATE, 1 << 20)
                .unwrap()
                .len(),
            2
        );
        let bad_char = pem.replace("YWJj", "YW*j");
        assert!(decode_one(bad_char.as_bytes(), LABEL_CERTIFICATE, 1 << 20).is_err());
    }
}
