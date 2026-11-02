//! FR-18 AC2: the CRL address is only written into certificates, never contacted.
//!
//! The issuance runs in a child process (this unit-test binary run again, as the
//! SEC-03 tests do) with the production socket filter installed: no socket other
//! than AF_UNIX can be created there, so any attempt to reach the address would
//! fail. Issuance must still succeed and write the address exactly as entered.
//!
//! These are unit tests because the socket filter is compiled only into production
//! builds and this crate's own tests. The keys come from keystone-testkit (TEST-11);
//! the test kit links the library build of keystone-core, whose key type differs
//! from this test build's, so only bytes and closures cross between them.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::process::Command;

use time::{Duration, OffsetDateTime};

use super::*;
use crate::cert::SignError;
use crate::crypto::CryptoError;
use crate::hardening::{child, seccomp};
use crate::model::NameFields;
use crate::profile::{CrlUrl, plan_validity};

/// An address as an operator might type it: unusual but valid, so any rewriting
/// (case, port, percent-encoding, query) would show. `.test` is reserved (RFC 2606),
/// so it can never resolve.
const CRL_URL: &str = "http://CRL.Keystone.TEST:8080/pki/Main%20CA.crl?v=1&x=%7e";

/// Signs `message` with a keystone-testkit key; errors as text.
type SignFn = dyn Fn(&[u8]) -> Result<Vec<u8>, String>;

/// A signer around a keystone-testkit key, through a closure.
struct TestkitSigner<'a> {
    public_key_der: Vec<u8>,
    sign: &'a SignFn,
}

impl Sha384Signer for TestkitSigner<'_> {
    fn signer_public_key_der(&mut self) -> Result<Vec<u8>, SignError> {
        Ok(self.public_key_der.clone())
    }

    fn sign_sha384(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        (self.sign)(message).map_err(|e| SignError::Crypto(CryptoError::OpenSsl(e)))
    }
}

fn name(common_name: &str) -> ValidatedName {
    ValidatedName::new(&NameFields {
        common_name: common_name.to_owned(),
        organization: None,
        country: None,
    })
    .expect("test name")
}

/// Issues a sub-intermediate under a test main intermediate, with [`CRL_URL`] as the
/// main intermediate's CRL address.
fn issue_with_crl_url() -> IssuedCertificate {
    use keystone_testkit::x509::{TestCertSpec, TestIssuer, build_test_certificate, cn_name_der};

    let main_key = keystone_testkit::keys::rsa4096(0);
    let main_spki = main_key.public_key_spki_der().expect("main key");
    let now = OffsetDateTime::now_utc();
    // A main intermediate (path length 1, not self-issued) holding `main_key`. Its own
    // signature is irrelevant here, so `main_key` signs it under a stand-in name.
    let main = build_test_certificate(&TestCertSpec {
        subject_der: cn_name_der("KEYSTONE TEST FR-18 Main"),
        subject_public_key_der: main_spki.clone(),
        issuer: Some(TestIssuer {
            name_der: &cn_name_der("KEYSTONE TEST FR-18 Master"),
            key: main_key,
        }),
        self_key: None,
        not_before: now - Duration::days(1),
        not_after: now + Duration::days(365 * 10),
        extensions: keystone_testkit::x509::test_ca_extensions(&main_spki, Some(1)),
    });
    let main_info = parse_certificate_der(&main).expect("main certificate");
    let sub_spki = keystone_testkit::keys::rsa4096(1)
        .public_key_spki_der()
        .expect("sub key");
    let subject = name("KEYSTONE TEST FR-18 Sub");
    let crl = CrlLocation::Url(CrlUrl::parse(CRL_URL).expect("valid address"));
    let constraints = NameConstraintsChoice::Constrained(
        NameConstraintsSpec::new(&["starnet"], &[] as &[&str]).expect("constraints"),
    );
    let request = CaCertificateRequest {
        level: CaLevel::SubIntermediate,
        subject: &subject,
        subject_public_key_der: &sub_spki,
        validity: plan_validity(CaLevel::SubIntermediate, 5, now, Some(main_info.not_after))
            .expect("validity"),
        serial: plan_serial(&mut |_| false).expect("serial"),
        issuer: Issuer::Certificate(&main),
        issuer_crl: Some(&crl),
        name_constraints: Some(&constraints),
    };
    let sign = |message: &[u8]| {
        main_key
            .sign_sha384_pkcs1(message)
            .map_err(|e| e.to_string())
    };
    let mut signer = TestkitSigner {
        public_key_der: main_spki,
        sign: &sign,
    };
    issue_ca_certificate(&request, &mut signer).expect("issuance under the socket filter")
}

/// What a non-local socket attempt gives in this process: `ok` or the errno.
fn inet_socket_attempt() -> String {
    let output = Command::new("perl")
        .args([
            "-e",
            "use Socket; print socket(my $s, AF_INET, SOCK_STREAM, 0) ? 'ok' : ($! + 0)",
        ])
        .output()
        .expect("perl (Ubuntu's perl-base) must be installed");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Child half of `fr18_ac2_the_crl_address_is_written_verbatim_and_never_contacted`.
#[test]
fn fr18_ac2_child() {
    let Some(dir) = child::child_dir() else {
        assert_eq!(
            CrlUrl::parse(CRL_URL).expect("valid address").as_str(),
            CRL_URL
        );
        return;
    };
    seccomp::install_socket_filter().expect("socket filter");
    let mode = seccomp::seccomp_mode().expect("seccomp mode");
    let inet = inet_socket_attempt();
    let issued = issue_with_crl_url();
    let report = [
        format!("seccomp={mode}"),
        format!("inet_socket={inet}"),
        format!("urls={}", issued.info.crl_distribution_urls.join(" ")),
        format!(
            "der_contains_url={}",
            issued
                .der
                .windows(CRL_URL.len())
                .any(|window| window == CRL_URL.as_bytes())
        ),
    ];
    std::fs::write(dir.join("fr18.txt"), report.join("\n")).expect("write report");
}

#[test]
fn fr18_ac2_the_crl_address_is_written_verbatim_and_never_contacted() {
    // Covers: FR-18 AC2, FR-18 AC1
    let dir = tempfile::tempdir().expect("tempdir");
    child::run("cert::issue::tests::fr18_ac2_child", dir.path());
    let text = std::fs::read_to_string(dir.path().join("fr18.txt")).expect("report");
    let report: BTreeMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    // The issuance ran with the socket filter active ...
    assert_eq!(report.get("seccomp"), Some(&"2"), "{text}");
    // ... where no network socket can be created (EAFNOSUPPORT) ...
    assert_eq!(report.get("inet_socket"), Some(&"97"), "{text}");
    // ... and it succeeded, writing the address exactly as entered.
    assert_eq!(report.get("urls"), Some(&CRL_URL), "{text}");
    assert_eq!(report.get("der_contains_url"), Some(&"true"), "{text}");
}
