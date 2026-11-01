//! A complete test CA hierarchy built through keystone-core's public API:
//! master (software RSA 8,192) -> main intermediate (on a `SimulatedYubiKey`) ->
//! sub-intermediate (software RSA 4,096), each issuer with its first empty CRL.
#![forbid(unsafe_code)]

use keystone_core::cert::{
    CaCertificateRequest, IssuedCertificate, Issuer, SoftwareSigner, issue_ca_certificate,
    plan_serial,
};
use keystone_core::crl::{IssuedCrl, first_crl};
use keystone_core::crypto::RsaPrivateKey;
use keystone_core::crypto::secret::SecretString;
use keystone_core::model::CaLevel;
use keystone_core::profile::{
    CrlLocation, CrlUrl, NameConstraintsChoice, NameConstraintsSpec, ValidatedName, plan_validity,
};
use keystone_core::token::{
    AttestationExpectation, SIGNING_SLOT, TokenCaSigner, TokenSigner, check_firmware,
    ensure_hardened, ensure_slot_empty, verify_piv_attestation,
};
use time::OffsetDateTime;

use crate::keys;
use crate::names::test_name;
use crate::simulator::{SimulatedYubiKey, SimulatorConfig, harden};

/// The PIN every test hierarchy's simulated YubiKey ends up with.
pub const TEST_PIN: &str = "KsT#2468";
/// The PUK every test hierarchy's simulated YubiKey ends up with.
pub const TEST_PUK: &str = "KsT#9753";
/// CRL address written into main intermediates.
pub const MASTER_CRL_URL: &str = "http://crl.keystone.test/master.crl";
/// CRL address written into sub-intermediates.
pub const MAIN_CRL_URL: &str = "http://crl.keystone.test/main.crl";

/// Options for [`TestHierarchy::build`].
#[derive(Debug, Clone)]
pub struct HierarchyOptions {
    /// Which cached master key (`keys::master`).
    pub master_key_index: usize,
    /// Which cached RSA 4,096 key for the sub-intermediate (`keys::rsa4096`).
    pub sub_key_index: usize,
    /// Label inside every Common Name, to tell hierarchies apart.
    pub label: String,
    /// Permitted DNS names for the sub-intermediate.
    pub permitted_dns: Vec<String>,
    /// Permitted IP ranges for the sub-intermediate.
    pub permitted_ip: Vec<String>,
    /// Build the sub-intermediate without name constraints (explicit choice).
    pub unconstrained_sub: bool,
    /// Simulator settings.
    pub simulator: SimulatorConfig,
}

impl Default for HierarchyOptions {
    fn default() -> Self {
        HierarchyOptions {
            master_key_index: 0,
            sub_key_index: 0,
            label: "A".to_owned(),
            permitted_dns: vec!["starnet".to_owned()],
            permitted_ip: Vec::new(),
            unconstrained_sub: false,
            simulator: SimulatorConfig::default(),
        }
    }
}

/// A built hierarchy.
#[derive(Debug)]
pub struct TestHierarchy {
    /// Master key.
    pub master_key: &'static RsaPrivateKey,
    /// Master certificate.
    pub master: IssuedCertificate,
    /// Master's first CRL.
    pub master_crl: IssuedCrl,
    /// The simulated YubiKey holding the main intermediate key and certificate.
    pub token: SimulatedYubiKey,
    /// Main intermediate certificate.
    pub main: IssuedCertificate,
    /// Main intermediate's first CRL.
    pub main_crl: IssuedCrl,
    /// Sub-intermediate key.
    pub sub_key: &'static RsaPrivateKey,
    /// Sub-intermediate certificate.
    pub sub: IssuedCertificate,
}

fn secret(text: &str) -> SecretString {
    SecretString::from_str_copy(text).expect("locked memory")
}

/// The PIN of test hierarchies, as a secret.
pub fn test_pin() -> SecretString {
    secret(TEST_PIN)
}

impl TestHierarchy {
    /// Builds a fresh hierarchy (new certificates, serials and simulated device)
    /// following Flows A, B and C through keystone-core.
    pub fn build(options: &HierarchyOptions) -> TestHierarchy {
        let now = OffsetDateTime::now_utc();
        let mut serials = std::collections::HashSet::new();
        let mut next_serial = || {
            let planned = plan_serial(&mut |s| serials.contains(s)).expect("serial");
            serials.insert(planned.serial());
            planned
        };

        // Flow A: master.
        let master_key = keys::master(options.master_key_index);
        let master_spki = master_key.public_key_spki_der().expect("master key");
        let master_name =
            ValidatedName::new(&test_name(&format!("{} Master", options.label))).expect("name");
        let master = issue_ca_certificate(
            &CaCertificateRequest {
                level: CaLevel::Master,
                subject: &master_name,
                subject_public_key_der: &master_spki,
                validity: plan_validity(CaLevel::Master, 20, now, None).expect("validity"),
                serial: next_serial(),
                issuer: Issuer::SelfSigned,
                issuer_crl: None,
                name_constraints: None,
            },
            &mut SoftwareSigner::new(master_key),
        )
        .expect("master certificate");
        let master_crl =
            first_crl(&master.der, now, &mut SoftwareSigner::new(master_key)).expect("master CRL");

        // Flow B: YubiKey and main intermediate.
        let mut token = SimulatedYubiKey::new(options.simulator);
        let device = token.device_info().expect("device info");
        check_firmware(&device).expect("firmware");
        harden(&mut token, TEST_PIN, TEST_PUK).expect("hardening");
        let pin = test_pin();
        let report = token.reopen_and_verify_hardening(&pin).expect("re-verify");
        keystone_core::token::check_hardening_report(&report).expect("hardened");
        ensure_hardened(&token.credential_status().expect("status")).expect("hardened");
        ensure_slot_empty(&token.slot_status(SIGNING_SLOT).expect("slot")).expect("empty slot");
        let main_spki = token.generate_signing_key(&pin).expect("on-device key");
        let attestation = token.attest_signing_key().expect("attestation");
        verify_piv_attestation(
            &token.attestation_trust(),
            &attestation,
            &AttestationExpectation {
                device: &device,
                public_key_der: &main_spki,
            },
            now,
        )
        .expect("attestation verifies");
        let main_name =
            ValidatedName::new(&test_name(&format!("{} Main", options.label))).expect("name");
        let master_crl_location = CrlLocation::Url(CrlUrl::parse(MASTER_CRL_URL).expect("url"));
        let main = issue_ca_certificate(
            &CaCertificateRequest {
                level: CaLevel::MainIntermediate,
                subject: &main_name,
                subject_public_key_der: &main_spki,
                validity: plan_validity(
                    CaLevel::MainIntermediate,
                    10,
                    now,
                    Some(master.info.not_after),
                )
                .expect("validity"),
                serial: next_serial(),
                issuer: Issuer::Certificate(&master.der),
                issuer_crl: Some(&master_crl_location),
                name_constraints: None,
            },
            &mut SoftwareSigner::new(master_key),
        )
        .expect("main certificate");
        token
            .write_signing_certificate(&pin, &main.der)
            .expect("store certificate");
        let main_crl =
            first_crl(&main.der, now, &mut TokenCaSigner::new(&mut token, &pin)).expect("main CRL");

        // Flow C: sub-intermediate.
        let sub_key = keys::rsa4096(options.sub_key_index);
        let sub_spki = sub_key.public_key_spki_der().expect("sub key");
        let sub_name =
            ValidatedName::new(&test_name(&format!("{} Sub", options.label))).expect("name");
        let choice = if options.unconstrained_sub {
            NameConstraintsChoice::ExplicitlyUnconstrained
        } else {
            NameConstraintsChoice::Constrained(
                NameConstraintsSpec::new(&options.permitted_dns, &options.permitted_ip)
                    .expect("constraints"),
            )
        };
        let main_crl_location = CrlLocation::Url(CrlUrl::parse(MAIN_CRL_URL).expect("url"));
        let sub = issue_ca_certificate(
            &CaCertificateRequest {
                level: CaLevel::SubIntermediate,
                subject: &sub_name,
                subject_public_key_der: &sub_spki,
                validity: plan_validity(
                    CaLevel::SubIntermediate,
                    5,
                    now,
                    Some(main.info.not_after),
                )
                .expect("validity"),
                serial: next_serial(),
                issuer: Issuer::Certificate(&main.der),
                issuer_crl: Some(&main_crl_location),
                name_constraints: Some(&choice),
            },
            &mut TokenCaSigner::new(&mut token, &pin),
        )
        .expect("sub certificate");

        TestHierarchy {
            master_key,
            master,
            master_crl,
            token,
            main,
            main_crl,
            sub_key,
            sub,
        }
    }
}
