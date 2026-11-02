//! Helpers for the operations-layer tests: temporary drives (TEST-12), confirmed
//! passphrases, confirmed times, cached test keys (TEST-11) and whole flows.
#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use keystone_core::clock;
use keystone_core::crypto::CancelFlag;
use keystone_core::crypto::secret::SecretString;
use keystone_core::crypto::verify::{RevocationCheck, VerifyOptions, verify_chain};
use keystone_core::model::Serial;
use keystone_core::ops::{
    Ca, ConfirmedTime, CreateMasterOutcome, CreateMasterRequest, MainIntermediateOutcome,
    MainIntermediateRequest, NoProgress, PinEntry, RecoveryAction, RecoverySecrets,
    SubIntermediateOutcome, SubIntermediatePlan, SubIntermediateRequest, YubikeySecrets,
    assess_clock_for_new_ca, inspect_yubikey, plan_create_master, testing,
};
use keystone_core::passphrase::{ConfirmedPassphrase, EnteredPassphrase, NewPassphrase};
use keystone_core::profile::{CrlLocation, CrlUrl, NameConstraintsChoice, NameConstraintsSpec};
use keystone_core::store::{DriveComparison, OperationState, RecordSource, SignedObject};
use keystone_core::token::TokenSigner;
use keystone_core::token::{NewPin, NewPuk};
use keystone_testkit::names::test_name;
use keystone_testkit::{SimController, SimulatedYubiKey, SimulatorConfig, TestDrives, keys};
use time::{Duration, OffsetDateTime};

/// The PIN every test YubiKey gets.
pub const PIN: &str = "KsT#2468";
/// The PUK every test YubiKey gets.
pub const PUK: &str = "KsT#9753";
/// CRL address of the master.
pub const MASTER_CRL_URL: &str = "http://crl.keystone.test/master.crl";
/// CRL address of a main intermediate.
pub const MAIN_CRL_URL: &str = "http://crl.keystone.test/main.crl";

pub fn s(text: &str) -> SecretString {
    SecretString::from_str_copy(text).expect("locked memory")
}

/// A start time: now, in whole seconds (the simulator's attestation certificates are
/// valid around the real time).
pub fn base_time() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0).expect("whole seconds")
}

/// A confirmed time for a new CA (Flow A).
pub fn confirmed_new(at: OffsetDateTime) -> ConfirmedTime {
    clock::confirm(&assess_clock_for_new_ca(at), false).expect("time confirms")
}

/// A confirmed time for an existing CA.
pub fn confirmed(ca: &Ca, at: OffsetDateTime) -> ConfirmedTime {
    clock::confirm(&ca.assess_clock(at), false).expect("time confirms")
}

fn confirm_words(words: NewPassphrase) -> (ConfirmedPassphrase, String) {
    let text: Vec<&str> = (1..=words.word_count())
        .map(|n| words.word(n).expect("word"))
        .collect();
    let text = text.join(" ");
    let mut session = words.into_confirmation();
    session.set_written_down(true);
    for (index, word) in text.split(' ').enumerate() {
        session.enter_word(index + 1, word).expect("list word");
    }
    for group in 1..=session.group_count() {
        session.check_group(group).expect("check");
    }
    (session.finish().expect("confirmed"), text)
}

/// A confirmed 10-word master passphrase and its words (for unlocking later).
pub fn master_passphrase() -> (ConfirmedPassphrase, String) {
    confirm_words(NewPassphrase::generate_master(10).expect("passphrase"))
}

/// A confirmed sub-intermediate passphrase and its words.
pub fn sub_passphrase() -> (ConfirmedPassphrase, String) {
    confirm_words(NewPassphrase::generate_sub_intermediate().expect("passphrase"))
}

pub fn entered(words: &str) -> EnteredPassphrase {
    EnteredPassphrase::parse(words).expect("passphrase")
}

pub fn master_crl() -> CrlLocation {
    CrlLocation::Url(CrlUrl::parse(MASTER_CRL_URL).expect("url"))
}

pub fn main_crl() -> CrlLocation {
    CrlLocation::Url(CrlUrl::parse(MAIN_CRL_URL).expect("url"))
}

pub fn constrained(dns: &[&str]) -> NameConstraintsChoice {
    NameConstraintsChoice::Constrained(
        NameConstraintsSpec::new(dns, &[] as &[&str]).expect("constraints"),
    )
}

pub fn token(serial: u32) -> (SimulatedYubiKey, SimController) {
    let token = SimulatedYubiKey::new(SimulatorConfig {
        serial,
        ..SimulatorConfig::default()
    });
    let controller = token.controller();
    (token, controller)
}

/// Secrets for a factory-fresh YubiKey.
pub fn fresh_secrets(master: &EnteredPassphrase) -> YubikeySecrets<'_> {
    YubikeySecrets {
        pin: PinEntry::New(NewPin::from_entries(&s(PIN), &s(PIN)).expect("pin")),
        new_puk: Some(NewPuk::from_entries(&s(PUK), &s(PUK)).expect("puk")),
        master_passphrase: Some(master),
    }
}

/// Secrets for a YubiKey whose PIN and PUK were already changed.
pub fn current_secrets(master: Option<&EnteredPassphrase>) -> YubikeySecrets<'_> {
    YubikeySecrets {
        pin: PinEntry::Current(s(PIN)),
        new_puk: None,
        master_passphrase: master,
    }
}

/// A CA under construction in temporary drives.
pub struct TestCa {
    pub drives: TestDrives,
    pub ca: Ca,
    pub master_words: String,
    /// The time of the last operation; every later step uses a later time.
    pub now: OffsetDateTime,
    pub master: CreateMasterOutcomeSummary,
}

/// What a test keeps from Flow A.
#[derive(Debug, Clone)]
pub struct CreateMasterOutcomeSummary {
    pub serial: Serial,
    pub fingerprint_text: String,
}

impl TestCa {
    /// The next operation time (one minute after the last).
    pub fn tick(&mut self) -> ConfirmedTime {
        self.now += Duration::minutes(1);
        confirmed(&self.ca, self.now)
    }

    /// Re-opens the CA from its drives, as after a restart.
    pub fn reopen(&mut self) {
        testing::reset();
        let roots: Vec<&Path> = self
            .drives
            .ca_drives()
            .iter()
            .map(PathBuf::as_path)
            .collect();
        self.ca = Ca::open(&roots).expect("reopen");
    }

    pub fn master_entered(&self) -> EnteredPassphrase {
        entered(&self.master_words)
    }

    pub fn export(&self) -> &Path {
        self.drives.export_drive()
    }
}

/// Flow A on two new temporary drives with the cached master key.
pub fn new_ca(label: &str) -> TestCa {
    new_ca_with(label, 2, false)
}

/// Flow A with `drive_count` drives, exporting the first CRL when `export` is true.
pub fn new_ca_with(label: &str, drive_count: usize, export: bool) -> TestCa {
    let drives = TestDrives::new(drive_count);
    let now = base_time();
    let (passphrase, words) = master_passphrase();
    let outcome = run_flow_a(
        &drives,
        label,
        now,
        &passphrase,
        export.then(|| drives.export_drive()),
    )
    .expect("Flow A");
    let summary = CreateMasterOutcomeSummary {
        serial: outcome.serial,
        fingerprint_text: outcome.fingerprint_text.clone(),
    };
    TestCa {
        ca: outcome.ca,
        drives,
        master_words: words,
        now,
        master: summary,
    }
}

pub fn run_flow_a(
    drives: &TestDrives,
    label: &str,
    now: OffsetDateTime,
    passphrase: &ConfirmedPassphrase,
    export: Option<&Path>,
) -> Result<CreateMasterOutcome, keystone_core::ops::OpsError> {
    testing::supply_generated_key(keys::master(0));
    let backups: Vec<&Path> = drives.ca_drives()[1..]
        .iter()
        .map(PathBuf::as_path)
        .collect();
    let request = CreateMasterRequest::new(
        drives.ca_drive(0),
        &backups,
        test_name(&format!("{label} Master")),
    );
    let plan = plan_create_master(request, confirmed_new(now))?;
    plan.execute(passphrase, export, &NoProgress, &CancelFlag::new())
}

/// Flow B on a fresh simulated YubiKey.
pub fn run_flow_b(
    test: &mut TestCa,
    token: &mut SimulatedYubiKey,
    label: &str,
    export: bool,
) -> Result<MainIntermediateOutcome, keystone_core::ops::OpsError> {
    let time = test.tick();
    let master = test.master_entered();
    let request =
        MainIntermediateRequest::new(test_name(&format!("{label} Main")), Some(master_crl()));
    let request = if test
        .ca
        .state()
        .expect("state")
        .crl_location(test.master.serial)
        .expect("loc")
        .is_some()
    {
        MainIntermediateRequest {
            master_crl: None,
            ..request
        }
    } else {
        request
    };
    let plan = test.ca.plan_yubikey_setup(token, &request, time)?;
    let trust = token.attestation_trust();
    plan.execute(
        &test.ca,
        token,
        &fresh_secrets(&master),
        &trust,
        export.then(|| test.drives.export_drive()),
        &NoProgress,
        &CancelFlag::new(),
    )
}

/// Flow C up to the review: the plan, a confirmed sub passphrase and its words.
pub fn plan_flow_c(
    test: &mut TestCa,
    label: &str,
) -> Result<(SubIntermediatePlan, ConfirmedPassphrase, String), keystone_core::ops::OpsError> {
    let time = test.tick();
    let state = test.ca.state().expect("state");
    let main = state.active_main(test.now).expect("active main").serial();
    let main_crl_location = state
        .crl_location(main)
        .expect("loc")
        .is_none()
        .then(main_crl);
    let request = SubIntermediateRequest::new(
        test_name(&format!("{label} Sub")),
        constrained(&["starnet"]),
        main_crl_location,
    );
    let plan = test.ca.plan_sub_intermediate(&request, time)?;
    let (passphrase, words) = sub_passphrase();
    Ok((plan, passphrase, words))
}

/// Flow C with the cached 4,096-bit key `key_index`.
pub fn run_flow_c(
    test: &mut TestCa,
    token: &mut SimulatedYubiKey,
    label: &str,
    key_index: usize,
    export: bool,
) -> Result<(SubIntermediateOutcome, String), keystone_core::ops::OpsError> {
    let (plan, passphrase, words) = plan_flow_c(test, label)?;
    testing::supply_generated_key(keys::rsa4096(key_index));
    let outcome = plan.execute(
        &test.ca,
        token,
        &s(PIN),
        &passphrase,
        export.then(|| test.drives.export_drive()),
        &NoProgress,
        &CancelFlag::new(),
    )?;
    Ok((outcome, words))
}

/// The secrets a YubiKey needs in its current state (asked again after an
/// interruption, FR-22 AC7).
pub fn secrets_for<'a>(
    token: &mut SimulatedYubiKey,
    master: Option<&'a EnteredPassphrase>,
) -> YubikeySecrets<'a> {
    let inspection = inspect_yubikey(token).expect("inspect");
    YubikeySecrets {
        pin: if inspection.needs_new_pin {
            PinEntry::New(NewPin::from_entries(&s(PIN), &s(PIN)).expect("pin"))
        } else {
            PinEntry::Current(s(PIN))
        },
        new_puk: inspection
            .needs_new_puk
            .then(|| NewPuk::from_entries(&s(PUK), &s(PUK)).expect("puk")),
        master_passphrase: master,
    }
}

/// The main intermediate request a test used for `label` (the master CRL address only
/// while the master has no child yet).
pub fn main_request(test: &TestCa, label: &str) -> MainIntermediateRequest {
    let stored = test
        .ca
        .state()
        .expect("state")
        .crl_location(test.master.serial)
        .expect("location")
        .is_some();
    MainIntermediateRequest::new(
        test_name(&format!("{label} Main")),
        (!stored).then(master_crl),
    )
}

/// Runs the first offered recovery action of every interrupted operation until none is
/// left; YubiKey actions resume with `token`. Returns the actions taken.
pub fn recover_all(
    test: &mut TestCa,
    mut token: Option<&mut SimulatedYubiKey>,
    label: &str,
) -> Vec<RecoveryAction> {
    let mut taken = Vec::new();
    for _ in 0..4 {
        test.now += Duration::minutes(1);
        let time = confirmed(&test.ca, test.now);
        let items = test
            .ca
            .recovery_items(token.as_deref_mut().map(|t| t as &mut dyn TokenSigner))
            .expect("recovery items");
        let Some(item) = items.first() else {
            break;
        };
        assert!(item.actions.len() <= 2, "{item:?}");
        let choice = item.actions.first().unwrap_or_else(|| {
            panic!(
                "no action for {}: {:?}",
                item.operation, item.blocked_reason
            )
        });
        taken.push(choice.action.clone());
        let master = test.master_entered();
        match &choice.action {
            RecoveryAction::ResumeYubikeySetup { .. }
            | RecoveryAction::CompleteSetupWithExistingKey => {
                let token = token.as_deref_mut().expect("a YubiKey for the resume");
                let secrets = secrets_for(token, Some(&master));
                let request = main_request(test, label);
                let trust = token.attestation_trust();
                test.ca
                    .resume_yubikey_setup(
                        item.operation,
                        token,
                        Some(&request),
                        &secrets,
                        &trust,
                        time,
                        None,
                        &NoProgress,
                        &CancelFlag::new(),
                    )
                    .expect("resume");
            }
            other => test
                .ca
                .run_recovery(
                    item.operation,
                    other,
                    &RecoverySecrets {
                        master_passphrase: Some(&master),
                    },
                    token.as_deref_mut().map(|t| t as &mut dyn TokenSigner),
                    time,
                )
                .expect("recovery action"),
        }
    }
    taken
}

/// FR-22 AC3, AC6: no signed certificate is lost: every certificate journaled as signed
/// is in the issuance record from its record file, its operation completed, and no
/// operation is left half-done.
pub fn assert_no_lost_record(ca: &Ca) {
    assert_consistent(ca);
    let record = ca.drive_set().issuance_record().expect("record");
    for cert in record.certificates() {
        assert_eq!(
            cert.source,
            RecordSource::RecordFile,
            "{:?}",
            cert.certificate.serial
        );
    }
    for (operation, journal) in ca.drive_set().drives()[0].journal().expect("journal") {
        for object in journal.signed() {
            if let SignedObject::Certificate { record: cert, .. } = object {
                assert_eq!(journal.state(), OperationState::Completed, "{operation}");
                assert!(
                    record.get(cert.serial).is_some(),
                    "{operation} lost {}",
                    cert.serial
                );
            }
        }
    }
}

/// A CA with master, main intermediate (YubiKey serial `serial`) and nothing else.
pub fn ca_with_main(label: &str, serial: u32) -> (TestCa, SimulatedYubiKey, SimController) {
    let mut test = new_ca(label);
    let (mut token, controller) = token(serial);
    run_flow_b(&mut test, &mut token, label, false).expect("Flow B");
    (test, token, controller)
}

/// Every drive's file under `keystone/<rel>`.
pub fn drive_files(drives: &TestDrives, rel: &str) -> Vec<Vec<u8>> {
    drives
        .ca_drives()
        .iter()
        .map(|drive| {
            std::fs::read(drive.join("keystone").join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        })
        .collect()
}

/// The same file on every drive.
pub fn same_on_every_drive(drives: &TestDrives, rel: &str) -> Vec<u8> {
    let files = drive_files(drives, rel);
    for file in &files[1..] {
        assert_eq!(file, &files[0], "{rel} differs between drives");
    }
    files[0].clone()
}

/// The CA is consistent: drives in sync, no interrupted operation, every journal
/// finished, the issuance record readable and the same everywhere.
pub fn assert_consistent(ca: &Ca) {
    let set = ca.drive_set();
    assert_eq!(set.compare().expect("compare"), DriveComparison::InSync);
    assert!(set.recovery_report().expect("report").is_clean());
    for drive in set.drives() {
        for (operation, journal) in drive.journal().expect("journal") {
            assert_ne!(
                journal.state(),
                OperationState::Pending,
                "{operation} is pending"
            );
        }
    }
    set.issuance_record().expect("record");
}

/// Verification options at `at` with CRL checks on every certificate.
pub fn crl_check(at: OffsetDateTime) -> VerifyOptions {
    VerifyOptions {
        at,
        revocation: RevocationCheck::CrlCheckAll,
        strict: false,
    }
}

/// Verifies `leaf` up to `master` with every CRL given.
pub fn verify_with_crls(
    leaf: &[u8],
    untrusted: &[&[u8]],
    master: &[u8],
    crls: &[&[u8]],
    at: OffsetDateTime,
) -> Result<(), keystone_core::crypto::CryptoError> {
    verify_chain(leaf, untrusted, &[master], crls, &crl_check(at))
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// A copy of the CA on new temporary drives (same CA, same drive identities), so a test
/// can interrupt the same operation many times from the same starting point.
pub fn clone_ca(test: &TestCa) -> TestCa {
    let drives = TestDrives::new(test.drives.ca_drives().len());
    for (from, to) in test.drives.ca_drives().iter().zip(drives.ca_drives()) {
        copy_tree(&from.join("keystone"), &to.join("keystone"));
    }
    let roots: Vec<&Path> = drives.ca_drives().iter().map(PathBuf::as_path).collect();
    let ca = Ca::open(&roots).expect("open the copy");
    TestCa {
        drives,
        ca,
        master_words: test.master_words.clone(),
        now: test.now,
        master: test.master.clone(),
    }
}
