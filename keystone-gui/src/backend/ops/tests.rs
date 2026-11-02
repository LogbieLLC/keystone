//! Tests of the GUI's operations-layer backend, with temporary drives, the YubiKey
//! simulator and synthetic keys from `keystone-testkit` (TEST-11, TEST-12).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use keystone_core::clock::{assess, confirm};
use keystone_core::crypto::secret::SecretString;
use keystone_core::model::{CaLevel, NameFields, RevocationReason, Timestamp};
use keystone_core::ops::testing;
use keystone_core::passphrase::{ConfirmedPassphrase, EnteredPassphrase, NewPassphrase};
use keystone_core::profile::{CrlLocation, CrlUrl, NameConstraintsChoice, NameConstraintsSpec};
use keystone_core::store::{DriveRole, DriveSet};
use keystone_core::token::{NewPin, NewPuk, WipeConfirmation};
use keystone_testkit::simulator::{KeySource, SlotPreset};
use keystone_testkit::{SimulatedYubiKey, SimulatorConfig};

use super::*;
use crate::backend::{
    ClockConfirmation, CreateMasterPlan, DriveSelection, ReplaceDrivePlan, ResumeCredentials,
};
use crate::worker::{CancelPhase, ProgressUpdate};

const PIN: &str = "246810";
const PUK: &str = "13572468";

struct Drives {
    dir: tempfile::TempDir,
    selection: DriveSelection,
}

fn drives() -> Drives {
    let dir = tempfile::tempdir().expect("tempdir");
    let make = |name: &str| {
        let path = dir.path().join(name);
        std::fs::create_dir(&path).expect("mkdir");
        path
    };
    let selection = DriveSelection {
        primary: Some(make("primary")),
        backups: vec![make("backup")],
        export: make("export"),
    };
    Drives { dir, selection }
}

fn secret(text: &str) -> SecretString {
    SecretString::from_str_copy(text).expect("secret")
}

/// A fresh confirmation for one step (SEC-16).
fn clock() -> ClockConfirmation {
    let build = keystone_core::build_info::build_date();
    let now = time::OffsetDateTime::now_utc().max(build + time::Duration::hours(1));
    ClockConfirmation::new(confirm(&assess(now, None, build), false).expect("confirm"))
}

fn ctx(
    selection: &DriveSelection,
    token: Option<&SharedToken>,
    cancellable: bool,
) -> (ExecContext, Receiver<ProgressUpdate>) {
    let (progress, updates) = Progress::new(cancellable);
    (
        ExecContext {
            drives: selection.clone(),
            clock: clock(),
            progress,
            token: token.cloned(),
        },
        updates,
    )
}

fn name(cn: &str) -> keystone_core::profile::ValidatedName {
    keystone_core::profile::ValidatedName::new(&NameFields {
        common_name: format!("KEYSTONE TEST {cn}"),
        organization: None,
        country: None,
    })
    .expect("name")
}

/// A confirmed passphrase and its words (synthetic, for typing it in again).
fn confirmed(generated: NewPassphrase) -> (ConfirmedPassphrase, String) {
    let mut session = generated.into_confirmation();
    session.set_written_down(true);
    let words: Vec<&'static str> = (1..=session.word_count())
        .map(|n| session.view_words().word(n).expect("word"))
        .collect();
    for (index, word) in words.iter().enumerate() {
        session.enter_word(index + 1, word).expect("enter");
    }
    for group in 1..=session.group_count() {
        session.check_group(group).expect("check");
    }
    (session.finish().expect("confirmed"), words.join(" "))
}

fn entered(words: &str) -> EnteredPassphrase {
    EnteredPassphrase::parse(words).expect("entered")
}

fn token() -> SharedToken {
    SharedToken::new(Box::new(SimulatedYubiKey::new(SimulatorConfig {
        key_source: KeySource::Pool,
        ..SimulatorConfig::default()
    })))
}

fn url(text: &str) -> CrlLocation {
    CrlLocation::Url(CrlUrl::parse(text).expect("url"))
}

fn messages(updates: &Receiver<ProgressUpdate>) -> Vec<String> {
    updates.try_iter().map(|update| update.message).collect()
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(files_in(&path));
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// Creates the master with a cached synthetic RSA 8,192 key (on this thread).
fn create_master(d: &Drives) -> (FlowOutcome, String) {
    testing::reset();
    testing::supply_generated_key(keystone_testkit::keys::master(0));
    let (passphrase, words) = confirmed(NewPassphrase::generate_master(10).expect("generate"));
    let (ctx, _updates) = ctx(&d.selection, None, true);
    let outcome = OpsBackend::default()
        .create_master(
            ctx,
            CreateMasterPlan {
                name: name("Backend Root"),
                validity_years: 20,
                passphrase,
            },
        )
        .expect("master");
    (outcome, words)
}

#[test]
fn flows_a_to_e_run_through_the_operations_layer() {
    // Covers: FR-02 AC1, FR-07 AC3, FR-08 AC2, FR-09 AC1, FR-12 AC2, FR-13 AC1, FR-13 AC4, FR-15 AC1, FR-18 AC1, FR-20 AC1, SEC-04, SEC-16
    let d = drives();
    let backend = OpsBackend::default();
    let ca_drives = |s: &DriveSelection| -> Vec<PathBuf> {
        s.ca_drives().iter().map(|p| p.to_path_buf()).collect()
    };

    // Flow A.
    let (master, words) = create_master(&d);
    assert_eq!(master.certificates.len(), 1);
    let master_cert = master.certificates[0].clone();
    assert_eq!(master_cert.level, CaLevel::Master);
    assert_eq!(master.drive_writes.len(), 2);
    for write in &master.drive_writes {
        assert!(write.verified, "{write:?}");
        assert!(
            write.files.iter().any(|f| f == "keys/master.key"),
            "{write:?}"
        );
        assert!(
            write.files.iter().any(|f| f == "certs/master.crt"),
            "{write:?}"
        );
    }
    assert_eq!(master.crls[0].crl_number, 1);
    assert!(
        master
            .export_files
            .iter()
            .all(|f| f.extension().is_some_and(|e| e == "crl") && f.exists()),
        "{:?}",
        master.export_files
    );
    let ca = Ca::open(
        &ca_drives(&d.selection)
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>(),
    )
    .expect("open");
    let state = ca.state().expect("state");
    assert_eq!(
        state.master().expect("master").record.fingerprint,
        master_cert.fingerprint,
        "FR-20: the fingerprint shown is the recorded one"
    );

    // Flow B: harden, key on the YubiKey, main intermediate, first CRL.
    let shared = token();
    let device = shared.lock().device_info().expect("device");
    let (ctx_b, updates) = ctx(&d.selection, Some(&shared), true);
    let main = backend
        .setup_yubikey(
            ctx_b,
            SetupYubikeyPlan {
                device,
                credentials: YubikeyCredentials::SetNew {
                    pin: NewPin::from_entries(&secret(PIN), &secret(PIN)).expect("pin"),
                    puk: NewPuk::from_entries(&secret(PUK), &secret(PUK)).expect("puk"),
                },
                master_crl: Some(url("http://pki.keystone-test.invalid/master.crl")),
                name: name("Backend Main"),
                validity_years: 10,
                master_passphrase: entered(&words),
            },
        )
        .expect("flow B");
    let main_cert = main.certificates[0].clone();
    assert_eq!(main_cert.level, CaLevel::MainIntermediate);
    assert_eq!(main.crls[0].crl_number, 1);
    assert!(main.drive_writes.iter().all(|w| w.verified));
    let progress = messages(&updates);
    assert!(
        progress
            .iter()
            .any(|m| m.starts_with("Changing the YubiKey PIN")),
        "{progress:?}"
    );
    assert_eq!(
        backend
            .issuer_crl_location(&d.selection, master_cert.serial)
            .expect("location"),
        Some(url("http://pki.keystone-test.invalid/master.crl"))
    );
    assert_eq!(
        backend
            .issuer_crl_location(&d.selection, main_cert.serial)
            .expect("location"),
        None,
        "FR-18: asked before the main intermediate's first child"
    );

    // Flow C twice: with name constraints, then explicitly without.
    let mut subs = Vec::new();
    for (index, constraints) in [
        NameConstraintsChoice::Constrained(
            NameConstraintsSpec::new(&["starnet"], &[] as &[&str]).expect("spec"),
        ),
        NameConstraintsChoice::ExplicitlyUnconstrained,
    ]
    .into_iter()
    .enumerate()
    {
        testing::supply_generated_key(keystone_testkit::keys::rsa4096(index));
        let (passphrase, _) =
            confirmed(NewPassphrase::generate_sub_intermediate().expect("generate"));
        let (ctx_c, _) = ctx(&d.selection, Some(&shared), true);
        let sub = backend
            .create_sub_intermediate(
                ctx_c,
                SubIntermediatePlan {
                    name: name(&format!("Backend Sub {index}")),
                    validity_years: 5,
                    name_constraints: constraints,
                    issuer_crl: (index == 0)
                        .then(|| url("http://pki.keystone-test.invalid/main.crl")),
                    passphrase,
                    pin: secret(PIN),
                },
            )
            .expect("flow C");
        assert_eq!(sub.certificates[0].level, CaLevel::SubIntermediate);
        assert!(sub.drive_writes.iter().all(|w| w.verified));
        let names: Vec<String> = sub
            .export_files
            .iter()
            .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert!(names.iter().any(|n| n.ends_with(".crt")), "{names:?}");
        assert!(names.iter().any(|n| n.ends_with(".key")), "{names:?}");
        assert!(names.iter().any(|n| n.ends_with("-chain.pem")), "{names:?}");
        subs.push(sub.certificates[0].serial);
    }
    // SEC-04: no plaintext private key anywhere on the drives or the export drive.
    assert_eq!(
        keystone_testkit::find_plaintext_private_keys(d.dir.path()).expect("scan"),
        Vec::<PathBuf>::new()
    );

    // Flow D: the YubiKey revokes the first sub-intermediate.
    let (ctx_d, _) = ctx(&d.selection, Some(&shared), true);
    let revoked = backend
        .revoke(
            ctx_d,
            RevokePlan {
                serial: subs[0],
                level: CaLevel::SubIntermediate,
                reason: RevocationReason::Superseded,
                credential: IssuerCredential::YubikeyPin(secret(PIN)),
            },
        )
        .expect("flow D");
    assert_eq!(revoked.crls[0].crl_number, 2);
    assert!(
        revoked.notes.iter().any(|n| n.starts_with("Revoked: ")),
        "{:?}",
        revoked.notes
    );

    // Refresh CRL: the master's.
    let (ctx_r, _) = ctx(&d.selection, None, true);
    let refreshed = backend
        .refresh_crl(
            ctx_r,
            RefreshCrlPlan {
                issuer: master_cert.serial,
                credential: IssuerCredential::MasterPassphrase(entered(&words)),
            },
        )
        .expect("refresh");
    assert_eq!(refreshed.crls[0].crl_number, 2);

    // A wrong master passphrase stops before anything is signed.
    let other_words = {
        let (_, words) = confirmed(NewPassphrase::generate_master(10).expect("generate"));
        words
    };
    let (ctx_w, _) = ctx(&d.selection, None, true);
    let error = backend
        .refresh_crl(
            ctx_w,
            RefreshCrlPlan {
                issuer: master_cert.serial,
                credential: IssuerCredential::MasterPassphrase(entered(&other_words)),
            },
        )
        .expect_err("wrong passphrase");
    let BackendError::Failed(text) = &error else {
        panic!("{error:?}");
    };
    assert!(text.contains("the master passphrase is wrong"), "{text}");
    assert!(
        text.contains("stopped before anything was signed"),
        "{text}"
    );
    assert!(!text.contains(&other_words), "never shows the passphrase");

    // Flow E: the master revokes the main intermediate; the second sub is cut off.
    let (ctx_e, _) = ctx(&d.selection, None, true);
    let replaced = backend
        .replace_yubikey(
            ctx_e,
            ReplaceYubikeyPlan {
                old_main_intermediate: main_cert.serial,
                reason: RevocationReason::CaCompromise,
                master_passphrase: entered(&words),
            },
        )
        .expect("flow E");
    assert_eq!(replaced.crls[0].crl_number, 3);
    assert!(replaced.follow_up.contains(&FollowUp::SetUpNewYubikey));
    assert!(
        replaced
            .follow_up
            .contains(&FollowUp::ReissueSubIntermediates(vec![subs[1]])),
        "{:?}",
        replaced.follow_up
    );
    testing::reset();
}

#[test]
fn fr22_an_interrupted_operation_is_finished_from_the_recovery_screen() {
    // Covers: FR-22 AC4, FR-22 AC6, FR-12 AC2, FR-13 AC4
    let d = drives();
    let backend = OpsBackend::default();
    let (master, words) = create_master(&d);
    // The refresh is interrupted after its outputs were moved into place (as if the
    // process died there; ops test seam, never in production builds).
    testing::arm_fault(testing::FaultPoint::AfterCommit);
    let (ctx_r, _) = ctx(&d.selection, None, true);
    let error = backend
        .refresh_crl(
            ctx_r,
            RefreshCrlPlan {
                issuer: master.certificates[0].serial,
                credential: IssuerCredential::MasterPassphrase(entered(&words)),
            },
        )
        .expect_err("interrupted");
    assert!(matches!(error, BackendError::Failed(_)));
    testing::reset();
    let items = backend.recovery_items(&d.selection, None).expect("items");
    assert_eq!(items.len(), 1);
    let choice = items[0].actions.first().expect("an action").clone();
    assert!(items[0].actions.len() <= 2, "FR-22 AC8");
    let (ctx_f, _) = ctx(&d.selection, None, false);
    let finished = backend
        .recover(
            ctx_f,
            RecoveryPlan {
                operation: items[0].operation,
                action: choice.action,
                resume: Some(ResumeCredentials::default()),
            },
        )
        .expect("recovered");
    assert!(
        finished.title.ends_with("was finished"),
        "{}",
        finished.title
    );
    assert!(
        finished.drive_writes.iter().all(|w| w.verified),
        "{finished:?}"
    );
    assert!(
        finished
            .export_files
            .iter()
            .any(|f| f.to_string_lossy().contains("-crl-000002")),
        "the finished CRL is exported: {:?}",
        finished.export_files
    );
    assert!(
        backend
            .recovery_items(&d.selection, None)
            .expect("items")
            .is_empty()
    );
}

#[test]
fn fr22_ac7_an_interrupted_yubikey_setup_is_resumed_from_the_recovery_screen() {
    // Covers: FR-22 AC7, FR-22 AC4, FR-06 AC2
    use keystone_core::store::YubikeySetupStep;
    let d = drives();
    let backend = OpsBackend::default();
    let (_, words) = create_master(&d);
    let shared = token();
    let device = shared.lock().device_info().expect("device");
    // Interrupted after the PUK change was journaled (ops test seam).
    testing::arm_fault(testing::FaultPoint::AfterTokenStepRecorded(
        YubikeySetupStep::PukChanged,
    ));
    let (ctx_b, _) = ctx(&d.selection, Some(&shared), true);
    let error = backend
        .setup_yubikey(
            ctx_b,
            SetupYubikeyPlan {
                device,
                credentials: YubikeyCredentials::SetNew {
                    pin: NewPin::from_entries(&secret(PIN), &secret(PIN)).expect("pin"),
                    puk: NewPuk::from_entries(&secret(PUK), &secret(PUK)).expect("puk"),
                },
                master_crl: Some(url("http://pki.keystone-test.invalid/master.crl")),
                name: name("Resumed Main"),
                validity_years: 10,
                master_passphrase: entered(&words),
            },
        )
        .expect_err("interrupted");
    assert!(matches!(error, BackendError::Failed(_)));
    testing::reset();
    // The recovery screen, read with this YubiKey connected, offers only the resume.
    let items = backend
        .recovery_items(&d.selection, Some(&shared))
        .expect("items");
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert!(item.yubikey.is_some(), "the YubiKey column is filled");
    assert_eq!(item.actions.len(), 1, "{:?}", item.actions);
    let action = item.actions[0].action.clone();
    assert!(matches!(action, RecoveryAction::ResumeYubikeySetup { .. }));
    let needs = crate::vm::recovery::resume_needs(item, &action);
    assert!(
        needs.current_pin && !needs.new_puk && needs.unsigned,
        "{needs:?}"
    );
    let (ctx_r, _) = ctx(&d.selection, Some(&shared), true);
    let resumed = backend
        .recover(
            ctx_r,
            RecoveryPlan {
                operation: item.operation,
                action,
                resume: Some(ResumeCredentials {
                    current_pin: Some(secret(PIN)),
                    master_passphrase: Some(entered(&words)),
                    main_intermediate: Some(crate::backend::ResumeMainIntermediate {
                        name: name("Resumed Main"),
                        validity_years: 10,
                        master_crl: Some(url("http://pki.keystone-test.invalid/master.crl")),
                    }),
                    ..ResumeCredentials::default()
                }),
            },
        )
        .expect("resumed");
    assert_eq!(resumed.certificates[0].level, CaLevel::MainIntermediate);
    assert!(resumed.drive_writes.iter().all(|w| w.verified));
    assert!(
        backend
            .recovery_items(&d.selection, Some(&shared))
            .expect("items")
            .is_empty()
    );
}

#[test]
fn fr16_ac2_cancel_during_key_generation_leaves_no_output() {
    // Covers: FR-16 AC1, FR-16 AC2, NFR-03
    let d = drives();
    let backend = OpsBackend { slow_keygen: true };
    let selection = d.selection.clone();
    let (passphrase, _) = confirmed(NewPassphrase::generate_master(10).expect("generate"));
    let (progress, updates, result) = crate::worker::spawn(true, move |progress: &Progress| {
        let ctx = ExecContext {
            drives: selection,
            clock: clock(),
            progress: progress.clone(),
            token: None,
        };
        backend.create_master(
            ctx,
            CreateMasterPlan {
                name: name("Cancelled Root"),
                validity_years: 20,
                passphrase,
            },
        )
    })
    .expect("spawn");
    // Wait until key generation reports progress, then press Cancel.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let update = updates
            .recv_timeout(deadline - std::time::Instant::now())
            .expect("key generation progress");
        if update.message.contains("candidate numbers tested") {
            break;
        }
    }
    assert_eq!(progress.phase(), CancelPhase::Cancellable);
    assert!(progress.request_cancel());
    let outcome = result
        .recv_timeout(Duration::from_secs(60))
        .expect("finished");
    assert_eq!(outcome.expect_err("cancelled"), BackendError::Cancelled);
    // Nothing is left: no output file, no staged file; the journal says cancelled.
    for root in d.selection.ca_drives() {
        let keystone = root.join("keystone");
        for folder in ["certs", "keys", "crls", "staging", "record"] {
            assert_eq!(
                files_in(&keystone.join(folder)),
                Vec::<PathBuf>::new(),
                "{folder} on {}",
                root.display()
            );
        }
        let journal = files_in(&keystone.join("journal"));
        assert!(
            journal
                .iter()
                .any(|f| f.to_string_lossy().ends_with("-cancelled.json")),
            "{journal:?}"
        );
    }
    assert!(files_in(&d.selection.export).is_empty());
    assert_eq!(
        keystone_testkit::find_plaintext_private_keys(d.dir.path()).expect("scan"),
        Vec::<PathBuf>::new()
    );
}

#[test]
fn fr16_ac2_cancel_before_the_start_writes_nothing() {
    // Covers: FR-16 AC2
    let d = drives();
    let (passphrase, _) = confirmed(NewPassphrase::generate_master(10).expect("generate"));
    let (ctx, _) = ctx(&d.selection, None, true);
    assert!(ctx.progress.request_cancel());
    let result = OpsBackend::default().create_master(
        ctx,
        CreateMasterPlan {
            name: name("Never Root"),
            validity_years: 20,
            passphrase,
        },
    );
    assert_eq!(result.expect_err("cancelled"), BackendError::Cancelled);
    assert!(files_in(d.dir.path()).is_empty());
}

#[test]
fn fr16_ac2_the_cancel_button_goes_before_the_first_persistent_change() {
    // Covers: FR-16 AC2
    let (progress, _updates) = Progress::new(true);
    let sink = OpsBackend::default().sink(&progress);
    sink.report(ops::Progress::Step {
        step: Step::GeneratingKey,
        cancel_available: true,
    });
    assert_eq!(progress.phase(), CancelPhase::Cancellable);
    // Cancelling reports `cancel_available: false` but is no persistent change.
    sink.report(ops::Progress::Step {
        step: Step::Cancelling,
        cancel_available: false,
    });
    assert_eq!(progress.phase(), CancelPhase::Cancellable);
    for step in [
        Step::SigningCertificate,
        Step::SigningCrl,
        Step::ChangingPin,
        Step::GeneratingKeyOnYubiKey,
        Step::MovingIntoPlace,
    ] {
        let (progress, _updates) = Progress::new(true);
        OpsBackend::default()
            .sink(&progress)
            .report(ops::Progress::Step {
                step,
                cancel_available: true,
            });
        assert_eq!(progress.phase(), CancelPhase::Committed, "{step:?}");
        assert!(!progress.request_cancel(), "{step:?}");
    }
}

#[test]
fn adr0003_a_lost_primary_is_replaced_and_a_backup_promoted() {
    // Covers: SEC-11 (ADR 0003), FR-12 AC2
    let d = drives();
    let created = Timestamp::utc(keystone_core::build_info::build_date());
    let primary = d.selection.primary.clone().expect("primary");
    DriveSet::create(&primary, &[d.selection.backups[0].as_path()], created).expect("create");
    let new_drive = d.dir.path().join("new");
    std::fs::create_dir(&new_drive).expect("mkdir");
    // The primary is lost: only the backup is connected.
    let lost = DriveSelection {
        primary: None,
        backups: d.selection.backups.clone(),
        export: d.selection.export.clone(),
    };
    let backend = OpsBackend::default();
    let review = backend
        .review_replace_drive(&lost, &new_drive, &clock())
        .expect("review");
    assert!(review.promotes.is_some(), "{review:?}");
    assert!(review.lines.iter().any(|(label, _)| label == "New drive"));
    let (ctx, _) = ctx(&lost, None, false);
    let outcome = backend
        .replace_drive(
            ctx,
            ReplaceDrivePlan {
                new_drive: new_drive.clone(),
            },
        )
        .expect("replaced");
    assert_eq!(outcome.title, "The lost drive was replaced");
    assert_eq!(outcome.drive_writes.len(), 2);
    assert!(outcome.drive_writes.iter().all(|w| w.verified));
    assert!(
        outcome
            .notes
            .iter()
            .any(|n| n.contains("is now the primary drive")),
        "{:?}",
        outcome.notes
    );
    let ca = Ca::open(&[d.selection.backups[0].as_path(), new_drive.as_path()]).expect("open");
    let roles: Vec<DriveRole> = ca.drive_roles().into_iter().map(|(_, role)| role).collect();
    assert_eq!(roles, [DriveRole::Primary, DriveRole::Backup]);
    // A drive that is not empty is refused, with a reason.
    let other = d.dir.path().join("other");
    std::fs::create_dir(&other).expect("mkdir");
    std::fs::write(other.join("notes.txt"), b"KEYSTONE TEST other files").expect("write");
    let error = backend
        .review_replace_drive(&lost, &other, &clock())
        .expect_err("not empty");
    assert!(matches!(error, BackendError::Failed(_)), "{error:?}");
}

#[test]
fn fr07_ac4_the_typed_serial_wipe_empties_the_slot() {
    // Covers: FR-07 AC4
    let d = drives();
    let created = Timestamp::utc(keystone_core::build_info::build_date());
    let primary = d.selection.primary.clone().expect("primary");
    DriveSet::create(&primary, &[d.selection.backups[0].as_path()], created).expect("create");
    let shared = SharedToken::new(Box::new(SimulatedYubiKey::new(SimulatorConfig {
        key_source: KeySource::Pool,
        slot: SlotPreset::KeyWithoutCertificate,
        ..SimulatorConfig::default()
    })));
    let device = shared.lock().device_info().expect("device");
    let confirmation =
        WipeConfirmation::new(&device.serial.to_string(), &device).expect("typed serial");
    let (ctx, _) = ctx(&d.selection, Some(&shared), false);
    let outcome = OpsBackend::default()
        .wipe_signing_slot(
            ctx,
            WipeSlotPlan {
                confirmation,
                pin: secret(keystone_core::token::DEFAULT_PIN),
            },
        )
        .expect("wiped");
    assert!(outcome.title.contains("wiped"));
    let slot = shared
        .lock()
        .slot_status(keystone_core::token::SIGNING_SLOT)
        .expect("slot");
    assert!(slot.is_empty());
}

#[test]
fn errors_are_plain_sentences_without_secrets() {
    // Covers: FR-04 AC3, SEC-07
    use keystone_core::crypto::CryptoError;
    let wrong = cause_text(&OpsError::Crypto(CryptoError::WrongPassphrase));
    assert!(wrong.contains("passphrase is wrong"), "{wrong}");
    // A malformed key file is not reported as a wrong passphrase.
    let damaged = cause_text(&OpsError::Crypto(CryptoError::Der("bad".into())));
    assert!(
        damaged.contains("this is not a wrong passphrase"),
        "{damaged}"
    );
    let unsupported = cause_text(&OpsError::Crypto(CryptoError::UnsupportedKeyEncryption(
        "scrypt N".into(),
    )));
    assert!(
        unsupported.contains("this is not a wrong passphrase"),
        "{unsupported}"
    );
    let serial = keystone_core::model::Serial::from_bytes([9; 20]).expect("serial");
    let stopped = failure(
        "Refreshing the CRL",
        OpsError::Stopped {
            operation: keystone_core::store::OperationId(4),
            reserved_serials: vec![serial],
            cause: Box::new(OpsError::Crypto(CryptoError::WrongPassphrase)),
        },
    );
    let BackendError::Failed(text) = stopped else {
        panic!("{stopped:?}");
    };
    assert!(
        text.starts_with("Refreshing the CRL stopped before anything was signed"),
        "{text}"
    );
    assert!(text.contains("Operation 4 was cancelled"), "{text}");
    assert!(text.contains(&serial.to_hex()), "{text}");
    assert_eq!(
        failure(
            "x",
            OpsError::Cancelled {
                operation: keystone_core::store::OperationId(1),
                reserved_serials: Vec::new(),
            }
        ),
        BackendError::Cancelled
    );
    // StoreError::Damaged names every problem (nothing can be signed).
    let damaged = cause_text(&OpsError::Store(keystone_core::store::StoreError::Damaged(
        vec!["certs/x.crt is missing on backup drive 1a2b3c4d".into()],
    )));
    assert!(damaged.contains("cannot be verified"), "{damaged}");
    assert!(damaged.contains("certs/x.crt is missing"), "{damaged}");
    let interrupted = failure(
        "Creating the master",
        OpsError::Interrupted {
            operation: keystone_core::store::OperationId(2),
            cause: Box::new(OpsError::NotReady("drive pulled".into())),
        },
    );
    assert!(interrupted.to_string().contains("Open the recovery screen"));
}
