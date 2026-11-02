//! Flow C: a sub-intermediate (FR-08, FR-09 AC1, AC2, FR-10 AC1, AC2, FR-13 AC6, FR-16,
//! FR-18, FR-21 AC1, AC6).
#![forbid(unsafe_code)]

use std::sync::mpsc;
use std::time::{Duration as StdDuration, Instant};

use keystone_core::cert::parse_certificate_pem;
use keystone_core::crypto::CancelFlag;
use keystone_core::crypto::pkcs8::decrypt_key_pem;
use keystone_core::crypto::verify::{VerifyOptions, certificates_pem_to_der, verify_chain};
use keystone_core::model::CaLevel;
use keystone_core::ops::{
    Ca, ExportStatus, NoProgress, OpsError, Progress, Step, SubIntermediateRequest, testing,
};
use keystone_core::profile::{NAME_CONSTRAINTS_OFF_WARNING, NameConstraintsChoice, ProfileError};
use keystone_core::store::{AuditAction, OperationState};
use keystone_core::token::TokenSigner;
use keystone_testkit::keys;
use keystone_testkit::names::test_name;
use keystone_testkit::simulator::{TouchBehaviour, harden};

use crate::support::*;

#[test]
fn flow_c_writes_crt_encrypted_key_and_chain_to_every_drive_and_the_export_drive() {
    // Covers: FR-08 AC1, FR-08 AC2, FR-09 AC1, FR-09 AC2, FR-21 AC6, FR-18 AC1, FR-20 AC1, FR-12 AC1, SEC-15
    let (mut test, mut token, controller) = ca_with_main("C1", 30_000_001);
    let touches = controller.touch_requests();
    let time = test.tick();
    let request = SubIntermediateRequest::new(
        test_name("C1 Sub"),
        constrained(&["starnet", "example.test"]),
        Some(main_crl()),
    );
    let plan = test.ca.plan_sub_intermediate(&request, time).unwrap();
    // FR-21 AC6: the permitted names are on the review step.
    let constraints = plan.review().value("Name constraints").unwrap().to_owned();
    assert!(constraints.contains("permitted DNS: starnet") && constraints.contains("example.test"));
    assert!(
        plan.review()
            .value("Files")
            .unwrap()
            .contains(".key (encrypted)")
    );
    let stem = plan.file_stem();
    let (passphrase, words) = sub_passphrase();
    testing::supply_generated_key(keys::rsa4096(0));
    let outcome = plan
        .execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &passphrase,
            Some(test.export()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("Flow C");
    assert_eq!(outcome.file_stem, stem);
    assert!(stem.starts_with("keystone-test-c1-sub-"));
    // FR-08 AC2: one YubiKey signature (PIN + touch).
    assert_eq!(controller.touch_requests(), touches + 1);

    let state = test.ca.state().unwrap();
    let sub = state.certificate(outcome.serial).unwrap();
    let main = state.active_main(test.now).unwrap();
    let master = state.master().unwrap();
    let crt = same_on_every_drive(&test.drives, &format!("certs/{stem}.crt"));
    let key = same_on_every_drive(&test.drives, &format!("keys/{stem}.key"));
    let chain = same_on_every_drive(&test.drives, &format!("certs/{stem}-chain.pem"));
    let (sub_der, info) = parse_certificate_pem(&crt).unwrap();
    assert_eq!(info.ca_level(), Some(CaLevel::SubIntermediate));
    assert_eq!(info.not_after.year() - info.not_before.year(), 5);
    assert_eq!(info.crl_distribution_urls, [MAIN_CRL_URL]);
    assert!(info.name_constraints.as_ref().unwrap().critical);
    assert_eq!(
        outcome.fingerprint_text,
        info.fingerprint.to_fingerprint_string()
    );
    // FR-09 AC1: the chain file holds sub, main, master in that order.
    let ders = certificates_pem_to_der(&chain).unwrap();
    assert_eq!(
        ders,
        [sub_der.clone(), main.der.clone(), master.der.clone()]
    );
    // FR-09 AC2: the chain verifies up to the master.
    verify_chain(
        &sub_der,
        &[&main.der],
        &[&master.der],
        &[],
        &VerifyOptions::at(test.now),
    )
    .unwrap();
    // SEC-15: the key is encrypted with its own passphrase and matches the certificate.
    assert!(key.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    let decrypted = decrypt_key_pem(&key, entered(&words).secret()).unwrap();
    assert_eq!(decrypted.public_key_spki_der().unwrap(), info.spki_der);
    assert!(decrypt_key_pem(&key, test.master_entered().secret()).is_err());
    // The export drive holds the three files.
    let ExportStatus::Written(files) = &outcome.export else {
        panic!("{:?}", outcome.export);
    };
    let mut names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    let mut expected = [
        format!("{stem}-chain.pem"),
        format!("{stem}.crt"),
        format!("{stem}.key"),
    ];
    expected.sort();
    assert_eq!(
        names,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
    for file in files {
        assert_eq!(
            std::fs::read(&file.path).unwrap(),
            same_on_every_drive(
                &test.drives,
                &format!(
                    "{}/{}",
                    if file.name.ends_with(".key") {
                        "keys"
                    } else {
                        "certs"
                    },
                    file.name
                )
            )
        );
    }
    // FR-21 AC6: permitted names in the issuance record and the audit entry.
    assert_eq!(sub.record.permitted_dns, ["starnet", "example.test"]);
    assert!(sub.record.name_constraints);
    let log = test.ca.drive_set().audit_log().unwrap();
    let entry = log
        .entries()
        .iter()
        .find(|e| e.action == AuditAction::CreateSubIntermediate)
        .unwrap();
    let details = entry.details.as_ref().unwrap();
    assert_eq!(
        details.permitted_dns.as_deref(),
        Some(&["starnet".to_owned(), "example.test".to_owned()][..])
    );
    assert_eq!(details.name_constraints, Some(true));
    assert!(details.note.as_deref().unwrap().contains(MAIN_CRL_URL));
    assert_consistent(&test.ca);
}

#[test]
fn fr18_ac1_later_children_reuse_the_stored_crl_address() {
    // Covers: FR-18 AC1
    let (mut test, mut token, _) = ca_with_main("C2", 30_000_002);
    run_flow_c(&mut test, &mut token, "C2a", 1, false).expect("first sub");
    let time = test.tick();
    let changed = SubIntermediateRequest::new(
        test_name("C2b Sub"),
        constrained(&["starnet"]),
        Some(master_crl()),
    );
    let error = test.ca.plan_sub_intermediate(&changed, time).unwrap_err();
    assert!(error.to_string().contains("already set"), "{error}");
    let (second, _) = run_flow_c(&mut test, &mut token, "C2b", 2, false).expect("second sub");
    let state = test.ca.state().unwrap();
    assert_eq!(
        state
            .certificate(second.serial)
            .unwrap()
            .info
            .crl_distribution_urls,
        [MAIN_CRL_URL]
    );
}

#[test]
fn fr10_ac1_a_sub_intermediate_never_outlives_the_main_intermediate() {
    // Covers: FR-10 AC1, FR-10 AC3
    let mut test = new_ca("C3");
    let (mut token, _) = token(30_000_003);
    let time = test.tick();
    let mut request =
        keystone_core::ops::MainIntermediateRequest::new(test_name("C3 Main"), Some(master_crl()));
    request.validity_years = 3;
    let master = test.master_entered();
    let trust = token.attestation_trust();
    test.ca
        .plan_yubikey_setup(&mut token, &request, time)
        .unwrap()
        .execute(
            &test.ca,
            &mut token,
            &fresh_secrets(&master),
            &trust,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let time = test.tick();
    assert_eq!(test.ca.max_sub_intermediate_years(test.now).unwrap(), 2);
    let request = SubIntermediateRequest::new(
        test_name("C3 Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    let error = test.ca.plan_sub_intermediate(&request, time).unwrap_err();
    assert!(
        matches!(
            error,
            OpsError::Profile(ProfileError::OutlivesIssuer { max_years: 2, .. })
        ),
        "{error}"
    );
    let request = SubIntermediateRequest {
        validity_years: 2,
        ..request
    };
    test.ca
        .plan_sub_intermediate(&request, time)
        .expect("2 years fit");
}

#[test]
fn fr10_ac2_a_serial_seen_in_any_history_is_never_used_again() {
    // Covers: FR-10 AC2, FR-22 AC4
    let (mut test, mut token, controller) = ca_with_main("C4", 30_000_004);
    // A serial reserved by a cancelled operation stays reserved.
    controller.set_touch(TouchBehaviour::NoTouch);
    let error = run_flow_c(&mut test, &mut token, "C4a", 3, false).unwrap_err();
    let OpsError::Stopped {
        reserved_serials, ..
    } = &error
    else {
        panic!("{error}");
    };
    let reserved = reserved_serials[0];
    controller.set_touch(TouchBehaviour::Touch);
    let master_serial = test.master.serial;
    for used in [reserved, master_serial] {
        testing::queue_serial_candidate(used);
        let time = test.tick();
        let request = SubIntermediateRequest::new(
            test_name("C4b Sub"),
            constrained(&["starnet"]),
            Some(main_crl()),
        );
        let plan = test.ca.plan_sub_intermediate(&request, time).unwrap();
        assert_ne!(plan.serial(), used);
    }
    // An unused candidate is taken, so the check above really ran.
    let fresh = keystone_core::crypto::rand::random_serial().unwrap();
    testing::queue_serial_candidate(fresh);
    let time = test.tick();
    let request = SubIntermediateRequest::new(
        test_name("C4c Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    assert_eq!(
        test.ca
            .plan_sub_intermediate(&request, time)
            .unwrap()
            .serial(),
        fresh
    );
    assert!(
        test.ca
            .drive_set()
            .known_serials()
            .unwrap()
            .contains(&reserved)
    );
}

#[test]
fn fr16_ac2_failures_before_the_signature_cancel_and_keep_the_serial() {
    // Covers: FR-16 AC2, FR-08 AC2
    let (mut test, mut token, controller) = ca_with_main("C5", 30_000_005);
    // No touch: nothing was signed, the operation is cancelled, its staged key deleted.
    controller.set_touch(TouchBehaviour::NoTouch);
    let error = run_flow_c(&mut test, &mut token, "C5", 4, false).unwrap_err();
    let OpsError::Stopped {
        operation, cause, ..
    } = &error
    else {
        panic!("{error}");
    };
    assert!(matches!(**cause, OpsError::Cert(_)), "{cause}");
    assert!(
        error.root_cause().to_string().contains("not touched"),
        "{error}"
    );
    let journal = test.ca.drive_set().drives()[0]
        .operation_journal(*operation)
        .unwrap()
        .unwrap();
    assert_eq!(journal.state(), OperationState::Cancelled);
    for drive in test.drives.ca_drives() {
        assert_eq!(
            std::fs::read_dir(drive.join("keystone/staging"))
                .unwrap()
                .count(),
            0
        );
    }
    // A wrong PIN is the same: nothing changed.
    controller.set_touch(TouchBehaviour::Touch);
    let time = test.tick();
    let request = SubIntermediateRequest::new(
        test_name("C5 Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    let plan = test.ca.plan_sub_intermediate(&request, time).unwrap();
    let (passphrase, _) = sub_passphrase();
    testing::supply_generated_key(keys::rsa4096(4));
    let error = plan
        .execute(
            &test.ca,
            &mut token,
            &s("Wrong#12"),
            &passphrase,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap_err();
    assert!(matches!(error, OpsError::Stopped { .. }), "{error}");
    // The YubiKey removed before signing (boundary): stopped cleanly too.
    controller.remove();
    let error = run_flow_c(&mut test, &mut token, "C5", 4, false).unwrap_err();
    assert!(matches!(error, OpsError::Stopped { .. }), "{error}");
    assert!(error.to_string().contains("YubiKey"), "{error}");
    controller.reinsert();
    // A different YubiKey cannot sign for the main intermediate. Its key is generated
    // fresh: the simulator's pooled keys are shared by every device in the process, so a
    // pooled key could equal the main intermediate's key.
    let mut other = keystone_testkit::SimulatedYubiKey::new(keystone_testkit::SimulatorConfig {
        serial: 30_000_055,
        key_source: keystone_testkit::simulator::KeySource::Fresh,
        ..keystone_testkit::SimulatorConfig::default()
    });
    harden(&mut other, PIN, PUK).unwrap();
    other.generate_signing_key(&s(PIN)).unwrap();
    let error = run_flow_c(&mut test, &mut other, "C5", 4, false).unwrap_err();
    assert!(error.to_string().contains("does not belong"), "{error}");
    // After all that, the right YubiKey signs and the CA is consistent.
    let (outcome, _) = run_flow_c(&mut test, &mut token, "C5", 4, false).expect("Flow C");
    assert!(
        test.ca
            .state()
            .unwrap()
            .certificate(outcome.serial)
            .is_some()
    );
    assert_consistent(&test.ca);
}

#[test]
fn fr21_ac1_turning_name_constraints_off_needs_an_explicit_choice_and_warns() {
    // Covers: FR-21 AC1
    let (mut test, mut token, _) = ca_with_main("C6", 30_000_006);
    let time = test.tick();
    let request = SubIntermediateRequest::new(
        test_name("C6 Sub"),
        NameConstraintsChoice::ExplicitlyUnconstrained,
        Some(main_crl()),
    );
    let plan = test.ca.plan_sub_intermediate(&request, time).unwrap();
    assert_eq!(plan.review().warnings, [NAME_CONSTRAINTS_OFF_WARNING]);
    let (passphrase, _) = sub_passphrase();
    testing::supply_generated_key(keys::rsa4096(5));
    let outcome = plan
        .execute(
            &test.ca,
            &mut token,
            &s(PIN),
            &passphrase,
            None,
            &NoProgress,
            &CancelFlag::new(),
        )
        .unwrap();
    let state = test.ca.state().unwrap();
    let sub = state.certificate(outcome.serial).unwrap();
    assert!(!sub.record.name_constraints && sub.record.permitted_dns.is_empty());
    assert!(sub.info.name_constraints.is_none());
}

#[test]
fn fr16_ac1_operations_run_on_a_worker_thread_and_report_progress() {
    // Covers: FR-16 AC1, NFR-03
    let (mut test, token, controller) = ca_with_main("C7", 30_000_007);
    // A slow touch keeps the signature busy; the "GUI" thread keeps polling.
    controller.set_delay(
        keystone_testkit::simulator::SimOp::Sign,
        StdDuration::from_millis(400),
    );
    let time = test.tick();
    let request = SubIntermediateRequest::new(
        test_name("C7 Sub"),
        constrained(&["starnet"]),
        Some(main_crl()),
    );
    let plan = test.ca.plan_sub_intermediate(&request, time).unwrap();
    let (passphrase, _) = sub_passphrase();
    let (sender, receiver) = mpsc::channel::<Progress>();
    let sender = std::sync::Mutex::new(sender);
    let ca: Ca = std::mem::replace(&mut test.ca, Ca::open(&[test.drives.ca_drive(0)]).unwrap());
    let worker = std::thread::spawn(move || {
        let mut token = token;
        testing::supply_generated_key(keys::rsa4096(0));
        let sink = move |progress: Progress| {
            let _ = sender.lock().unwrap().send(progress);
        };
        let outcome = plan.execute(
            &ca,
            &mut token as &mut dyn TokenSigner,
            &s(PIN),
            &passphrase,
            None,
            &sink,
            &CancelFlag::new(),
        );
        (ca, outcome)
    });
    // The "GUI" loop keeps running and receives progress while the worker signs. (Wall
    // clock gaps are not asserted: they measure the test machine's scheduler, not
    // Keystone.)
    let mut events = Vec::new();
    let mut polls_while_running = 0u32;
    let mut events_while_running = 0usize;
    let started = Instant::now();
    while !worker.is_finished() {
        if let Ok(event) = receiver.recv_timeout(StdDuration::from_millis(10)) {
            events.push(event);
        }
        polls_while_running += 1;
        events_while_running = events.len();
    }
    let elapsed = started.elapsed();
    let (ca, outcome) = worker.join().unwrap();
    events.extend(receiver.try_iter());
    outcome.expect("Flow C on a worker thread");
    assert!(elapsed >= StdDuration::from_millis(400), "{elapsed:?}");
    assert!(polls_while_running >= 5, "{polls_while_running} polls");
    assert!(events_while_running >= 3, "{events_while_running} events");
    assert!(events.contains(&Progress::TouchYubiKey));
    for step in [
        Step::Journaling,
        Step::GeneratingKey,
        Step::SigningCertificate,
        Step::Done,
    ] {
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Progress::Step { step: s, .. } if *s == step)),
            "{step:?} missing"
        );
    }
    assert_consistent(&ca);
}
