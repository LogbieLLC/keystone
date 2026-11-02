//! Writes complete synthetic KEYSTONE TEST hierarchies to a folder, for the CI jobs
//! that lint every certificate and CRL (FR-10 AC4, SEC-13) and scan every output
//! for plaintext private keys (SEC-04).
//!
//! - `constrained/` and `unconstrained/`: hierarchies built directly with the
//!   certificate and CRL builders.
//! - `flows/`: what Keystone itself writes. Flows A, B, C (with and without name
//!   constraints), D, Refresh CRL and E run through `keystone_core::ops` against the
//!   simulated YubiKey, and every file of the primary drive and the export drive is
//!   copied here unchanged (certificates, chains, DER CRLs, encrypted keys, audit log,
//!   journals, issuance record).
//!
//! Usage: cargo run -p keystone-testkit --example generate_samples -- <empty output dir>
//!
//! Development tool only: it uses synthetic test keys from keystone-testkit
//! (TEST-11) and is never part of a production build.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use keystone_core::clock;
use keystone_core::crypto::CancelFlag;
use keystone_core::model::Serial;
use keystone_core::ops::{
    Ca, ConfirmedTime, CreateMasterRequest, IssuerUnlock, MainIntermediateRequest, NoProgress,
    PinEntry, SubIntermediateRequest, YubikeySecrets, assess_clock_for_new_ca, plan_create_master,
    testing,
};
use keystone_core::passphrase::{ConfirmedPassphrase, EnteredPassphrase, NewPassphrase};
use keystone_core::profile::{CrlLocation, CrlUrl, NameConstraintsChoice, NameConstraintsSpec};
use keystone_core::token::{NewPin, NewPuk};
use keystone_testkit::names::test_name;
use keystone_testkit::{SimulatedYubiKey, SimulatorConfig, TestDrives, keys};
use time::{Duration, OffsetDateTime};

use keystone_core::cert::{SoftwareSigner, chain_pem};
use keystone_core::crl::{RevokedEntry, crl_with_revocation};
use keystone_core::crypto::pkcs8::{encrypt_master_key_pem, encrypt_sub_key_pem};
use keystone_core::crypto::secret::SecretString;
use keystone_core::model::RevocationReason;
use keystone_testkit::hierarchy::{HierarchyOptions, TestHierarchy};

fn main() {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: generate_samples <empty output dir>");
    fs::create_dir_all(&output).expect("create output dir");
    assert!(
        fs::read_dir(&output)
            .expect("read output dir")
            .next()
            .is_none(),
        "output dir must be empty"
    );

    let constrained = TestHierarchy::build(&HierarchyOptions::default());
    write_hierarchy(&output.join("constrained"), &constrained);

    let unconstrained = TestHierarchy::build(&HierarchyOptions {
        unconstrained_sub: true,
        label: "unconstrained".to_owned(),
        ..HierarchyOptions::default()
    });
    write_hierarchy(&output.join("unconstrained"), &unconstrained);

    write_flow_outputs(&output.join("flows"));
}

fn write_hierarchy(dir: &Path, hierarchy: &TestHierarchy) {
    fs::create_dir_all(dir).expect("create hierarchy dir");
    let write = |name: &str, contents: &[u8]| {
        fs::write(dir.join(name), contents).expect("write sample");
    };
    write("master.crt", hierarchy.master.pem.as_bytes());
    write("main.crt", hierarchy.main.pem.as_bytes());
    write("sub.crt", hierarchy.sub.pem.as_bytes());
    write("master.crl", hierarchy.master_crl.pem.as_bytes());
    write("main.crl", hierarchy.main_crl.pem.as_bytes());
    let chain = chain_pem(
        &hierarchy.sub.der,
        &hierarchy.main.der,
        &hierarchy.master.der,
    )
    .expect("chain");
    write("sub-chain.pem", chain.as_bytes());

    // A master CRL that revokes the main intermediate, signed by the master key.
    let mut master_signer = SoftwareSigner::new(hierarchy.master_key);
    let revoked = crl_with_revocation(
        &hierarchy.master_crl.der,
        &hierarchy.master.der,
        RevokedEntry {
            serial: hierarchy.main.info.serial,
            revocation_date: hierarchy.master_crl.info.this_update,
            reason: RevocationReason::KeyCompromise,
        },
        hierarchy.master_crl.info.this_update,
        &mut master_signer,
    )
    .expect("revocation CRL");
    write("master-revoked.crl", revoked.pem.as_bytes());

    // Encrypted keys (the only form a private key is ever written in, SEC-04).
    let passphrase =
        SecretString::from_str_copy("keystone test sample passphrase only").expect("locked memory");
    let master_key = encrypt_master_key_pem(hierarchy.master_key, &passphrase).expect("encrypt");
    write("master.key", master_key.as_bytes());
    let sub_key = encrypt_sub_key_pem(hierarchy.sub_key, &passphrase).expect("encrypt");
    write("sub.key", sub_key.as_bytes());
}

/// Test PIN of the simulated YubiKey (synthetic, TEST-11).
const PIN: &str = "KsT#2468";
/// Test PUK of the simulated YubiKey (synthetic, TEST-11).
const PUK: &str = "KsT#9753";

fn secret(text: &str) -> SecretString {
    SecretString::from_str_copy(text).expect("locked memory")
}

fn crl_url(url: &str) -> CrlLocation {
    CrlLocation::Url(CrlUrl::parse(url).expect("CRL address"))
}

/// A generated passphrase, confirmed word by word as the operator would (FR-03), and
/// its words for unlocking later.
fn confirm(words: NewPassphrase) -> (ConfirmedPassphrase, String) {
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

/// Runs Flows A to E through the operations layer on temporary drives and copies every
/// file Keystone wrote into `dir`.
fn write_flow_outputs(dir: &Path) {
    let drives = TestDrives::new(2);
    // Whole seconds near the real time: the simulator's attestation certificates are
    // valid around it.
    let mut now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole seconds");

    // Flow A: the master, with the cached test key (TEST-11).
    testing::supply_generated_key(keys::master(0));
    let (master_passphrase, master_words) =
        confirm(NewPassphrase::generate_master(10).expect("passphrase"));
    let backups = [drives.ca_drive(1)];
    let request =
        CreateMasterRequest::new(drives.ca_drive(0), &backups, test_name("Samples Master"));
    let confirmed_now = clock::confirm(&assess_clock_for_new_ca(now), false).expect("time");
    let ca = plan_create_master(request, confirmed_now)
        .expect("Flow A plan")
        .execute(
            &master_passphrase,
            Some(drives.export_drive()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("Flow A")
        .ca;
    drop(master_passphrase);
    let master_entered = EnteredPassphrase::parse(&master_words).expect("passphrase");

    // Flow B: YubiKey setup, main intermediate and its first CRL.
    let mut token = SimulatedYubiKey::new(SimulatorConfig {
        serial: 30_000_001,
        ..SimulatorConfig::default()
    });
    let request = MainIntermediateRequest::new(
        test_name("Samples Main"),
        Some(crl_url("http://crl.keystone.test/master.crl")),
    );
    let time = next(&ca, &mut now);
    let plan = ca
        .plan_yubikey_setup(&mut token, &request, time)
        .expect("Flow B plan");
    let trust = token.attestation_trust();
    let secrets = YubikeySecrets {
        pin: PinEntry::New(NewPin::from_entries(&secret(PIN), &secret(PIN)).expect("PIN")),
        new_puk: Some(NewPuk::from_entries(&secret(PUK), &secret(PUK)).expect("PUK")),
        master_passphrase: Some(&master_entered),
    };
    plan.execute(
        &ca,
        &mut token,
        &secrets,
        &trust,
        Some(drives.export_drive()),
        &NoProgress,
        &CancelFlag::new(),
    )
    .expect("Flow B");
    drop(secrets);

    // Flow C twice: with name constraints (the default) and explicitly without.
    let pin = secret(PIN);
    let constrained = NameConstraintsChoice::Constrained(
        NameConstraintsSpec::new(&["starnet"], &[] as &[&str]).expect("constraints"),
    );
    let mut subs: Vec<Serial> = Vec::new();
    for (index, (label, choice)) in [
        ("Samples Sub Constrained", constrained),
        (
            "Samples Sub Unconstrained",
            NameConstraintsChoice::ExplicitlyUnconstrained,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let time = next(&ca, &mut now);
        let state = ca.state().expect("state");
        let main = state.active_main(now).expect("active main").serial();
        let main_crl = state
            .crl_location(main)
            .expect("CRL location")
            .is_none()
            .then(|| crl_url("http://crl.keystone.test/main.crl"));
        let request = SubIntermediateRequest::new(test_name(label), choice, main_crl);
        let plan = ca
            .plan_sub_intermediate(&request, time)
            .expect("Flow C plan");
        let (sub_passphrase, _) =
            confirm(NewPassphrase::generate_sub_intermediate().expect("passphrase"));
        testing::supply_generated_key(keys::rsa4096(index));
        let outcome = plan
            .execute(
                &ca,
                &mut token,
                &pin,
                &sub_passphrase,
                Some(drives.export_drive()),
                &NoProgress,
                &CancelFlag::new(),
            )
            .expect("Flow C");
        subs.push(outcome.serial);
    }

    // Flow D: revoke the unconstrained sub-intermediate (main intermediate's CRL #2).
    let time = next(&ca, &mut now);
    ca.plan_revoke(subs[1], RevocationReason::KeyCompromise, time)
        .expect("Flow D plan")
        .execute(
            &ca,
            IssuerUnlock::YubiKey {
                token: &mut token,
                pin: &pin,
            },
            Some(drives.export_drive()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("Flow D");

    // Refresh CRL: the master's CRL #2, with the master passphrase.
    let state = ca.state().expect("state");
    let master_serial = state.master().expect("master").serial();
    let time = next(&ca, &mut now);
    ca.plan_refresh_crl(master_serial, time)
        .expect("Refresh CRL plan")
        .execute(
            &ca,
            IssuerUnlock::Master(&master_entered),
            Some(drives.export_drive()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("Refresh CRL");

    // Flow E: the main intermediate's YubiKey is replaced, so the master revokes it
    // (master CRL #3 lists it).
    let time = next(&ca, &mut now);
    ca.plan_replace_yubikey(RevocationReason::KeyCompromise, time)
        .expect("Flow E plan")
        .execute(
            &ca,
            IssuerUnlock::Master(&master_entered),
            Some(drives.export_drive()),
            &NoProgress,
            &CancelFlag::new(),
        )
        .expect("Flow E");

    copy_tree(&drives.ca_drive(0).join("keystone"), &dir.join("primary"));
    copy_tree(
        &drives.export_drive().join("keystone-export"),
        &dir.join("export"),
    );
}

/// The confirmed time of the next operation: one minute after the last (SEC-16: each
/// confirmed time is used for one operation only).
fn next(ca: &Ca, now: &mut OffsetDateTime) -> ConfirmedTime {
    *now += Duration::minutes(1);
    clock::confirm(&ca.assess_clock(*now), false).expect("time confirms")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create sample dir");
    for entry in fs::read_dir(from).expect("read drive folder") {
        let entry = entry.expect("folder entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy sample");
        }
    }
}
