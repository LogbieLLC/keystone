//! E2E test helper: prepares synthetic CA drive states in folders the E2E runner
//! created with `mktemp -d` (TESTING.md TEST-11, TEST-12). Uses only the public
//! keystone-core API (store, and ops for the real-CA scenarios). Every name carries
//! `KEYSTONE TEST`. The store-only scenarios write placeholder PEM text, never real
//! keys; the `master` scenario creates a real CA through `ops` (the master key is
//! generated now and stored only encrypted) with a generated synthetic passphrase,
//! printed on stdout for the test to type in the GUI.
//!
//! ```text
//! cargo run -p keystone-gui --example e2e_prepare -- <scenario> <primary> <backup>
//! scenarios:
//!   pending       an interrupted "create master" operation: signed and staged on
//!                 both drives, nothing moved into place (FR-22 AC4, AC8)
//!   broken-audit  a CA whose backup drive's first audit entry was edited, which
//!                 breaks its hash chain (FR-14 AC3)
//!   diverged      a CA whose backup drive's last audit entry was edited: both chains
//!                 verify, but the histories differ (FR-12 AC3)
//!   lost-primary  a CA with one audit entry on both drives; the test then connects
//!                 only the backup (ADR 0003, "Replace a lost drive")
//! cargo run -p keystone-gui --example e2e_prepare -- behind <primary> <backup> <second>
//!   behind        a CA on three drives whose second backup missed one audit entry
//!                 (FR-12 AC3)
//! cargo run -p keystone-gui --example e2e_prepare -- master <primary> <backup> <export>
//!   master        Flow A through ops: a real master "KEYSTONE TEST E2E Root" and its
//!                 first CRL; prints the 10 passphrase words on one line
//! cargo run -p keystone-gui --example e2e_prepare -- interrupt-refresh <primary> <backup> <export>
//!   interrupt-refresh
//!                 reads the master passphrase from stdin and refreshes the master's
//!                 CRL through ops, stopped by the ops test seam right after the
//!                 outputs were moved into place (as if the process died there,
//!                 FR-22 AC6): the operation stays pending for the recovery screen
//! ```
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use keystone_core::model::{CaLevel, Serial, Sha256Digest, Timestamp};
use keystone_core::store::{
    AuditAction, AuditDraft, AuditResult, CertificateRecord, DriveSet, OperationKind, OutputDir,
    OutputPath, SignedObject, SubjectName,
};

fn ts(seconds: i64) -> Timestamp {
    Timestamp::utc(keystone_core::build_info::build_date() + time::Duration::seconds(seconds))
}

fn name(cn: &str) -> SubjectName {
    SubjectName {
        common_name: format!("KEYSTONE TEST {cn}"),
        organization: None,
        country: None,
    }
}

fn pending(primary: &Path, backup: &Path) -> Result<(), String> {
    let set = DriveSet::create(primary, &[backup], ts(0)).map_err(|e| e.to_string())?;
    let mut bytes = [0u8; 20];
    bytes[0] = 0x3e;
    bytes[19] = 0x01;
    let serial = Serial::from_bytes(bytes).ok_or("serial")?;
    let record = CertificateRecord {
        serial,
        level: CaLevel::Master,
        subject: name("E2E Root"),
        issuer_serial: serial,
        issuer: name("E2E Root"),
        not_before: ts(60),
        not_after: ts(60 + 20 * 365 * 86_400),
        fingerprint: Sha256Digest([0x5a; 32]),
        name_constraints: false,
        permitted_dns: Vec::new(),
        permitted_ip: Vec::new(),
        attestation_pem: None,
    };
    let certificate = format!(
        "-----BEGIN CERTIFICATE-----\nKEYSTONE TEST placeholder {serial}\n-----END CERTIFICATE-----\n"
    );
    let key = format!(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEYSTONE TEST placeholder {serial}\n-----END ENCRYPTED PRIVATE KEY-----\n"
    );
    let mut op = set
        .begin_operation(
            OperationKind::CreateMaster,
            &record.subject.display(),
            &[serial],
            ts(60),
        )
        .map_err(|e| e.to_string())?;
    op.record_signed(
        SignedObject::Certificate {
            record: Box::new(record),
            pem: certificate.clone(),
        },
        ts(61),
    )
    .map_err(|e| e.to_string())?;
    let hex = serial.to_hex();
    let cert_path =
        OutputPath::new(OutputDir::Certs, &format!("{hex}.crt")).map_err(|e| e.to_string())?;
    let key_path =
        OutputPath::new(OutputDir::Keys, &format!("{hex}.key")).map_err(|e| e.to_string())?;
    op.stage(cert_path, certificate.as_bytes())
        .map_err(|e| e.to_string())?;
    op.stage(key_path, key.as_bytes())
        .map_err(|e| e.to_string())?;
    op.seal_staging(ts(62)).map_err(|e| e.to_string())?;
    // Interrupted here: nothing was moved into place, no audit entry, no completed entry.
    Ok(())
}

/// Two audit entries on both drives, then the backup's copy of entry `edit` ("first" or
/// "second") is changed. Editing the first entry breaks the backup's hash chain
/// (FR-14 AC3); editing the last entry keeps each chain valid but makes the two
/// histories differ after entry 1 (FR-12 AC3).
fn edited_audit(primary: &Path, backup: &Path, edit: &str) -> Result<(), String> {
    let set = DriveSet::create(primary, &[backup], ts(0)).map_err(|e| e.to_string())?;
    set.append_audit(
        &[
            AuditDraft::new(
                AuditAction::Export,
                "CN=KEYSTONE TEST first",
                AuditResult::Success,
            ),
            AuditDraft::new(
                AuditAction::Export,
                "CN=KEYSTONE TEST second",
                AuditResult::Success,
            ),
        ],
        ts(30),
    )
    .map_err(|e| e.to_string())?;
    let log = backup.join("keystone").join("audit.log");
    let text = std::fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let original = format!("KEYSTONE TEST {edit}");
    if !text.contains(&original) {
        return Err(format!("no entry {original:?} to edit"));
    }
    std::fs::write(&log, text.replacen(&original, "KEYSTONE TEST edited", 1))
        .map_err(|e| e.to_string())
}

/// A CA on three drives; one audit entry is written with only the primary and the
/// first backup connected, so the second backup is behind (FR-12 AC3).
fn behind(primary: &Path, backup: &Path, second: &Path) -> Result<(), String> {
    DriveSet::create(primary, &[backup, second], ts(0)).map_err(|e| e.to_string())?;
    let two = DriveSet::open(&[primary, backup]).map_err(|e| e.to_string())?;
    two.append_audit(
        &[AuditDraft::new(
            AuditAction::Export,
            "CN=KEYSTONE TEST missed",
            AuditResult::Success,
        )],
        ts(30),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// A CA with one audit entry on both drives (ADR 0003 test: the primary is "lost").
fn lost_primary(primary: &Path, backup: &Path) -> Result<(), String> {
    let set = DriveSet::create(primary, &[backup], ts(0)).map_err(|e| e.to_string())?;
    set.append_audit(
        &[AuditDraft::new(
            AuditAction::Export,
            "CN=KEYSTONE TEST before the loss",
            AuditResult::Success,
        )],
        ts(30),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn confirmed_now() -> Result<keystone_core::clock::ConfirmedTime, String> {
    let now = time::OffsetDateTime::now_utc();
    keystone_core::clock::confirm(&keystone_core::ops::assess_clock_for_new_ca(now), false)
        .map_err(|e| e.to_string())
}

/// Flow A through ops with a generated, confirmed synthetic passphrase; returns its words.
fn master(primary: &Path, backup: &Path, export: &Path) -> Result<String, String> {
    use keystone_core::ops::{CancelFlag, CreateMasterRequest, NoProgress, plan_create_master};
    use keystone_core::passphrase::NewPassphrase;
    let mut session = NewPassphrase::generate_master(10)
        .map_err(|e| e.to_string())?
        .into_confirmation();
    session.set_written_down(true);
    let words: Vec<&'static str> = (1..=session.word_count())
        .filter_map(|n| session.view_words().word(n))
        .collect();
    for (index, word) in words.iter().enumerate() {
        session
            .enter_word(index + 1, word)
            .map_err(|e| e.to_string())?;
    }
    for group in 1..=session.group_count() {
        session.check_group(group).map_err(|e| e.to_string())?;
    }
    let passphrase = session
        .finish()
        .map_err(|_| "the passphrase was not confirmed".to_string())?;
    let request = CreateMasterRequest::new(
        primary,
        &[backup],
        keystone_core::model::NameFields {
            common_name: "KEYSTONE TEST E2E Root".into(),
            organization: None,
            country: None,
        },
    );
    plan_create_master(request, confirmed_now()?)
        .and_then(|plan| plan.execute(&passphrase, Some(export), &NoProgress, &CancelFlag::new()))
        .map_err(|e| e.to_string())?;
    Ok(words.join(" "))
}

/// Refreshes the master's CRL and stops right after its outputs were moved into place.
fn interrupt_refresh(primary: &Path, backup: &Path, export: &Path) -> Result<(), String> {
    use keystone_core::ops::{Ca, CancelFlag, IssuerUnlock, NoProgress, OpsError, testing};
    use keystone_core::passphrase::EnteredPassphrase;
    use std::io::Read;
    let mut words = String::new();
    std::io::stdin()
        .read_to_string(&mut words)
        .map_err(|e| e.to_string())?;
    let passphrase = EnteredPassphrase::parse(words.trim()).map_err(|e| e.to_string())?;
    words.clear();
    let ca = Ca::open(&[primary, backup]).map_err(|e| e.to_string())?;
    let master = ca
        .state()
        .map_err(|e| e.to_string())?
        .master()
        .map(|m| m.serial())
        .ok_or("no master")?;
    let plan = ca
        .plan_refresh_crl(master, confirmed_now()?)
        .map_err(|e| e.to_string())?;
    testing::arm_fault(testing::FaultPoint::AfterCommit);
    let result = plan.execute(
        &ca,
        IssuerUnlock::Master(&passphrase),
        Some(export),
        &NoProgress,
        &CancelFlag::new(),
    );
    testing::reset();
    match result {
        Err(OpsError::InjectedFault(_)) => Ok(()),
        Err(other) => Err(other.to_string()),
        Ok(_) => Err("the refresh was not interrupted".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [scenario, primary, backup] => {
            let (primary, backup) = (Path::new(primary), Path::new(backup));
            match scenario.as_str() {
                "pending" => pending(primary, backup),
                "broken-audit" => edited_audit(primary, backup, "first"),
                "diverged" => edited_audit(primary, backup, "second"),
                "lost-primary" => lost_primary(primary, backup),
                _ => Err(format!("unknown scenario {scenario}")),
            }
        }
        [scenario, primary, backup, export] if scenario == "master" => {
            match master(Path::new(primary), Path::new(backup), Path::new(export)) {
                Ok(words) => {
                    use std::io::Write;
                    // The synthetic test passphrase goes to the test through a pipe.
                    let _ = writeln!(std::io::stdout(), "{words}");
                    Ok(())
                }
                Err(message) => Err(message),
            }
        }
        [scenario, primary, backup, export] if scenario == "interrupt-refresh" => {
            interrupt_refresh(Path::new(primary), Path::new(backup), Path::new(export))
        }
        [scenario, primary, backup, second] if scenario == "behind" => {
            behind(Path::new(primary), Path::new(backup), Path::new(second))
        }
        _ => return ExitCode::from(2),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "e2e_prepare: {message}");
            ExitCode::FAILURE
        }
    }
}
