//! The journaled operation pipeline shared by every flow (FR-12, FR-16 AC2, FR-22
//! AC1-AC3) and the deterministic output builder shared by normal execution and recovery.
//!
//! An operation's outputs and audit entries are a pure function of its journal (what was
//! signed), the CA state before it and, for Flows A and C, the encrypted key staged
//! before signing ([`assemble`]). Normal execution and the recovery action "rebuild from
//! the journal" both call it, so an interrupted operation is finished with exactly the
//! files it would have written.
#![forbid(unsafe_code)]

use crate::cert::{IssuedCertificate, PlannedSerial, chain_pem, plan_serial};
use crate::clock::ConfirmedTime;
use crate::crl::{IssuedCrl, RevokedEntry, parse_crl_pem};
use crate::crypto::CancelFlag;
use crate::crypto::hash::sha256;
use crate::crypto::verify::crl_pem_to_der;
use crate::limits::MAX_OUTPUT_FILE_BYTES;
use crate::model::{CaLevel, Serial, Timestamp};
use crate::profile::{CrlLocation, NameConstraintsChoice};
use crate::store::audit::with_serials;
use crate::store::{
    AuditAction, AuditDetails, AuditDraft, AuditResult, CertStatus, CertificateRecord,
    OperationHandle, OperationId, OperationJournal, OperationKind, OutputDir, OutputPath,
    RecordChange, RecordUpdate, SignedCrl, SignedObject, StoreError, SubjectName,
};

use super::seam::{self, FaultPoint};
use super::state::{CaState, certificate_path, chain_path, crl_path, key_path};
use super::{Ca, OpsError, Progress, ProgressSink, Step};

/// What every step of a running operation needs.
pub(crate) struct OpContext<'a> {
    pub(crate) time: ConfirmedTime,
    pub(crate) progress: &'a dyn ProgressSink,
    pub(crate) cancel: &'a CancelFlag,
    /// Set before any call that may make a persistent change outside the journal (a
    /// YubiKey credential change or on-device key generation), and after any signature.
    pub(crate) persistent: bool,
}

impl<'a> OpContext<'a> {
    pub(crate) fn new(
        time: ConfirmedTime,
        progress: &'a dyn ProgressSink,
        cancel: &'a CancelFlag,
    ) -> Self {
        OpContext {
            time,
            progress,
            cancel,
            persistent: false,
        }
    }

    pub(crate) fn ts(&self) -> Timestamp {
        self.time.get()
    }

    fn cancellable(&self, handle: &OperationHandle<'_>) -> bool {
        !self.persistent && !handle.has_persistent_change()
    }

    /// Reports a new step.
    pub(crate) fn step(&self, handle: &OperationHandle<'_>, step: Step) {
        self.progress.report(Progress::Step {
            step,
            cancel_available: self.cancellable(handle),
        });
    }

    /// FR-16 AC2: stops when Cancel was pressed and nothing persistent happened yet.
    pub(crate) fn check_cancel(&self, handle: &OperationHandle<'_>) -> Result<(), OpsError> {
        if self.cancel.is_cancelled() && self.cancellable(handle) {
            return Err(OpsError::CancelRequested);
        }
        Ok(())
    }
}

/// Draws a serial that no record or journal on any connected drive has seen
/// (FR-10 AC2).
pub(crate) fn plan_unique_serial(ca: &Ca) -> Result<PlannedSerial, OpsError> {
    let known = ca.drive_set().known_serials()?;
    if let Some(candidate) = seam::serial_candidate()
        && !known.contains(&candidate)
    {
        return Ok(PlannedSerial::from_reserved(candidate));
    }
    Ok(plan_serial(&mut |serial| known.contains(serial))?)
}

/// Writes the pending entry (FR-22 AC1). Cancel before this point writes nothing.
pub(crate) fn begin<'a>(
    ca: &'a Ca,
    ctx: &OpContext<'_>,
    kind: OperationKind,
    subject: &str,
    serials: &[Serial],
) -> Result<OperationHandle<'a>, OpsError> {
    if ctx.cancel.is_cancelled() {
        return Err(OpsError::CancelledBeforeStart);
    }
    ctx.progress.report(Progress::Step {
        step: Step::Journaling,
        cancel_available: true,
    });
    Ok(ca
        .drive_set()
        .begin_operation(kind, subject, serials, ctx.ts())?)
}

/// Runs `body` on a begun operation, then writes the completed entry last. A failure is
/// turned into a cancel (nothing persistent yet) or left pending for recovery.
pub(crate) fn run<T>(
    mut handle: OperationHandle<'_>,
    ctx: &mut OpContext<'_>,
    body: impl FnOnce(&mut OperationHandle<'_>, &mut OpContext<'_>) -> Result<T, OpsError>,
) -> Result<(OperationId, T), OpsError> {
    match body(&mut handle, ctx) {
        Ok(value) => {
            let operation = handle.id();
            ctx.step(&handle, Step::Completing);
            handle
                .complete(ctx.ts())
                .map_err(|error| OpsError::Interrupted {
                    operation,
                    cause: Box::new(error.into()),
                })?;
            ctx.progress.report(Progress::Step {
                step: Step::Done,
                cancel_available: false,
            });
            Ok((operation, value))
        }
        Err(error) => Err(abort(handle, ctx, error)),
    }
}

/// Ends a failed operation: nothing after a simulated crash; cancel when nothing
/// persistent happened (FR-16 AC2); otherwise leave it pending (FR-22 AC4).
pub(crate) fn abort(handle: OperationHandle<'_>, ctx: &OpContext<'_>, error: OpsError) -> OpsError {
    let operation = handle.id();
    if seam::simulating_crash() || matches!(error, OpsError::InjectedFault(_)) {
        return error;
    }
    if !ctx.cancellable(&handle) {
        return OpsError::Interrupted {
            operation,
            cause: Box::new(error),
        };
    }
    let reserved_serials = handle.planned_serials().to_vec();
    ctx.progress.report(Progress::Step {
        step: Step::Cancelling,
        cancel_available: false,
    });
    match handle.cancel(ctx.ts()) {
        Ok(()) => match error {
            OpsError::CancelRequested => OpsError::Cancelled {
                operation,
                reserved_serials,
            },
            cause => OpsError::Stopped {
                operation,
                reserved_serials,
                cause: Box::new(cause),
            },
        },
        Err(_) => OpsError::Interrupted {
            operation,
            cause: Box::new(error),
        },
    }
}

/// The record entry of a newly signed certificate (FR-11 AC1, FR-21 AC6, FR-07 AC5).
/// `issuer` is `None` for the self-signed master.
pub(crate) fn certificate_record(
    level: CaLevel,
    issued: &IssuedCertificate,
    subject: SubjectName,
    issuer: Option<&CertificateRecord>,
    constraints: Option<&NameConstraintsChoice>,
    attestation_pem: Option<String>,
) -> CertificateRecord {
    let info = &issued.info;
    let (permitted_dns, permitted_ip, constrained) = match constraints {
        Some(NameConstraintsChoice::Constrained(spec)) => (
            spec.permitted_dns()
                .iter()
                .map(ToString::to_string)
                .collect(),
            spec.permitted_ip()
                .iter()
                .map(ToString::to_string)
                .collect(),
            true,
        ),
        _ => (Vec::new(), Vec::new(), false),
    };
    CertificateRecord {
        serial: info.serial,
        level,
        issuer_serial: issuer.map_or(info.serial, |i| i.serial),
        issuer: issuer.map_or_else(|| subject.clone(), |i| i.subject.clone()),
        subject,
        not_before: Timestamp::utc(info.not_before),
        not_after: Timestamp::utc(info.not_after),
        fingerprint: info.fingerprint,
        name_constraints: constrained,
        permitted_dns,
        permitted_ip,
        attestation_pem,
    }
}

/// A signed CRL as journaled (FR-22 AC3).
pub(crate) fn signed_crl(issuer_serial: Serial, crl: &IssuedCrl) -> SignedCrl {
    SignedCrl {
        issuer_serial,
        crl_number: crl.info.crl_number,
        this_update: Timestamp::utc(crl.info.this_update),
        next_update: Timestamp::utc(crl.info.next_update),
        sha256: crl.info.fingerprint,
        pem: crl.pem.clone(),
    }
}

/// Journals a signed certificate right after signing (FR-22 AC3).
pub(crate) fn record_certificate(
    handle: &mut OperationHandle<'_>,
    ctx: &mut OpContext<'_>,
    record: CertificateRecord,
    pem: String,
) -> Result<(), OpsError> {
    ctx.persistent = true;
    seam::fault(FaultPoint::AfterSigning)?;
    handle.record_signed(
        SignedObject::Certificate {
            record: Box::new(record),
            pem,
        },
        ctx.ts(),
    )?;
    seam::fault(FaultPoint::AfterSignedRecorded)
}

/// Journals a signed CRL right after signing (FR-22 AC3).
pub(crate) fn record_crl(
    handle: &mut OperationHandle<'_>,
    ctx: &mut OpContext<'_>,
    crl: SignedCrl,
) -> Result<(), OpsError> {
    ctx.persistent = true;
    seam::fault(FaultPoint::AfterSigning)?;
    handle.record_signed(SignedObject::Crl(Box::new(crl)), ctx.ts())?;
    seam::fault(FaultPoint::AfterSignedRecorded)
}

/// An operation's outputs and audit entries.
#[derive(Debug)]
pub(crate) struct Assembly {
    /// Files, in staging order.
    pub(crate) files: Vec<(OutputPath, Vec<u8>)>,
    /// Audit entries.
    pub(crate) audit: Vec<AuditDraft>,
}

fn certificates(journal: &OperationJournal) -> Vec<(&CertificateRecord, &str)> {
    journal
        .signed()
        .filter_map(|object| match object {
            SignedObject::Certificate { record, pem } => Some((&**record, pem.as_str())),
            SignedObject::Crl(_) => None,
        })
        .collect()
}

fn crls(journal: &OperationJournal) -> Vec<&SignedCrl> {
    journal
        .signed()
        .filter_map(|object| match object {
            SignedObject::Crl(crl) => Some(&**crl),
            SignedObject::Certificate { .. } => None,
        })
        .collect()
}

fn one<T>(items: Vec<T>, what: &str, operation: OperationId) -> Result<T, OpsError> {
    let count = items.len();
    let mut items = items.into_iter();
    match (items.next(), count) {
        (Some(item), 1) => Ok(item),
        _ => Err(OpsError::NotReady(format!(
            "{operation} journaled {count} {what}; exactly one is needed"
        ))),
    }
}

fn crl_file(crl: &SignedCrl) -> Result<Vec<u8>, OpsError> {
    let der = crl_pem_to_der(crl.pem.as_bytes())?;
    if sha256(&der) != crl.sha256 {
        return Err(OpsError::Damaged(format!(
            "CRL {} does not match its journaled SHA-256",
            crl.crl_number
        )));
    }
    Ok(der)
}

fn draft(
    action: AuditAction,
    subject: String,
    serial: Option<Serial>,
    record: Option<&CertificateRecord>,
    details: AuditDetails,
) -> AuditDraft {
    let mut draft = AuditDraft::new(action, subject, AuditResult::Success);
    draft.serial = serial;
    draft.fingerprint = record.map(|r| r.fingerprint);
    draft.details = Some(details);
    draft
}

fn crl_address_note(
    state: &CaState,
    issuer: &CertificateRecord,
    child: &CertificateRecord,
    child_pem: &str,
) -> Result<Option<String>, OpsError> {
    if state.crl_location(issuer.serial)?.is_some() {
        return Ok(None);
    }
    let (_, info) = crate::cert::parse_certificate_pem(child_pem.as_bytes())?;
    let _ = child;
    Ok(Some(match info.crl_distribution_urls.first() {
        Some(url) => format!(
            "CRL address of {} set to {url} (FR-18)",
            issuer.subject.display()
        ),
        None => format!(
            "CRL address of {} explicitly left empty; revocation of its certificates cannot be checked (FR-18)",
            issuer.subject.display()
        ),
    }))
}

/// Builds an operation's outputs and audit entries from its journal (see module docs).
pub(crate) fn assemble(
    journal: &OperationJournal,
    state: &CaState,
    staged_key: Option<&[u8]>,
) -> Result<Assembly, OpsError> {
    let operation = journal.operation();
    let need_key = || {
        staged_key.map(<[u8]>::to_vec).ok_or_else(|| {
            OpsError::NotReady(format!(
                "the encrypted key of {operation} is not staged on any drive"
            ))
        })
    };
    let mut files = Vec::new();
    let audit = match journal.kind() {
        OperationKind::CreateMaster => {
            let (cert, pem) = one(certificates(journal), "certificates", operation)?;
            let crl = one(crls(journal), "CRLs", operation)?;
            files.push((
                key_path(CaLevel::Master, &cert.subject.common_name, cert.serial),
                need_key()?,
            ));
            files.push((certificate_path(cert), pem.as_bytes().to_vec()));
            files.push((crl_path(cert, crl.crl_number), crl_file(crl)?));
            files.push(record_file(operation, vec![issued(cert)]));
            vec![draft(
                AuditAction::CreateMaster,
                cert.subject.display(),
                Some(cert.serial),
                Some(cert),
                AuditDetails {
                    crl_number: Some(crl.crl_number),
                    note: Some(
                        "RSA 8,192 master key stored encrypted (PBES2, scrypt, AES-256-CBC); first empty CRL signed (FR-13 AC6)"
                            .to_owned(),
                    ),
                    ..AuditDetails::default()
                },
            )]
        }
        OperationKind::SetupYubikey => {
            let (cert, pem) = one(certificates(journal), "certificates", operation)?;
            let crl = one(crls(journal), "CRLs", operation)?;
            let master = state
                .certificate(cert.issuer_serial)
                .ok_or_else(|| OpsError::NotReady("the master is not in the record".into()))?;
            files.push((certificate_path(cert), pem.as_bytes().to_vec()));
            files.push((crl_path(cert, crl.crl_number), crl_file(crl)?));
            files.push(record_file(operation, vec![issued(cert)]));
            let mut notes = Vec::new();
            if let Some((_, device)) = journal.yubikey_steps().first() {
                notes.push(format!("YubiKey serial {device}"));
            }
            notes.push("key generated on the YubiKey, attestation verified (FR-07 AC5); first empty CRL signed by the YubiKey (FR-13 AC6)".to_owned());
            notes.extend(crl_address_note(state, &master.record, cert, pem)?);
            vec![draft(
                AuditAction::SetupYubikey,
                cert.subject.display(),
                Some(cert.serial),
                Some(cert),
                AuditDetails {
                    issuer_serial: Some(cert.issuer_serial),
                    crl_number: Some(crl.crl_number),
                    note: Some(notes.join("; ")),
                    ..AuditDetails::default()
                },
            )]
        }
        OperationKind::CreateSubIntermediate => {
            let (cert, pem) = one(certificates(journal), "certificates", operation)?;
            let main = state.certificate(cert.issuer_serial).ok_or_else(|| {
                OpsError::NotReady("the main intermediate is not in the record".into())
            })?;
            let master = state
                .master()
                .ok_or_else(|| OpsError::NotReady("the master is not in the record".into()))?;
            let (sub_der, _) = crate::cert::parse_certificate_pem(pem.as_bytes())?;
            let chain = chain_pem(&sub_der, &main.der, &master.der)?;
            files.push((
                key_path(
                    CaLevel::SubIntermediate,
                    &cert.subject.common_name,
                    cert.serial,
                ),
                need_key()?,
            ));
            files.push((certificate_path(cert), pem.as_bytes().to_vec()));
            files.push((chain_path(cert), chain.into_bytes()));
            files.push(record_file(operation, vec![issued(cert)]));
            let note = crl_address_note(state, &main.record, cert, pem)?;
            vec![draft(
                AuditAction::CreateSubIntermediate,
                cert.subject.display(),
                Some(cert.serial),
                Some(cert),
                AuditDetails {
                    issuer_serial: Some(cert.issuer_serial),
                    name_constraints: Some(cert.name_constraints),
                    permitted_dns: Some(cert.permitted_dns.clone()),
                    permitted_ip: Some(cert.permitted_ip.clone()),
                    note,
                    ..AuditDetails::default()
                },
            )]
        }
        OperationKind::RefreshCrl => {
            let crl = one(crls(journal), "CRLs", operation)?;
            let issuer = state.certificate(crl.issuer_serial).ok_or_else(|| {
                OpsError::NotReady("the CRL's issuer is not in the record".into())
            })?;
            files.push((crl_path(&issuer.record, crl.crl_number), crl_file(crl)?));
            vec![draft(
                AuditAction::RefreshCrl,
                issuer.record.subject.display(),
                Some(issuer.serial()),
                Some(&issuer.record),
                AuditDetails {
                    crl_number: Some(crl.crl_number),
                    note: Some("CRL re-signed without new revocations (FR-13 AC4)".to_owned()),
                    ..AuditDetails::default()
                },
            )]
        }
        kind @ (OperationKind::Revoke | OperationKind::ReplaceYubikey) => {
            let crl = one(crls(journal), "CRLs", operation)?;
            let issuer = state.certificate(crl.issuer_serial).ok_or_else(|| {
                OpsError::NotReady("the CRL's issuer is not in the record".into())
            })?;
            let entry = new_revocation(state, crl)?;
            let target = state.certificate(entry.serial).ok_or_else(|| {
                OpsError::NotReady(format!(
                    "revoked certificate {} is not in the record",
                    entry.serial
                ))
            })?;
            let date = Timestamp::utc(entry.revocation_date);
            let mut changes = vec![RecordChange::Revoked {
                serial: entry.serial,
                date,
                reason: entry.reason,
            }];
            let cut_off = cut_off_children(state, entry.serial);
            changes.extend(
                cut_off
                    .iter()
                    .map(|serial| RecordChange::RevokedByAncestor {
                        serial: *serial,
                        ancestor: entry.serial,
                        date,
                    }),
            );
            files.push((crl_path(&issuer.record, crl.crl_number), crl_file(crl)?));
            files.push(record_file(operation, changes));
            // The note stays short whatever the number of children: the serials go in
            // `details.serials`, over several entries when needed (FR-14 AC1; a long
            // list in the note made the audit append fail after the CRL was signed).
            let mut note = format!("revoked by {}", issuer.record.subject.display());
            if !cut_off.is_empty() {
                note.push_str(&format!(
                    "; {} sub-intermediate(s) marked revoked by ancestor, listed with it in serials",
                    cut_off.len()
                ));
            }
            let action = if kind == OperationKind::Revoke {
                AuditAction::Revoke
            } else {
                AuditAction::ReplaceYubikey
            };
            let first = draft(
                action,
                target.record.subject.display(),
                Some(entry.serial),
                Some(&target.record),
                AuditDetails {
                    issuer_serial: Some(issuer.serial()),
                    revocation_reason: Some(entry.reason),
                    crl_number: Some(crl.crl_number),
                    note: Some(note),
                    ..AuditDetails::default()
                },
            );
            if cut_off.is_empty() {
                vec![first]
            } else {
                let serials: Vec<Serial> = std::iter::once(entry.serial)
                    .chain(cut_off.iter().copied())
                    .collect();
                with_serials(first, &serials)
            }
        }
    };
    Ok(Assembly { files, audit })
}

fn issued(cert: &CertificateRecord) -> RecordChange {
    RecordChange::Issued {
        certificate: Box::new(cert.clone()),
    }
}

fn record_file(operation: OperationId, changes: Vec<RecordChange>) -> (OutputPath, Vec<u8>) {
    let update = RecordUpdate::new(operation, changes);
    (update.output_path(), update.to_bytes())
}

/// The one entry a revocation CRL adds to the issuer's current CRL.
fn new_revocation(state: &CaState, crl: &SignedCrl) -> Result<RevokedEntry, OpsError> {
    let (_, info) = parse_crl_pem(crl.pem.as_bytes())?;
    let previous = state
        .current_crl(crl.issuer_serial)
        .map(|current| current.info.revoked.clone())
        .unwrap_or_default();
    let added: Vec<RevokedEntry> = info
        .revoked
        .into_iter()
        .filter(|entry| !previous.iter().any(|p| p.serial == entry.serial))
        .collect();
    one(added, "new revocations", OperationId(0)).map_err(|_| {
        OpsError::Damaged(format!(
            "CRL {} does not add exactly one revocation to the previous CRL",
            crl.crl_number
        ))
    })
}

/// Valid sub-intermediates under a main intermediate being revoked (FR-15 AC1).
pub(crate) fn cut_off_children(state: &CaState, revoked: Serial) -> Vec<Serial> {
    match state.certificate(revoked) {
        Some(cert) if cert.level() == CaLevel::MainIntermediate => state
            .children_of(revoked)
            .into_iter()
            .filter(|child| child.status == CertStatus::Valid)
            .map(|child| child.serial())
            .collect(),
        _ => Vec::new(),
    }
}

/// Stages every output not staged yet, seals staging, moves the outputs into place and
/// writes the audit entries (FR-22 AC2, FR-12 AC2). The completed entry follows.
pub(crate) fn finish(
    handle: &mut OperationHandle<'_>,
    ctx: &OpContext<'_>,
    assembly: &Assembly,
) -> Result<(), OpsError> {
    ctx.step(handle, Step::StagingOutputs);
    for (path, data) in &assembly.files {
        match handle.outputs().iter().find(|output| output.path == *path) {
            Some(output) if output.sha256 == sha256(data) => {}
            Some(_) => {
                return Err(OpsError::Damaged(format!(
                    "{path} was staged with different content"
                )));
            }
            None => {
                handle.stage(path.clone(), data)?;
            }
        }
    }
    handle.seal_staging(ctx.ts())?;
    seam::fault(FaultPoint::AfterStaged)?;
    ctx.step(handle, Step::MovingIntoPlace);
    handle.commit()?;
    seam::fault(FaultPoint::AfterCommit)?;
    ctx.step(handle, Step::WritingAuditLog);
    handle.append_audit(&assembly.audit, ctx.ts())?;
    seam::fault(FaultPoint::AfterAudit)
}

/// Re-reads the operation's journal from the primary drive and finishes it.
pub(crate) fn assemble_and_finish(
    ca: &Ca,
    handle: &mut OperationHandle<'_>,
    ctx: &OpContext<'_>,
    state: &CaState,
    staged_key: Option<&[u8]>,
) -> Result<(), OpsError> {
    let journal = ca.drive_set().drives()[0]
        .operation_journal(handle.id())?
        .ok_or_else(|| OpsError::Damaged(format!("{} has no journal", handle.id())))?;
    let assembly = assemble(&journal, state, staged_key)?;
    finish(handle, ctx, &assembly)
}

/// The encrypted key a Flow A or C operation staged before signing, read from the
/// staging folder of the drives (recovery). Every copy found must be identical.
pub(crate) fn staged_key(
    ca: &Ca,
    operation: OperationId,
    path: &OutputPath,
) -> Result<Option<Vec<u8>>, OpsError> {
    let rel = format!(
        "{}/{}/{}",
        crate::store::STAGING_DIR,
        operation.stem(),
        OutputDir::Keys.name()
    );
    let mut found: Option<Vec<u8>> = None;
    for drive in ca.drive_set().drives() {
        if let Some(data) = drive.read_at(&rel, path.name(), MAX_OUTPUT_FILE_BYTES)? {
            match &found {
                Some(existing) if *existing != data => {
                    return Err(OpsError::Store(StoreError::Unsafe(format!(
                        "the drives hold different staged copies of {path}; no automatic action is safe"
                    ))));
                }
                _ => found = Some(data),
            }
        }
    }
    Ok(found)
}

/// The location a request gives for an issuer's CRL, checked against the stored one
/// (FR-18 AC1: asked once per issuer, before its first child).
pub(crate) fn resolve_crl_location(
    state: &CaState,
    issuer: Serial,
    issuer_name: &str,
    requested: Option<&CrlLocation>,
) -> Result<(CrlLocation, bool), OpsError> {
    match (state.crl_location(issuer)?, requested) {
        (Some(stored), None) => Ok((stored, false)),
        (Some(stored), Some(requested)) if stored == *requested => Ok((stored, false)),
        (Some(stored), Some(_)) => Err(OpsError::NotReady(format!(
            "the CRL address of {issuer_name} is already set to {}; it cannot change for later certificates",
            match &stored {
                CrlLocation::Url(url) => url.to_string(),
                CrlLocation::ExplicitlyNone => "none".to_owned(),
            }
        ))),
        (None, Some(requested)) => Ok((requested.clone(), true)),
        (None, None) => Err(OpsError::NotReady(format!(
            "enter the address where {issuer_name}'s CRL will be hosted, or choose explicitly to leave it empty (FR-18)"
        ))),
    }
}
