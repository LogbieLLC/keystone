//! Flow A: create the master (FR-02, FR-03, FR-04, FR-13 AC6, FR-20, SEC-20).
//!
//! Plan (nothing written) → review → execute: set up the empty drives, write the
//! pending entry with the planned serial, generate the RSA 8,192 key (progress, cancel),
//! encrypt it with the confirmed passphrase and stage it on every drive, self-sign the
//! master certificate, sign the first empty CRL, write everything to every drive, and
//! export the CRL.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use crate::cert::{
    CaCertificateRequest, Issuer, PlannedSerial, SoftwareSigner, issue_ca_certificate,
};
use crate::clock::ConfirmedTime;
use crate::crl::first_crl;
use crate::crypto::pkcs8::encrypt_master_key_pem;
use crate::crypto::{CancelFlag, CryptoError};
use crate::model::{CaLevel, Fingerprint, NameFields, Serial};
use crate::passphrase::{ConfirmedPassphrase, PassphraseKind};
use crate::profile::{
    CertValidity, MASTER, ValidatedName, default_crl_next_update, plan_validity, rfc3339,
};
use crate::store::{
    DriveClass, DriveSet, OperationId, OperationKind, StoreError, SubjectName, classify_drive,
};

use super::ca::ExportStatus;
use super::pipeline::{
    OpContext, assemble_and_finish, begin, certificate_record, plan_unique_serial,
    record_certificate, record_crl, run, signed_crl,
};
use super::seam::{self, FaultPoint, generate_key};
use super::state::{CaState, key_path};
use super::{Ca, OpsError, ProgressSink, Review, Step};

/// What the operator entered for Flow A.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateMasterRequest {
    /// The primary CA drive's mount point.
    pub primary: PathBuf,
    /// Backup CA drives (at least one, FR-12 AC1).
    pub backups: Vec<PathBuf>,
    /// The master's name fields (FR-02 AC4).
    pub subject: NameFields,
    /// Validity in years (1 to 25, default 20; FR-10 AC3).
    pub validity_years: u8,
}

impl CreateMasterRequest {
    /// A request with the default validity (20 years).
    pub fn new(primary: &Path, backups: &[&Path], subject: NameFields) -> Self {
        CreateMasterRequest {
            primary: primary.to_path_buf(),
            backups: backups.iter().map(|p| p.to_path_buf()).collect(),
            subject,
            validity_years: MASTER.default_validity_years,
        }
    }
}

/// A checked Flow A plan. Nothing was written.
#[derive(Debug)]
pub struct CreateMasterPlan {
    request: CreateMasterRequest,
    name: ValidatedName,
    validity: CertValidity,
    serial: PlannedSerial,
    time: ConfirmedTime,
    reuse: bool,
    review: Review,
}

/// The result of Flow A.
#[derive(Debug)]
pub struct CreateMasterOutcome {
    /// The new CA, opened on its drives.
    pub ca: Ca,
    /// The journaled operation.
    pub operation: OperationId,
    /// The master's serial.
    pub serial: Serial,
    /// SHA-256 fingerprint of the master certificate (FR-20).
    pub fingerprint: Fingerprint,
    /// The fingerprint as `AB:CD:...` for the operator to record (FR-20 AC1).
    pub fingerprint_text: String,
    /// The master certificate (PEM).
    pub certificate_pem: String,
    /// The first CRL's number (always 1).
    pub crl_number: u64,
    /// Export of the first CRL (FR-13 AC6).
    pub export: ExportStatus,
}

fn roots(request: &CreateMasterRequest) -> Vec<&Path> {
    std::iter::once(request.primary.as_path())
        .chain(request.backups.iter().map(PathBuf::as_path))
        .collect()
}

/// Checks whether the drives can take a new CA (SEC-20): all empty, or all one drive set
/// that holds no certificate (only cancelled or abandoned attempts). Returns true for the
/// second case.
fn check_drives(request: &CreateMasterRequest) -> Result<bool, OpsError> {
    if request.backups.is_empty() {
        return Err(StoreError::NotEnoughDrives {
            primaries: 1,
            backups: 0,
        }
        .into());
    }
    let roots = roots(request);
    let mut empty = 0;
    for root in &roots {
        match classify_drive(root)? {
            DriveClass::Empty => empty += 1,
            DriveClass::KeystoneCa(_) => {}
            DriveClass::DamagedKeystone(_) => {
                return Err(StoreError::DriveHoldsCa {
                    root: root.to_path_buf(),
                }
                .into());
            }
            DriveClass::KeystoneExport | DriveClass::Other => {
                return Err(StoreError::DriveNotEmpty {
                    root: root.to_path_buf(),
                }
                .into());
            }
        }
    }
    if empty == roots.len() {
        return Ok(false);
    }
    let holds_ca = || StoreError::DriveHoldsCa {
        root: request.primary.clone(),
    };
    if empty != 0 {
        return Err(holds_ca().into());
    }
    let set = DriveSet::open(&roots)?;
    let state = CaState::load(&set.drives()[0])?;
    if !state.is_empty() || !set.recovery_report()?.is_clean() {
        return Err(holds_ca().into());
    }
    Ok(true)
}

/// Flow A, steps 1 to 4: checks the drives (SEC-20), the name (FR-02 AC4) and the
/// validity (FR-10 AC3) and prepares the review. Nothing is written.
pub fn plan_create_master(
    request: CreateMasterRequest,
    time: ConfirmedTime,
) -> Result<CreateMasterPlan, OpsError> {
    let reuse = check_drives(&request)?;
    let name = ValidatedName::new(&request.subject)?;
    let validity = plan_validity(
        CaLevel::Master,
        request.validity_years,
        time.get().get(),
        None,
    )?;
    let serial = if reuse {
        let set = DriveSet::open(&roots(&request))?;
        plan_unique_serial(&Ca::from_set(set))?
    } else {
        crate::cert::plan_serial(&mut |_| false)?
    };
    let crl_next = default_crl_next_update(CaLevel::Master, validity.not_before())?;
    let mut review = Review::new("Create the master (root) certificate");
    review.line("Common Name", name.common_name());
    review.line("Organization", name.organization().unwrap_or("(none)"));
    review.line("Country", name.country().unwrap_or("(none)"));
    review.line(
        "Key",
        "RSA 8,192 bits, public exponent 65537, stored only encrypted (PBES2, scrypt, AES-256-CBC)",
    );
    review.line("Signature", "SHA-384 with RSA (PKCS#1 v1.5)");
    review.line("Valid from", rfc3339(validity.not_before()));
    review.line("Valid until", rfc3339(validity.not_after()));
    review.line("Basic constraints", "critical; CA; no path length limit");
    review.line("Key usage", "critical; certificate signing, CRL signing");
    review.line("Serial number", serial.serial().to_hex());
    review.line(
        "First CRL",
        format!("empty, number 1, next update {}", rfc3339(crl_next)),
    );
    review.line("Primary drive", request.primary.display().to_string());
    review.line(
        "Backup drives",
        request
            .backups
            .iter()
            .map(|b| b.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    Ok(CreateMasterPlan {
        request,
        name,
        validity,
        serial,
        time,
        reuse,
        review,
    })
}

fn cancel_error(error: CryptoError) -> OpsError {
    match error {
        CryptoError::Cancelled => OpsError::CancelRequested,
        other => other.into(),
    }
}

impl CreateMasterPlan {
    /// What the review step shows.
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// The serial the master will get.
    pub fn serial(&self) -> Serial {
        self.serial.serial()
    }

    /// Flow A, steps 5 and 6. `passphrase` is the master passphrase the operator just
    /// confirmed (FR-03); it encrypts the key and is never stored. `export` is the
    /// export drive for the first CRL (FR-13 AC6), or `None` to export later.
    pub fn execute(
        self,
        passphrase: &ConfirmedPassphrase,
        export: Option<&Path>,
        progress: &dyn ProgressSink,
        cancel: &CancelFlag,
    ) -> Result<CreateMasterOutcome, OpsError> {
        if passphrase.kind() != PassphraseKind::Master {
            return Err(OpsError::NotReady(
                "the master needs a master passphrase of 10 to 20 words".into(),
            ));
        }
        if cancel.is_cancelled() {
            return Err(OpsError::CancelledBeforeStart);
        }
        progress.report(super::Progress::Step {
            step: Step::PreparingDrives,
            cancel_available: true,
        });
        let roots = roots(&self.request);
        let set = if self.reuse {
            check_drives(&self.request)?;
            DriveSet::open(&roots)?
        } else {
            let backups: Vec<&Path> = roots[1..].to_vec();
            DriveSet::create(roots[0], &backups, self.time.get())?
        };
        let ca = Ca::from_set(set);
        let state = ca.ready_for_signing(self.time)?;
        if !state.is_empty() {
            return Err(StoreError::DriveHoldsCa {
                root: self.request.primary.clone(),
            }
            .into());
        }
        let mut ctx = OpContext::new(self.time, progress, cancel);
        let subject = SubjectName::from(&self.name.to_fields());
        let handle = begin(
            &ca,
            &ctx,
            OperationKind::CreateMaster,
            &subject.display(),
            &[self.serial.serial()],
        )?;
        let (operation, (record, pem, crl_number)) = run(handle, &mut ctx, |handle, ctx| {
            ctx.step(handle, Step::GeneratingKey);
            ctx.check_cancel(handle)?;
            let key = generate_key(MASTER.key_bits, cancel, progress).map_err(cancel_error)?;
            ctx.check_cancel(handle)?;
            ctx.step(handle, Step::EncryptingKey);
            let key_pem = encrypt_master_key_pem(key.key(), passphrase.secret())?;
            ctx.check_cancel(handle)?;
            ctx.step(handle, Step::StagingKey);
            let path = key_path(
                CaLevel::Master,
                self.name.common_name(),
                self.serial.serial(),
            );
            handle.stage(path, key_pem.as_bytes())?;
            ctx.check_cancel(handle)?;
            seam::fault(FaultPoint::BeforeSigning)?;
            ctx.step(handle, Step::SigningCertificate);
            let spki = key.key().public_key_spki_der()?;
            let mut signer = SoftwareSigner::new(key.key());
            let cert = issue_ca_certificate(
                &CaCertificateRequest {
                    level: CaLevel::Master,
                    subject: &self.name,
                    subject_public_key_der: &spki,
                    validity: self.validity,
                    serial: self.serial,
                    issuer: Issuer::SelfSigned,
                    issuer_crl: None,
                    name_constraints: None,
                },
                &mut signer,
            )?;
            let record =
                certificate_record(CaLevel::Master, &cert, subject.clone(), None, None, None);
            record_certificate(handle, ctx, record.clone(), cert.pem.clone())?;
            ctx.step(handle, Step::SigningCrl);
            let crl = first_crl(&cert.der, self.time.get().get(), &mut signer)?;
            record_crl(handle, ctx, signed_crl(cert.info.serial, &crl))?;
            drop(key);
            assemble_and_finish(&ca, handle, ctx, &state, Some(key_pem.as_bytes()))?;
            Ok((record, cert.pem, crl.info.crl_number))
        })?;
        let export = ca.export_after(operation, export, self.time, progress);
        Ok(CreateMasterOutcome {
            operation,
            serial: record.serial,
            fingerprint: record.fingerprint,
            fingerprint_text: record.fingerprint.to_fingerprint_string(),
            certificate_pem: pem,
            crl_number,
            export,
            ca,
        })
    }
}
