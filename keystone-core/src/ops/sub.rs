//! Flow C: create a sub-intermediate (FR-08, FR-09 AC1, FR-13 AC6, FR-18, FR-21).
//!
//! Plan (nothing written) → review (names, validity, permitted names, CRL address, file
//! names) → execute: pending entry with the planned serial, RSA 4,096 key generated in
//! software (progress, cancel), encrypted with its own confirmed 10-word passphrase and
//! staged on every drive, signed by the main intermediate on the YubiKey (PIN + touch),
//! then `<name>.crt`, `<name>.key` and `<name>-chain.pem` written to every drive and the
//! export drive.
#![forbid(unsafe_code)]

use std::path::Path;

use time::OffsetDateTime;

use crate::cert::{CaCertificateRequest, Issuer, PlannedSerial, issue_ca_certificate};
use crate::clock::ConfirmedTime;
use crate::crypto::pkcs8::encrypt_sub_key_pem;
use crate::crypto::secret::SecretString;
use crate::crypto::{CancelFlag, CryptoError};
use crate::model::{CaLevel, Fingerprint, NameFields, Serial};
use crate::passphrase::{ConfirmedPassphrase, PassphraseKind};
use crate::profile::{
    CRL_NONE_WARNING, CertValidity, CrlLocation, NAME_CONSTRAINTS_OFF_WARNING,
    NameConstraintsChoice, SUB_INTERMEDIATE, ValidatedName, max_validity_years, plan_validity,
    rfc3339,
};
use crate::store::{OperationId, OperationKind, SubjectName};
use crate::token::{TokenCaSigner, TokenSigner};

use super::ca::ExportStatus;
use super::pipeline::{
    OpContext, assemble_and_finish, begin, certificate_record, plan_unique_serial,
    record_certificate, resolve_crl_location, run,
};
use super::seam::{self, FaultPoint, generate_key};
use super::state::{CaState, StoredCert, file_stem, key_path};
use super::{Ca, OpsError, Progress, ProgressSink, Review, Step};

/// What the operator entered for Flow C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubIntermediateRequest {
    /// Name fields.
    pub subject: NameFields,
    /// Validity in years (1 to 10, default 5, never past the main intermediate).
    pub validity_years: u8,
    /// Name constraints (FR-21): on by default; off only by explicit choice.
    pub name_constraints: NameConstraintsChoice,
    /// The main intermediate's CRL address (FR-18): required for its first child,
    /// then stored; `None` reuses the stored one.
    pub main_crl: Option<CrlLocation>,
}

impl SubIntermediateRequest {
    /// A request with the default validity (5 years).
    pub fn new(
        subject: NameFields,
        name_constraints: NameConstraintsChoice,
        main_crl: Option<CrlLocation>,
    ) -> Self {
        SubIntermediateRequest {
            subject,
            validity_years: SUB_INTERMEDIATE.default_validity_years,
            name_constraints,
            main_crl,
        }
    }
}

/// A checked Flow C plan. Nothing was written.
#[derive(Debug)]
pub struct SubIntermediatePlan {
    main_serial: Serial,
    name: ValidatedName,
    validity: CertValidity,
    serial: PlannedSerial,
    constraints: NameConstraintsChoice,
    main_crl: CrlLocation,
    time: ConfirmedTime,
    review: Review,
}

/// The result of Flow C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubIntermediateOutcome {
    /// The journaled operation.
    pub operation: OperationId,
    /// The sub-intermediate's serial.
    pub serial: Serial,
    /// SHA-256 fingerprint (FR-20).
    pub fingerprint: Fingerprint,
    /// The fingerprint as `AB:CD:...` (FR-20 AC1).
    pub fingerprint_text: String,
    /// The certificate (PEM).
    pub certificate_pem: String,
    /// `<name>` of the files `<name>.crt`, `<name>.key`, `<name>-chain.pem` (FR-09 AC1).
    pub file_stem: String,
    /// Export of the three files.
    pub export: ExportStatus,
}

fn main_ready(state: &CaState, now: OffsetDateTime) -> Result<&StoredCert, OpsError> {
    if state.master().is_none() {
        return Err(OpsError::NotReady(
            "create the master first (Flow A)".into(),
        ));
    }
    let main = state.active_main(now).ok_or_else(|| {
        OpsError::NotReady(
            "there is no valid main intermediate; set up the YubiKey first (Flow B)".into(),
        )
    })?;
    if state.current_crl(main.serial()).is_none() {
        return Err(OpsError::NotReady(
            "the main intermediate has no CRL yet; it cannot sign its first child (FR-13 AC6)"
                .into(),
        ));
    }
    Ok(main)
}

fn location_text(location: &CrlLocation) -> String {
    match location {
        CrlLocation::Url(url) => url.to_string(),
        CrlLocation::ExplicitlyNone => "none (explicit choice)".to_owned(),
    }
}

impl Ca {
    /// The longest validity (in years) a new sub-intermediate can have at `now` without
    /// outliving the active main intermediate (FR-10 AC1); 0 when none fits.
    pub fn max_sub_intermediate_years(&self, now: OffsetDateTime) -> Result<u8, OpsError> {
        let state = self.state()?;
        let main = main_ready(&state, now)?;
        Ok(max_validity_years(
            CaLevel::SubIntermediate,
            now,
            Some(main.info.not_after),
        ))
    }

    /// Flow C review: checks the CA (an active main intermediate whose first CRL exists,
    /// FR-13 AC6), the name, the validity (never past the main intermediate, FR-10 AC1),
    /// the name constraints (FR-21 AC4) and the CRL address (FR-18). Nothing is written.
    pub fn plan_sub_intermediate(
        &self,
        request: &SubIntermediateRequest,
        time: ConfirmedTime,
    ) -> Result<SubIntermediatePlan, OpsError> {
        let state = self.ready_for_signing(time)?;
        let main = main_ready(&state, time.get().get())?;
        let name = ValidatedName::new(&request.subject)?;
        let validity = plan_validity(
            CaLevel::SubIntermediate,
            request.validity_years,
            time.get().get(),
            Some(main.info.not_after),
        )?;
        let (main_crl, new_address) = resolve_crl_location(
            &state,
            main.serial(),
            &main.record.subject.display(),
            request.main_crl.as_ref(),
        )?;
        let serial = plan_unique_serial(self)?;
        let stem = file_stem(
            CaLevel::SubIntermediate,
            name.common_name(),
            serial.serial(),
        );
        let mut review = Review::new("Create a sub-intermediate");
        review.line("Common Name", name.common_name());
        review.line("Organization", name.organization().unwrap_or("(none)"));
        review.line("Country", name.country().unwrap_or("(none)"));
        review.line(
            "Key",
            "RSA 4,096 bits, generated in software, stored only encrypted with its own 10-word passphrase (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC)",
        );
        review.line(
            "Signed by",
            format!("{} (YubiKey, PIN + touch)", main.record.subject.display()),
        );
        review.line("Valid from", rfc3339(validity.not_before()));
        review.line("Valid until", rfc3339(validity.not_after()));
        review.line("Basic constraints", "critical; CA; path length 0");
        review.line("Key usage", "critical; certificate signing, CRL signing");
        match &request.name_constraints {
            NameConstraintsChoice::Constrained(spec) => {
                review.line(
                    "Name constraints",
                    format!("critical; {}", spec.summary_lines().join("; ")),
                );
            }
            NameConstraintsChoice::ExplicitlyUnconstrained => {
                review.line("Name constraints", "none (explicit choice)");
                review
                    .warnings
                    .push(NAME_CONSTRAINTS_OFF_WARNING.to_owned());
            }
        }
        review.line(
            "Main intermediate CRL address",
            format!(
                "{}{}",
                location_text(&main_crl),
                if new_address {
                    " (set now, used for every later sub-intermediate)"
                } else {
                    ""
                }
            ),
        );
        if main_crl == CrlLocation::ExplicitlyNone {
            review.warnings.push(CRL_NONE_WARNING.to_owned());
        }
        review.line("Serial number", serial.serial().to_hex());
        review.line(
            "Files",
            format!("{stem}.crt, {stem}.key (encrypted), {stem}-chain.pem"),
        );
        Ok(SubIntermediatePlan {
            main_serial: main.serial(),
            name,
            validity,
            serial,
            constraints: request.name_constraints.clone(),
            main_crl,
            time,
            review,
        })
    }
}

fn cancel_error(error: CryptoError) -> OpsError {
    match error {
        CryptoError::Cancelled => OpsError::CancelRequested,
        other => other.into(),
    }
}

impl SubIntermediatePlan {
    /// What the review step shows (FR-21 AC6: the permitted names are on it).
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// The serial the sub-intermediate will get.
    pub fn serial(&self) -> Serial {
        self.serial.serial()
    }

    /// `<name>` of the three files (FR-09 AC1).
    pub fn file_stem(&self) -> String {
        file_stem(
            CaLevel::SubIntermediate,
            self.name.common_name(),
            self.serial.serial(),
        )
    }

    /// Flow C, steps 2 to 4. `passphrase` is the sub-intermediate's own confirmed
    /// 10-word passphrase (FR-03 AC2, SEC-15); `pin` unlocks the YubiKey for the one
    /// signature (PIN + touch, FR-08 AC2).
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        self,
        ca: &Ca,
        token: &mut dyn TokenSigner,
        pin: &SecretString,
        passphrase: &ConfirmedPassphrase,
        export: Option<&Path>,
        progress: &dyn ProgressSink,
        cancel: &CancelFlag,
    ) -> Result<SubIntermediateOutcome, OpsError> {
        if passphrase.kind() != PassphraseKind::SubIntermediate {
            return Err(OpsError::NotReady(
                "a sub-intermediate needs its own 10-word sub-intermediate passphrase".into(),
            ));
        }
        if cancel.is_cancelled() {
            return Err(OpsError::CancelledBeforeStart);
        }
        let state = ca.ready_for_signing(self.time)?;
        let main = main_ready(&state, self.time.get().get())?;
        if main.serial() != self.main_serial {
            return Err(OpsError::NotReady(
                "the active main intermediate changed since the review; review again".into(),
            ));
        }
        let mut ctx = OpContext::new(self.time, progress, cancel);
        let subject = SubjectName::from(&self.name.to_fields());
        let handle = begin(
            ca,
            &ctx,
            OperationKind::CreateSubIntermediate,
            &subject.display(),
            &[self.serial.serial()],
        )?;
        let (operation, (record, pem)) = run(handle, &mut ctx, |handle, ctx| {
            ctx.step(handle, Step::GeneratingKey);
            ctx.check_cancel(handle)?;
            let key =
                generate_key(SUB_INTERMEDIATE.key_bits, cancel, progress).map_err(cancel_error)?;
            ctx.check_cancel(handle)?;
            ctx.step(handle, Step::EncryptingKey);
            let key_pem = encrypt_sub_key_pem(key.key(), passphrase.secret())?;
            let spki = key.key().public_key_spki_der()?;
            drop(key);
            ctx.check_cancel(handle)?;
            ctx.step(handle, Step::StagingKey);
            let path = key_path(
                CaLevel::SubIntermediate,
                self.name.common_name(),
                self.serial.serial(),
            );
            handle.stage(path, key_pem.as_bytes())?;
            ctx.check_cancel(handle)?;
            seam::fault(FaultPoint::BeforeSigning)?;
            ctx.step(handle, Step::SigningCertificate);
            progress.report(Progress::TouchYubiKey);
            let issued = issue_ca_certificate(
                &CaCertificateRequest {
                    level: CaLevel::SubIntermediate,
                    subject: &self.name,
                    subject_public_key_der: &spki,
                    validity: self.validity,
                    serial: self.serial,
                    issuer: Issuer::Certificate(&main.der),
                    issuer_crl: Some(&self.main_crl),
                    name_constraints: Some(&self.constraints),
                },
                &mut TokenCaSigner::new(token, pin),
            )?;
            let record = certificate_record(
                CaLevel::SubIntermediate,
                &issued,
                subject.clone(),
                Some(&main.record),
                Some(&self.constraints),
                None,
            );
            record_certificate(handle, ctx, record.clone(), issued.pem.clone())?;
            assemble_and_finish(ca, handle, ctx, &state, Some(key_pem.as_bytes()))?;
            Ok((record, issued.pem))
        })?;
        let export = ca.export_after(operation, export, self.time, progress);
        Ok(SubIntermediateOutcome {
            operation,
            serial: record.serial,
            fingerprint: record.fingerprint,
            fingerprint_text: record.fingerprint.to_fingerprint_string(),
            certificate_pem: pem,
            file_stem: file_stem(
                CaLevel::SubIntermediate,
                &record.subject.common_name,
                record.serial,
            ),
            export,
        })
    }
}
