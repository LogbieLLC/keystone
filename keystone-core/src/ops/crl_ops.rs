//! Operations that sign a CRL: Flow D (revoke and publish a CRL), Refresh CRL
//! (FR-13 AC4) and Flow E steps 1, 2 and 4 (replace a lost YubiKey, FR-15 AC1).
//!
//! The master signs the CRL covering main intermediates (passphrase); the main
//! intermediate signs the CRL covering sub-intermediates on the YubiKey (PIN + touch)
//! (FR-13 AC1). Revoking a main intermediate also marks every sub-intermediate under it
//! "revoked by ancestor" in the same operation, so no CRL from a lost YubiKey is needed.
#![forbid(unsafe_code)]

use std::path::Path;

use time::OffsetDateTime;

use crate::cert::SoftwareSigner;
use crate::clock::ConfirmedTime;
use crate::crl::{IssuedCrl, RevokedEntry, crl_with_revocation, refresh_crl};
use crate::crypto::CancelFlag;
use crate::crypto::secret::SecretString;
use crate::model::{CaLevel, RevocationReason, Serial};
use crate::passphrase::EnteredPassphrase;
use crate::profile::{default_crl_next_update, rfc3339};
use crate::store::record::MAX_CHANGES;
use crate::store::{CertStatus, OperationId, OperationKind};
use crate::token::{TokenCaSigner, TokenSigner};

use super::ca::ExportStatus;
use super::pipeline::{
    OpContext, assemble_and_finish, begin, cut_off_children, record_crl, run, signed_crl,
};
use super::seam::{self, FaultPoint};
use super::state::{CaState, StoredCert};
use super::yubikey::unlock_master;
use super::{Ca, OpsError, Progress, ProgressSink, Review, Step};

/// Which CRL operation a [`CrlPlan`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlPlanKind {
    /// Flow D: revoke `target` and publish the issuer's new CRL.
    Revoke {
        /// The certificate to revoke.
        target: Serial,
        /// Why.
        reason: RevocationReason,
    },
    /// FR-13 AC4: re-sign the issuer's current CRL without new revocations.
    Refresh,
    /// Flow E: the master revokes the old main intermediate (its YubiKey may be absent).
    ReplaceYubikey {
        /// The old main intermediate.
        old_main: Serial,
        /// Why.
        reason: RevocationReason,
    },
}

/// How the issuer signs: the master with its passphrase, or the main intermediate on
/// the YubiKey with the PIN (and a touch).
pub enum IssuerUnlock<'a> {
    /// The master: its passphrase (the key is wiped right after signing).
    Master(&'a EnteredPassphrase),
    /// The main intermediate on the YubiKey.
    YubiKey {
        /// The YubiKey holding the main intermediate's key.
        token: &'a mut dyn TokenSigner,
        /// Its PIN.
        pin: &'a SecretString,
    },
}

impl std::fmt::Debug for IssuerUnlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerUnlock::Master(_) => f.write_str("IssuerUnlock::Master([REDACTED])"),
            IssuerUnlock::YubiKey { .. } => f.write_str("IssuerUnlock::YubiKey([PIN REDACTED])"),
        }
    }
}

/// A checked CRL operation. Nothing was written.
#[derive(Debug)]
pub struct CrlPlan {
    kind: CrlPlanKind,
    issuer_serial: Serial,
    issuer_level: CaLevel,
    current_crl_number: u64,
    subject: String,
    cut_off: Vec<Serial>,
    time: ConfirmedTime,
    review: Review,
}

/// The result of a CRL operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlOutcome {
    /// The journaled operation.
    pub operation: OperationId,
    /// The issuer that signed the CRL.
    pub issuer_serial: Serial,
    /// The new CRL's number.
    pub crl_number: u64,
    /// thisUpdate.
    pub this_update: OffsetDateTime,
    /// nextUpdate.
    pub next_update: OffsetDateTime,
    /// The certificate revoked by this operation, if any.
    pub revoked: Option<Serial>,
    /// Sub-intermediates marked "revoked by ancestor" (FR-15 AC1); re-issue them under
    /// the new main intermediate (Flow C).
    pub revoked_by_ancestor: Vec<Serial>,
    /// Export of the CRL (FR-13 AC4).
    pub export: ExportStatus,
}

fn usable_issuer(
    state: &CaState,
    serial: Serial,
    now: OffsetDateTime,
) -> Result<&StoredCert, OpsError> {
    let issuer = state
        .certificate(serial)
        .ok_or_else(|| OpsError::NotReady(format!("certificate {serial} is not in the record")))?;
    match issuer.level() {
        CaLevel::Master => {}
        CaLevel::MainIntermediate if issuer.is_usable(now) => {}
        CaLevel::MainIntermediate => {
            return Err(OpsError::NotReady(format!(
                "{} is revoked or expired; its last CRL stays hosted until it expires and can no longer be refreshed",
                issuer.record.subject.display()
            )));
        }
        CaLevel::SubIntermediate => {
            return Err(OpsError::NotReady(
                "Keystone signs no CRL for sub-intermediates; their issuing systems do".into(),
            ));
        }
    }
    if state.current_crl(serial).is_none() {
        return Err(OpsError::NotReady(format!(
            "{} has no CRL yet",
            issuer.record.subject.display()
        )));
    }
    Ok(issuer)
}

fn signer_text(level: CaLevel) -> &'static str {
    match level {
        CaLevel::Master => "the master (passphrase)",
        _ => "the main intermediate on the YubiKey (PIN + touch)",
    }
}

fn revocable(state: &CaState, serial: Serial) -> Result<&StoredCert, OpsError> {
    let target = state
        .certificate(serial)
        .ok_or_else(|| OpsError::NotReady(format!("certificate {serial} is not in the record")))?;
    match target.status {
        CertStatus::Valid => {}
        CertStatus::Revoked { .. } => {
            return Err(OpsError::NotReady(format!(
                "{} is already revoked",
                target.record.subject.display()
            )));
        }
        CertStatus::RevokedByAncestor { ancestor, .. } => {
            return Err(OpsError::NotReady(format!(
                "{} is already cut off: its issuer {ancestor} was revoked, and that issuer's CRL can no longer be updated",
                target.record.subject.display()
            )));
        }
    }
    if target.level() == CaLevel::Master {
        return Err(OpsError::NotReady(
            "the master (root) cannot be revoked by a CRL; stop trusting it instead".into(),
        ));
    }
    Ok(target)
}

/// A revocation's issuance-record update lists the revoked certificate and every
/// sub-intermediate it cuts off (FR-15 AC1), at most [`MAX_CHANGES`] changes. Refused
/// before anything is signed when they do not fit, so a revocation never fails after its
/// CRL was signed and no serial is ever left out (the audit entries take any number).
fn check_record_capacity(cut_off: usize) -> Result<(), OpsError> {
    if cut_off >= MAX_CHANGES {
        return Err(OpsError::NotReady(format!(
            "this revocation would mark {cut_off} sub-intermediates revoked by ancestor; one operation can record at most {}, so nothing was signed",
            MAX_CHANGES - 1
        )));
    }
    Ok(())
}

impl Ca {
    /// Flow D review: revoke `serial` for `reason`. A sub-intermediate is revoked by the
    /// main intermediate (YubiKey), a main intermediate by the master (passphrase).
    pub fn plan_revoke(
        &self,
        serial: Serial,
        reason: RevocationReason,
        time: ConfirmedTime,
    ) -> Result<CrlPlan, OpsError> {
        let state = self.ready_for_signing(time)?;
        let target = revocable(&state, serial)?;
        self.crl_plan(
            &state,
            CrlPlanKind::Revoke {
                target: serial,
                reason,
            },
            target.record.issuer_serial,
            target,
            time,
        )
    }

    /// FR-13 AC4 review: re-sign `issuer`'s current CRL (the master or a valid main
    /// intermediate) with a new thisUpdate, nextUpdate and a higher number.
    pub fn plan_refresh_crl(
        &self,
        issuer: Serial,
        time: ConfirmedTime,
    ) -> Result<CrlPlan, OpsError> {
        let state = self.ready_for_signing(time)?;
        let issuer_cert = usable_issuer(&state, issuer, time.get().get())?;
        self.crl_plan(&state, CrlPlanKind::Refresh, issuer, issuer_cert, time)
    }

    /// Flow E review (FR-15 AC1): the master revokes the active main intermediate (whose
    /// YubiKey may be absent) and issues a new master CRL; every sub-intermediate under
    /// it is marked "revoked by ancestor". Afterwards: Flow B on a new YubiKey, then
    /// re-issue each sub-intermediate (`CaState::reissue_candidates`).
    pub fn plan_replace_yubikey(
        &self,
        reason: RevocationReason,
        time: ConfirmedTime,
    ) -> Result<CrlPlan, OpsError> {
        let state = self.ready_for_signing(time)?;
        let old = state.active_main(time.get().get()).ok_or_else(|| {
            OpsError::NotReady("there is no valid main intermediate to replace".into())
        })?;
        let master = state
            .master()
            .ok_or_else(|| OpsError::NotReady("the CA has no master".into()))?;
        let mut plan = self.crl_plan(
            &state,
            CrlPlanKind::ReplaceYubikey {
                old_main: old.serial(),
                reason,
            },
            master.serial(),
            old,
            time,
        )?;
        plan.review.line(
            "Next",
            "set up the new YubiKey (Flow B), then re-issue each listed sub-intermediate under the new main intermediate (Flow C)",
        );
        Ok(plan)
    }

    fn crl_plan(
        &self,
        state: &CaState,
        kind: CrlPlanKind,
        issuer_serial: Serial,
        subject: &StoredCert,
        time: ConfirmedTime,
    ) -> Result<CrlPlan, OpsError> {
        let issuer = usable_issuer(state, issuer_serial, time.get().get())?;
        let current = state
            .current_crl(issuer_serial)
            .ok_or_else(|| OpsError::NotReady("the issuer has no CRL yet".into()))?;
        let cut_off = match kind {
            CrlPlanKind::Refresh => Vec::new(),
            CrlPlanKind::Revoke { target, .. }
            | CrlPlanKind::ReplaceYubikey {
                old_main: target, ..
            } => cut_off_children(state, target),
        };
        check_record_capacity(cut_off.len())?;
        let next = default_crl_next_update(issuer.level(), time.get().get())?;
        let mut review = Review::new(match kind {
            CrlPlanKind::Revoke { .. } => "Revoke a certificate and publish a new CRL",
            CrlPlanKind::Refresh => "Refresh a CRL",
            CrlPlanKind::ReplaceYubikey { .. } => "Replace a lost or broken YubiKey",
        });
        match kind {
            CrlPlanKind::Revoke { reason, .. } | CrlPlanKind::ReplaceYubikey { reason, .. } => {
                review.line("Revoke", subject.record.subject.display());
                review.line("Serial number", subject.serial().to_hex());
                review.line("Reason", format!("{reason:?}"));
            }
            CrlPlanKind::Refresh => {}
        }
        review.line("CRL issuer", issuer.record.subject.display());
        review.line("Signed by", signer_text(issuer.level()));
        review.line(
            "New CRL",
            format!(
                "number {}, this update {}, next update {}",
                current.info.crl_number + 1,
                rfc3339(time.get().get()),
                rfc3339(next)
            ),
        );
        review.line(
            "Revoked entries",
            format!(
                "{} on the new CRL ({} on the current one)",
                current.info.revoked.len() + usize::from(kind != CrlPlanKind::Refresh),
                current.info.revoked.len()
            ),
        );
        if !cut_off.is_empty() {
            review.line(
                "Marked revoked by ancestor",
                cut_off
                    .iter()
                    .filter_map(|serial| state.certificate(*serial))
                    .map(|cert| cert.record.subject.display())
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        Ok(CrlPlan {
            kind,
            issuer_serial,
            issuer_level: issuer.level(),
            current_crl_number: current.info.crl_number,
            subject: subject.record.subject.display(),
            cut_off,
            time,
            review,
        })
    }
}

impl CrlPlan {
    /// What the review step shows.
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// What this plan does.
    pub fn kind(&self) -> CrlPlanKind {
        self.kind
    }

    /// The issuer that will sign the CRL.
    pub fn issuer_serial(&self) -> Serial {
        self.issuer_serial
    }

    /// True when the master signs (passphrase); false for the YubiKey (PIN + touch).
    pub fn needs_master(&self) -> bool {
        self.issuer_level == CaLevel::Master
    }

    /// Signs and publishes the CRL, writes it with the record changes to every drive
    /// and exports it.
    pub fn execute(
        self,
        ca: &Ca,
        unlock: IssuerUnlock<'_>,
        export: Option<&Path>,
        progress: &dyn ProgressSink,
        cancel: &CancelFlag,
    ) -> Result<CrlOutcome, OpsError> {
        if cancel.is_cancelled() {
            return Err(OpsError::CancelledBeforeStart);
        }
        let state = ca.ready_for_signing(self.time)?;
        let now = self.time.get().get();
        let issuer = usable_issuer(&state, self.issuer_serial, now)?;
        let current = state
            .current_crl(self.issuer_serial)
            .ok_or_else(|| OpsError::NotReady("the issuer has no CRL yet".into()))?;
        if current.info.crl_number != self.current_crl_number {
            return Err(OpsError::NotReady(
                "the issuer's CRL changed since the review; review again".into(),
            ));
        }
        let revoke = match self.kind {
            CrlPlanKind::Revoke { target, reason }
            | CrlPlanKind::ReplaceYubikey {
                old_main: target,
                reason,
            } => {
                revocable(&state, target)?;
                check_record_capacity(cut_off_children(&state, target).len())?;
                Some(RevokedEntry {
                    serial: target,
                    revocation_date: now,
                    reason,
                })
            }
            CrlPlanKind::Refresh => None,
        };
        match (&unlock, self.issuer_level) {
            (IssuerUnlock::Master(_), CaLevel::Master)
            | (IssuerUnlock::YubiKey { .. }, CaLevel::MainIntermediate) => {}
            _ => {
                return Err(OpsError::NotReady(format!(
                    "this CRL is signed by {}",
                    signer_text(self.issuer_level)
                )));
            }
        }
        let operation_kind = match self.kind {
            CrlPlanKind::Revoke { .. } => OperationKind::Revoke,
            CrlPlanKind::Refresh => OperationKind::RefreshCrl,
            CrlPlanKind::ReplaceYubikey { .. } => OperationKind::ReplaceYubikey,
        };
        let mut ctx = OpContext::new(self.time, progress, cancel);
        let handle = begin(ca, &ctx, operation_kind, &self.subject, &[])?;
        let (operation, crl) = run(handle, &mut ctx, |handle, ctx| {
            let sign = |signer: &mut dyn crate::cert::Sha384Signer| -> Result<IssuedCrl, OpsError> {
                Ok(match revoke {
                    Some(entry) => {
                        crl_with_revocation(&current.der, &issuer.der, entry, now, signer)?
                    }
                    None => refresh_crl(&current.der, &issuer.der, now, signer)?,
                })
            };
            let crl = match unlock {
                IssuerUnlock::Master(passphrase) => {
                    ctx.step(handle, Step::UnlockingMaster);
                    let key = unlock_master(ca, issuer, passphrase)?;
                    ctx.check_cancel(handle)?;
                    seam::fault(FaultPoint::BeforeSigning)?;
                    ctx.step(handle, Step::SigningCrl);
                    let crl = sign(&mut SoftwareSigner::new(&key))?;
                    drop(key);
                    crl
                }
                IssuerUnlock::YubiKey { token, pin } => {
                    ctx.check_cancel(handle)?;
                    seam::fault(FaultPoint::BeforeSigning)?;
                    ctx.step(handle, Step::SigningCrl);
                    ctx.progress.report(Progress::TouchYubiKey);
                    sign(&mut TokenCaSigner::new(token, pin))?
                }
            };
            record_crl(handle, ctx, signed_crl(self.issuer_serial, &crl))?;
            assemble_and_finish(ca, handle, ctx, &state, None)?;
            Ok(crl)
        })?;
        let export = ca.export_after(operation, export, self.time, progress);
        Ok(CrlOutcome {
            operation,
            issuer_serial: self.issuer_serial,
            crl_number: crl.info.crl_number,
            this_update: crl.info.this_update,
            next_update: crl.info.next_update,
            revoked: revoke.map(|entry| entry.serial),
            revoked_by_ancestor: self.cut_off,
            export,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr14_ac1_a_revocation_that_cannot_be_recorded_whole_is_refused_before_signing() {
        // Covers: FR-14 AC1, FR-22 AC3, FR-15 AC1
        assert!(check_record_capacity(0).is_ok());
        assert!(check_record_capacity(MAX_CHANGES - 1).is_ok());
        let error = check_record_capacity(MAX_CHANGES).unwrap_err();
        assert!(matches!(error, OpsError::NotReady(_)));
        assert!(error.to_string().contains("nothing was signed"), "{error}");
    }
}
