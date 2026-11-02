//! The recovery screen (FR-22 AC4, AC5, AC7, AC8): every interrupted operation, one
//! column per drive and one for the YubiKey, and at most two safe actions, each with one
//! plain sentence saying what it will do and what it will not do. Recovery never formats,
//! deletes or overwrites anything.
//!
//! The store's analysis ([`crate::store::RecoveryReport`]) is refined here:
//! - "signed but never staged" (the store offers nothing) becomes
//!   [`RecoveryAction::RebuildFromJournal`]: the outputs are rebuilt from the journaled
//!   certificate or CRL (and, for Flows A and C, the encrypted key staged before signing)
//!   with the same code that writes them normally, so nothing is signed again. A Flow A
//!   whose first CRL was not signed yet needs the master passphrase to sign it.
//! - an interrupted YubiKey setup becomes [`RecoveryAction::ResumeYubikeySetup`], or
//!   [`RecoveryAction::CompleteSetupWithExistingKey`] when the connected YubiKey holds a
//!   key without a certificate (FR-22 AC5): it is never offered to replace the key, and
//!   a key whose attestation fails is never completed (replacing it stays the separate,
//!   typed-serial wipe of FR-07 AC4).
//! - YubiKey setup with nothing signed (maintainer's reading of FR-22 AC4, AC5, AC7):
//!   while the setup's YubiKey (by serial; any YubiKey when no step was journaled yet) is
//!   connected, only the resume is offered; when it is absent, "Abandon" is offered as
//!   well, for a YubiKey that is lost or will be replaced. Never more than two actions.
//! - YubiKey setup whose main intermediate the master already signed but whose first CRL
//!   the YubiKey never signed (review finding 5): resuming needs that YubiKey. While it
//!   is absent, [`RecoveryAction::FinishWithoutYubikey`] is offered as well: the signed
//!   certificate is recorded (FR-22 AC3) and the operation finished without that CRL;
//!   the main intermediate is then revoked with Replace lost YubiKey (Flow E). So every
//!   interrupted state has an action that needs no lost YubiKey.
#![forbid(unsafe_code)]

use crate::cert::{SoftwareSigner, parse_certificate_pem};
use crate::clock::ConfirmedTime;
use crate::crl::first_crl;
use crate::crypto::CancelFlag;
use crate::crypto::pkcs8::decrypt_key_pem;
use crate::model::{CaLevel, Serial};
use crate::passphrase::EnteredPassphrase;
use crate::store::{
    DriveOperationView, OperationId, OperationJournal, OperationKind, OperationState,
    PendingOperation, RecoveryAction as StoreAction, SignedObject, YubikeySetupStep,
};
use crate::token::{CredentialStatus, DeviceInfo, SIGNING_SLOT, TokenSigner};

use super::pipeline::{
    Assembly, OpContext, assemble_and_finish, finish, record_crl, run, signed_crl, staged_key,
};
use super::state::{certificate_path, key_path};
use super::{Ca, NoProgress, OpsError};
use crate::store::{
    AuditAction, AuditDetails, AuditDraft, AuditResult, RecordChange, RecordUpdate,
};

/// A safe recovery action (FR-22 AC4, AC5, AC7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Finish the writes from a drive that holds the verified output.
    FinishFrom {
        /// Index into the drive set.
        drive_index: usize,
        /// Drive label.
        drive: String,
    },
    /// Mark the operation abandoned; its serial stays reserved.
    Abandon,
    /// Something was signed but never staged: rebuild the outputs from the journal.
    RebuildFromJournal {
        /// Flow A whose first CRL is missing: the master passphrase signs it.
        needs_master_passphrase: bool,
    },
    /// Read the YubiKey's real state and continue from the first incomplete step
    /// ([`Ca::resume_yubikey_setup`]).
    ResumeYubikeySetup {
        /// The first step not yet journaled.
        next_step: Option<YubikeySetupStep>,
    },
    /// The YubiKey holds a key without a certificate: verify its attestation and have
    /// the master sign it ([`Ca::resume_yubikey_setup`], FR-22 AC5).
    CompleteSetupWithExistingKey,
    /// YubiKey setup whose main intermediate the master already signed, but whose first
    /// CRL the (now absent) YubiKey never signed: record the certificate (FR-22 AC3) and
    /// finish without that CRL, for a YubiKey that is lost. Offered only while the
    /// setup's YubiKey is not connected; the main intermediate must then be revoked with
    /// Replace lost YubiKey (Flow E). Nothing is signed (review finding 5).
    FinishWithoutYubikey,
}

/// One action with its sentence (FR-22 AC8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryChoice {
    /// The action.
    pub action: RecoveryAction,
    /// One plain sentence: what it will do and what it will not do.
    pub description: String,
}

/// The YubiKey column of the recovery screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenColumn {
    /// Serial and firmware.
    pub device: DeviceInfo,
    /// PIN, PUK and management-key state.
    pub credentials: CredentialStatus,
    /// What the signing slot holds, in words.
    pub slot: String,
    /// The slot holds a key but no certificate (FR-22 AC5).
    pub key_without_certificate: bool,
    /// True when this is the YubiKey the interrupted setup journaled (or the setup
    /// journaled no YubiKey step yet).
    pub is_this_operations_yubikey: bool,
}

/// One interrupted operation on the recovery screen (FR-22 AC4, AC8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    /// The operation.
    pub operation: OperationId,
    /// Its kind.
    pub kind: OperationKind,
    /// Its subject.
    pub subject: String,
    /// Serials it reserved (they stay reserved whatever happens).
    pub planned_serials: Vec<Serial>,
    /// One column per drive: exactly what each holds for this operation.
    pub drives: Vec<DriveOperationView>,
    /// The YubiKey column, when a YubiKey was connected.
    pub yubikey: Option<TokenColumn>,
    /// At most two safe actions.
    pub actions: Vec<RecoveryChoice>,
    /// Why no action can be offered, when `actions` is empty.
    pub blocked_reason: Option<String>,
}

/// Secrets a recovery action may need. None is stored.
#[derive(Debug, Default)]
pub struct RecoverySecrets<'a> {
    /// The master passphrase ([`RecoveryAction::RebuildFromJournal`] with
    /// `needs_master_passphrase`).
    pub master_passphrase: Option<&'a EnteredPassphrase>,
}

fn describe(action: &RecoveryAction, operation: OperationId) -> String {
    match action {
        RecoveryAction::FinishFrom { drive_index, drive } => StoreAction::FinishFrom {
            drive_index: *drive_index,
            drive: drive.clone(),
        }
        .description(operation),
        RecoveryAction::Abandon => StoreAction::Abandon.description(operation),
        RecoveryAction::ResumeYubikeySetup { next_step } => StoreAction::ResumeYubikeySetup {
            next_step: *next_step,
        }
        .description(operation),
        RecoveryAction::RebuildFromJournal {
            needs_master_passphrase: false,
        } => format!(
            "Rebuild the files of {operation} from what its journal recorded, write them to every drive and mark it completed; nothing is signed again, deleted or overwritten."
        ),
        RecoveryAction::RebuildFromJournal {
            needs_master_passphrase: true,
        } => format!(
            "Unlock the master with its passphrase to sign its missing first CRL, then write the files of {operation} to every drive and mark it completed; the master certificate is not signed again and nothing is deleted or overwritten."
        ),
        RecoveryAction::CompleteSetupWithExistingKey => format!(
            "Verify the attestation of the key already in the YubiKey, have the master sign it and finish {operation}; the key is not replaced and nothing is wiped."
        ),
        RecoveryAction::FinishWithoutYubikey => format!(
            "Record the main intermediate the master already signed and finish {operation} without its first CRL, for when this YubiKey is lost; then revoke it with Replace lost YubiKey, and nothing is signed, deleted or overwritten."
        ),
    }
}

fn choice(action: RecoveryAction, operation: OperationId) -> RecoveryChoice {
    RecoveryChoice {
        description: describe(&action, operation),
        action,
    }
}

/// True when `shorter`'s entries are the first entries of `longer`, byte for byte.
fn is_prefix(shorter: &OperationJournal, longer: &OperationJournal) -> bool {
    shorter.raw_entries().len() <= longer.raw_entries().len()
        && shorter
            .raw_entries()
            .iter()
            .zip(longer.raw_entries())
            .all(|(a, b)| a == b)
}

struct Signed {
    certificate: Option<(CaLevel, String, Serial)>,
    crl: bool,
}

fn signed(journal: &OperationJournal) -> Signed {
    let mut out = Signed {
        certificate: None,
        crl: false,
    };
    for object in journal.signed() {
        match object {
            SignedObject::Certificate { record, .. } => {
                out.certificate = Some((
                    record.level,
                    record.subject.common_name.clone(),
                    record.serial,
                ));
            }
            SignedObject::Crl(_) => out.crl = true,
        }
    }
    out
}

impl Ca {
    /// The recovery screen's content (FR-22 AC4, AC8). With `token` connected, each item
    /// gets the YubiKey column and an interrupted YubiKey setup gets the right action for
    /// the YubiKey's real state (FR-22 AC5, AC7). Reads only.
    pub fn recovery_items(
        &self,
        mut token: Option<&mut dyn TokenSigner>,
    ) -> Result<Vec<RecoveryItem>, OpsError> {
        let report = self.drive_set().recovery_report()?;
        let mut items = Vec::new();
        for pending in report.pending {
            let column = match token.as_deref_mut() {
                // A YubiKey that is absent or cannot be read gives no column; the
                // recovery screen must still open (Flow E runs without the old one).
                Some(token) => self.token_column(token, &pending).ok(),
                None => None,
            };
            items.push(self.refine(pending, column, report.unreadable.is_empty())?);
        }
        Ok(items)
    }

    /// The operation's journal on every drive where it can be read (a drive whose
    /// journal cannot be read is reported by the store, which then offers nothing).
    fn journals(&self, operation: OperationId) -> Vec<OperationJournal> {
        self.drive_set()
            .drives()
            .iter()
            .filter_map(|drive| drive.operation_journal(operation).ok().flatten())
            .collect()
    }

    fn token_column(
        &self,
        token: &mut dyn TokenSigner,
        pending: &PendingOperation,
    ) -> Result<TokenColumn, OpsError> {
        let device = token.device_info()?;
        let credentials = token.credential_status()?;
        let slot = token.slot_status(SIGNING_SLOT)?;
        let journaled: Vec<u32> = pending
            .drives
            .iter()
            .flat_map(|view| view.yubikey_steps.iter().map(|(_, serial)| *serial))
            .collect();
        Ok(TokenColumn {
            device,
            credentials,
            key_without_certificate: slot.key.is_some() && slot.certificate_der.is_none(),
            slot: slot.describe(),
            is_this_operations_yubikey: journaled.iter().all(|serial| *serial == device.serial),
        })
    }

    fn refine(
        &self,
        pending: PendingOperation,
        column: Option<TokenColumn>,
        every_journal_readable: bool,
    ) -> Result<RecoveryItem, OpsError> {
        let operation = pending.operation;
        let journals = self.journals(operation);
        let longest = journals
            .iter()
            .max_by_key(|journal| journal.entries().len())
            .ok_or_else(|| OpsError::Damaged(format!("{operation} has no journal")))?;
        let consistent = journals.iter().all(|journal| is_prefix(journal, longest));
        let sealed = longest.staged_outputs().is_some();
        let what = signed(longest);
        let existing_key = column
            .as_ref()
            .is_some_and(|c| c.key_without_certificate && c.is_this_operations_yubikey)
            && pending.kind == OperationKind::SetupYubikey
            && what.certificate.is_none();
        // FR-22 AC5, AC7 with the maintainer's reading of AC4 (review finding 10): while
        // the setup's YubiKey (by serial) is connected, only resuming from its real state
        // is offered; when it is absent, abandoning is offered as well, for a YubiKey
        // that is lost or will be replaced (nothing was signed).
        let setup_yubikey_present = pending.kind == OperationKind::SetupYubikey
            && column
                .as_ref()
                .is_some_and(|c| c.is_this_operations_yubikey);
        let mut actions = Vec::new();
        let mut blocked_reason = pending.blocked_reason.clone();
        for action in &pending.actions {
            match action {
                StoreAction::FinishFrom { drive_index, drive } => {
                    let ended = pending
                        .drives
                        .get(*drive_index)
                        .and_then(|view| view.state)
                        .filter(|state| {
                            matches!(state, OperationState::Cancelled | OperationState::Abandoned)
                        });
                    let action = RecoveryAction::FinishFrom {
                        drive_index: *drive_index,
                        drive: drive.clone(),
                    };
                    actions.push(match ended {
                        // An interrupted cancel or abandon: only its final entry (and
                        // audit entry) is copied; nothing is marked completed.
                        Some(state) => RecoveryChoice {
                            description: format!(
                                "Copy the {} entry of {operation} from {drive} to every other drive so they all record it the same way; nothing is signed, deleted or overwritten.",
                                if state == OperationState::Cancelled {
                                    "cancelled"
                                } else {
                                    "abandoned"
                                }
                            ),
                            action,
                        },
                        None => choice(action, operation),
                    });
                }
                StoreAction::Abandon if pending.kind == OperationKind::SetupYubikey => {
                    if !setup_yubikey_present {
                        actions.push(RecoveryChoice {
                            action: RecoveryAction::Abandon,
                            description: format!(
                                "Mark {operation} as abandoned, for when this YubiKey is lost or will be replaced; nothing was signed, its serial number stays reserved, and nothing is deleted, overwritten or wiped."
                            ),
                        });
                    }
                }
                StoreAction::Abandon => actions.push(choice(RecoveryAction::Abandon, operation)),
                StoreAction::ResumeYubikeySetup { next_step } => {
                    let action = if what.certificate.is_some() && what.crl {
                        RecoveryAction::RebuildFromJournal {
                            needs_master_passphrase: false,
                        }
                    } else if existing_key {
                        RecoveryAction::CompleteSetupWithExistingKey
                    } else {
                        RecoveryAction::ResumeYubikeySetup {
                            next_step: *next_step,
                        }
                    };
                    actions.push(choice(action, operation));
                }
            }
        }
        // Review finding 5: the master signed the main intermediate but the YubiKey never
        // signed its first CRL; resuming needs that YubiKey. While it is absent (lost),
        // the certificate can still be recorded and the operation finished.
        if pending.kind == OperationKind::SetupYubikey
            && !setup_yubikey_present
            && every_journal_readable
            && consistent
            && !sealed
            && what.certificate.is_some()
            && !what.crl
            && actions
                .iter()
                .any(|c| matches!(c.action, RecoveryAction::ResumeYubikeySetup { .. }))
        {
            actions.push(choice(RecoveryAction::FinishWithoutYubikey, operation));
        }
        if actions.is_empty()
            && every_journal_readable
            && consistent
            && !sealed
            && pending.signed_output_exists
            && pending.kind != OperationKind::SetupYubikey
        {
            match self.rebuildable(operation, pending.kind, &what) {
                Ok(needs_master_passphrase) => {
                    actions.push(choice(
                        RecoveryAction::RebuildFromJournal {
                            needs_master_passphrase,
                        },
                        operation,
                    ));
                    blocked_reason = None;
                }
                Err(reason) => blocked_reason = Some(reason),
            }
        }
        actions.truncate(2);
        Ok(RecoveryItem {
            operation,
            kind: pending.kind,
            subject: pending.subject,
            planned_serials: pending.planned_serials,
            drives: pending.drives,
            yubikey: column,
            actions,
            blocked_reason,
        })
    }

    /// Whether a signed-but-never-staged operation can be rebuilt; `Ok(true)` when the
    /// master passphrase is needed (Flow A without its first CRL).
    fn rebuildable(
        &self,
        operation: OperationId,
        kind: OperationKind,
        what: &Signed,
    ) -> Result<bool, String> {
        match kind {
            OperationKind::CreateMaster | OperationKind::CreateSubIntermediate => {
                let Some((level, common_name, serial)) = &what.certificate else {
                    return Err("no certificate was journaled".to_owned());
                };
                let path = key_path(*level, common_name, *serial);
                match staged_key(self, operation, &path) {
                    Ok(Some(_)) => Ok(kind == OperationKind::CreateMaster && !what.crl),
                    Ok(None) => Err(format!(
                        "the encrypted key {path} staged before signing is missing on every drive; the certificate cannot be completed"
                    )),
                    Err(error) => Err(error.to_string()),
                }
            }
            OperationKind::Revoke | OperationKind::RefreshCrl | OperationKind::ReplaceYubikey
                if what.crl =>
            {
                Ok(false)
            }
            _ => Err("nothing complete was journaled".to_owned()),
        }
    }

    /// Runs a recovery action that needs no YubiKey (FR-22 AC4): finish from a drive,
    /// abandon, or rebuild from the journal. The action must be one the recovery screen
    /// currently offers for `operation`. The YubiKey actions run through
    /// [`Ca::resume_yubikey_setup`].
    pub fn run_recovery(
        &self,
        operation: OperationId,
        action: &RecoveryAction,
        secrets: &RecoverySecrets<'_>,
        time: ConfirmedTime,
    ) -> Result<(), OpsError> {
        let items = self.recovery_items(None)?;
        let item = items
            .iter()
            .find(|item| item.operation == operation)
            .ok_or_else(|| OpsError::NotReady(format!("{operation} is not interrupted")))?;
        if !item.actions.iter().any(|c| c.action == *action) {
            return Err(OpsError::NotReady(format!(
                "that action is not offered for {operation}"
            )));
        }
        self.check_recovery_time(time)?;
        match action {
            RecoveryAction::FinishFrom { drive_index, .. } => Ok(self
                .drive_set()
                .finish_operation(operation, *drive_index, time.get())?),
            RecoveryAction::Abandon => {
                Ok(self.drive_set().abandon_operation(operation, time.get())?)
            }
            RecoveryAction::RebuildFromJournal { .. } => {
                self.rebuild(operation, item.kind, secrets, time)
            }
            RecoveryAction::FinishWithoutYubikey => self.finish_without_yubikey(operation, time),
            RecoveryAction::ResumeYubikeySetup { .. }
            | RecoveryAction::CompleteSetupWithExistingKey => Err(OpsError::NotReady(
                "connect the YubiKey and continue the setup with resume_yubikey_setup".into(),
            )),
        }
    }

    pub(super) fn check_recovery_time(&self, time: ConfirmedTime) -> Result<(), OpsError> {
        let baseline = self
            .drive_set()
            .drives()
            .iter()
            .filter_map(|drive| drive.audit_log().ok())
            .filter_map(|log| crate::clock::baseline(log.entries()))
            .max();
        if let Some(baseline) = baseline
            && time.get() < baseline
        {
            return Err(OpsError::Blocked(vec![
                super::Blocker::ClockConfirmationStale {
                    confirmed: time.get(),
                    baseline,
                },
            ]));
        }
        Ok(())
    }

    /// [`RecoveryAction::FinishWithoutYubikey`]: stages the journaled main-intermediate
    /// certificate and its record entry, and writes a `recovery_finish` audit entry;
    /// nothing is signed.
    fn finish_without_yubikey(
        &self,
        operation: OperationId,
        time: ConfirmedTime,
    ) -> Result<(), OpsError> {
        self.ready_for_recovery(operation, OperationKind::SetupYubikey, time)?;
        self.drive_set().sync_operation_journal(operation)?;
        let journal = self.drive_set().drives()[0]
            .operation_journal(operation)?
            .ok_or_else(|| OpsError::Damaged(format!("{operation} has no journal")))?;
        let (record, pem) = journal
            .signed()
            .find_map(|object| match object {
                SignedObject::Certificate { record, pem } => {
                    Some(((**record).clone(), pem.clone()))
                }
                SignedObject::Crl(_) => None,
            })
            .ok_or_else(|| OpsError::NotReady(format!("{operation} signed no certificate")))?;
        let update = RecordUpdate::new(
            operation,
            vec![RecordChange::Issued {
                certificate: Box::new(record.clone()),
            }],
        );
        let mut draft = AuditDraft::new(
            AuditAction::RecoveryFinish,
            record.subject.display(),
            AuditResult::Success,
        );
        draft.serial = Some(record.serial);
        draft.fingerprint = Some(record.fingerprint);
        draft.details = Some(AuditDetails {
            original_action: Some(AuditAction::SetupYubikey),
            issuer_serial: Some(record.issuer_serial),
            note: Some(
                "finished without the main intermediate's first CRL because its YubiKey is lost or will be replaced; revoke it with Replace lost YubiKey (FR-15)"
                    .to_owned(),
            ),
            ..AuditDetails::default()
        });
        let assembly = Assembly {
            files: vec![
                (certificate_path(&record), pem.into_bytes()),
                (update.output_path(), update.to_bytes()),
            ],
            audit: vec![draft],
        };
        let handle = self.drive_set().resume_operation(operation)?;
        let progress = NoProgress;
        let cancel = CancelFlag::new();
        let mut ctx = OpContext::new(time, &progress, &cancel);
        ctx.persistent = true;
        run(handle, &mut ctx, |handle, ctx| {
            finish(handle, ctx, &assembly)
        })?;
        Ok(())
    }

    fn rebuild(
        &self,
        operation: OperationId,
        kind: OperationKind,
        secrets: &RecoverySecrets<'_>,
        time: ConfirmedTime,
    ) -> Result<(), OpsError> {
        let state = self.ready_for_recovery(operation, kind, time)?;
        self.drive_set().sync_operation_journal(operation)?;
        let journal = self.drive_set().drives()[0]
            .operation_journal(operation)?
            .ok_or_else(|| OpsError::Damaged(format!("{operation} has no journal")))?;
        let what = signed(&journal);
        let key = match &what.certificate {
            Some((level @ (CaLevel::Master | CaLevel::SubIntermediate), cn, serial)) => {
                staged_key(self, operation, &key_path(*level, cn, *serial))?
            }
            _ => None,
        };
        let handle = self.drive_set().resume_operation(operation)?;
        let progress = NoProgress;
        let cancel = CancelFlag::new();
        let mut ctx = OpContext::new(time, &progress, &cancel);
        ctx.persistent = true;
        run(handle, &mut ctx, |handle, ctx| {
            if kind == OperationKind::CreateMaster && !what.crl {
                let passphrase = secrets.master_passphrase.ok_or_else(|| {
                    OpsError::NotReady("enter the master passphrase to sign its first CRL".into())
                })?;
                let (record, pem) = journal
                    .signed()
                    .find_map(|object| match object {
                        SignedObject::Certificate { record, pem } => {
                            Some((record.clone(), pem.clone()))
                        }
                        SignedObject::Crl(_) => None,
                    })
                    .ok_or_else(|| {
                        OpsError::Damaged("no master certificate was journaled".into())
                    })?;
                let (der, info) = parse_certificate_pem(pem.as_bytes())?;
                let key_pem = key.as_deref().ok_or_else(|| {
                    OpsError::Damaged("the encrypted master key is not staged".into())
                })?;
                let master_key = decrypt_key_pem(key_pem, passphrase.secret())?;
                if master_key.public_key_spki_der()? != info.spki_der {
                    return Err(OpsError::Damaged(
                        "the staged key does not belong to the master certificate".into(),
                    ));
                }
                let crl = first_crl(
                    &der,
                    time.get().get(),
                    &mut SoftwareSigner::new(&master_key),
                )?;
                drop(master_key);
                record_crl(handle, ctx, signed_crl(record.serial, &crl))?;
            }
            assemble_and_finish(self, handle, ctx, &state, key.as_deref())
        })?;
        Ok(())
    }
}
