//! Replace a lost drive (SEC-11, T-11; maintainer-approved feature, ADR 0003): plan,
//! review, execute, like every other flow.
//!
//! When a CA drive is lost or fails, the operator connects the healthy drives and one new,
//! empty drive. [`Ca::plan_replace_drive`] checks everything and prepares the review
//! (nothing is written); [`ReplaceDrivePlan::execute`] copies the complete CA to the new
//! drive, verifies every file by SHA-256, writes the new drive's identity last, promotes a
//! backup to primary when no primary is connected, and records it all in the audit log
//! on every drive. It signs nothing and never overwrites or deletes anything.
//!
//! It is the one writing action a CA with a single healthy drive (one primary and no
//! backup, or one backup and no primary) can run: every signing action still needs the
//! primary and at least one backup (FR-12 AC1).
#![forbid(unsafe_code)]

use std::path::Path;

use crate::clock::ConfirmedTime;
use crate::store::{AddDrivePlan, NewDriveState};

use super::{Ca, OpsError, Progress, ProgressSink, Review, Step};

/// A checked plan for replacing a lost drive. Nothing was written.
#[derive(Debug)]
pub struct ReplaceDrivePlan {
    plan: AddDrivePlan,
    time: ConfirmedTime,
    review: Review,
}

/// The result of replacing a lost drive.
#[derive(Debug)]
pub struct ReplaceDriveOutcome {
    /// The CA opened on the healthy drives and the new one.
    pub ca: Ca,
    /// The new drive's label.
    pub new_drive: String,
    /// The backup drive that became the primary, when no primary was connected.
    pub promoted: Option<String>,
    /// Journaled operations copied.
    pub operations_copied: usize,
    /// Output files copied (certificates, encrypted keys, CRLs, records).
    pub files_copied: usize,
    /// Audit entries copied.
    pub audit_entries_copied: usize,
}

impl Ca {
    /// Plans replacing a lost drive with the new, empty drive at `new_drive` (SEC-11).
    /// Refuses while the connected drives are behind, diverged or damaged, while an
    /// operation is interrupted, for a drive that is not empty (except an interrupted
    /// copy of this CA, which is continued), and for a confirmed time earlier than the
    /// newest audit entry. Nothing is written.
    pub fn plan_replace_drive(
        &self,
        new_drive: &Path,
        time: ConfirmedTime,
    ) -> Result<ReplaceDrivePlan, OpsError> {
        self.check_recovery_time(time)?;
        let plan = self.drive_set().plan_add_drive(new_drive)?;
        let mut review = Review::new("Replace a lost drive");
        review.line("New drive", new_drive.display().to_string());
        review.line(
            "New drive now",
            match plan.state {
                NewDriveState::Empty => "empty".to_owned(),
                NewDriveState::PartialCopy => {
                    "holds part of a copy of this CA from an interrupted attempt; the copy continues".to_owned()
                }
                NewDriveState::CopiedNotRecorded(_) => {
                    "holds a complete copy of this CA from an interrupted attempt; only the audit entries are written".to_owned()
                }
            },
        );
        review.line("Copied from", plan.source_label.clone());
        review.line(
            "Copy",
            format!(
                "{} operations, {} files and {} audit entries, each verified by SHA-256; the new drive's identity is written last",
                plan.operations, plan.files, plan.audit_entries
            ),
        );
        review.line("Role of the new drive", "backup");
        review.line(
            "Primary drive",
            match &plan.promote_label {
                Some(label) => {
                    format!("no primary drive is connected: {label} becomes the primary")
                }
                None => "unchanged".to_owned(),
            },
        );
        review.line(
            "What is not done",
            "nothing is signed; nothing on the connected drives is overwritten or deleted",
        );
        if plan.promote.is_some() {
            review.warnings.push(
                "Use this only when the primary drive is lost or broken. If it is found again it is used as a backup, never as a second primary.".to_owned(),
            );
        }
        Ok(ReplaceDrivePlan { plan, time, review })
    }
}

impl ReplaceDrivePlan {
    /// What the review step shows.
    pub fn review(&self) -> &Review {
        &self.review
    }

    /// The label of the backup drive that becomes the primary, if any.
    pub fn promotes(&self) -> Option<&str> {
        self.plan.promote_label.as_deref()
    }

    /// Copies the CA to the new drive, verifies it, writes its identity last and records
    /// the replacement (and a promotion) in the audit log on every drive. The plan is
    /// checked again first and must be unchanged.
    pub fn execute(
        self,
        ca: &Ca,
        progress: &dyn ProgressSink,
    ) -> Result<ReplaceDriveOutcome, OpsError> {
        ca.check_recovery_time(self.time)?;
        progress.report(Progress::Step {
            step: Step::PreparingDrives,
            cancel_available: false,
        });
        let set = ca.drive_set().add_drive(&self.plan, self.time.get())?;
        progress.report(Progress::Step {
            step: Step::Done,
            cancel_available: false,
        });
        let new_drive = set
            .drives()
            .iter()
            .find(|drive| drive.root() == self.plan.target)
            .map(|drive| drive.label())
            .unwrap_or_else(|| self.plan.target.display().to_string());
        let promoted = self.plan.promote.and_then(|id| {
            set.drives()
                .iter()
                .find(|drive| drive.identity().drive_id == id)
                .map(|drive| drive.label())
        });
        Ok(ReplaceDriveOutcome {
            ca: Ca::from_set(set),
            new_drive,
            promoted,
            operations_copied: self.plan.operations,
            files_copied: self.plan.files,
            audit_entries_copied: self.plan.audit_entries,
        })
    }
}
