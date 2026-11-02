//! Clock confirmation, sanity checks and the clock-correction baseline (FR-17, SEC-16).
//!
//! # Before any signing (FR-17 AC1, AC2)
//! The GUI shows the time and the operator confirms it or enters the correct time. Both go
//! through [`assess`], which runs the sanity checks *before* the operator confirms:
//! - earlier than the **baseline** (the newest audit-log timestamp, see below): blocked;
//! - earlier than the binary's build date: blocked;
//! - more than 5 years after the build date: a warning that needs an explicit
//!   confirmation.
//!
//! [`confirm`] turns an assessment into a [`ConfirmedTime`]; signing code takes that type,
//! so it cannot run without the operator's confirmation.
//!
//! # Correction baseline (FR-17 AC3)
//! If an entry was recorded with a wrong future date, "Correct clock baseline" appends a
//! `clock_correction` audit entry recording the previous newest timestamp and the time the
//! operator confirmed (still no earlier than the build date). Existing entries are never
//! changed. From then on the baseline is the newest timestamp among the **latest**
//! correction entry and every entry written after it; the erroneous timestamps before it
//! are ignored. The baseline keeps advancing with each later entry, so the clock can never
//! be moved back past it. [`future_dated_certificates`] lists certificates signed with a
//! future date so the operator can revoke and re-issue them.
//!
//! Decision (conservative reading): a correction is accepted only when it is needed, that
//! is when the confirmed time is earlier than the current baseline.
#![forbid(unsafe_code)]

use time::{Date, OffsetDateTime};

use crate::model::Timestamp;
use crate::store::audit::{
    AuditAction, AuditDetails, AuditDraft, AuditEntry, AuditResult, ClockCorrectionDetails,
};
use crate::store::record::{IssuanceRecord, RecordedCertificate};
use crate::store::{DriveSet, StoreError};

/// Years after the build date beyond which the time needs an explicit confirmation.
pub const FAR_FUTURE_YEARS: i32 = 5;

/// Source of the current time. The real one is [`SystemClock`]; tests use a controllable
/// clock (`keystone_testkit::TestClock`).
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> OffsetDateTime;
}

/// The operating system's clock, in UTC.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Errors from this module.
#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    /// Signing is blocked until the clock is corrected (FR-17 AC2).
    #[error("signing is blocked until the clock is corrected: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Blocked(Vec<ClockProblem>),
    /// The far-future warning was not explicitly confirmed (FR-17 AC2).
    #[error("{0}; confirm explicitly that this time is correct")]
    WarningNotConfirmed(ClockWarning),
    /// A correction that would not move the baseline back (FR-17 AC3).
    #[error(
        "no correction is needed: the confirmed time is not earlier than the newest audit-log entry"
    )]
    CorrectionNotNeeded,
    /// A time that cannot be stored (out of range).
    #[error("the time cannot be used: {0}")]
    InvalidTime(String),
    /// Writing the correction entry failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A check that blocks signing (FR-17 AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockProblem {
    /// Earlier than the newest audit entry or the correction baseline.
    #[error("the time {now} is earlier than the newest audit-log entry ({baseline})")]
    EarlierThanBaseline {
        /// The assessed time.
        now: OffsetDateTime,
        /// The baseline.
        baseline: OffsetDateTime,
    },
    /// Earlier than this binary's build date.
    #[error("the time {now} is earlier than this program's build date ({build_date})")]
    EarlierThanBuildDate {
        /// The assessed time.
        now: OffsetDateTime,
        /// The build date.
        build_date: OffsetDateTime,
    },
}

/// A check that needs an explicit confirmation (FR-17 AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockWarning {
    /// More than 5 years after the build date.
    #[error(
        "the time {now} is more than {FAR_FUTURE_YEARS} years after this program's build date ({build_date})"
    )]
    FarAfterBuildDate {
        /// The assessed time.
        now: OffsetDateTime,
        /// The build date.
        build_date: OffsetDateTime,
    },
}

/// Result of the sanity checks, shown before the operator confirms (FR-17 AC2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockAssessment {
    /// The assessed time (system time, or the time the operator entered).
    pub now: OffsetDateTime,
    /// The baseline it was compared with, if the log has entries.
    pub baseline: Option<OffsetDateTime>,
    /// Problems that block signing.
    pub blocked: Vec<ClockProblem>,
    /// Warnings that need an explicit confirmation.
    pub warnings: Vec<ClockWarning>,
}

impl ClockAssessment {
    /// True when signing is blocked.
    pub fn is_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// True when a warning needs an explicit confirmation.
    pub fn needs_explicit_confirmation(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// A time the operator confirmed after the sanity checks passed (FR-17 AC1, SEC-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedTime(Timestamp);

impl ConfirmedTime {
    /// The confirmed time (UTC, whole seconds).
    pub fn get(self) -> Timestamp {
        self.0
    }
}

fn whole_utc(time: OffsetDateTime) -> Result<Timestamp, ClockError> {
    time.replace_nanosecond(0)
        .map(Timestamp::utc)
        .map_err(|e| ClockError::InvalidTime(e.to_string()))
}

/// The baseline of FR-17 AC2 and AC3: the newest timestamp among the latest
/// clock-correction entry and every entry after it, or among all entries when there is no
/// correction. `None` for an empty log.
pub fn baseline(entries: &[AuditEntry]) -> Option<Timestamp> {
    let start = entries
        .iter()
        .rposition(|entry| entry.action == AuditAction::ClockCorrection)
        .unwrap_or(0);
    entries[start..]
        .iter()
        .map(|entry| match (&entry.action, &entry.details) {
            (AuditAction::ClockCorrection, Some(details)) => details
                .clock_correction
                .map_or(entry.time, |correction| correction.confirmed),
            _ => entry.time,
        })
        .max()
}

/// The date `years` calendar years after `date` (29 February becomes 28 February).
fn years_after(time: OffsetDateTime, years: i32) -> OffsetDateTime {
    let date = time.date();
    let year = date.year() + years;
    let shifted = Date::from_calendar_date(year, date.month(), date.day())
        .or_else(|_| Date::from_calendar_date(year, date.month(), date.day() - 1))
        .unwrap_or(Date::MAX);
    time.replace_date(shifted)
}

/// FR-17 AC2: sanity checks for `now` against the baseline and the build date.
pub fn assess(
    now: OffsetDateTime,
    baseline: Option<Timestamp>,
    build_date: OffsetDateTime,
) -> ClockAssessment {
    let mut blocked = Vec::new();
    let mut warnings = Vec::new();
    let baseline = baseline.map(Timestamp::get);
    if let Some(baseline) = baseline
        && now < baseline
    {
        blocked.push(ClockProblem::EarlierThanBaseline { now, baseline });
    }
    if now < build_date {
        blocked.push(ClockProblem::EarlierThanBuildDate { now, build_date });
    }
    if now > years_after(build_date, FAR_FUTURE_YEARS) {
        warnings.push(ClockWarning::FarAfterBuildDate { now, build_date });
    }
    ClockAssessment {
        now,
        baseline,
        blocked,
        warnings,
    }
}

/// FR-17 AC2 against the drives' audit log and this binary's build date.
pub fn assess_for_log(now: OffsetDateTime, entries: &[AuditEntry]) -> ClockAssessment {
    assess(now, baseline(entries), crate::build_info::build_date())
}

/// FR-17 AC1: the operator confirms the assessed time. Refused while a check blocks
/// signing, and when a warning is shown but `warning_confirmed` is false.
pub fn confirm(
    assessment: &ClockAssessment,
    warning_confirmed: bool,
) -> Result<ConfirmedTime, ClockError> {
    if assessment.is_blocked() {
        return Err(ClockError::Blocked(assessment.blocked.clone()));
    }
    if let Some(warning) = assessment.warnings.first()
        && !warning_confirmed
    {
        return Err(ClockError::WarningNotConfirmed(*warning));
    }
    Ok(ConfirmedTime(whole_utc(assessment.now)?))
}

/// A planned clock-correction entry (FR-17 AC3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockCorrection {
    previous_newest: Timestamp,
    confirmed: Timestamp,
}

impl ClockCorrection {
    /// Plans a correction: the operator confirmed `confirmed` as the current time. It must
    /// not be earlier than `build_date`, and it must be earlier than the current baseline
    /// (otherwise no correction is needed).
    pub fn plan(
        entries: &[AuditEntry],
        confirmed: OffsetDateTime,
        build_date: OffsetDateTime,
    ) -> Result<ClockCorrection, ClockError> {
        if confirmed < build_date {
            return Err(ClockError::Blocked(vec![
                ClockProblem::EarlierThanBuildDate {
                    now: confirmed,
                    build_date,
                },
            ]));
        }
        let previous_newest = baseline(entries).ok_or(ClockError::CorrectionNotNeeded)?;
        let confirmed = whole_utc(confirmed)?;
        if confirmed >= previous_newest {
            return Err(ClockError::CorrectionNotNeeded);
        }
        Ok(ClockCorrection {
            previous_newest,
            confirmed,
        })
    }

    /// The newest timestamp before the correction (the wrong, future one).
    pub fn previous_newest(&self) -> Timestamp {
        self.previous_newest
    }

    /// The confirmed current time.
    pub fn confirmed(&self) -> Timestamp {
        self.confirmed
    }

    /// The audit entry to append (its time is the confirmed time).
    pub fn audit_draft(&self) -> AuditDraft {
        let mut draft = AuditDraft::new(AuditAction::ClockCorrection, "", AuditResult::Success);
        draft.details = Some(AuditDetails {
            clock_correction: Some(ClockCorrectionDetails {
                previous_newest: self.previous_newest,
                confirmed: self.confirmed,
            }),
            ..AuditDetails::default()
        });
        draft
    }

    /// Appends the correction entry on every drive. Existing entries are never changed.
    pub fn record(&self, drives: &DriveSet) -> Result<AuditEntry, ClockError> {
        let mut added = drives.append_audit(&[self.audit_draft()], self.confirmed)?;
        added
            .pop()
            .ok_or_else(|| ClockError::InvalidTime("no entry was written".to_string()))
    }
}

/// FR-17 AC3: certificates whose validity starts after `now` (signed while the clock was
/// ahead), so the operator can revoke and re-issue them.
pub fn future_dated_certificates(
    record: &IssuanceRecord,
    now: Timestamp,
) -> Vec<&RecordedCertificate> {
    record
        .certificates()
        .iter()
        .filter(|cert| cert.certificate.not_before > now)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::audit::{AuditLog, parse_audit_log};
    use time::Duration;

    fn at(days: i64) -> OffsetDateTime {
        crate::build_info::build_date() + Duration::days(days)
    }

    fn log(times: &[OffsetDateTime]) -> AuditLog {
        let mut current = AuditLog::empty();
        for time in times {
            let draft = AuditDraft::new(AuditAction::Export, "KEYSTONE TEST", AuditResult::Success);
            let (bytes, _) = current
                .with_appended(&[draft], Timestamp::utc(*time))
                .expect("append");
            current = parse_audit_log(&bytes).expect("valid");
        }
        current
    }

    fn with_correction(log: &AuditLog, correction: &ClockCorrection) -> AuditLog {
        let (bytes, _) = log
            .with_appended(&[correction.audit_draft()], correction.confirmed())
            .expect("append");
        parse_audit_log(&bytes).expect("valid")
    }

    #[test]
    fn fr17_ac2_earlier_than_newest_entry_or_build_date_is_blocked() {
        // Covers: FR-17 AC2, SEC-16
        let entries = log(&[at(10), at(30), at(20)]);
        let assessment = assess_for_log(at(25), entries.entries());
        assert_eq!(assessment.baseline, Some(at(30)));
        assert!(assessment.is_blocked());
        assert!(matches!(
            assessment.blocked[0],
            ClockProblem::EarlierThanBaseline { .. }
        ));
        assert!(confirm(&assessment, true).is_err());
        assert!(!assess_for_log(at(30), entries.entries()).is_blocked());
        let before_build = assess(at(-1), None, at(0));
        assert_eq!(
            before_build.blocked,
            vec![ClockProblem::EarlierThanBuildDate {
                now: at(-1),
                build_date: at(0)
            }]
        );
        let message = confirm(&before_build, true)
            .expect_err("blocked")
            .to_string();
        assert!(message.contains("build date"), "{message}");
    }

    #[test]
    fn fr17_ac2_more_than_five_years_after_build_needs_explicit_confirmation() {
        // Covers: FR-17 AC2
        let five_years = years_after(at(0), 5);
        let at_limit = assess(five_years, None, at(0));
        assert!(!at_limit.needs_explicit_confirmation());
        let beyond = assess(five_years + Duration::seconds(1), None, at(0));
        assert!(beyond.needs_explicit_confirmation());
        assert!(!beyond.is_blocked());
        assert!(matches!(
            confirm(&beyond, false),
            Err(ClockError::WarningNotConfirmed(_))
        ));
        assert!(confirm(&beyond, true).is_ok());
    }

    #[test]
    fn fr17_ac1_confirmation_yields_the_time_used_for_signing() {
        // Covers: FR-17 AC1, SEC-16
        let now = at(1) + Duration::milliseconds(500);
        let confirmed = confirm(&assess(now, None, at(0)), false).expect("ok");
        assert_eq!(
            confirmed.get().get(),
            now.replace_nanosecond(0).expect("valid")
        );
    }

    #[test]
    fn fr17_ac3_correction_baseline_ignores_earlier_wrong_timestamps() {
        // Covers: FR-17 AC3
        // An entry was recorded ten years in the future.
        let wrong = log(&[at(1), at(3650)]);
        assert!(assess_for_log(at(2), wrong.entries()).is_blocked());
        let correction = ClockCorrection::plan(wrong.entries(), at(2), at(0)).expect("plan");
        assert_eq!(correction.previous_newest().get(), at(3650));
        let corrected = with_correction(&wrong, &correction);
        // Existing entries are unchanged: the old log is a prefix of the new one.
        assert!(wrong.is_prefix_of(&corrected));
        let details = corrected.entries()[2]
            .details
            .as_ref()
            .and_then(|d| d.clock_correction)
            .expect("details");
        assert_eq!(details.previous_newest.get(), at(3650));
        assert_eq!(details.confirmed.get(), at(2));
        // Signing resumes at the confirmed time.
        assert_eq!(
            baseline(corrected.entries()).map(Timestamp::get),
            Some(at(2))
        );
        assert!(!assess_for_log(at(2), corrected.entries()).is_blocked());
        // Later legitimate entries advance the baseline again.
        let (bytes, _) = corrected
            .with_appended(
                &[AuditDraft::new(
                    AuditAction::Export,
                    "x",
                    AuditResult::Success,
                )],
                Timestamp::utc(at(5)),
            )
            .expect("append");
        let later = parse_audit_log(&bytes).expect("valid");
        assert!(assess_for_log(at(4), later.entries()).is_blocked());
        assert!(!assess_for_log(at(5), later.entries()).is_blocked());
    }

    #[test]
    fn fr17_ac3_correction_rules() {
        // Covers: FR-17 AC3
        let entries = log(&[at(10)]);
        assert!(matches!(
            ClockCorrection::plan(entries.entries(), at(-1), at(0)),
            Err(ClockError::Blocked(_))
        ));
        assert!(matches!(
            ClockCorrection::plan(entries.entries(), at(11), at(0)),
            Err(ClockError::CorrectionNotNeeded)
        ));
        assert!(matches!(
            ClockCorrection::plan(&[], at(1), at(0)),
            Err(ClockError::CorrectionNotNeeded)
        ));
        // Only the latest correction counts.
        let first = ClockCorrection::plan(entries.entries(), at(5), at(0)).expect("plan");
        let once = with_correction(&entries, &first);
        let second = ClockCorrection::plan(once.entries(), at(3), at(0)).expect("plan");
        let twice = with_correction(&once, &second);
        assert_eq!(baseline(twice.entries()).map(Timestamp::get), Some(at(3)));
    }

    #[test]
    fn leap_day_build_dates_are_handled() {
        let leap = OffsetDateTime::from_unix_timestamp(1_709_164_800).expect("2024-02-29");
        assert_eq!(years_after(leap, 5).date().to_string(), "2029-02-28");
    }
}
