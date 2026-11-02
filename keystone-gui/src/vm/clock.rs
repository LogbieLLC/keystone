//! Clock confirmation (FR-17, SEC-16).
//!
//! The sanity checks are core's (`clock::assess_for_log`, `clock::confirm`,
//! `clock::ClockCorrection`); this module phrases them and decides which buttons the
//! screen offers:
//! - blocked (earlier than the newest audit entry or the build date): no Confirm;
//!   "Check again" after fixing the system clock, or "Enter the correct time";
//! - blocked only by a newer audit entry, with a time after the build date: also
//!   "Correct clock baseline" (FR-17 AC3);
//! - more than 5 years after the build date: Confirm needs an explicit tick.
//!
//! Decision: an operator-entered time is a whole UTC date and time
//! (`YYYY-MM-DD` and `HH:MM` or `HH:MM:SS`); Keystone never changes the system clock.
#![forbid(unsafe_code)]

use keystone_core::clock::{ClockAssessment, ClockProblem, ClockWarning};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use super::{Line, Status, format_utc};

/// Where the assessed time came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// The system clock.
    System,
    /// Typed by the operator.
    Entered,
}

/// What the clock screen shows for one assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockView {
    /// The assessed time, in UTC.
    pub time_text: String,
    /// Check results.
    pub lines: Vec<Line>,
    /// Signing is blocked until the clock is corrected.
    pub blocked: bool,
    /// The far-future warning needs an explicit tick.
    pub needs_explicit_confirmation: bool,
    /// Offer "Correct clock baseline" (FR-17 AC3).
    pub offer_baseline_correction: bool,
}

impl ClockView {
    /// True when the Confirm button may be pressed.
    pub fn can_confirm(&self, warning_ticked: bool) -> bool {
        !self.blocked && (!self.needs_explicit_confirmation || warning_ticked)
    }
}

fn problem_text(problem: &ClockProblem) -> String {
    match problem {
        ClockProblem::EarlierThanBaseline { baseline, .. } => format!(
            "This time is earlier than the newest audit-log entry ({}). Signing is blocked until the clock is corrected.",
            format_utc(*baseline)
        ),
        ClockProblem::EarlierThanBuildDate { build_date, .. } => format!(
            "This time is earlier than this program's build date ({}). Signing is blocked until the clock is corrected.",
            format_utc(*build_date)
        ),
    }
}

fn warning_text(warning: &ClockWarning) -> String {
    match warning {
        ClockWarning::FarAfterBuildDate { build_date, .. } => format!(
            "This time is more than {} years after this program's build date ({}). If it is really correct, tick the box to confirm it explicitly.",
            keystone_core::clock::FAR_FUTURE_YEARS,
            format_utc(*build_date)
        ),
    }
}

/// The view of one assessment.
pub fn view(assessment: &ClockAssessment, source: TimeSource) -> ClockView {
    let mut lines = vec![Line::new(
        Status::Info,
        format!(
            "{} {}.",
            match source {
                TimeSource::System => "The system clock says",
                TimeSource::Entered => "You entered",
            },
            format_utc(assessment.now)
        ),
    )];
    for problem in &assessment.blocked {
        lines.push(Line::new(Status::Blocked, problem_text(problem)));
    }
    for warning in &assessment.warnings {
        lines.push(Line::new(Status::Warning, warning_text(warning)));
    }
    if !assessment.is_blocked() && assessment.warnings.is_empty() {
        lines.push(Line::new(
            Status::Ok,
            match assessment.baseline {
                Some(baseline) => format!(
                    "The time passes the checks: it is after the build date and after the newest audit-log entry ({}).",
                    format_utc(baseline)
                ),
                None => "The time passes the checks: it is after this program's build date."
                    .to_string(),
            },
        ));
    }
    let only_baseline = !assessment.blocked.is_empty()
        && assessment
            .blocked
            .iter()
            .all(|p| matches!(p, ClockProblem::EarlierThanBaseline { .. }));
    ClockView {
        time_text: format_utc(assessment.now),
        lines,
        blocked: assessment.is_blocked(),
        needs_explicit_confirmation: assessment.needs_explicit_confirmation(),
        offer_baseline_correction: only_baseline,
    }
}

/// Parses an operator-entered UTC date (`YYYY-MM-DD`) and time (`HH:MM[:SS]`).
pub fn parse_entered_time(date: &str, time_of_day: &str) -> Result<OffsetDateTime, String> {
    let date_parts: Vec<&str> = date.trim().split('-').collect();
    let [year, month, day] = date_parts.as_slice() else {
        return Err("Enter the date as YYYY-MM-DD, for example 2026-11-02.".to_string());
    };
    let number = |text: &str, digits: usize| -> Option<u32> {
        (text.len() == digits && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    };
    let (Some(year), Some(month), Some(day)) = (number(year, 4), number(month, 2), number(day, 2))
    else {
        return Err("Enter the date as YYYY-MM-DD, for example 2026-11-02.".to_string());
    };
    let month = u8::try_from(month)
        .ok()
        .and_then(|m| Month::try_from(m).ok())
        .ok_or_else(|| "The month must be 01 to 12.".to_string())?;
    let date = Date::from_calendar_date(
        i32::try_from(year).map_err(|_| "The year is out of range.".to_string())?,
        month,
        u8::try_from(day).map_err(|_| "The day is out of range.".to_string())?,
    )
    .map_err(|_| "That date does not exist.".to_string())?;
    let time_parts: Vec<&str> = time_of_day.trim().split(':').collect();
    let (hour, minute, second) = match time_parts.as_slice() {
        [h, m] => (number(h, 2), number(m, 2), Some(0)),
        [h, m, s] => (number(h, 2), number(m, 2), number(s, 2)),
        _ => (None, None, None),
    };
    let (Some(hour), Some(minute), Some(second)) = (hour, minute, second) else {
        return Err("Enter the time as HH:MM or HH:MM:SS in UTC, for example 14:05.".to_string());
    };
    let time = Time::from_hms(
        u8::try_from(hour).unwrap_or(99),
        u8::try_from(minute).unwrap_or(99),
        u8::try_from(second).unwrap_or(99),
    )
    .map_err(|_| "That time does not exist; use 00:00 to 23:59.".to_string())?;
    Ok(PrimitiveDateTime::new(date, time).assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::clock::assess;
    use keystone_core::model::Timestamp;
    use time::Duration;

    fn build() -> OffsetDateTime {
        keystone_core::build_info::build_date()
    }

    #[test]
    fn fr17_ac1_a_sane_time_can_be_confirmed() {
        // Covers: FR-17 AC1, SEC-16
        let assessment = assess(build() + Duration::days(1), None, build());
        let v = view(&assessment, TimeSource::System);
        assert!(!v.blocked);
        assert!(v.can_confirm(false));
        assert!(v.lines[0].text.starts_with("The system clock says"));
        assert!(v.time_text.ends_with("UTC"));
    }

    #[test]
    fn fr17_ac2_earlier_than_newest_entry_blocks_and_offers_baseline_correction() {
        // Covers: FR-17 AC2, FR-17 AC3
        let baseline = Timestamp::utc(build() + Duration::days(3650));
        let assessment = assess(build() + Duration::days(2), Some(baseline), build());
        let v = view(&assessment, TimeSource::System);
        assert!(v.blocked);
        assert!(!v.can_confirm(true));
        assert!(v.offer_baseline_correction);
        assert!(
            v.lines
                .iter()
                .any(|l| l.status == Status::Blocked && l.text.contains("newest audit-log entry"))
        );
    }

    #[test]
    fn fr17_ac2_earlier_than_build_date_blocks_without_baseline_correction() {
        // Covers: FR-17 AC2
        let assessment = assess(build() - Duration::days(1), None, build());
        let v = view(&assessment, TimeSource::Entered);
        assert!(v.blocked);
        assert!(!v.offer_baseline_correction);
        assert!(v.lines[1].text.contains("build date"));
        assert!(v.lines[0].text.starts_with("You entered"));
    }

    #[test]
    fn fr17_ac2_five_years_after_build_needs_an_explicit_tick() {
        // Covers: FR-17 AC2
        let assessment = assess(build() + Duration::days(366 * 6), None, build());
        let v = view(&assessment, TimeSource::System);
        assert!(!v.blocked);
        assert!(v.needs_explicit_confirmation);
        assert!(!v.can_confirm(false));
        assert!(v.can_confirm(true));
        assert!(v.lines.iter().any(|l| l.status == Status::Warning));
    }

    #[test]
    fn entered_times_are_parsed_strictly_as_utc() {
        let parsed = parse_entered_time("2026-11-02", "14:05").expect("valid");
        assert_eq!(format_utc(parsed), "2026-11-02 14:05:00 UTC");
        let parsed = parse_entered_time(" 2026-02-28 ", "23:59:59").expect("valid");
        assert_eq!(format_utc(parsed), "2026-02-28 23:59:59 UTC");
        for (date, time) in [
            ("2026-2-28", "10:00"),
            ("2026-02-30", "10:00"),
            ("2026-13-01", "10:00"),
            ("2026-11-02", "24:00"),
            ("2026-11-02", "10"),
            ("2026/11/02", "10:00"),
            ("2026-11-02", "1:00"),
        ] {
            assert!(parse_entered_time(date, time).is_err(), "{date} {time}");
        }
    }
}
