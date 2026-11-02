//! View models: pure functions that turn core results into what the screens show.
//!
//! Nothing here touches GTK, so every rule about what the operator sees is unit-tested
//! without a display. The GUI holds no CA rules: every decision comes from
//! keystone-core; these modules only phrase and arrange it.
#![forbid(unsafe_code)]

pub mod clock;
pub mod crl;
pub mod drives;
pub mod forms;
pub mod home;
pub mod passphrase;
pub mod record;
pub mod recovery;
pub mod result;
pub mod startup;
pub mod token;

use time::OffsetDateTime;

/// The status of a line on screen. Always shown as an icon *and* a leading word, never
/// by colour alone (NFR-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Fine.
    Ok,
    /// Neutral information.
    Info,
    /// Needs attention but does not block.
    Warning,
    /// Blocks the next step.
    Blocked,
}

impl Status {
    /// The word that starts the line.
    pub fn word(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Info => "Note",
            Status::Warning => "Warning",
            Status::Blocked => "Blocked",
        }
    }

    /// The symbolic icon shown before the line.
    pub fn icon_name(self) -> &'static str {
        match self {
            Status::Ok => "emblem-ok-symbolic",
            Status::Info => "dialog-information-symbolic",
            Status::Warning => "dialog-warning-symbolic",
            Status::Blocked => "dialog-error-symbolic",
        }
    }

    /// `"<word>: <text>"`, the text read by everyone (and by screen readers).
    pub fn line(self, text: &str) -> String {
        format!("{}: {text}", self.word())
    }
}

/// One status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Its status.
    pub status: Status,
    /// The text (without the status word).
    pub text: String,
}

impl Line {
    /// A line.
    pub fn new(status: Status, text: impl Into<String>) -> Self {
        Line {
            status,
            text: text.into(),
        }
    }
}

/// `2026-11-02 14:03:12 UTC`: every time Keystone shows is UTC, labelled as such.
pub fn format_utc(time: OffsetDateTime) -> String {
    let t = time.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// `2026-11-02` (UTC).
pub fn format_date(time: OffsetDateTime) -> String {
    let t = time.to_offset(time::UtcOffset::UTC);
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfr04_status_is_spelled_out_not_only_coloured() {
        // Covers: NFR-04
        for status in [Status::Ok, Status::Info, Status::Warning, Status::Blocked] {
            let line = status.line("something");
            assert!(line.starts_with(status.word()), "{line}");
            assert!(status.icon_name().ends_with("-symbolic"));
        }
        assert_eq!(Status::Blocked.line("x"), "Blocked: x");
    }

    #[test]
    fn times_are_shown_in_utc() {
        let time = OffsetDateTime::from_unix_timestamp(1_793_491_200 + 3_723).expect("time");
        assert_eq!(format_utc(time), "2026-11-01 01:02:03 UTC");
        assert_eq!(format_date(time), "2026-11-01");
    }
}
