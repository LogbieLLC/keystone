//! Live validation of the input forms. Every rule is core's (`profile`, `token`); this
//! module maps form text to core types and errors to plain feedback.
//!
//! - Names (FR-02 AC4): `profile::ValidatedName`.
//! - Validity (FR-10 AC1, AC3): `profile::plan_validity` within the level's bounds and
//!   never past the issuer.
//! - CRL address (FR-18): `profile::CrlUrl`, with "no address" as its own explicit
//!   choice that shows `profile::CRL_NONE_WARNING`.
//! - Name constraints (FR-21 AC1, AC4): `profile::NameConstraintsSpec`, on by default;
//!   off is its own explicit choice that shows `profile::NAME_CONSTRAINTS_OFF_WARNING`.
//! - PIN and PUK (FR-06 AC2): `token::NewPin` / `token::NewPuk` on submit; while typing
//!   only the length is shown, so the secret is never copied out of the entry early.
//! - Wipe confirmation (FR-07 AC4): `token::WipeConfirmation`.
#![forbid(unsafe_code)]

use keystone_core::model::{CaLevel, NameFields};
use keystone_core::profile::{
    CertValidity, CrlLocation, CrlUrl, NameConstraintsChoice, NameConstraintsSpec, ValidatedName,
    level_profile, max_validity_years, plan_validity,
};
use time::OffsetDateTime;

use super::{Line, Status, format_utc};

/// FR-02 AC4: validates the name fields; empty optional fields mean "not set".
pub fn name(common_name: &str, organization: &str, country: &str) -> Result<ValidatedName, String> {
    let optional = |text: &str| (!text.is_empty()).then(|| text.to_string());
    ValidatedName::new(&NameFields {
        common_name: common_name.to_string(),
        organization: optional(organization),
        country: optional(country),
    })
    .map_err(|e| capitalise(&e.to_string()))
}

/// The bounds of the validity spinner for `level` (FR-10 AC3).
pub fn validity_bounds(level: CaLevel) -> (u8, u8, u8) {
    let profile = level_profile(level);
    (
        profile.min_validity_years,
        profile.max_validity_years,
        profile.default_validity_years,
    )
}

/// The default years, lowered to what fits under the issuer (FR-10 AC1).
pub fn default_years(
    level: CaLevel,
    now: OffsetDateTime,
    issuer_not_after: Option<OffsetDateTime>,
) -> u8 {
    let (_, _, default) = validity_bounds(level);
    let fits = max_validity_years(level, now, issuer_not_after);
    if fits == 0 {
        default
    } else {
        default.min(fits)
    }
}

/// FR-10 AC1, AC3: the planned validity or the reason it is refused.
pub fn validity(
    level: CaLevel,
    years: u8,
    now: OffsetDateTime,
    issuer_not_after: Option<OffsetDateTime>,
) -> Result<CertValidity, String> {
    plan_validity(level, years, now, issuer_not_after).map_err(|e| capitalise(&e.to_string()))
}

/// The line under the validity spinner.
pub fn validity_line(result: &Result<CertValidity, String>) -> Line {
    match result {
        Ok(planned) => Line::new(
            Status::Ok,
            format!(
                "Valid from {} to {}.",
                format_utc(planned.not_before()),
                format_utc(planned.not_after())
            ),
        ),
        Err(reason) => Line::new(Status::Blocked, format!("{reason}.")),
    }
}

/// The operator's CRL address choice (FR-18 AC1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlChoice {
    /// Use the typed address.
    Address(String),
    /// Explicitly no address.
    NoAddress,
}

/// FR-18: the CRL location, or why the address is refused.
pub fn crl_location(choice: &CrlChoice) -> Result<CrlLocation, String> {
    match choice {
        CrlChoice::Address(text) => CrlUrl::parse(text.trim())
            .map(CrlLocation::Url)
            .map_err(|e| capitalise(&e.to_string())),
        CrlChoice::NoAddress => Ok(CrlLocation::ExplicitlyNone),
    }
}

/// The operator's name-constraints choice (FR-21 AC1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintsChoice {
    /// On (the default): the typed DNS names and optional IP ranges.
    On {
        /// Permitted DNS names, separated by commas, spaces or new lines.
        dns: String,
        /// Permitted IP ranges in CIDR form, same separators.
        ip: String,
    },
    /// Explicitly off.
    Off,
}

/// Splits a list typed in one field: commas, spaces and new lines separate entries.
pub fn split_list(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// FR-21 AC1, AC4: the choice, or why the entries block the action.
pub fn name_constraints(choice: &ConstraintsChoice) -> Result<NameConstraintsChoice, String> {
    match choice {
        ConstraintsChoice::On { dns, ip } => {
            NameConstraintsSpec::new(&split_list(dns), &split_list(ip))
                .map(NameConstraintsChoice::Constrained)
                .map_err(|e| capitalise(&e.to_string()))
        }
        ConstraintsChoice::Off => Ok(NameConstraintsChoice::ExplicitlyUnconstrained),
    }
}

/// Lines for the review step (FR-21 AC6).
pub fn name_constraints_lines(choice: &NameConstraintsChoice) -> Vec<String> {
    match choice {
        NameConstraintsChoice::Constrained(spec) => spec.summary_lines(),
        NameConstraintsChoice::ExplicitlyUnconstrained => {
            vec!["Name constraints: off (this sub-intermediate may issue for any name)".to_string()]
        }
    }
}

/// FR-06 AC2: the hint under a new PIN or PUK field from its length alone (the text
/// is not copied while typing).
pub fn credential_length_line(what: &str, chars: usize) -> Line {
    if chars == 0 {
        Line::new(
            Status::Info,
            format!(
                "The {what} must be 6 to 8 characters: letters, digits and symbols, no spaces."
            ),
        )
    } else if (6..=8).contains(&chars) {
        Line::new(Status::Ok, format!("The {what} has {chars} characters."))
    } else {
        Line::new(
            Status::Blocked,
            format!("The {what} has {chars} characters; it must have 6 to 8."),
        )
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::crypto::secret::SecretString;
    use keystone_core::token::{DeviceInfo, FirmwareVersion, NewPin, NewPuk, WipeConfirmation};
    use time::Duration;

    fn now() -> OffsetDateTime {
        keystone_core::build_info::build_date() + Duration::days(1)
    }

    #[test]
    fn fr02_ac4_name_feedback_gives_clear_reasons() {
        // Covers: FR-02 AC4
        assert_eq!(
            name("", "", "").expect_err("missing"),
            "The Common Name is required"
        );
        assert!(
            name("KEYSTONE TEST Root", "", "USA")
                .expect_err("country")
                .contains("exactly 2 letters")
        );
        assert!(
            name(" KEYSTONE TEST", "", "")
                .expect_err("space")
                .contains("must not start or end")
        );
        let ok = name("KEYSTONE TEST Root", "Logbie", "us").expect("valid");
        assert_eq!(ok.country(), Some("US"));
        assert_eq!(ok.organization(), Some("Logbie"));
    }

    #[test]
    fn fr10_ac1_ac3_validity_within_bounds_and_never_past_the_issuer() {
        // Covers: FR-10 AC1, FR-10 AC3
        assert_eq!(validity_bounds(CaLevel::Master), (1, 25, 20));
        assert_eq!(validity_bounds(CaLevel::MainIntermediate), (1, 15, 10));
        assert_eq!(validity_bounds(CaLevel::SubIntermediate), (1, 10, 5));
        assert!(validity(CaLevel::Master, 26, now(), None).is_err());
        let issuer_end = now() + Duration::days(365 * 3);
        let refused =
            validity(CaLevel::SubIntermediate, 5, now(), Some(issuer_end)).expect_err("outlives");
        assert!(refused.contains("after its issuer"), "{refused}");
        assert!(refused.contains("choose at most 2 years"), "{refused}");
        assert_eq!(validity_line(&Err(refused)).status, Status::Blocked);
        let planned = validity(CaLevel::SubIntermediate, 2, now(), Some(issuer_end));
        assert_eq!(validity_line(&planned).status, Status::Ok);
        assert_eq!(
            default_years(CaLevel::SubIntermediate, now(), Some(issuer_end)),
            2
        );
        assert_eq!(default_years(CaLevel::Master, now(), None), 20);
    }

    #[test]
    fn fr18_no_address_is_an_explicit_choice() {
        // Covers: FR-18 AC1
        assert!(
            crl_location(&CrlChoice::Address(String::new()))
                .expect_err("empty")
                .contains("choose \"no CRL address\" explicitly")
        );
        assert!(crl_location(&CrlChoice::Address("ftp://x".into())).is_err());
        assert_eq!(
            crl_location(&CrlChoice::NoAddress),
            Ok(CrlLocation::ExplicitlyNone)
        );
        assert!(matches!(
            crl_location(&CrlChoice::Address("http://crl.starnet/main.crl".into())),
            Ok(CrlLocation::Url(_))
        ));
        assert!(!keystone_core::profile::CRL_NONE_WARNING.is_empty());
    }

    #[test]
    fn fr21_ac1_ac4_constraints_on_by_default_invalid_entries_block() {
        // Covers: FR-21 AC1, FR-21 AC4, FR-21 AC6
        let on = |dns: &str, ip: &str| ConstraintsChoice::On {
            dns: dns.into(),
            ip: ip.into(),
        };
        assert!(
            name_constraints(&on("", ""))
                .expect_err("none")
                .contains("at least one")
        );
        assert!(
            name_constraints(&on("*.starnet", ""))
                .expect_err("wildcard")
                .contains("wildcards")
        );
        assert!(
            name_constraints(&on("starnet.", ""))
                .expect_err("dot")
                .contains("trailing dot")
        );
        assert!(
            name_constraints(&on("starnet", "10.0.0.1/8"))
                .expect_err("cidr")
                .contains("host bits")
        );
        let choice =
            name_constraints(&on("starnet, example.org\nlab", "10.0.0.0/8")).expect("valid");
        let lines = name_constraints_lines(&choice);
        assert!(lines.contains(&"permitted DNS: starnet".to_string()));
        assert!(lines.contains(&"permitted IP: 10.0.0.0/8".to_string()));
        assert_eq!(
            name_constraints(&ConstraintsChoice::Off),
            Ok(NameConstraintsChoice::ExplicitlyUnconstrained)
        );
        assert!(
            name_constraints_lines(&NameConstraintsChoice::ExplicitlyUnconstrained)[0]
                .contains("off")
        );
        assert_eq!(split_list(" a, b\nc ,,"), vec!["a", "b", "c"]);
    }

    #[test]
    fn fr06_ac2_pin_and_puk_entered_twice_six_to_eight_characters() {
        // Covers: FR-06 AC2, SEC-07
        assert_eq!(credential_length_line("PIN", 0).status, Status::Info);
        assert_eq!(credential_length_line("PIN", 5).status, Status::Blocked);
        assert_eq!(credential_length_line("PUK", 8).status, Status::Ok);
        assert_eq!(credential_length_line("PUK", 9).status, Status::Blocked);
        let s = |t: &str| SecretString::from_str_copy(t).expect("secret");
        assert!(NewPin::from_entries(&s("135790"), &s("135790")).is_ok());
        assert!(NewPin::from_entries(&s("135790"), &s("135791")).is_err());
        assert!(NewPuk::from_entries(&s("12345678"), &s("12345678")).is_err());
    }

    #[test]
    fn fr07_ac4_wipe_needs_the_exact_serial() {
        // Covers: FR-07 AC4
        let device = DeviceInfo {
            serial: 31_415_926,
            firmware: FirmwareVersion::new(5, 7, 4),
        };
        assert!(WipeConfirmation::new("31415926", &device).is_ok());
        assert!(WipeConfirmation::new(" 31415926", &device).is_err());
        assert!(WipeConfirmation::new("3141592", &device).is_err());
    }
}
