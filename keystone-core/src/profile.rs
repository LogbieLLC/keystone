//! The fixed certificate profile and operator-editable fields (PRD section 5,
//! FR-02, FR-07, FR-08, FR-10, FR-13 AC2, FR-18, FR-21).
//!
//! Everything structural is a constant here (FR-10 AC3): key size, signature
//! algorithm, key usage, basicConstraints and path lengths. The operator can change
//! only what has a type in this module: [`ValidatedName`] (name fields), the validity
//! in whole years within [`LevelProfile`] bounds and never past the issuer
//! ([`plan_validity`]), [`NameConstraintsChoice`] (FR-21) and [`CrlLocation`]
//! (FR-18). The certificate builder (`crate::cert`) takes only these types.
//!
//! Decisions on points the PRD leaves open (most conservative reading):
//! - Name fields must not start or end with whitespace and must not contain control
//!   characters; they are rejected, never trimmed. Lengths follow the RFC 5280 upper
//!   bounds in characters (ub-common-name 64, ub-organization-name 64).
//! - The Country is two ASCII letters and is stored in upper case (ISO 3166-1
//!   alpha-2), so `us` becomes `US`. An empty optional field means "not set".
//! - Validity is chosen in whole years. A child that would outlive its issuer is an
//!   error ([`ProfileError::OutlivesIssuer`]); the end date is never shortened
//!   silently (FR-10 AC1). A year added to 29 February ends on 28 February.
//! - Permitted DNS names are stored in lower case. A name whose last label is all
//!   digits is refused, because it looks like an IP address.
//! - When IP ranges are entered for only one address family, the other family is
//!   still excluded entirely (0.0.0.0/0 or ::/0), which keeps FR-21 AC3's
//!   "excluded unless entered" true per family.
//! - CRL addresses must be `http://` or `https://` URLs of printable ASCII.
#![forbid(unsafe_code)]

use core::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;

use time::{Date, Duration, Month, OffsetDateTime, UtcOffset};

use crate::model::{CaLevel, NameFields};

/// Errors from this module. Every message is written for the operator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// FR-02 AC4.
    #[error("the Common Name is required")]
    CommonNameMissing,
    /// A name field exceeds the RFC 5280 upper bound.
    #[error("the {field} is {actual} characters long; at most {max} are allowed")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Upper bound in characters.
        max: usize,
        /// Actual length in characters.
        actual: usize,
    },
    /// A name field starts or ends with whitespace.
    #[error("the {field} must not start or end with a space")]
    FieldWhitespace {
        /// Field name.
        field: &'static str,
    },
    /// A name field contains a control character.
    #[error("the {field} contains a control character")]
    FieldControlCharacter {
        /// Field name.
        field: &'static str,
    },
    /// FR-02 AC4.
    #[error("the Country must be exactly 2 letters (for example US), not {0:?}")]
    CountryInvalid(String),
    /// FR-10 AC3 bounds.
    #[error("a {level} certificate can be valid for {min} to {max} years, not {years}")]
    ValidityOutOfBounds {
        /// Level display name.
        level: &'static str,
        /// Requested years.
        years: u8,
        /// Lower bound.
        min: u8,
        /// Upper bound.
        max: u8,
    },
    /// FR-10 AC1: the child would end after its issuer.
    #[error(
        "the certificate would end on {not_after}, after its issuer ends on {issuer_not_after}; choose at most {max_years} years"
    )]
    OutlivesIssuer {
        /// Requested end (RFC 3339).
        not_after: String,
        /// Issuer's end (RFC 3339).
        issuer_not_after: String,
        /// The largest whole number of years that fits (0 = none).
        max_years: u8,
    },
    /// An issuer was given for the master, or none for an intermediate.
    #[error("{0}")]
    IssuerMismatch(&'static str),
    /// A date is outside the range certificates can encode.
    #[error("date out of range")]
    DateOutOfRange,
    /// FR-18.
    #[error("invalid CRL address {url:?}: {reason}")]
    CrlUrlInvalid {
        /// The text entered.
        url: String,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// FR-21 AC4.
    #[error("invalid permitted DNS name {name:?}: {reason}")]
    DnsNameInvalid {
        /// The text entered.
        name: String,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// FR-21 AC4.
    #[error("invalid IP range {range:?}: {reason}")]
    IpRangeInvalid {
        /// The text entered.
        range: String,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// FR-21 AC1: at least one permitted DNS name.
    #[error("enter at least one permitted DNS name")]
    NoPermittedDnsNames,
    /// The same entry twice.
    #[error("{0:?} is listed twice")]
    DuplicateEntry(String),
    /// Name constraints were given for a level that never carries them.
    #[error("only sub-intermediates carry name constraints")]
    NameConstraintsNotAllowed,
    /// A sub-intermediate needs an explicit name-constraints choice.
    #[error(
        "a sub-intermediate needs permitted DNS names or an explicit choice to turn name constraints off"
    )]
    NameConstraintsRequired,
    /// Only the master and the main intermediate sign CRLs in Keystone.
    #[error("a {0} does not sign CRLs in Keystone")]
    NoCrlForLevel(&'static str),
}

/// How long a CRL is valid by default (FR-13 AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlInterval {
    /// Whole calendar years.
    Years(u8),
    /// Days.
    Days(u16),
}

/// The fixed profile of one CA level (PRD section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelProfile {
    /// The level.
    pub level: CaLevel,
    /// RSA modulus size.
    pub key_bits: u32,
    /// Default validity in years.
    pub default_validity_years: u8,
    /// Shortest validity the operator can choose.
    pub min_validity_years: u8,
    /// Longest validity the operator can choose.
    pub max_validity_years: u8,
    /// basicConstraints pathLenConstraint (`None` = no limit).
    pub path_len_constraint: Option<u8>,
    /// Default CRL lifetime for CRLs this level signs (`None` = signs no CRL).
    pub crl_next_update: Option<CrlInterval>,
    /// Whether certificates of this level carry name constraints (FR-21).
    pub name_constraints: bool,
}

/// Master (root): RSA 8,192, 20 years (1 to 25), no path length, CRL 1 year.
pub const MASTER: LevelProfile = LevelProfile {
    level: CaLevel::Master,
    key_bits: 8192,
    default_validity_years: 20,
    min_validity_years: 1,
    max_validity_years: 25,
    path_len_constraint: None,
    crl_next_update: Some(CrlInterval::Years(1)),
    name_constraints: false,
};

/// Main intermediate (YubiKey): RSA 4,096, 10 years (1 to 15), path length 1, CRL 90 days.
pub const MAIN_INTERMEDIATE: LevelProfile = LevelProfile {
    level: CaLevel::MainIntermediate,
    key_bits: 4096,
    default_validity_years: 10,
    min_validity_years: 1,
    max_validity_years: 15,
    path_len_constraint: Some(1),
    crl_next_update: Some(CrlInterval::Days(90)),
    name_constraints: false,
};

/// Sub-intermediate: RSA 4,096, 5 years (1 to 10), path length 0, name constraints.
pub const SUB_INTERMEDIATE: LevelProfile = LevelProfile {
    level: CaLevel::SubIntermediate,
    key_bits: 4096,
    default_validity_years: 5,
    min_validity_years: 1,
    max_validity_years: 10,
    path_len_constraint: Some(0),
    crl_next_update: None,
    name_constraints: true,
};

/// The fixed profile of `level`.
pub const fn level_profile(level: CaLevel) -> &'static LevelProfile {
    match level {
        CaLevel::Master => &MASTER,
        CaLevel::MainIntermediate => &MAIN_INTERMEDIATE,
        CaLevel::SubIntermediate => &SUB_INTERMEDIATE,
    }
}

/// sha384WithRSAEncryption (RFC 4055), the only signature algorithm (PKCS#1 v1.5).
pub const SIGNATURE_ALGORITHM_OID: &str = "1.2.840.113549.1.1.12";
/// The only RSA public exponent.
pub const PUBLIC_EXPONENT: u64 = 65_537;
/// Days before a CRL's nextUpdate when the GUI starts warning (FR-13 AC3).
pub const CRL_WARNING_DAYS: i64 = 30;
/// RFC 5280 ub-common-name, in characters.
pub const MAX_COMMON_NAME_CHARS: usize = 64;
/// RFC 5280 ub-organization-name, in characters.
pub const MAX_ORGANIZATION_CHARS: usize = 64;
/// Longest CRL address accepted.
pub const MAX_CRL_URL_LEN: usize = 1024;
/// RFC 1035 limit for a DNS name in text form without the trailing dot.
pub const MAX_DNS_NAME_LEN: usize = 253;

// ---------------------------------------------------------------------------
// Names (FR-02 AC4)
// ---------------------------------------------------------------------------

/// Name fields that passed validation (FR-02 AC4). The builder encodes them as
/// C (PrintableString), O (UTF8String), CN (UTF8String), in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedName {
    common_name: String,
    organization: Option<String>,
    country: Option<String>,
}

fn check_text(field: &'static str, value: &str, max: usize) -> Result<(), ProfileError> {
    if value.trim() != value {
        return Err(ProfileError::FieldWhitespace { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ProfileError::FieldControlCharacter { field });
    }
    let chars = value.chars().count();
    if chars > max {
        return Err(ProfileError::FieldTooLong {
            field,
            max,
            actual: chars,
        });
    }
    Ok(())
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|text| !text.is_empty())
}

impl ValidatedName {
    /// Validates the operator's name fields.
    pub fn new(fields: &NameFields) -> Result<Self, ProfileError> {
        if fields.common_name.is_empty() {
            return Err(ProfileError::CommonNameMissing);
        }
        check_text("Common Name", &fields.common_name, MAX_COMMON_NAME_CHARS)?;
        let organization = match non_empty(&fields.organization) {
            Some(org) => {
                check_text("Organization", org, MAX_ORGANIZATION_CHARS)?;
                Some(org.to_owned())
            }
            None => None,
        };
        let country = match non_empty(&fields.country) {
            Some(country) => {
                if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_alphabetic()) {
                    return Err(ProfileError::CountryInvalid(country.to_owned()));
                }
                Some(country.to_ascii_uppercase())
            }
            None => None,
        };
        Ok(ValidatedName {
            common_name: fields.common_name.clone(),
            organization,
            country,
        })
    }

    /// Common Name.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// Organization, if set.
    pub fn organization(&self) -> Option<&str> {
        self.organization.as_deref()
    }

    /// Country (two upper-case letters), if set.
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// The fields as stored (Country in upper case).
    pub fn to_fields(&self) -> NameFields {
        NameFields {
            common_name: self.common_name.clone(),
            organization: self.organization.clone(),
            country: self.country.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Validity (FR-10 AC1, AC3)
// ---------------------------------------------------------------------------

/// A planned validity period (UTC, whole seconds) for one CA level. Only
/// [`plan_validity`] creates it, so its bounds were checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertValidity {
    level: CaLevel,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl CertValidity {
    /// The level this validity was planned for.
    pub fn level(&self) -> CaLevel {
        self.level
    }

    /// Start of validity.
    pub fn not_before(&self) -> OffsetDateTime {
        self.not_before
    }

    /// End of validity.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }
}

/// `value` in UTC with sub-second precision removed (certificate times are whole
/// seconds).
pub fn to_whole_seconds_utc(value: OffsetDateTime) -> Result<OffsetDateTime, ProfileError> {
    OffsetDateTime::from_unix_timestamp(value.unix_timestamp())
        .map(|v| v.to_offset(UtcOffset::UTC))
        .map_err(|_| ProfileError::DateOutOfRange)
}

/// Adds whole calendar years; 29 February becomes 28 February in a common year.
pub fn add_years(start: OffsetDateTime, years: u8) -> Result<OffsetDateTime, ProfileError> {
    let year = start.year() + i32::from(years);
    let month = start.month();
    let day = start.day().min(days_in_month(year, month));
    let date =
        Date::from_calendar_date(year, month, day).map_err(|_| ProfileError::DateOutOfRange)?;
    Ok(start.replace_date(date))
}

fn days_in_month(year: i32, month: Month) -> u8 {
    time::util::days_in_month(month, year)
}

pub(crate) fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| value.to_string())
}

/// The longest whole number of years (within the level's bounds) that a certificate
/// starting at `now` can have without ending after `issuer_not_after`; 0 when even
/// the minimum does not fit. For the master (no issuer) this is the level maximum.
pub fn max_validity_years(
    level: CaLevel,
    now: OffsetDateTime,
    issuer_not_after: Option<OffsetDateTime>,
) -> u8 {
    let profile = level_profile(level);
    let Ok(start) = to_whole_seconds_utc(now) else {
        return 0;
    };
    let Some(limit) = issuer_not_after else {
        return profile.max_validity_years;
    };
    (profile.min_validity_years..=profile.max_validity_years)
        .rev()
        .find(|years| add_years(start, *years).is_ok_and(|end| end <= limit))
        .unwrap_or(0)
}

/// Plans the validity of a new certificate of `level`: from `now` (whole seconds,
/// UTC) for `years` years (FR-10 AC3), never ending after `issuer_not_after`
/// (FR-10 AC1). `issuer_not_after` is `None` exactly for the self-signed master.
pub fn plan_validity(
    level: CaLevel,
    years: u8,
    now: OffsetDateTime,
    issuer_not_after: Option<OffsetDateTime>,
) -> Result<CertValidity, ProfileError> {
    let profile = level_profile(level);
    match (level.issuer_level(), issuer_not_after) {
        (None, Some(_)) => {
            return Err(ProfileError::IssuerMismatch(
                "the master is self-signed and has no issuer",
            ));
        }
        (Some(_), None) => {
            return Err(ProfileError::IssuerMismatch(
                "an intermediate needs its issuer's end date",
            ));
        }
        _ => {}
    }
    if !(profile.min_validity_years..=profile.max_validity_years).contains(&years) {
        return Err(ProfileError::ValidityOutOfBounds {
            level: level.display_name(),
            years,
            min: profile.min_validity_years,
            max: profile.max_validity_years,
        });
    }
    let not_before = to_whole_seconds_utc(now)?;
    let not_after = add_years(not_before, years)?;
    if let Some(limit) = issuer_not_after
        && not_after > limit
    {
        return Err(ProfileError::OutlivesIssuer {
            not_after: rfc3339(not_after),
            issuer_not_after: rfc3339(limit),
            max_years: max_validity_years(level, now, Some(limit)),
        });
    }
    Ok(CertValidity {
        level,
        not_before,
        not_after,
    })
}

/// Default nextUpdate for a CRL signed by `issuer_level` at `this_update`
/// (FR-13 AC2: 1 year for the master, 90 days for the main intermediate).
pub fn default_crl_next_update(
    issuer_level: CaLevel,
    this_update: OffsetDateTime,
) -> Result<OffsetDateTime, ProfileError> {
    let start = to_whole_seconds_utc(this_update)?;
    match level_profile(issuer_level).crl_next_update {
        Some(CrlInterval::Years(years)) => add_years(start, years),
        Some(CrlInterval::Days(days)) => start
            .checked_add(Duration::days(i64::from(days)))
            .ok_or(ProfileError::DateOutOfRange),
        None => Err(ProfileError::NoCrlForLevel(issuer_level.display_name())),
    }
}

// ---------------------------------------------------------------------------
// CRL location (FR-18)
// ---------------------------------------------------------------------------

/// A validated CRL Distribution Point URL. Keystone only writes this text into
/// certificates; it never contacts it (FR-18 AC2, HR-1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CrlUrl(String);

impl CrlUrl {
    /// Validates an `http://` or `https://` URL of printable ASCII with a host.
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        let invalid = |reason| ProfileError::CrlUrlInvalid {
            url: text.to_owned(),
            reason,
        };
        if text.is_empty() {
            return Err(invalid(
                "the address is empty; choose \"no CRL address\" explicitly instead",
            ));
        }
        if text.len() > MAX_CRL_URL_LEN {
            return Err(invalid("the address is too long"));
        }
        if !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(invalid("only printable ASCII without spaces is allowed"));
        }
        let rest = text
            .strip_prefix("http://")
            .or_else(|| text.strip_prefix("https://"))
            .ok_or_else(|| invalid("the address must start with http:// or https://"))?;
        let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..host_end];
        if authority.is_empty() || authority.contains('@') {
            return Err(invalid("the address needs a host name"));
        }
        if rest[host_end..].contains('#') {
            return Err(invalid("a CRL address cannot contain a fragment (#)"));
        }
        Ok(CrlUrl(text.to_owned()))
    }

    /// The URL text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CrlUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where an issuer's CRL will be hosted (FR-18 AC1). Leaving it empty is a
/// separate, explicit choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlLocation {
    /// The issuer's CRL is hosted at this address; it goes into every child.
    Url(CrlUrl),
    /// The operator explicitly chose to write no CRL address; the GUI shows
    /// [`CRL_NONE_WARNING`].
    ExplicitlyNone,
}

/// Warning shown when the operator chooses no CRL address (FR-18 AC1).
pub const CRL_NONE_WARNING: &str = "Without a CRL address, relying systems cannot find out \
that a certificate signed by this issuer was revoked. Revocation of those certificates could \
then not be checked.";

// ---------------------------------------------------------------------------
// Name constraints (FR-21)
// ---------------------------------------------------------------------------

/// A validated permitted DNS name (lower case, LDH labels, no wildcard, no
/// trailing dot). It covers the name itself and every name under it (FR-21 AC1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsConstraint(String);

impl DnsConstraint {
    /// Validates one permitted DNS name (FR-21 AC4).
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        let invalid = |reason| ProfileError::DnsNameInvalid {
            name: text.to_owned(),
            reason,
        };
        if text.is_empty() {
            return Err(invalid("the name is empty"));
        }
        if text.contains('*') {
            return Err(invalid(
                "wildcards are not allowed; enter the name itself (it covers every name under it)",
            ));
        }
        if text.ends_with('.') {
            return Err(invalid("remove the trailing dot"));
        }
        if text.starts_with('.') {
            return Err(invalid("remove the leading dot"));
        }
        if text.len() > MAX_DNS_NAME_LEN {
            return Err(invalid("the name is longer than 253 characters"));
        }
        if !text.is_ascii() {
            return Err(invalid(
                "use the ASCII form (xn--...) of internationalised names",
            ));
        }
        let lower = text.to_ascii_lowercase();
        for label in lower.split('.') {
            if label.is_empty() {
                return Err(invalid("the name has an empty label (two dots in a row)"));
            }
            if label.len() > 63 {
                return Err(invalid("a label is longer than 63 characters"));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(invalid(
                    "only letters, digits, hyphens and dots are allowed",
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(invalid("a label cannot start or end with a hyphen"));
            }
        }
        if lower
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid(
                "this looks like an IP address; enter IP ranges as IP ranges",
            ));
        }
        Ok(DnsConstraint(lower))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated IP range in CIDR form (FR-21 AC3, AC4). Host bits must be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpRange {
    /// IPv4 network and prefix length.
    V4(Ipv4Addr, u8),
    /// IPv6 network and prefix length.
    V6(Ipv6Addr, u8),
}

impl IpRange {
    /// Parses `address/prefix` (FR-21 AC4).
    ///
    /// `core::net` is used only for its address parsers; it holds no sockets.
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        let invalid = |reason| ProfileError::IpRangeInvalid {
            range: text.to_owned(),
            reason,
        };
        let (address, prefix) = text
            .split_once('/')
            .ok_or_else(|| invalid("use CIDR form, for example 10.0.0.0/8"))?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) || prefix.len() > 3 {
            return Err(invalid("the prefix length must be a number"));
        }
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| invalid("the prefix length must be a number"))?;
        if let Ok(v4) = address.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return Err(invalid("an IPv4 prefix length is at most 32"));
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            if u32::from(v4) & !mask != 0 {
                return Err(invalid(
                    "the address has bits set after the prefix (host bits); use the network address",
                ));
            }
            return Ok(IpRange::V4(v4, prefix));
        }
        if let Ok(v6) = address.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return Err(invalid("an IPv6 prefix length is at most 128"));
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            if u128::from(v6) & !mask != 0 {
                return Err(invalid(
                    "the address has bits set after the prefix (host bits); use the network address",
                ));
            }
            return Ok(IpRange::V6(v6, prefix));
        }
        Err(invalid("not an IPv4 or IPv6 address"))
    }

    /// The iPAddress name-constraint encoding: address followed by mask
    /// (8 bytes for IPv4, 32 for IPv6; RFC 5280 section 4.2.1.10).
    pub fn constraint_bytes(&self) -> Vec<u8> {
        match *self {
            IpRange::V4(address, prefix) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                let mut out = address.octets().to_vec();
                out.extend_from_slice(&mask.to_be_bytes());
                out
            }
            IpRange::V6(address, prefix) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(prefix))
                };
                let mut out = address.octets().to_vec();
                out.extend_from_slice(&mask.to_be_bytes());
                out
            }
        }
    }

    /// True for an IPv4 range.
    pub fn is_v4(&self) -> bool {
        matches!(self, IpRange::V4(..))
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpRange::V4(address, prefix) => write!(f, "{address}/{prefix}"),
            IpRange::V6(address, prefix) => write!(f, "{address}/{prefix}"),
        }
    }
}

/// The only domain permitted for email (rfc822Name) and URI names in a
/// sub-intermediate's name constraints (FR-21 AC3, ADR 0001).
///
/// `.invalid` is reserved by RFC 2606 and RFC 6761 and can never be a real host or
/// mail domain, so permitting only names under it blocks every real email address
/// and URI. The leading dot means "any name under this domain" for both forms
/// (RFC 5280 section 4.2.1.10).
pub const RESERVED_CONSTRAINT_DOMAIN: &str = ".keystone.invalid";

/// Validated name constraints for a sub-intermediate (FR-21).
///
/// Encoded as a critical extension with (ADR 0001):
/// - permittedSubtrees: every DNS name and every IP range entered, then an
///   rfc822Name and a uniformResourceIdentifier of [`RESERVED_CONSTRAINT_DOMAIN`];
/// - excludedSubtrees: 0.0.0.0/0 when no IPv4 range was entered and ::/0 when no
///   IPv6 range was entered.
///
/// Why email and URI names are blocked through permittedSubtrees: a zero-length
/// rfc822Name or URI in excludedSubtrees is read as "all names" by Go and NSS but
/// compared literally by OpenSSL, which then excludes nothing. Permitting only the
/// reserved `.invalid` domain is enforced the same way by OpenSSL and Go: a leaf with
/// any real email address or URI fails verification with both (tested in
/// `tests/interop/name_constraints.rs`). Permitting a name form does not restrict
/// the other forms, so DNS names and IP addresses keep their own rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameConstraintsSpec {
    permitted_dns: Vec<DnsConstraint>,
    permitted_ip: Vec<IpRange>,
}

impl NameConstraintsSpec {
    /// Validates the operator's entries (FR-21 AC4). At least one DNS name is
    /// required (FR-21 AC1); IP ranges are optional (FR-21 AC3).
    pub fn new<D: AsRef<str>, I: AsRef<str>>(dns: &[D], ip: &[I]) -> Result<Self, ProfileError> {
        if dns.is_empty() {
            return Err(ProfileError::NoPermittedDnsNames);
        }
        let mut permitted_dns = Vec::with_capacity(dns.len());
        for entry in dns {
            let name = DnsConstraint::parse(entry.as_ref())?;
            if permitted_dns.contains(&name) {
                return Err(ProfileError::DuplicateEntry(name.0));
            }
            permitted_dns.push(name);
        }
        let mut permitted_ip = Vec::with_capacity(ip.len());
        for entry in ip {
            let range = IpRange::parse(entry.as_ref())?;
            if permitted_ip.contains(&range) {
                return Err(ProfileError::DuplicateEntry(range.to_string()));
            }
            permitted_ip.push(range);
        }
        Ok(NameConstraintsSpec {
            permitted_dns,
            permitted_ip,
        })
    }

    /// Permitted DNS names, in entry order.
    pub fn permitted_dns(&self) -> &[DnsConstraint] {
        &self.permitted_dns
    }

    /// Permitted IP ranges, in entry order.
    pub fn permitted_ip(&self) -> &[IpRange] {
        &self.permitted_ip
    }

    /// True when every IPv4 address is excluded (no IPv4 range entered).
    pub fn excludes_all_ipv4(&self) -> bool {
        !self.permitted_ip.iter().any(IpRange::is_v4)
    }

    /// True when every IPv6 address is excluded (no IPv6 range entered).
    pub fn excludes_all_ipv6(&self) -> bool {
        self.permitted_ip.iter().all(IpRange::is_v4)
    }

    /// One line per permitted entry and exclusion, for the review step, the
    /// issuance record and the audit log (FR-21 AC6). The lines state exactly what
    /// the extension contains (ADR 0001).
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .permitted_dns
            .iter()
            .map(|name| format!("permitted DNS: {name}"))
            .collect();
        lines.extend(
            self.permitted_ip
                .iter()
                .map(|range| format!("permitted IP: {range}")),
        );
        if self.excludes_all_ipv4() {
            lines.push("excluded IP: 0.0.0.0/0 (all IPv4)".to_owned());
        }
        if self.excludes_all_ipv6() {
            lines.push("excluded IP: ::/0 (all IPv6)".to_owned());
        }
        lines.push(format!(
            "email addresses: none allowed (only the reserved {RESERVED_CONSTRAINT_DOMAIN} domain is permitted)"
        ));
        lines.push(format!(
            "URIs: none allowed (only the reserved {RESERVED_CONSTRAINT_DOMAIN} domain is permitted)"
        ));
        lines
    }
}

/// The operator's name-constraints choice for a sub-intermediate (FR-21 AC1).
/// Turning constraints off is its own variant, never a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameConstraintsChoice {
    /// Constraints on (the default in the GUI).
    Constrained(NameConstraintsSpec),
    /// The operator explicitly turned constraints off after seeing
    /// [`NAME_CONSTRAINTS_OFF_WARNING`].
    ExplicitlyUnconstrained,
}

/// Warning shown when name constraints are turned off (FR-21 AC1).
pub const NAME_CONSTRAINTS_OFF_WARNING: &str = "Without name constraints this sub-intermediate \
could issue certificates for any name. If its key is stolen, the thief could impersonate any \
service that trusts your master.";

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    }

    fn fields(cn: &str, org: Option<&str>, country: Option<&str>) -> NameFields {
        NameFields {
            common_name: cn.to_owned(),
            organization: org.map(str::to_owned),
            country: country.map(str::to_owned),
        }
    }

    #[test]
    fn fr10_ac3_profile_table_matches_prd_section_5() {
        // Covers: FR-10 AC3, FR-02 AC1, FR-07 AC1, FR-08 AC1, FR-13 AC2, SEC-14
        assert_eq!(MASTER.key_bits, 8192);
        assert_eq!(MAIN_INTERMEDIATE.key_bits, 4096);
        assert_eq!(SUB_INTERMEDIATE.key_bits, 4096);
        assert_eq!(
            [MASTER, MAIN_INTERMEDIATE, SUB_INTERMEDIATE].map(|p| p.default_validity_years),
            [20, 10, 5]
        );
        assert_eq!(
            [MASTER, MAIN_INTERMEDIATE, SUB_INTERMEDIATE]
                .map(|p| (p.min_validity_years, p.max_validity_years)),
            [(1, 25), (1, 15), (1, 10)]
        );
        assert_eq!(
            [MASTER, MAIN_INTERMEDIATE, SUB_INTERMEDIATE].map(|p| p.path_len_constraint),
            [None, Some(1), Some(0)]
        );
        assert_eq!(MASTER.crl_next_update, Some(CrlInterval::Years(1)));
        assert_eq!(
            MAIN_INTERMEDIATE.crl_next_update,
            Some(CrlInterval::Days(90))
        );
        assert_eq!(SUB_INTERMEDIATE.crl_next_update, None);
        assert_eq!(
            [MASTER, MAIN_INTERMEDIATE, SUB_INTERMEDIATE].map(|p| p.name_constraints),
            [false, false, true]
        );
        assert_eq!(SIGNATURE_ALGORITHM_OID, "1.2.840.113549.1.1.12");
        for level in [
            CaLevel::Master,
            CaLevel::MainIntermediate,
            CaLevel::SubIntermediate,
        ] {
            assert_eq!(level_profile(level).level, level);
        }
    }

    #[test]
    fn fr02_ac4_common_name_required_org_and_country_optional() {
        // Covers: FR-02 AC4
        assert_eq!(
            ValidatedName::new(&fields("", None, None)),
            Err(ProfileError::CommonNameMissing)
        );
        let only_cn = ValidatedName::new(&fields("KEYSTONE TEST Root", None, None)).unwrap();
        assert_eq!(only_cn.organization(), None);
        assert_eq!(only_cn.country(), None);
        let all =
            ValidatedName::new(&fields("KEYSTONE TEST Root", Some("Org"), Some("us"))).unwrap();
        assert_eq!(all.country(), Some("US"));
        assert_eq!(all.organization(), Some("Org"));
        let empty_optional = ValidatedName::new(&fields("CN", Some(""), Some(""))).unwrap();
        assert_eq!(empty_optional.organization(), None);
        assert_eq!(empty_optional.country(), None);
    }

    #[test]
    fn fr02_ac4_country_must_be_two_letters() {
        // Covers: FR-02 AC4
        for bad in ["U", "USA", "U1", "1U", "Ü1", " U", "ÜS"] {
            assert!(
                matches!(
                    ValidatedName::new(&fields("CN", None, Some(bad))),
                    Err(ProfileError::CountryInvalid(_))
                ),
                "{bad:?}"
            );
        }
        assert!(ValidatedName::new(&fields("CN", None, Some("DE"))).is_ok());
    }

    #[test]
    fn fr02_ac4_rfc5280_upper_bounds_and_text_rules() {
        // Covers: FR-02 AC4
        let cn64 = "é".repeat(64);
        assert!(ValidatedName::new(&fields(&cn64, None, None)).is_ok());
        let cn65 = "a".repeat(65);
        assert!(matches!(
            ValidatedName::new(&fields(&cn65, None, None)),
            Err(ProfileError::FieldTooLong {
                max: 64,
                actual: 65,
                ..
            })
        ));
        let org65 = "o".repeat(65);
        assert!(matches!(
            ValidatedName::new(&fields("CN", Some(&org65), None)),
            Err(ProfileError::FieldTooLong {
                field: "Organization",
                ..
            })
        ));
        assert!(matches!(
            ValidatedName::new(&fields(" CN", None, None)),
            Err(ProfileError::FieldWhitespace { .. })
        ));
        assert!(matches!(
            ValidatedName::new(&fields("C\nN", None, None)),
            Err(ProfileError::FieldControlCharacter { .. })
        ));
    }

    #[test]
    fn fr10_ac1_validity_never_outlives_issuer() {
        // Covers: FR-10 AC1, FR-10 AC3
        let now = at("2026-11-01T12:00:00.75Z");
        let master = plan_validity(CaLevel::Master, 20, now, None).unwrap();
        assert_eq!(master.not_before(), at("2026-11-01T12:00:00Z"));
        assert_eq!(master.not_after(), at("2046-11-01T12:00:00Z"));
        let issuer_end = at("2030-01-01T00:00:00Z");
        let error =
            plan_validity(CaLevel::MainIntermediate, 10, now, Some(issuer_end)).unwrap_err();
        assert!(
            matches!(error, ProfileError::OutlivesIssuer { max_years: 3, .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("choose at most 3 years"));
        let ok = plan_validity(CaLevel::MainIntermediate, 3, now, Some(issuer_end)).unwrap();
        assert!(ok.not_after() <= issuer_end);
        // Exactly equal end dates are allowed.
        let exact = plan_validity(
            CaLevel::SubIntermediate,
            5,
            now,
            Some(at("2031-11-01T12:00:00Z")),
        );
        assert!(exact.is_ok());
        let expired = plan_validity(
            CaLevel::SubIntermediate,
            1,
            now,
            Some(at("2026-12-01T00:00:00Z")),
        );
        assert!(matches!(
            expired,
            Err(ProfileError::OutlivesIssuer { max_years: 0, .. })
        ));
    }

    #[test]
    fn fr10_ac3_validity_bounds_per_level() {
        // Covers: FR-10 AC3
        let now = at("2026-11-01T00:00:00Z");
        let far = Some(at("2099-01-01T00:00:00Z"));
        assert!(plan_validity(CaLevel::Master, 0, now, None).is_err());
        assert!(plan_validity(CaLevel::Master, 25, now, None).is_ok());
        assert!(plan_validity(CaLevel::Master, 26, now, None).is_err());
        assert!(plan_validity(CaLevel::MainIntermediate, 15, now, far).is_ok());
        assert!(plan_validity(CaLevel::MainIntermediate, 16, now, far).is_err());
        assert!(plan_validity(CaLevel::SubIntermediate, 10, now, far).is_ok());
        assert!(plan_validity(CaLevel::SubIntermediate, 11, now, far).is_err());
        assert!(plan_validity(CaLevel::Master, 20, now, far).is_err());
        assert!(plan_validity(CaLevel::SubIntermediate, 5, now, None).is_err());
        assert_eq!(max_validity_years(CaLevel::Master, now, None), 25);
        assert_eq!(max_validity_years(CaLevel::SubIntermediate, now, far), 10);
    }

    #[test]
    fn leap_day_plus_one_year_is_feb_28() {
        let start = at("2028-02-29T10:00:00Z");
        assert_eq!(add_years(start, 1).unwrap(), at("2029-02-28T10:00:00Z"));
        assert_eq!(add_years(start, 4).unwrap(), at("2032-02-29T10:00:00Z"));
    }

    #[test]
    fn fr13_ac2_default_crl_next_update() {
        // Covers: FR-13 AC2
        let now = at("2026-11-01T00:00:00Z");
        assert_eq!(
            default_crl_next_update(CaLevel::Master, now).unwrap(),
            at("2027-11-01T00:00:00Z")
        );
        assert_eq!(
            default_crl_next_update(CaLevel::MainIntermediate, now).unwrap(),
            at("2027-01-30T00:00:00Z")
        );
        assert!(default_crl_next_update(CaLevel::SubIntermediate, now).is_err());
    }

    #[test]
    fn fr18_ac1_crl_url_validation() {
        // Covers: FR-18 AC1
        assert!(CrlUrl::parse("http://pki.starnet/crl/master.crl").is_ok());
        assert!(CrlUrl::parse("https://pki.starnet:8443/crl/main.crl").is_ok());
        for bad in [
            "",
            "pki.starnet/crl",
            "ftp://pki.starnet/x.crl",
            "http://",
            "http:///path",
            "http://pki starnet/x.crl",
            "http://pki.starnet/x.crl#frag",
            "http://user@pki.starnet/x.crl",
            "http://pkí.starnet/x.crl",
        ] {
            assert!(CrlUrl::parse(bad).is_err(), "{bad:?}");
        }
        assert!(CRL_NONE_WARNING.contains("could"));
    }

    #[test]
    fn fr21_ac4_dns_names_are_validated() {
        // Covers: FR-21 AC4
        for good in [
            "starnet",
            "pki.starnet",
            "Example.COM",
            "a-b.example",
            "xn--bcher-kva.example",
        ] {
            assert!(DnsConstraint::parse(good).is_ok(), "{good:?}");
        }
        assert_eq!(
            DnsConstraint::parse("Example.COM").unwrap().as_str(),
            "example.com"
        );
        for bad in [
            "",
            "*.starnet",
            "starnet.",
            ".starnet",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b.example",
            "bücher.example",
            "10.0.0.1",
            "host.123",
            "a b",
        ] {
            assert!(
                matches!(
                    DnsConstraint::parse(bad),
                    Err(ProfileError::DnsNameInvalid { .. })
                ),
                "{bad:?}"
            );
        }
        let long_label = format!("{}.example", "a".repeat(64));
        assert!(DnsConstraint::parse(&long_label).is_err());
        let long_name = vec!["abcdefghi"; 26].join(".");
        assert!(long_name.len() > 253);
        assert!(DnsConstraint::parse(&long_name).is_err());
    }

    #[test]
    fn fr21_ac4_ip_ranges_are_validated() {
        // Covers: FR-21 AC4, FR-21 AC3
        let v4 = IpRange::parse("10.0.0.0/8").unwrap();
        assert_eq!(v4.constraint_bytes(), vec![10, 0, 0, 0, 255, 0, 0, 0]);
        let v6 = IpRange::parse("fd00::/8").unwrap();
        let bytes = v6.constraint_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0xfd);
        assert_eq!(bytes[16], 0xff);
        assert_eq!(bytes[17], 0x00);
        assert_eq!(
            IpRange::parse("192.0.2.7/32").unwrap().to_string(),
            "192.0.2.7/32"
        );
        assert_eq!(
            IpRange::parse("0.0.0.0/0").unwrap().constraint_bytes(),
            vec![0; 8]
        );
        for bad in [
            "10.0.0.0",
            "10.0.0.1/8",
            "10.0.0.0/33",
            "fd00::1/8",
            "fd00::/129",
            "10.0.0/8",
            "host/8",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/8/9",
        ] {
            assert!(
                matches!(
                    IpRange::parse(bad),
                    Err(ProfileError::IpRangeInvalid { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn fr21_ac1_ac3_constraints_spec_rules() {
        // Covers: FR-21 AC1, FR-21 AC3, FR-21 AC6
        let empty: [&str; 0] = [];
        assert_eq!(
            NameConstraintsSpec::new(&empty, &empty),
            Err(ProfileError::NoPermittedDnsNames)
        );
        assert!(matches!(
            NameConstraintsSpec::new(&["starnet", "STARNET"], &empty),
            Err(ProfileError::DuplicateEntry(_))
        ));
        let dns_only = NameConstraintsSpec::new(&["starnet"], &empty).unwrap();
        assert!(dns_only.excludes_all_ipv4() && dns_only.excludes_all_ipv6());
        let lines = dns_only.summary_lines();
        assert!(lines.contains(&"permitted DNS: starnet".to_owned()));
        assert!(lines.iter().any(|l| l.contains("0.0.0.0/0")));
        assert!(lines.iter().any(|l| l.contains("::/0")));
        assert!(lines.iter().any(|l| l.contains("email")));
        assert!(lines.iter().any(|l| l.contains("URI")));
        let with_v4 = NameConstraintsSpec::new(&["starnet"], &["10.0.0.0/8"]).unwrap();
        assert!(!with_v4.excludes_all_ipv4());
        assert!(with_v4.excludes_all_ipv6());
        assert!(NAME_CONSTRAINTS_OFF_WARNING.contains("any name"));
    }

    #[test]
    fn fr21_ac6_summary_states_exactly_what_is_written() {
        // Covers: FR-21 AC6, FR-21 AC3
        // ADR 0001: the summary describes the extension as written, line by line.
        let empty: [&str; 0] = [];
        let dns_only = NameConstraintsSpec::new(&["starnet"], &empty).unwrap();
        assert_eq!(
            dns_only.summary_lines(),
            [
                "permitted DNS: starnet",
                "excluded IP: 0.0.0.0/0 (all IPv4)",
                "excluded IP: ::/0 (all IPv6)",
                "email addresses: none allowed (only the reserved .keystone.invalid domain is permitted)",
                "URIs: none allowed (only the reserved .keystone.invalid domain is permitted)",
            ]
        );
        let with_v6 = NameConstraintsSpec::new(&["starnet"], &["2001:db8::/32"]).unwrap();
        assert_eq!(
            with_v6.summary_lines(),
            [
                "permitted DNS: starnet",
                "permitted IP: 2001:db8::/32",
                "excluded IP: 0.0.0.0/0 (all IPv4)",
                "email addresses: none allowed (only the reserved .keystone.invalid domain is permitted)",
                "URIs: none allowed (only the reserved .keystone.invalid domain is permitted)",
            ]
        );
        assert_eq!(RESERVED_CONSTRAINT_DOMAIN, ".keystone.invalid");
        assert!(RESERVED_CONSTRAINT_DOMAIN.ends_with(".invalid"));
    }
}
