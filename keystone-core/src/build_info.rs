//! Facts fixed at build time.
#![forbid(unsafe_code)]

use time::OffsetDateTime;

/// Build date as seconds since the Unix epoch, from `SOURCE_DATE_EPOCH` (see `build.rs`).
pub const BUILD_EPOCH_SECONDS: i64 = parse_epoch(env!("KEYSTONE_BUILD_EPOCH"));

/// The binary's build date (UTC). Signing is blocked when the clock is earlier (FR-17 AC2).
pub fn build_date() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(BUILD_EPOCH_SECONDS)
        .expect("build.rs guarantees a valid positive epoch")
}

/// True when this binary was compiled with the `production` feature.
pub const fn is_production_build() -> bool {
    cfg!(feature = "production")
}

const fn parse_epoch(text: &str) -> i64 {
    let bytes = text.as_bytes();
    let mut value: i64 = 0;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(
            digit.is_ascii_digit(),
            "KEYSTONE_BUILD_EPOCH must be digits"
        );
        value = value * 10 + (digit - b'0') as i64;
        index += 1;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_date_is_after_project_start() {
        // Covers: FR-17 AC2 (build date is embedded)
        assert!(build_date().year() >= 2026);
    }
}
