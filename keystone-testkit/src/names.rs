//! Test certificate names (TESTING.md TEST-11): every Common Name contains
//! `KEYSTONE TEST`.
#![forbid(unsafe_code)]

use keystone_core::model::NameFields;

use crate::TEST_CN_MARKER;

/// A Common Name `KEYSTONE TEST <label>`.
pub fn test_cn(label: &str) -> String {
    format!("{TEST_CN_MARKER} {label}")
}

/// Name fields with CN `KEYSTONE TEST <label>`, organization `KEYSTONE TEST` and
/// country `US`.
pub fn test_name(label: &str) -> NameFields {
    NameFields {
        common_name: test_cn(label),
        organization: Some(TEST_CN_MARKER.to_owned()),
        country: Some("US".to_owned()),
    }
}

/// Name fields with only a Common Name `KEYSTONE TEST <label>`.
pub fn test_name_cn_only(label: &str) -> NameFields {
    NameFields {
        common_name: test_cn(label),
        organization: None,
        country: None,
    }
}

/// Panics unless `common_name` carries the test marker.
pub fn assert_test_cn(common_name: &str) {
    assert!(
        common_name.contains(TEST_CN_MARKER),
        "test certificate CN {common_name:?} lacks {TEST_CN_MARKER:?} (TEST-11)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_names_carry_marker() {
        assert_test_cn(&test_name("Root").common_name);
        assert_test_cn(&test_name_cn_only("Sub").common_name);
    }
}
