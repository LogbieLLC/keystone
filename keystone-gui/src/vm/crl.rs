//! CRL nextUpdate warnings (FR-13 AC3).
//!
//! The current CRL of each issuer is the one with the highest CRL number among the
//! `signed` journal entries of *completed* operations. Whether to warn is decided by
//! `keystone_core::crl::crl_freshness` (30 days before nextUpdate). The warning opens
//! the guided Refresh CRL action (FR-13 AC4).
//!
//! Note for the lead: core has no "current CRL per issuer" query yet; this module reads
//! it from the journals. A core function (for example `DriveSet::current_crls`) would
//! be the better home.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use keystone_core::crl::{CrlFreshness, crl_freshness};
use keystone_core::model::{Serial, Timestamp};
use keystone_core::store::{
    IssuanceRecord, OperationId, OperationJournal, OperationState, SignedObject,
};
use time::OffsetDateTime;

use super::{Status, format_utc};

/// The newest CRL of one issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCrl {
    /// The issuing certificate's serial.
    pub issuer: Serial,
    /// The issuer's name for the operator.
    pub issuer_name: String,
    /// CRL number.
    pub crl_number: u64,
    /// nextUpdate.
    pub next_update: Timestamp,
}

/// The newest CRL of every issuer, from completed operations only.
pub fn current_crls(
    journals: &BTreeMap<OperationId, OperationJournal>,
    record: &IssuanceRecord,
) -> Vec<CurrentCrl> {
    let mut newest: BTreeMap<Serial, CurrentCrl> = BTreeMap::new();
    for journal in journals.values() {
        if journal.state() != OperationState::Completed {
            continue;
        }
        for signed in journal.signed() {
            let SignedObject::Crl(crl) = signed else {
                continue;
            };
            let replace = newest
                .get(&crl.issuer_serial)
                .is_none_or(|known| crl.crl_number > known.crl_number);
            if replace {
                let issuer_name = record.get(crl.issuer_serial).map_or_else(
                    || format!("issuer {}", crl.issuer_serial),
                    |cert| cert.certificate.subject.display(),
                );
                newest.insert(
                    crl.issuer_serial,
                    CurrentCrl {
                        issuer: crl.issuer_serial,
                        issuer_name,
                        crl_number: crl.crl_number,
                        next_update: crl.next_update,
                    },
                );
            }
        }
    }
    newest.into_values().collect()
}

/// A warning banner that opens Refresh CRL for one issuer (FR-13 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlWarning {
    /// The issuer to refresh.
    pub issuer: Serial,
    /// Warning or blocked (already past nextUpdate).
    pub status: Status,
    /// The banner text.
    pub text: String,
}

/// Warnings for CRLs within 30 days of nextUpdate or past it.
pub fn warnings(crls: &[CurrentCrl], now: OffsetDateTime) -> Vec<CrlWarning> {
    crls.iter()
        .filter_map(|crl| {
            let when = format_utc(crl.next_update.get());
            match crl_freshness(crl.next_update.get(), now) {
                CrlFreshness::Fresh => None,
                CrlFreshness::RefreshSoon { days_left } => Some(CrlWarning {
                    issuer: crl.issuer,
                    status: Status::Warning,
                    text: format!(
                        "The CRL of {} (number {}) must be refreshed: its next update is {when}, in {days_left} day{}. Refresh it and upload it to where it is hosted.",
                        crl.issuer_name,
                        crl.crl_number,
                        if days_left == 1 { "" } else { "s" }
                    ),
                }),
                CrlFreshness::Expired => Some(CrlWarning {
                    issuer: crl.issuer,
                    status: Status::Blocked,
                    text: format!(
                        "The CRL of {} (number {}) passed its next update on {when}. Relying systems may now reject its certificates. Refresh it and upload it now.",
                        crl.issuer_name, crl.crl_number
                    ),
                }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn serial(n: u8) -> Serial {
        let mut bytes = [0u8; 20];
        bytes[0] = 0x22;
        bytes[19] = n;
        Serial::from_bytes(bytes).expect("serial")
    }

    fn crl(days_from_now: i64, now: OffsetDateTime) -> CurrentCrl {
        CurrentCrl {
            issuer: serial(1),
            issuer_name: "CN=KEYSTONE TEST Root".to_string(),
            crl_number: 3,
            next_update: Timestamp::utc(now + Duration::days(days_from_now)),
        }
    }

    #[test]
    fn fr13_ac3_warns_thirty_days_before_next_update() {
        // Covers: FR-13 AC3
        let now = OffsetDateTime::from_unix_timestamp(1_793_491_200).expect("now");
        assert!(warnings(&[crl(31, now)], now).is_empty());
        let soon = warnings(&[crl(30, now)], now);
        assert_eq!(soon.len(), 1);
        assert_eq!(soon[0].status, Status::Warning);
        assert!(soon[0].text.contains("in 30 days"), "{}", soon[0].text);
        assert!(soon[0].text.contains("Refresh it"));
        let past = warnings(&[crl(-1, now)], now);
        assert_eq!(past[0].status, Status::Blocked);
        assert!(past[0].text.contains("passed its next update"));
        assert_eq!(past[0].issuer, serial(1));
    }

    #[test]
    fn current_crls_of_an_empty_ca_are_empty() {
        assert!(current_crls(&BTreeMap::new(), &IssuanceRecord::empty()).is_empty());
    }
}
