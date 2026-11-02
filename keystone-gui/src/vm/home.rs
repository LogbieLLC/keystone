//! Which actions the home screen offers (PRD section 6).
//!
//! This only greys out what is obviously impossible and says why; the operations layer
//! re-checks every rule when a plan is executed. With divergent or damaged drives every
//! signing action is disabled (FR-12 AC3).
#![forbid(unsafe_code)]

use keystone_core::model::CaLevel;
use keystone_core::store::{IssuanceRecord, RecordedCertificate, StatusFilter};
use time::OffsetDateTime;

/// The actions on the home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// Flow A.
    CreateMaster,
    /// Flow B.
    SetupYubikey,
    /// Flow C.
    NewSubIntermediate,
    /// Flow D.
    Revoke,
    /// FR-13 AC4.
    RefreshCrl,
    /// Flow E.
    ReplaceYubikey,
}

impl FlowKind {
    /// Every action, in the order the home screen lists them.
    pub const ALL: [FlowKind; 6] = [
        FlowKind::CreateMaster,
        FlowKind::SetupYubikey,
        FlowKind::NewSubIntermediate,
        FlowKind::Revoke,
        FlowKind::RefreshCrl,
        FlowKind::ReplaceYubikey,
    ];

    /// Button label.
    pub fn label(self) -> &'static str {
        match self {
            FlowKind::CreateMaster => "Create new CA",
            FlowKind::SetupYubikey => "Set up YubiKey and main intermediate",
            FlowKind::NewSubIntermediate => "New sub-intermediate",
            FlowKind::Revoke => "Revoke a certificate",
            FlowKind::RefreshCrl => "Refresh a CRL",
            FlowKind::ReplaceYubikey => "Replace lost YubiKey",
        }
    }

    /// One sentence under the button.
    pub fn summary(self) -> &'static str {
        match self {
            FlowKind::CreateMaster => {
                "Create the master (root) key and certificate on the empty drives, protected by a generated passphrase."
            }
            FlowKind::SetupYubikey => {
                "Harden a YubiKey, generate the main intermediate key on it and have the master sign its certificate."
            }
            FlowKind::NewSubIntermediate => {
                "Create a sub-intermediate for an issuing system such as StarnetAuth, signed by the YubiKey."
            }
            FlowKind::Revoke => "Revoke a certificate and publish a new CRL.",
            FlowKind::RefreshCrl => {
                "Re-sign an issuer's current CRL with a new next update, without new revocations."
            }
            FlowKind::ReplaceYubikey => {
                "Revoke the main intermediate of a lost or broken YubiKey, then set up a new one."
            }
        }
    }
}

/// One action and whether it is offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    /// The action.
    pub flow: FlowKind,
    /// `None`: offered. `Some(reason)`: greyed out, with the reason shown in words.
    pub unavailable: Option<String>,
}

/// What the drives hold, for the home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaState<'a> {
    /// Empty drives: only Flow A.
    NewCa,
    /// An existing CA. `blocked` is the reason signing is disabled, if it is.
    Existing {
        /// The issuance record.
        record: &'a IssuanceRecord,
        /// Why every signing action is disabled, if it is.
        blocked: Option<&'a str>,
    },
}

fn valid(
    record: &IssuanceRecord,
    level: CaLevel,
    now: OffsetDateTime,
) -> Vec<&RecordedCertificate> {
    record
        .filter(None, Some(StatusFilter::Valid), now)
        .into_iter()
        .filter(|cert| cert.certificate.level == level)
        .collect()
}

/// Which actions are offered.
pub fn availability(state: CaState<'_>, now: OffsetDateTime) -> Vec<Availability> {
    FlowKind::ALL
        .iter()
        .map(|flow| Availability {
            flow: *flow,
            unavailable: reason(*flow, state, now),
        })
        .collect()
}

fn reason(flow: FlowKind, state: CaState<'_>, now: OffsetDateTime) -> Option<String> {
    let (record, blocked) = match state {
        CaState::NewCa => {
            return (flow != FlowKind::CreateMaster)
                .then(|| "Not available: the drives are empty. Create the CA first.".to_string());
        }
        CaState::Existing { record, blocked } => (record, blocked),
    };
    if flow == FlowKind::CreateMaster {
        return Some(
            "Not available: these drives already hold a CA. A new CA is never created over an existing one."
                .to_string(),
        );
    }
    if let Some(blocked) = blocked {
        return Some(format!("Not available: {blocked}"));
    }
    let masters = valid(record, CaLevel::Master, now);
    let mains = valid(record, CaLevel::MainIntermediate, now);
    let subs = valid(record, CaLevel::SubIntermediate, now);
    if masters.is_empty() {
        return Some("Not available: the record holds no valid master certificate.".to_string());
    }
    match flow {
        FlowKind::CreateMaster => None,
        FlowKind::SetupYubikey if !mains.is_empty() => Some(
            "Not available: a valid main intermediate exists. To replace a lost YubiKey, use Replace lost YubiKey."
                .to_string(),
        ),
        FlowKind::NewSubIntermediate | FlowKind::ReplaceYubikey if mains.is_empty() => Some(
            "Not available: there is no valid main intermediate. Set up the YubiKey first.".to_string(),
        ),
        FlowKind::Revoke if mains.is_empty() && subs.is_empty() => Some(
            "Not available: there is no valid intermediate to revoke.".to_string(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ca_offers_only_flow_a() {
        let now = keystone_core::build_info::build_date();
        let list = availability(CaState::NewCa, now);
        assert_eq!(list.len(), 6);
        for item in list {
            assert_eq!(
                item.unavailable.is_none(),
                item.flow == FlowKind::CreateMaster
            );
        }
    }

    #[test]
    fn fr12_ac3_blocked_drives_disable_every_signing_action() {
        // Covers: FR-12 AC3, SEC-22
        let now = keystone_core::build_info::build_date();
        let record = IssuanceRecord::empty();
        let list = availability(
            CaState::Existing {
                record: &record,
                blocked: Some("the drives hold different histories."),
            },
            now,
        );
        assert!(list.iter().all(|a| a.unavailable.is_some()));
        assert!(
            list[1]
                .unavailable
                .as_deref()
                .expect("reason")
                .contains("different histories")
        );
        assert!(list.iter().all(|a| {
            a.unavailable
                .as_deref()
                .is_some_and(|r| r.starts_with("Not available"))
        }));
    }

    #[test]
    fn labels_and_summaries_are_plain_words() {
        for flow in FlowKind::ALL {
            assert!(!flow.label().is_empty());
            assert!(flow.summary().ends_with('.'));
        }
    }
}
