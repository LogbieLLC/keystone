//! What the GUI shows about the YubiKey (FR-05 AC2, AC3, FR-06 AC1, FR-07 AC4).
//!
//! The rules are core's: `token::check_firmware`, `token::ensure_hardened`,
//! `token::ensure_slot_empty`. This module only phrases their results.
#![forbid(unsafe_code)]

use keystone_core::token::{
    CredentialStatus, DeviceInfo, SlotStatus, check_firmware, ensure_hardened, ensure_slot_empty,
};

use super::{Line, Status};

/// The message shown when this build has no YubiKey driver (production builds until
/// the real PIV driver is added).
pub const DRIVER_MISSING: &str = "The real YubiKey driver is not included in this build of Keystone, so YubiKey steps cannot run here. Nothing was changed.";

/// What the YubiKey looks like, read before any action (FR-05 AC3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenState {
    /// This build has no YubiKey driver.
    #[cfg_attr(
        all(feature = "simulator", not(test)),
        allow(dead_code, reason = "constructed only in builds without the simulator")
    )]
    DriverMissing,
    /// No YubiKey could be read; the text says why.
    Unavailable(String),
    /// A YubiKey was read.
    Present {
        /// Serial and firmware.
        info: DeviceInfo,
        /// Credential metadata (`None` when it could not be read).
        credentials: Option<CredentialStatus>,
        /// What slot 9C holds (`None` when it could not be read).
        slot: Option<SlotStatus>,
    },
}

/// What the YubiKey step of Flow B allows next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenNext {
    /// Nothing: fix the problem shown (no driver, no key, old firmware).
    Stop,
    /// The slot holds something: only the typed-serial wipe is offered (FR-07 AC4).
    OfferWipe,
    /// Factory defaults: ask for a new PIN and PUK (FR-06 AC1, AC2).
    Harden,
    /// Already hardened, slot empty: ask for the current PIN.
    UseCurrentPin,
}

/// Lines describing the YubiKey, and what Flow B can do next.
pub fn describe(state: &TokenState) -> (Vec<Line>, TokenNext) {
    match state {
        TokenState::DriverMissing => (
            vec![Line::new(Status::Blocked, DRIVER_MISSING)],
            TokenNext::Stop,
        ),
        TokenState::Unavailable(reason) => (
            vec![Line::new(Status::Blocked, reason.clone())],
            TokenNext::Stop,
        ),
        TokenState::Present {
            info,
            credentials,
            slot,
        } => {
            let mut lines = vec![Line::new(
                Status::Info,
                format!(
                    "YubiKey serial number {}, firmware {}.",
                    info.serial, info.firmware
                ),
            )];
            if let Err(error) = check_firmware(info) {
                lines.push(Line::new(Status::Blocked, error.to_string()));
                return (lines, TokenNext::Stop);
            }
            lines.push(Line::new(Status::Ok, "The firmware is 5.7 or newer."));
            let Some(slot) = slot else {
                lines.push(Line::new(
                    Status::Blocked,
                    "The signing slot could not be read. Remove and insert the YubiKey, then check again.",
                ));
                return (lines, TokenNext::Stop);
            };
            if let Err(error) = ensure_slot_empty(slot) {
                lines.push(Line::new(
                    Status::Blocked,
                    format!(
                        "{error}. Keystone never overwrites a slot. The only way forward is an explicit wipe, confirmed by typing this YubiKey's serial number."
                    ),
                ));
                return (lines, TokenNext::OfferWipe);
            }
            lines.push(Line::new(Status::Ok, "The signing slot is empty."));
            let Some(credentials) = credentials else {
                lines.push(Line::new(
                    Status::Blocked,
                    "The PIN and PUK state could not be read. Remove and insert the YubiKey, then check again.",
                ));
                return (lines, TokenNext::Stop);
            };
            match ensure_hardened(credentials) {
                Ok(()) => {
                    lines.push(Line::new(
                        Status::Ok,
                        "The PIN, PUK and management key are not factory defaults.",
                    ));
                    (lines, TokenNext::UseCurrentPin)
                }
                Err(error) => {
                    lines.push(Line::new(
                        Status::Info,
                        format!(
                            "{error}. Keystone will set a new PIN and PUK that you choose, and a random management key protected by the PIN."
                        ),
                    ));
                    (lines, TokenNext::Harden)
                }
            }
        }
    }
}

/// The YubiKey column of the recovery screen (FR-22 AC8).
pub fn recovery_lines(state: &TokenState) -> Vec<Line> {
    match state {
        TokenState::DriverMissing => vec![Line::new(Status::Info, DRIVER_MISSING)],
        TokenState::Unavailable(reason) => vec![Line::new(Status::Info, reason.clone())],
        TokenState::Present { info, slot, .. } => {
            let mut lines = vec![Line::new(
                Status::Info,
                format!(
                    "YubiKey serial number {}, firmware {}.",
                    info.serial, info.firmware
                ),
            )];
            lines.push(match slot {
                Some(slot) if slot.is_empty() => Line::new(
                    Status::Info,
                    "Signing slot: empty (no key, no certificate).",
                ),
                Some(slot) => {
                    Line::new(Status::Info, format!("Signing slot: {}.", slot.describe()))
                }
                None => Line::new(Status::Warning, "Signing slot: could not be read."),
            });
            lines
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::token::{
        FirmwareVersion, KeyOrigin, ManagementKeyAlgorithm, PinPolicy, SlotKeyInfo, TouchPolicy,
    };

    fn info(minor: u8) -> DeviceInfo {
        DeviceInfo {
            serial: 31_415_926,
            firmware: FirmwareVersion::new(5, minor, 4),
        }
    }

    fn credentials(default: bool) -> CredentialStatus {
        CredentialStatus {
            pin_is_default: default,
            puk_is_default: default,
            management_key_is_default: default,
            management_key_algorithm: if default {
                ManagementKeyAlgorithm::Aes192
            } else {
                ManagementKeyAlgorithm::Aes256
            },
            management_key_pin_protected: !default,
            pin_retries_left: 3,
            puk_retries_left: 3,
        }
    }

    #[test]
    fn production_build_without_driver_says_so_clearly() {
        let (lines, next) = describe(&TokenState::DriverMissing);
        assert_eq!(next, TokenNext::Stop);
        assert!(
            lines[0]
                .text
                .contains("real YubiKey driver is not included")
        );
    }

    #[test]
    fn fr05_ac2_ac3_serial_and_firmware_shown_old_firmware_refused() {
        // Covers: FR-05 AC2, FR-05 AC3
        let (lines, next) = describe(&TokenState::Present {
            info: info(4),
            credentials: Some(credentials(true)),
            slot: Some(SlotStatus::default()),
        });
        assert!(lines[0].text.contains("31415926"));
        assert!(lines[0].text.contains("5.4.4"));
        assert_eq!(next, TokenNext::Stop);
        assert!(lines.iter().any(|l| l.text.contains("5.7.0 or newer")));
    }

    #[test]
    fn fr06_ac1_defaults_lead_to_hardening() {
        // Covers: FR-06 AC1
        let state = TokenState::Present {
            info: info(7),
            credentials: Some(credentials(true)),
            slot: Some(SlotStatus::default()),
        };
        assert_eq!(describe(&state).1, TokenNext::Harden);
        let hardened = TokenState::Present {
            info: info(7),
            credentials: Some(credentials(false)),
            slot: Some(SlotStatus::default()),
        };
        assert_eq!(describe(&hardened).1, TokenNext::UseCurrentPin);
    }

    #[test]
    fn fr07_ac4_occupied_slot_offers_only_the_wipe() {
        // Covers: FR-07 AC4, SEC-23
        let slot = SlotStatus {
            key: Some(SlotKeyInfo {
                rsa_bits: 4096,
                pin_policy: PinPolicy::Always,
                touch_policy: TouchPolicy::Always,
                origin: KeyOrigin::Generated,
                public_key_der: Vec::new(),
            }),
            certificate_der: None,
        };
        let state = TokenState::Present {
            info: info(7),
            credentials: Some(credentials(false)),
            slot: Some(slot),
        };
        let (lines, next) = describe(&state);
        assert_eq!(next, TokenNext::OfferWipe);
        let blocked = lines
            .iter()
            .find(|l| l.status == Status::Blocked)
            .expect("blocked line");
        assert!(
            blocked.text.contains("device-generated key"),
            "{}",
            blocked.text
        );
        assert!(blocked.text.contains("never overwrites"));
        let column = recovery_lines(&state);
        assert!(column[1].text.contains("device-generated key"));
    }
}
