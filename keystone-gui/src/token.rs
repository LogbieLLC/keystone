//! The YubiKey behind the `TokenSigner` trait (NFR-08).
//!
//! - Development and test builds (`simulator` feature): `keystone_testkit`'s
//!   `SimulatedYubiKey`, one device for the whole session, configured from the command
//!   line (`--sim-*`).
//! - Production builds: the real PIV driver is not part of this build yet, so every
//!   YubiKey step shows [`crate::vm::token::DRIVER_MISSING`] instead of failing.
//!
//! Reading the device (serial, firmware, credential state, slot state) never changes
//! it; every change goes through the operations layer (`backend`).
#![forbid(unsafe_code)]

use keystone_core::token::SIGNING_SLOT;

use crate::backend::SharedToken;
use crate::cli::SimOptions;
use crate::vm::token::TokenState;

/// Connects to the YubiKey, or explains why there is none.
#[cfg(feature = "simulator")]
pub fn connect(options: &SimOptions) -> Result<SharedToken, TokenState> {
    use crate::cli::SimSlot;
    use keystone_core::token::FirmwareVersion;
    use keystone_testkit::simulator::{KeySource, SlotPreset};
    use keystone_testkit::{SimulatedYubiKey, SimulatorConfig};

    let mut config = SimulatorConfig {
        key_source: KeySource::Pool,
        ..SimulatorConfig::default()
    };
    if let Some(serial) = options.serial {
        config.serial = serial;
    }
    if let Some((major, minor, patch)) = options.firmware {
        config.firmware = FirmwareVersion::new(major, minor, patch);
    }
    config.slot = match options.slot {
        SimSlot::Empty => SlotPreset::Empty,
        SimSlot::KeyOnly => SlotPreset::KeyWithoutCertificate,
        SimSlot::KeyAndCertificate => SlotPreset::KeyAndCertificate,
        SimSlot::CertificateOnly => SlotPreset::CertificateOnly,
    };
    Ok(SharedToken::new(Box::new(SimulatedYubiKey::new(config))))
}

/// Connects to the YubiKey, or explains why there is none.
#[cfg(not(feature = "simulator"))]
pub fn connect(_options: &SimOptions) -> Result<SharedToken, TokenState> {
    Err(TokenState::DriverMissing)
}

/// Reads serial, firmware, credential state and slot 9C (FR-05 AC3, FR-06 AC1,
/// FR-07 AC4). Run it off the GUI thread.
pub fn read_state(token: &SharedToken) -> TokenState {
    let mut device = token.lock();
    let info = match device.device_info() {
        Ok(info) => info,
        Err(error) => return TokenState::Unavailable(capitalised(&error.to_string())),
    };
    let credentials = device.credential_status().ok();
    let slot = device.slot_status(SIGNING_SLOT).ok();
    TokenState::Present {
        info,
        credentials,
        slot,
    }
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect::<String>() + ".",
        None => String::new(),
    }
}

#[cfg(all(test, feature = "simulator"))]
mod tests {
    use super::*;
    use crate::cli::SimSlot;
    use crate::vm::token::{TokenNext, describe};

    #[test]
    fn fr05_ac3_simulator_is_read_before_any_action() {
        // Covers: FR-05 AC3, NFR-08
        let token = connect(&SimOptions {
            serial: Some(4242),
            firmware: Some((5, 7, 4)),
            slot: SimSlot::Empty,
        })
        .expect("simulator");
        let state = read_state(&token);
        let (lines, next) = describe(&state);
        assert!(lines[0].text.contains("4242"), "{lines:?}");
        assert_eq!(next, TokenNext::Harden);
    }

    #[test]
    fn fr07_ac4_occupied_simulator_slot_offers_the_wipe() {
        // Covers: FR-07 AC4
        let token = connect(&SimOptions {
            slot: SimSlot::KeyOnly,
            ..SimOptions::default()
        })
        .expect("simulator");
        assert_eq!(describe(&read_state(&token)).1, TokenNext::OfferWipe);
    }
}
