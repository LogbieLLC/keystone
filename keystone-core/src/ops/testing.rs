//! Test seams for the operations layer (FR-22 AC6, AC7; TESTING.md "Fault injection").
//!
//! **Compiled only without the `production` feature**: a production build has no such
//! module, so none of this can be enabled there (see [`super::TEST_SEAMS_COMPILED`]).
//! Everything here is thread-local and inert until a test arms it, and every armed seam
//! fires once.
//!
//! - [`arm_fault`]: stop the next operation on this thread at a named [`FaultPoint`],
//!   as if the process died there (no clean-up).
//! - [`crash_on_drive_change`]: make the N-th file-system change on a CA drive fail
//!   (counting every atomic write, move and delete on every drive, so an operation can be
//!   interrupted between the writes to two drives) and treat the failure as a crash.
//! - [`drive_change_count`]: how many drive changes happened since the last call, to
//!   enumerate every interruption point of an operation.
//! - [`supply_generated_key`]: let the next software key generation of that size use a
//!   cached synthetic key from `keystone-testkit` (RSA 8,192 generation takes minutes).
//! - [`queue_serial_candidate`]: make serial planning try a given value first, to prove
//!   that a serial seen in any history is never used again (FR-10 AC2).
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};

use crate::crypto::RsaPrivateKey;
use crate::model::Serial;

pub use super::seam::FaultPoint;

thread_local! {
    static FAULT: Cell<Option<FaultPoint>> = const { Cell::new(None) };
    static CRASH_MODE: Cell<bool> = const { Cell::new(false) };
    static KEYS: RefCell<Vec<&'static RsaPrivateKey>> = const { RefCell::new(Vec::new()) };
    static SERIALS: RefCell<Vec<Serial>> = const { RefCell::new(Vec::new()) };
}

/// Stops the next operation on this thread when it reaches `point` (once).
pub fn arm_fault(point: FaultPoint) {
    FAULT.with(|fault| fault.set(Some(point)));
}

/// Makes the drive change after the next `allowed` ones fail (once), and makes the
/// failing operation stop without any clean-up, as after a crash.
pub fn crash_on_drive_change(allowed: u32) {
    CRASH_MODE.with(|mode| mode.set(true));
    crate::store::fault::fail_after(allowed);
}

/// Number of drive changes (atomic writes, moves, deletes) on this thread since the
/// last call; resets the count.
pub fn drive_change_count() -> u32 {
    crate::store::fault::take_count()
}

/// Lets the next software RSA key generation of `key.bits()` bits on this thread use
/// `key` (a cached synthetic test key) instead of generating one. Keys are used in the
/// order supplied.
pub fn supply_generated_key(key: &'static RsaPrivateKey) {
    KEYS.with(|keys| keys.borrow_mut().push(key));
}

/// Makes serial planning on this thread try `serial` before any random candidate.
pub fn queue_serial_candidate(serial: Serial) {
    SERIALS.with(|serials| serials.borrow_mut().push(serial));
}

/// Removes every armed seam on this thread (faults, crash mode, supplied keys and
/// serial candidates).
pub fn reset() {
    FAULT.with(|fault| fault.set(None));
    CRASH_MODE.with(|mode| mode.set(false));
    crate::store::fault::disarm();
    KEYS.with(|keys| keys.borrow_mut().clear());
    SERIALS.with(|serials| serials.borrow_mut().clear());
}

pub(crate) fn take_fault(point: FaultPoint) -> bool {
    FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            CRASH_MODE.with(|mode| mode.set(true));
            true
        } else {
            false
        }
    })
}

pub(crate) fn crash_mode() -> bool {
    CRASH_MODE.with(Cell::get)
}

pub(crate) fn take_supplied_key(bits: u32) -> Option<&'static RsaPrivateKey> {
    KEYS.with(|keys| {
        let mut keys = keys.borrow_mut();
        let index = keys.iter().position(|key| key.bits() == bits)?;
        Some(keys.remove(index))
    })
}

pub(crate) fn take_serial_candidate() -> Option<Serial> {
    SERIALS.with(|serials| {
        let mut serials = serials.borrow_mut();
        (!serials.is_empty()).then(|| serials.remove(0))
    })
}
