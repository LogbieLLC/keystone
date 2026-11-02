//! Test-only fault injection (FR-22 AC6 style): makes the N-th file-system change on this
//! thread fail, to interrupt an operation, a repair or a recovery at every step.
//!
//! Compiled only for unit tests (`cfg(test)`); production code never contains it.
#![forbid(unsafe_code)]

use std::cell::Cell;

use super::StoreError;

thread_local! {
    static FAIL_AFTER: Cell<Option<u32>> = const { Cell::new(None) };
    static CHANGES: Cell<u32> = const { Cell::new(0) };
}

/// Called before every file-system change (write, rename, delete).
pub(crate) fn check(path: &std::path::Path) -> Result<(), StoreError> {
    CHANGES.with(|changes| changes.set(changes.get() + 1));
    FAIL_AFTER.with(|fail| match fail.get() {
        Some(0) => {
            fail.set(None);
            Err(StoreError::Io {
                action: "change (injected fault)",
                path: path.to_path_buf(),
                source: std::io::Error::other("injected fault"),
            })
        }
        Some(n) => {
            fail.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })
}

/// Lets `allowed` more changes succeed, then fails the next one (once).
pub(crate) fn fail_after(allowed: u32) {
    FAIL_AFTER.with(|fail| fail.set(Some(allowed)));
}

/// Removes any pending fault.
pub(crate) fn disarm() {
    FAIL_AFTER.with(|fail| fail.set(None));
}

/// Counts changes from now on; returns the count so far and resets it.
pub(crate) fn take_count() -> u32 {
    CHANGES.with(|changes| changes.replace(0))
}
