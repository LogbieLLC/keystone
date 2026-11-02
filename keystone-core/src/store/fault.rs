//! Test-only seams of the store: fault injection (FR-22 AC6 style), which makes the N-th
//! file-system change on this thread fail, to interrupt an operation, a repair or a
//! recovery at every step; and simulated devices (SEC-11), because test drives are
//! folders on one file system while every real CA drive must be its own device.
//!
//! Compiled for unit tests and for development builds, never with the `production`
//! feature, so a production binary never contains it: there the real device numbers are
//! always compared. Integration tests reach it only through `crate::ops::testing`
//! (FR-22 AC6: interrupting an operation between drive writes). It is inert until a test
//! arms it.
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use super::StoreError;

thread_local! {
    static FAIL_AFTER: Cell<Option<u32>> = const { Cell::new(None) };
    static CHANGES: Cell<u32> = const { Cell::new(0) };
    static DEVICES: RefCell<Vec<(PathBuf, u64)>> = const { RefCell::new(Vec::new()) };
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

/// The folder's canonical path (links resolved), or the path as given.
fn canonical(folder: &Path) -> PathBuf {
    std::fs::canonicalize(folder).unwrap_or_else(|_| folder.to_path_buf())
}

/// SEC-11 seam: from now on, on this thread, `folder` and everything inside it are on
/// simulated device `device`. Give two folders the same number to simulate two folders
/// on one USB drive, different numbers to simulate separate USB drives.
pub(crate) fn put_on_device(folder: &Path, device: u64) {
    let folder = canonical(folder);
    DEVICES.with(|devices| devices.borrow_mut().push((folder, device)));
}

/// Forgets every simulated device on this thread.
pub(crate) fn clear_devices() {
    DEVICES.with(|devices| devices.borrow_mut().clear());
}

/// The simulated device of `folder`: that of the innermost folder put on a device that
/// holds it, if any.
fn simulated_device(folder: &Path) -> Option<u64> {
    let folder = canonical(folder);
    DEVICES.with(|devices| {
        devices
            .borrow()
            .iter()
            .filter(|(root, _)| folder.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
            .map(|(_, device)| *device)
    })
}

/// Whether two folders count as one device in a non-production build. When a test put
/// both on simulated devices, their numbers decide. Otherwise folders on one real device
/// stand in for separate USB drives (test drives, GUI end-to-end tests), unless one is
/// inside the other: a folder inside a drive is on that drive's device.
pub(crate) fn same_device(a: &Path, b: &Path, same_real_device: bool) -> bool {
    if let (Some(left), Some(right)) = (simulated_device(a), simulated_device(b)) {
        return left == right;
    }
    let (a, b) = (canonical(a), canonical(b));
    same_real_device && (a.starts_with(&b) || b.starts_with(&a))
}
