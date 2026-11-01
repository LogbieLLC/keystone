//! The single reviewed FFI module (SEC-18). The only file in the workspace where
//! `unsafe` code is allowed. Every unsafe block carries a `// SAFETY:` comment, and
//! `scripts/check-boundaries.sh` fails CI if one is missing.
//!
//! Contents:
//! - `LockedRegion`: page-aligned memory that is locked into RAM (never swapped),
//!   excluded from core dumps, and wiped before it is freed (SEC-07).

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::c_void;
use std::ptr::NonNull;

use zeroize::Zeroize;

use super::CryptoError;

/// Page size of the only supported target (x86_64-unknown-linux-gnu).
const PAGE_SIZE: usize = 4096;

/// Locked, wiped-on-drop memory for secrets (SEC-07).
///
/// Each region owns whole pages, so unlocking one region on drop can never unlock
/// the page of another live secret.
pub(crate) struct LockedRegion {
    ptr: NonNull<u8>,
    size: usize,
}

// SAFETY: `LockedRegion` exclusively owns its allocation (like `Box<[u8]>`), so it can
// move between threads, and shared references only allow reads.
unsafe impl Send for LockedRegion {}
// SAFETY: see `Send` above; `&LockedRegion` exposes only `&[u8]`.
unsafe impl Sync for LockedRegion {}

impl LockedRegion {
    /// Allocates at least `min_len` zeroed bytes, rounded up to whole pages, and
    /// locks them into RAM. Fails if the memory cannot be locked: a secret is never
    /// held in memory that could be swapped to disk.
    pub(crate) fn new(min_len: usize) -> Result<Self, CryptoError> {
        let size = min_len
            .max(1)
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(CryptoError::LockedMemory)?;
        let layout =
            Layout::from_size_align(size, PAGE_SIZE).map_err(|_| CryptoError::LockedMemory)?;
        // SAFETY: `layout` has a non-zero size (at least one page).
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or(CryptoError::LockedMemory)?;
        // From here on, `Drop` frees the allocation on every early return.
        let region = LockedRegion { ptr, size };
        // SAFETY: `ptr..ptr+size` is a live allocation owned by `region`.
        unsafe { rustix::mm::mlock(region.ptr.as_ptr().cast::<c_void>(), region.size) }
            .map_err(|_| CryptoError::LockedMemory)?;
        // SAFETY: same range as above. MADV_DONTDUMP keeps the pages out of core dumps
        // even if core dumps were re-enabled; failure is not fatal because core dumps
        // are also disabled for the whole process (hardening module).
        let _ = unsafe {
            rustix::mm::madvise(
                region.ptr.as_ptr().cast::<c_void>(),
                region.size,
                rustix::mm::Advice::LinuxDontDump,
            )
        };
        Ok(region)
    }

    /// Total usable bytes (whole pages).
    pub(crate) fn capacity(&self) -> usize {
        self.size
    }

    /// The whole region.
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `size` initialised (zeroed at allocation) bytes for
        // the lifetime of `self`, and no mutable reference exists while `&self` is held.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// The whole region, writable.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`, and `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }
}

impl Drop for LockedRegion {
    fn drop(&mut self) {
        // Volatile wipe that the compiler cannot remove.
        self.as_mut_slice().zeroize();
        // SAFETY: the range is the live allocation owned by `self`; unlocking pages that
        // were never locked (when `mlock` failed in `new`) is harmless.
        let _ = unsafe { rustix::mm::munlock(self.ptr.as_ptr().cast::<c_void>(), self.size) };
        // SAFETY: allocated in `new` with exactly this size and alignment, freed once.
        unsafe {
            dealloc(
                self.ptr.as_ptr(),
                Layout::from_size_align_unchecked(self.size, PAGE_SIZE),
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec07_locked_region_is_page_sized_zeroed_and_writable() {
        // Covers: SEC-07
        let mut region = LockedRegion::new(10).expect("mlock within RLIMIT_MEMLOCK");
        assert_eq!(region.capacity(), PAGE_SIZE);
        assert!(region.as_slice().iter().all(|b| *b == 0));
        region.as_mut_slice()[0] = 7;
        assert_eq!(region.as_slice()[0], 7);
        let large = LockedRegion::new(PAGE_SIZE + 1).expect("mlock");
        assert_eq!(large.capacity(), 2 * PAGE_SIZE);
    }
}
