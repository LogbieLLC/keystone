//! Temporary CA drives for tests (TESTING.md TEST-12) with a plaintext-key scan (PRD SEC-04).
//!
//! [`TestDrives`] creates N empty "USB drive" folders plus one export folder inside a
//! single `tempfile::TempDir`. When it is dropped (and the test is not already
//! panicking), it scans every file it holds for unencrypted private-key PEM markers and
//! panics if one is found, so a test that ever writes a plaintext key fails.
#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Key types of the unencrypted private-key PEM labels `-----BEGIN <type>PRIVATE KEY-----`
/// (SEC-04): PKCS#8, RSA, EC, DSA and OpenSSH. `-----BEGIN ENCRYPTED PRIVATE KEY-----`
/// (encrypted PKCS#8) matches none of them and is allowed.
pub const PLAINTEXT_KEY_TYPES: [&str; 5] = ["", "RSA ", "EC ", "DSA ", "OPENSSH "];

/// The unencrypted private-key PEM markers. Built at run time, so this crate's source and
/// binary never contain a marker for the plaintext-key scanner to find.
pub fn plaintext_key_markers() -> Vec<String> {
    PLAINTEXT_KEY_TYPES
        .iter()
        .map(|kind| format!("-----BEGIN {kind}PRIVATE KEY-----"))
        .collect()
}

/// N temporary CA drives and one export drive, deleted when dropped.
#[derive(Debug)]
pub struct TestDrives {
    dir: tempfile::TempDir,
    ca_drives: Vec<PathBuf>,
    export: PathBuf,
}

impl TestDrives {
    /// Creates `ca_drives` empty drive folders (`drive-1`, `drive-2`, ...) and an empty
    /// export folder, all inside one new temporary directory.
    ///
    /// # Panics
    /// If the temporary directory cannot be created (a broken test environment).
    pub fn new(ca_drives: usize) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("keystone-test-drives-")
            .tempdir()
            .expect("create temporary directory for test drives");
        let mut drives = TestDrives {
            export: dir.path().join("export"),
            dir,
            ca_drives: Vec::new(),
        };
        fs::create_dir(&drives.export).expect("create export drive");
        for _ in 0..ca_drives {
            drives.add_ca_drive();
        }
        drives
    }

    /// Adds one more empty CA drive folder and returns its path.
    pub fn add_ca_drive(&mut self) -> PathBuf {
        let path = self
            .dir
            .path()
            .join(format!("drive-{}", self.ca_drives.len() + 1));
        fs::create_dir(&path).expect("create test drive");
        self.ca_drives.push(path.clone());
        path
    }

    /// The root of CA drive `index` (0-based).
    ///
    /// # Panics
    /// If there is no such drive.
    pub fn ca_drive(&self, index: usize) -> &Path {
        &self.ca_drives[index]
    }

    /// Every CA drive root, in creation order.
    pub fn ca_drives(&self) -> &[PathBuf] {
        &self.ca_drives
    }

    /// The export drive root.
    pub fn export_drive(&self) -> &Path {
        &self.export
    }

    /// The temporary directory holding all drives.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Files under all drives that contain a plaintext private-key marker.
    pub fn plaintext_key_files(&self) -> io::Result<Vec<PathBuf>> {
        find_plaintext_private_keys(self.dir.path())
    }
}

impl Drop for TestDrives {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        match self.plaintext_key_files() {
            Ok(hits) if hits.is_empty() => {}
            Ok(hits) => panic!("PLAINTEXT PRIVATE KEY FOUND (SEC-04) in test drives: {hits:?}"),
            Err(error) => panic!("could not scan test drives for plaintext keys: {error}"),
        }
    }
}

/// Recursively finds regular files under `root` that contain any of
/// [`plaintext_key_markers`]. Symbolic links are not followed.
pub fn find_plaintext_private_keys(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut hits = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                pending.push(path);
            } else if meta.is_file() && contains_marker(&fs::read(&path)?) {
                hits.push(path);
            }
        }
    }
    hits.sort();
    Ok(hits)
}

fn contains_marker(content: &[u8]) -> bool {
    plaintext_key_markers().iter().any(|marker| {
        content
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test12_drives_live_in_a_temporary_directory() {
        // Covers: TEST-12
        let drives = TestDrives::new(3);
        assert_eq!(drives.ca_drives().len(), 3);
        for drive in drives.ca_drives() {
            assert!(drive.starts_with(std::env::temp_dir()));
            assert!(drive.is_dir());
            assert_eq!(fs::read_dir(drive).expect("read").count(), 0);
        }
        assert!(drives.export_drive().is_dir());
        let root = drives.root().to_path_buf();
        drop(drives);
        assert!(!root.exists(), "temporary drives are removed");
    }

    #[test]
    fn sec04_drop_panics_on_a_plaintext_private_key() {
        // Covers: SEC-04
        for marker in plaintext_key_markers() {
            let result = std::panic::catch_unwind(|| {
                let drives = TestDrives::new(1);
                let nested = drives.ca_drive(0).join("keystone/keys");
                fs::create_dir_all(&nested).expect("mkdir");
                fs::write(nested.join("leak.key"), format!("x\n{marker}\nAAAA\n")).expect("write");
                drop(drives);
            });
            assert!(result.is_err(), "marker {marker} must be detected");
        }
    }

    #[test]
    fn sec04_encrypted_keys_are_allowed() {
        // Covers: SEC-04
        let drives = TestDrives::new(1);
        let encrypted =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        fs::write(drives.export_drive().join("sub.key"), encrypted).expect("write");
        assert!(drives.plaintext_key_files().expect("scan").is_empty());
    }

    #[test]
    fn scan_does_not_follow_symbolic_links() {
        let drives = TestDrives::new(1);
        let outside = tempfile::tempdir().expect("tempdir");
        fs::write(outside.path().join("k"), &plaintext_key_markers()[0]).expect("write");
        std::os::unix::fs::symlink(outside.path(), drives.ca_drive(0).join("link"))
            .expect("symlink");
        assert!(drives.plaintext_key_files().expect("scan").is_empty());
    }
}
