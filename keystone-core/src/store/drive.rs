//! CA drives, drive sets and the export drive (FR-12 AC1, AC2, FR-19, SEC-11, SEC-20).
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::fsio::{Dir, EntryKind, WriteMode};
use super::ids::{CaId, DriveId};
use super::paths::{
    AUDIT_LOG_FILE, EXPORT_DIR, IDENTITY_FILE, JOURNAL_DIR, KEYSTONE_DIR, OutputDir, STAGING_DIR,
    is_valid_name,
};
use super::{ParseError, StoreError};
use crate::crypto::hash::sha256;
use crate::limits::{MAX_METADATA_BYTES, MAX_OUTPUT_FILE_BYTES};
use crate::model::{Sha256Digest, Timestamp};

/// Current version of the drive identity format.
pub const IDENTITY_FORMAT: u32 = 1;

/// Role of a CA drive (FR-12 AC1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriveRole {
    /// The primary drive.
    Primary,
    /// A backup drive.
    Backup,
}

/// `keystone/drive.json`: which CA a drive belongs to and which drive it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveIdentity {
    /// Always [`IDENTITY_FORMAT`].
    pub format: u32,
    /// The CA this drive belongs to (the same on every drive of the CA).
    pub ca_id: CaId,
    /// This drive.
    pub drive_id: DriveId,
    /// Primary or backup.
    pub role: DriveRole,
    /// When the drive was set up.
    pub created: Timestamp,
}

/// Parses a drive identity file (SEC-08).
pub fn parse_drive_identity(bytes: &[u8]) -> Result<DriveIdentity, ParseError> {
    check_len(bytes, MAX_METADATA_BYTES)?;
    let identity: DriveIdentity = serde_json::from_slice(bytes)
        .map_err(|e| ParseError::invalid(format!("drive identity: {e}")))?;
    if identity.format != IDENTITY_FORMAT {
        return Err(ParseError::invalid(format!(
            "unsupported drive identity format {}",
            identity.format
        )));
    }
    check_timestamp(identity.created, "created")?;
    Ok(identity)
}

pub(crate) fn check_len(bytes: &[u8], limit: usize) -> Result<(), ParseError> {
    if bytes.len() > limit {
        return Err(ParseError::TooLarge {
            len: bytes.len(),
            limit,
        });
    }
    Ok(())
}

/// Persisted timestamps are UTC with whole seconds.
pub(crate) fn check_timestamp(value: Timestamp, field: &str) -> Result<(), ParseError> {
    let time = value.get();
    if !time.offset().is_utc() || time.nanosecond() != 0 {
        return Err(ParseError::invalid(format!(
            "{field} must be UTC with whole seconds"
        )));
    }
    Ok(())
}

/// Pretty JSON plus a final newline, for the human-readable files on a drive.
pub(crate) fn to_json_file<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(value).expect("in-memory JSON serialization");
    out.push(b'\n');
    out
}

/// What a drive holds, before Keystone uses it (SEC-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveClass {
    /// Nothing except an ext4 `lost+found` folder.
    Empty,
    /// A Keystone CA drive.
    KeystoneCa(DriveIdentity),
    /// A `keystone/` folder whose identity cannot be read: treated as holding a CA.
    DamagedKeystone(String),
    /// A Keystone export drive (has `keystone-export/` and no `keystone/`).
    KeystoneExport,
    /// Something else.
    Other,
}

/// Classifies the drive mounted at `root` (empty / Keystone CA / something else).
pub fn classify_drive(root: &Path) -> Result<DriveClass, StoreError> {
    let dir = Dir::open(root)?;
    let entries: Vec<(String, EntryKind)> = dir
        .entries()?
        .into_iter()
        .filter(|(name, kind)| !(name == "lost+found" && *kind == EntryKind::Dir))
        .collect();
    if let Some((_, kind)) = entries.iter().find(|(name, _)| name == KEYSTONE_DIR) {
        if *kind != EntryKind::Dir {
            return Ok(DriveClass::DamagedKeystone(format!(
                "{KEYSTONE_DIR} is not a folder"
            )));
        }
        let keystone = dir.open_dir(KEYSTONE_DIR)?;
        return Ok(match read_identity(&keystone) {
            Ok(identity) => DriveClass::KeystoneCa(identity),
            Err(error) => DriveClass::DamagedKeystone(error.to_string()),
        });
    }
    if entries.is_empty() {
        Ok(DriveClass::Empty)
    } else if entries
        .iter()
        .any(|(name, kind)| name == EXPORT_DIR && *kind == EntryKind::Dir)
    {
        Ok(DriveClass::KeystoneExport)
    } else {
        Ok(DriveClass::Other)
    }
}

fn read_identity(keystone: &Dir) -> Result<DriveIdentity, StoreError> {
    let bytes = keystone.read(IDENTITY_FILE, MAX_METADATA_BYTES)?;
    parse_drive_identity(&bytes).map_err(|source| StoreError::Parse {
        path: keystone.child(IDENTITY_FILE),
        source,
    })
}

/// One opened CA drive.
#[derive(Debug)]
pub struct CaDrive {
    root: PathBuf,
    keystone: Dir,
    identity: DriveIdentity,
}

impl CaDrive {
    /// Opens the CA drive mounted at `root`.
    pub fn open(root: &Path) -> Result<CaDrive, StoreError> {
        match classify_drive(root)? {
            DriveClass::KeystoneCa(identity) => Ok(CaDrive {
                root: root.to_path_buf(),
                keystone: Dir::open(root)?.open_dir(KEYSTONE_DIR)?,
                identity,
            }),
            DriveClass::DamagedKeystone(reason) => Err(StoreError::NotACaDrive {
                root: root.to_path_buf(),
                reason,
            }),
            _ => Err(StoreError::NotACaDrive {
                root: root.to_path_buf(),
                reason: "there is no keystone folder".to_string(),
            }),
        }
    }

    /// The drive's identity.
    pub fn identity(&self) -> &DriveIdentity {
        &self.identity
    }

    /// The drive's mount point.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A short label for the operator: `primary drive 1a2b3c4d (/media/usb1)`.
    pub fn label(&self) -> String {
        let role = match self.identity.role {
            DriveRole::Primary => "primary",
            DriveRole::Backup => "backup",
        };
        format!(
            "{role} drive {} ({})",
            self.identity.drive_id.short(),
            self.root.display()
        )
    }

    /// The `keystone/` folder.
    pub(crate) fn keystone(&self) -> &Dir {
        &self.keystone
    }

    /// Opens `rel` (folders separated by `/`) inside `keystone/`, creating missing folders
    /// when `create` is true. Returns `None` when it does not exist and `create` is false.
    pub(crate) fn dir_at(&self, rel: &str, create: bool) -> Result<Option<Dir>, StoreError> {
        let mut current = self.keystone.reopen()?;
        if rel.is_empty() {
            return Ok(Some(current));
        }
        for part in rel.split('/') {
            if !is_valid_name(part) {
                return Err(StoreError::Unsafe(format!("invalid folder name {part:?}")));
            }
            current = if create {
                current.ensure_dir(part)?
            } else {
                match current.open_dir_if_exists(part)? {
                    Some(dir) => dir,
                    None => return Ok(None),
                }
            };
        }
        Ok(Some(current))
    }

    /// Writes `rel/name` on this drive only, then verifies it by read-back SHA-256
    /// (repair and recovery copy whole operations one drive at a time).
    pub(crate) fn write_one_verified(
        &self,
        rel: &str,
        name: &str,
        data: &[u8],
        mode: WriteMode,
    ) -> Result<(), StoreError> {
        let dir = self
            .dir_at(rel, true)?
            .ok_or_else(|| StoreError::Unsafe(format!("cannot create {rel}")))?;
        dir.write_atomic(name, data, mode)?;
        let expected = sha256(data);
        let actual = sha256(&dir.read_back(name, data.len().max(MAX_OUTPUT_FILE_BYTES))?);
        if actual != expected {
            return Err(StoreError::ReadBackMismatch {
                drive: self.label(),
                path: dir.child(name),
                expected,
                actual,
            });
        }
        Ok(())
    }

    /// Reads `rel/name` inside `keystone/`, or `None` if missing.
    pub(crate) fn read_at(
        &self,
        rel: &str,
        name: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        match self.dir_at(rel, false)? {
            Some(dir) => dir.read_if_exists(name, limit),
            None => Ok(None),
        }
    }
}

/// A file written to every drive of a set but not yet read back (FR-12 AC2).
#[derive(Debug)]
pub(crate) struct WrittenCopies {
    rel: String,
    name: String,
    expected: Sha256Digest,
    len: usize,
}

/// The connected drives of one CA: the primary first, then backups.
#[derive(Debug)]
pub struct DriveSet {
    drives: Vec<CaDrive>,
}

impl DriveSet {
    /// Sets up a new CA on empty drives: one primary and at least one backup (FR-12 AC1).
    ///
    /// SEC-20: refuses any drive that already holds a CA (or a damaged `keystone/` folder)
    /// and any drive that is not empty. Nothing is written until every drive passed.
    pub fn create(
        primary: &Path,
        backups: &[&Path],
        created: Timestamp,
    ) -> Result<DriveSet, StoreError> {
        if backups.is_empty() {
            return Err(StoreError::NotEnoughDrives {
                primaries: 1,
                backups: 0,
            });
        }
        check_timestamp(created, "created").map_err(|e| StoreError::Unsafe(e.to_string()))?;
        let mut roots: Vec<(&Path, DriveRole)> = vec![(primary, DriveRole::Primary)];
        roots.extend(backups.iter().map(|root| (*root, DriveRole::Backup)));
        let mut seen = BTreeSet::new();
        for (root, _) in &roots {
            match classify_drive(root)? {
                DriveClass::Empty => {}
                DriveClass::KeystoneCa(_) | DriveClass::DamagedKeystone(_) => {
                    return Err(StoreError::DriveHoldsCa {
                        root: root.to_path_buf(),
                    });
                }
                DriveClass::KeystoneExport | DriveClass::Other => {
                    return Err(StoreError::DriveNotEmpty {
                        root: root.to_path_buf(),
                    });
                }
            }
            if !seen.insert(Dir::open(root)?.identity()?) {
                return Err(StoreError::DriveSet(format!(
                    "{} was given twice",
                    root.display()
                )));
            }
        }
        let ca_id = CaId::random()?;
        for (root, role) in &roots {
            let identity = DriveIdentity {
                format: IDENTITY_FORMAT,
                ca_id,
                drive_id: DriveId::random()?,
                role: *role,
                created,
            };
            init_drive(root, &identity)?;
        }
        let all: Vec<&Path> = roots.iter().map(|(root, _)| *root).collect();
        DriveSet::open(&all)
    }

    /// Opens the connected drives of one CA (FR-19 AC1). All must hold the same CA, and
    /// no drive may be given twice. Writing needs the primary and at least one backup
    /// ([`DriveSet::ensure_writable`]); reading, comparing and recovery analysis do not.
    pub fn open(roots: &[&Path]) -> Result<DriveSet, StoreError> {
        if roots.is_empty() {
            return Err(StoreError::NotEnoughDrives {
                primaries: 0,
                backups: 0,
            });
        }
        let mut drives = Vec::new();
        let mut folders = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for root in roots {
            let drive = CaDrive::open(root)?;
            if !folders.insert(drive.keystone.identity()?) || !ids.insert(drive.identity.drive_id) {
                return Err(StoreError::DriveSet(format!(
                    "{} is the same drive as another one given",
                    root.display()
                )));
            }
            drives.push(drive);
        }
        let ca = drives[0].identity.ca_id;
        if drives.iter().any(|drive| drive.identity.ca_id != ca) {
            return Err(StoreError::DriveSet(
                "the drives belong to different CAs".to_string(),
            ));
        }
        if drives
            .iter()
            .filter(|drive| drive.identity.role == DriveRole::Primary)
            .count()
            > 1
        {
            return Err(StoreError::DriveSet(
                "more than one drive is marked as the primary".to_string(),
            ));
        }
        drives.sort_by_key(|drive| (drive.identity.role, drive.identity.drive_id));
        Ok(DriveSet { drives })
    }

    /// The drives, primary first.
    pub fn drives(&self) -> &[CaDrive] {
        &self.drives
    }

    /// The CA these drives belong to.
    pub fn ca_id(&self) -> CaId {
        self.drives[0].identity.ca_id
    }

    /// FR-12 AC1: every change needs the primary drive and at least one backup.
    pub fn ensure_writable(&self) -> Result<(), StoreError> {
        let primaries = self
            .drives
            .iter()
            .filter(|drive| drive.identity.role == DriveRole::Primary)
            .count();
        let backups = self.drives.len() - primaries;
        if primaries == 1 && backups >= 1 {
            Ok(())
        } else {
            Err(StoreError::NotEnoughDrives { primaries, backups })
        }
    }

    /// Writes `rel/name` (inside `keystone/`) to every drive, then reads every copy back
    /// and compares SHA-256 (FR-12 AC1, AC2, AC4). Returns the SHA-256 on success.
    pub(crate) fn write_verified(
        &self,
        rel: &str,
        name: &str,
        data: &[u8],
        mode: WriteMode,
    ) -> Result<Sha256Digest, StoreError> {
        let copies = self.write_copies(rel, name, data, mode)?;
        self.verify_copies(&copies)
    }

    /// Phase 1 of [`DriveSet::write_verified`]: atomic write to every drive.
    pub(crate) fn write_copies(
        &self,
        rel: &str,
        name: &str,
        data: &[u8],
        mode: WriteMode,
    ) -> Result<WrittenCopies, StoreError> {
        self.ensure_writable()?;
        for drive in &self.drives {
            let dir = drive
                .dir_at(rel, true)?
                .ok_or_else(|| StoreError::Unsafe(format!("cannot create {rel}")))?;
            dir.write_atomic(name, data, mode)?;
        }
        Ok(WrittenCopies {
            rel: rel.to_string(),
            name: name.to_string(),
            expected: sha256(data),
            len: data.len(),
        })
    }

    /// Phase 2 of [`DriveSet::write_verified`]: read every copy back from the medium and
    /// compare SHA-256. Any mismatch is an error (FR-12 AC2).
    pub(crate) fn verify_copies(&self, copies: &WrittenCopies) -> Result<Sha256Digest, StoreError> {
        for drive in &self.drives {
            let dir = drive.dir_at(&copies.rel, false)?.ok_or_else(|| {
                StoreError::Unsafe(format!("{} disappeared from {}", copies.rel, drive.label()))
            })?;
            let back = dir.read_back(&copies.name, copies.len.max(MAX_OUTPUT_FILE_BYTES))?;
            let actual = sha256(&back);
            if actual != copies.expected {
                return Err(StoreError::ReadBackMismatch {
                    drive: drive.label(),
                    path: dir.child(&copies.name),
                    expected: copies.expected,
                    actual,
                });
            }
        }
        Ok(copies.expected)
    }
}

/// Creates the layout on one empty drive. `drive.json` is written last, so a drive
/// interrupted during setup is classified as damaged, never as a valid empty CA.
fn init_drive(root: &Path, identity: &DriveIdentity) -> Result<(), StoreError> {
    let keystone = Dir::open(root)?.create_dir(KEYSTONE_DIR)?;
    for name in [JOURNAL_DIR, STAGING_DIR]
        .into_iter()
        .chain(OutputDir::ALL.iter().map(|dir| dir.name()))
    {
        keystone.create_dir(name)?;
    }
    keystone.write_atomic(AUDIT_LOG_FILE, b"", WriteMode::CreateOnly)?;
    let bytes = to_json_file(identity);
    keystone.write_atomic(IDENTITY_FILE, &bytes, WriteMode::CreateOnly)?;
    let back = keystone.read_back(IDENTITY_FILE, MAX_METADATA_BYTES)?;
    if back != bytes {
        return Err(StoreError::ReadBackMismatch {
            drive: root.display().to_string(),
            path: keystone.child(IDENTITY_FILE),
            expected: sha256(&bytes),
            actual: sha256(&back),
        });
    }
    Ok(())
}

/// The export drive or folder: files carried by hand to issuing systems (FR-09, FR-22 AC2).
#[derive(Debug)]
pub struct ExportDrive {
    root: PathBuf,
    dir: Dir,
}

impl ExportDrive {
    /// Opens (creating if needed) `keystone-export/` on the drive at `root`. Refuses a CA
    /// drive, so CA drives are never carried to issuing systems.
    pub fn open(root: &Path) -> Result<ExportDrive, StoreError> {
        match classify_drive(root)? {
            DriveClass::KeystoneCa(_) | DriveClass::DamagedKeystone(_) => {
                Err(StoreError::DriveSet(format!(
                    "{} is a CA drive; use a separate export drive",
                    root.display()
                )))
            }
            _ => Ok(ExportDrive {
                root: root.to_path_buf(),
                dir: Dir::open(root)?.ensure_dir(EXPORT_DIR)?,
            }),
        }
    }

    /// The export drive's mount point.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of an exported file, for messages to the operator.
    pub fn path_of(&self, name: &str) -> PathBuf {
        self.dir.child(name)
    }

    /// Writes a new file (create-only, atomic) and verifies it by read-back SHA-256.
    pub fn write_file(&self, name: &str, data: &[u8]) -> Result<Sha256Digest, StoreError> {
        if !is_valid_name(name) {
            return Err(StoreError::Unsafe(format!(
                "invalid export file name {name:?}"
            )));
        }
        self.dir.write_atomic(name, data, WriteMode::CreateOnly)?;
        let expected = sha256(data);
        let actual = sha256(
            &self
                .dir
                .read_back(name, data.len().max(MAX_OUTPUT_FILE_BYTES))?,
        );
        if actual != expected {
            return Err(StoreError::ReadBackMismatch {
                drive: format!("export drive ({})", self.root.display()),
                path: self.dir.child(name),
                expected,
                actual,
            });
        }
        Ok(expected)
    }

    /// Reads an exported file.
    pub fn read_file(&self, name: &str, limit: usize) -> Result<Vec<u8>, StoreError> {
        self.dir.read(name, limit)
    }

    /// Reads an exported file of at most the output-file limit, or `None` if missing.
    pub(crate) fn read_existing(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        if !is_valid_name(name) {
            return Err(StoreError::Unsafe(format!(
                "invalid export file name {name:?}"
            )));
        }
        self.dir.read_if_exists(name, MAX_OUTPUT_FILE_BYTES)
    }
}

#[cfg(test)]
mod tests;
