//! CA drives, drive sets and the export drive (FR-12 AC1, AC2, FR-19, SEC-11, SEC-20).
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::audit::{AuditAction, AuditLog};
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
    /// The role the drive has now: the identity's role, unless the audit log records a
    /// later promotion of a backup to primary (Replace a lost drive). `drive.json` is
    /// create-only and never rewritten, so a promotion lives in the audit log.
    role: DriveRole,
}

impl CaDrive {
    /// Opens the CA drive mounted at `root`.
    pub fn open(root: &Path) -> Result<CaDrive, StoreError> {
        match classify_drive(root)? {
            DriveClass::KeystoneCa(identity) => Ok(CaDrive {
                root: root.to_path_buf(),
                keystone: Dir::open(root)?.open_dir(KEYSTONE_DIR)?,
                role: identity.role,
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

    /// The drive's identity, as stored in its `drive.json`.
    pub fn identity(&self) -> &DriveIdentity {
        &self.identity
    }

    /// The drive's role now: the identity's role, or primary/backup as the latest
    /// audited promotion in the connected drives' most complete audit log says
    /// ([`DriveSet::open`]). Use this, not `identity().role`, for what the drive is.
    pub fn role(&self) -> DriveRole {
        self.role
    }

    /// A drive being set up by "Replace a lost drive": its folder exists, its identity
    /// is only in memory until it is written last.
    pub(crate) fn provisional(root: &Path, keystone: Dir, identity: DriveIdentity) -> CaDrive {
        CaDrive {
            root: root.to_path_buf(),
            keystone,
            role: identity.role,
            identity,
        }
    }

    /// The drive's mount point.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A short label for the operator: `primary drive 1a2b3c4d (/media/usb1)`.
    pub fn label(&self) -> String {
        let role = match self.role {
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

/// The drive the latest audited promotion made the primary, read from the most complete
/// verified audit log among `drives` (Replace a lost drive).
fn promoted_primary(drives: &[CaDrive]) -> Option<DriveId> {
    drives
        .iter()
        .filter_map(|drive| drive.read_audit_log().valid().cloned())
        .max_by_key(AuditLog::len)?
        .entries()
        .iter()
        .rev()
        .find_map(|entry| {
            (entry.action == AuditAction::DriveRepair)
                .then(|| entry.details.as_ref()?.primary_promoted)
                .flatten()
        })
}

/// SEC-11: true when the folders `a` and `b` are on the same device (the same file
/// system), so they cannot be two separate CA drives: one drive failure would lose both.
/// The folders need not be mount points; a folder on a USB drive is on that drive.
///
/// A production build compares the device numbers (`st_dev`) the operating system
/// reports, always. Other builds go through the test seam in `store::fault`, because
/// test drives are folders on one file system: there two folders count as one device
/// when a test put them on the same simulated device, or when one is inside the other.
pub(crate) fn same_device(a: &Path, b: &Path) -> Result<bool, StoreError> {
    let same = Dir::open(a)?.identity()?.0 == Dir::open(b)?.identity()?.0;
    #[cfg(any(test, not(feature = "production")))]
    let same = super::fault::same_device(a, b, same);
    Ok(same)
}

/// SEC-11: refuses two of `drives` (folder and label) on one device ([`same_device`]).
pub(crate) fn check_separate_devices(drives: &[(&Path, String)]) -> Result<(), StoreError> {
    for (index, (first, first_label)) in drives.iter().enumerate() {
        for (second, second_label) in &drives[index + 1..] {
            if same_device(first, second)? {
                return Err(StoreError::DriveSet(format!(
                    "{second_label} is on the same device as {first_label}; every CA drive must be a separate USB drive, so one failed drive never takes two copies with it (SEC-11)"
                )));
            }
        }
    }
    Ok(())
}

/// The folders chosen for a new CA with a label for each, primary first.
fn chosen_labels<'a>(primary: &'a Path, backups: &[&'a Path]) -> Vec<(&'a Path, String)> {
    std::iter::once((
        primary,
        format!("the primary drive ({})", primary.display()),
    ))
    .chain(
        backups
            .iter()
            .map(|root| (*root, format!("the backup drive ({})", root.display()))),
    )
    .collect()
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
    /// and any drive that is not empty. SEC-11: refuses two drives on one device
    /// ([`same_device`]). Nothing is written until every drive passed.
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
        check_separate_devices(&chosen_labels(primary, backups))?;
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

    /// Opens the connected drives of one CA (FR-19 AC1). All must hold the same CA, no
    /// drive may be given twice, and no two drives may be on one device (SEC-11,
    /// [`same_device`]). Writing needs the primary and at least one backup
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
        let labelled: Vec<(&Path, String)> = drives
            .iter()
            .map(|drive| (drive.root(), drive.label()))
            .collect();
        check_separate_devices(&labelled)?;
        let ca = drives[0].identity.ca_id;
        if drives.iter().any(|drive| drive.identity.ca_id != ca) {
            return Err(StoreError::DriveSet(
                "the drives belong to different CAs".to_string(),
            ));
        }
        // A backup promoted to primary (Replace a lost drive) is the only primary; every
        // other drive, including a former primary found again, is a backup.
        if let Some(primary) = promoted_primary(&drives) {
            for drive in &mut drives {
                drive.role = if drive.identity.drive_id == primary {
                    DriveRole::Primary
                } else {
                    DriveRole::Backup
                };
            }
        }
        if drives
            .iter()
            .filter(|drive| drive.role == DriveRole::Primary)
            .count()
            > 1
        {
            return Err(StoreError::DriveSet(
                "more than one drive is marked as the primary".to_string(),
            ));
        }
        drives.sort_by_key(|drive| (drive.role, drive.identity.drive_id));
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
            .filter(|drive| drive.role == DriveRole::Primary)
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

/// The folders `init_drive` creates inside `keystone/`.
pub(crate) fn layout_folders() -> impl Iterator<Item = &'static str> {
    [JOURNAL_DIR, STAGING_DIR]
        .into_iter()
        .chain(OutputDir::ALL.iter().map(|dir| dir.name()))
}

/// Creates the layout on one empty drive. `drive.json` is written last, so a drive
/// interrupted during setup is classified as damaged, never as a valid empty CA.
fn init_drive(root: &Path, identity: &DriveIdentity) -> Result<(), StoreError> {
    let keystone = Dir::open(root)?.create_dir(KEYSTONE_DIR)?;
    for name in layout_folders() {
        keystone.create_dir(name)?;
    }
    keystone.write_atomic(AUDIT_LOG_FILE, b"", WriteMode::CreateOnly)?;
    write_identity(root, &keystone, identity)
}

pub(crate) fn write_identity(
    root: &Path,
    keystone: &Dir,
    identity: &DriveIdentity,
) -> Result<(), StoreError> {
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

/// What one drive holds of an interrupted [`DriveSet::create`] (review finding 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupProgress {
    /// Nothing: the setup never reached this drive.
    Empty,
    /// Only the layout of an interrupted setup: `keystone/` with empty layout folders, at
    /// most an empty `audit.log`, and the drive identity if setup got that far. Nothing
    /// else (no journal entry, record, key, certificate or CRL).
    Started {
        /// The drive identity, when it was written.
        identity: Option<DriveIdentity>,
    },
}

/// An unfinished CA setup: drives an interrupted [`DriveSet::create`] left behind
/// (review finding 11). [`DriveSet::finish_setup`] completes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnfinishedSetup {
    /// The CA the interrupted setup created, when a drive identity was written.
    pub ca_id: Option<CaId>,
    /// Each drive as chosen (primary first) with what it holds.
    pub drives: Vec<(PathBuf, DriveRole, SetupProgress)>,
}

/// What an interrupted setup left on `root`, or `None` when the drive holds anything
/// else (then it is a CA, damaged, or not empty, and never touched).
fn setup_progress(root: &Path) -> Result<Option<SetupProgress>, StoreError> {
    let top = Dir::open(root)?;
    let entries: Vec<(String, EntryKind)> = top
        .entries()?
        .into_iter()
        .filter(|(name, kind)| !(name == "lost+found" && *kind == EntryKind::Dir))
        .collect();
    if entries.is_empty() {
        return Ok(Some(SetupProgress::Empty));
    }
    if entries.len() != 1 || entries[0] != (KEYSTONE_DIR.to_string(), EntryKind::Dir) {
        return Ok(None);
    }
    let keystone = top.open_dir(KEYSTONE_DIR)?;
    let mut identity = None;
    for (name, kind) in keystone.entries()? {
        if name.starts_with('.') && kind == EntryKind::File {
            // A temporary file of a write the interruption cut off.
            continue;
        }
        if layout_folders().any(|folder| folder == name) {
            if kind != EntryKind::Dir || !keystone.open_dir(&name)?.entries()?.is_empty() {
                return Ok(None);
            }
        } else if name == AUDIT_LOG_FILE {
            if kind != EntryKind::File || !keystone.read(&name, 0).is_ok_and(|b| b.is_empty()) {
                return Ok(None);
            }
        } else if name == IDENTITY_FILE {
            match read_identity(&keystone) {
                Ok(found) => identity = Some(found),
                Err(_) => return Ok(None),
            }
        } else {
            return Ok(None);
        }
    }
    Ok(Some(SetupProgress::Started { identity }))
}

/// Review finding 11: recognises drives that an interrupted [`DriveSet::create`] left
/// behind. `Some` when every chosen drive is empty or holds only such a layout, at least
/// one holds a layout, at least one has no drive identity yet, and every identity found
/// names the same CA and the role chosen for that drive. `None` when the drives are
/// something else (all empty, a finished CA, or anything with other content: the
/// normal checks then apply). A different CA, or a drive chosen in the wrong role, is
/// refused (SEC-20).
pub fn unfinished_setup(
    primary: &Path,
    backups: &[&Path],
) -> Result<Option<UnfinishedSetup>, StoreError> {
    let mut drives = Vec::new();
    let mut seen = BTreeSet::new();
    let chosen = std::iter::once((primary, DriveRole::Primary))
        .chain(backups.iter().map(|root| (*root, DriveRole::Backup)));
    for (root, role) in chosen {
        if !seen.insert(Dir::open(root)?.identity()?) {
            return Err(StoreError::DriveSet(format!(
                "{} was given twice",
                root.display()
            )));
        }
        let Some(progress) = setup_progress(root)? else {
            return Ok(None);
        };
        drives.push((root.to_path_buf(), role, progress));
    }
    let identities: Vec<(&PathBuf, DriveRole, &DriveIdentity)> = drives
        .iter()
        .filter_map(|(root, role, progress)| match progress {
            SetupProgress::Started {
                identity: Some(identity),
            } => Some((root, *role, identity)),
            _ => None,
        })
        .collect();
    let ca_id = identities.first().map(|(_, _, identity)| identity.ca_id);
    for (root, role, identity) in &identities {
        if Some(identity.ca_id) != ca_id {
            return Err(StoreError::DriveSet(format!(
                "{} was set up for a different CA; drives of two CAs are never combined",
                root.display()
            )));
        }
        if identity.role != *role {
            return Err(StoreError::DriveSet(format!(
                "{} was set up as a {} drive; choose it in that role to finish the setup",
                root.display(),
                match identity.role {
                    DriveRole::Primary => "primary",
                    DriveRole::Backup => "backup",
                }
            )));
        }
    }
    let started = drives
        .iter()
        .any(|(_, _, progress)| matches!(progress, SetupProgress::Started { .. }));
    if !started || identities.len() == drives.len() {
        return Ok(None);
    }
    Ok(Some(UnfinishedSetup { ca_id, drives }))
}

impl DriveSet {
    /// Review finding 11: "Finish setting up these drives" after an interrupted
    /// [`DriveSet::create`]. Re-checks [`unfinished_setup`], then completes each drive's
    /// layout: missing folders, a missing empty `audit.log` and, last, a missing drive
    /// identity (with the CA id an earlier identity already holds, or a new one). Nothing
    /// that exists is overwritten or deleted.
    pub fn finish_setup(
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
        let setup = unfinished_setup(primary, backups)?.ok_or_else(|| {
            StoreError::Unsafe(
                "these drives do not hold an unfinished CA setup; nothing was changed".into(),
            )
        })?;
        check_separate_devices(&chosen_labels(primary, backups))?;
        let ca_id = match setup.ca_id {
            Some(ca_id) => ca_id,
            None => CaId::random()?,
        };
        for (root, role, progress) in &setup.drives {
            let keystone = match progress {
                SetupProgress::Empty => Dir::open(root)?.create_dir(KEYSTONE_DIR)?,
                SetupProgress::Started { .. } => Dir::open(root)?.open_dir(KEYSTONE_DIR)?,
            };
            for name in layout_folders() {
                keystone.ensure_dir(name)?;
            }
            if keystone.kind(AUDIT_LOG_FILE)?.is_none() {
                keystone.write_atomic(AUDIT_LOG_FILE, b"", WriteMode::CreateOnly)?;
            }
            if keystone.kind(IDENTITY_FILE)?.is_none() {
                let identity = DriveIdentity {
                    format: IDENTITY_FORMAT,
                    ca_id,
                    drive_id: DriveId::random()?,
                    role: *role,
                    created,
                };
                write_identity(root, &keystone, &identity)?;
            }
        }
        let all: Vec<&Path> = setup
            .drives
            .iter()
            .map(|(root, _, _)| root.as_path())
            .collect();
        DriveSet::open(&all)
    }
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
