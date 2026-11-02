//! Low-level file access on drives (FR-12 AC4, SEC-08, SEC-20).
//!
//! Every access goes through a [`Dir`] handle (an open folder). Names are opened with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`, so no
//! symbolic link on a drive is ever followed and no path can leave the folder.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags};
use rustix::io::Errno;

use super::{ParseError, StoreError};
use crate::crypto::rand::fill;

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// How a file is put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteMode {
    /// Fails with [`StoreError::AlreadyExists`] if the name exists (`RENAME_NOREPLACE`).
    CreateOnly,
    /// Atomically replaces an existing file (only `audit.log` and `binary.sha256`).
    Replace,
}

/// Kind of a folder entry (symbolic links are never followed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    /// A regular file.
    File,
    /// A folder.
    Dir,
    /// Anything else: symbolic link, device, pipe, socket.
    Other,
}

/// An open folder on a drive.
#[derive(Debug)]
pub(crate) struct Dir {
    fd: OwnedFd,
    path: PathBuf,
}

pub(crate) fn io_err(
    action: &'static str,
    path: &Path,
    error: impl Into<std::io::Error>,
) -> StoreError {
    StoreError::Io {
        action,
        path: path.to_path_buf(),
        source: error.into(),
    }
}

impl Dir {
    /// Opens a folder by absolute or relative path (the drive root chosen by the operator).
    pub(crate) fn open(path: &Path) -> Result<Dir, StoreError> {
        let fd = rfs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| io_err("open folder", path, e))?;
        Ok(Dir {
            fd,
            path: path.to_path_buf(),
        })
    }

    /// A second handle to the same folder.
    pub(crate) fn reopen(&self) -> Result<Dir, StoreError> {
        let fd = rfs::openat2(
            &self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE,
        )
        .map_err(|e| io_err("open folder", &self.path, e))?;
        Ok(Dir {
            fd,
            path: self.path.clone(),
        })
    }

    /// The folder's path, for messages.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Path of a name inside this folder, for messages.
    pub(crate) fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Opens a sub-folder (`name` may contain `/`), never following links.
    pub(crate) fn open_dir(&self, name: &str) -> Result<Dir, StoreError> {
        self.open_dir_if_exists(name)?.ok_or_else(|| {
            io_err(
                "open folder",
                &self.child(name),
                std::io::Error::from(Errno::NOENT),
            )
        })
    }

    /// Opens a sub-folder, or `None` if it does not exist.
    pub(crate) fn open_dir_if_exists(&self, name: &str) -> Result<Option<Dir>, StoreError> {
        let path = self.child(name);
        match rfs::openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE,
        ) {
            Ok(fd) => Ok(Some(Dir { fd, path })),
            Err(Errno::NOENT) => Ok(None),
            Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => Err(StoreError::NotAFile { path }),
            Err(error) => Err(io_err("open folder", &path, error)),
        }
    }

    /// Creates a new sub-folder (single name). Fails if it exists.
    pub(crate) fn create_dir(&self, name: &str) -> Result<Dir, StoreError> {
        let path = self.child(name);
        match rfs::mkdirat(&self.fd, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(Errno::EXIST) => return Err(StoreError::AlreadyExists { path }),
            Err(error) => return Err(io_err("create folder", &path, error)),
        }
        self.sync()?;
        self.open_dir(name)
    }

    /// Opens a sub-folder (single name), creating it if missing.
    pub(crate) fn ensure_dir(&self, name: &str) -> Result<Dir, StoreError> {
        match self.open_dir_if_exists(name)? {
            Some(dir) => Ok(dir),
            None => match self.create_dir(name) {
                Err(StoreError::AlreadyExists { .. }) => self.open_dir(name),
                other => other,
            },
        }
    }

    /// The kind of `name`, or `None` if it does not exist. Links are not followed.
    pub(crate) fn kind(&self, name: &str) -> Result<Option<EntryKind>, StoreError> {
        match rfs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(kind_of(stat.st_mode))),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(io_err("inspect", &self.child(name), error)),
        }
    }

    /// Every entry of this folder except `.` and `..`, sorted by name. Names that are not
    /// UTF-8 are returned lossily with kind `Other`.
    pub(crate) fn entries(&self) -> Result<Vec<(String, EntryKind)>, StoreError> {
        let mut out = Vec::new();
        let dir = rfs::Dir::read_from(&self.fd).map_err(|e| io_err("list", &self.path, e))?;
        for entry in dir {
            let entry = entry.map_err(|e| io_err("list", &self.path, e))?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            match std::str::from_utf8(raw) {
                Ok(name) => {
                    let kind = self.kind(name)?.unwrap_or(EntryKind::Other);
                    out.push((name.to_string(), kind));
                }
                Err(_) => out.push((String::from_utf8_lossy(raw).into_owned(), EntryKind::Other)),
            }
        }
        out.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(out)
    }

    /// Reads a regular file of at most `limit` bytes (SEC-08).
    pub(crate) fn read(&self, name: &str, limit: usize) -> Result<Vec<u8>, StoreError> {
        self.read_if_exists(name, limit)?.ok_or_else(|| {
            io_err(
                "read",
                &self.child(name),
                std::io::Error::from(Errno::NOENT),
            )
        })
    }

    /// Reads a regular file of at most `limit` bytes, or `None` if it does not exist.
    pub(crate) fn read_if_exists(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.read_inner(name, limit, false)
    }

    /// Like [`Dir::read`], but first drops the file's clean pages from the page cache so
    /// the bytes come from the medium itself (FR-12 AC2 read-back).
    pub(crate) fn read_back(&self, name: &str, limit: usize) -> Result<Vec<u8>, StoreError> {
        self.read_inner(name, limit, true)?.ok_or_else(|| {
            io_err(
                "read back",
                &self.child(name),
                std::io::Error::from(Errno::NOENT),
            )
        })
    }

    fn read_inner(
        &self,
        name: &str,
        limit: usize,
        uncached: bool,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.child(name);
        // O_NONBLOCK: opening a pipe planted on a drive must not hang.
        let fd = match rfs::openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
            RESOLVE,
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::LOOP | Errno::XDEV) => return Err(StoreError::NotAFile { path }),
            Err(error) => return Err(io_err("open", &path, error)),
        };
        let stat = rfs::fstat(&fd).map_err(|e| io_err("inspect", &path, e))?;
        if kind_of(stat.st_mode) != EntryKind::File {
            return Err(StoreError::NotAFile { path });
        }
        let size = usize::try_from(stat.st_size).unwrap_or(usize::MAX);
        if size > limit {
            return Err(StoreError::Parse {
                path,
                source: ParseError::TooLarge { len: size, limit },
            });
        }
        if uncached {
            // Best effort: the data was fsynced, so its pages are clean and can be dropped.
            let _ = rfs::fadvise(&fd, 0, None, rfs::Advice::DontNeed);
        }
        let mut data = Vec::with_capacity(size);
        let mut file = File::from(fd);
        (&mut file)
            .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|e| io_err("read", &path, e))?;
        if data.len() > limit {
            return Err(StoreError::Parse {
                path,
                source: ParseError::TooLarge {
                    len: data.len(),
                    limit,
                },
            });
        }
        Ok(Some(data))
    }

    /// Writes `data` atomically as `name` (FR-12 AC4): temporary file in this folder,
    /// write all, fsync, rename (create-only or replace), fsync the folder.
    pub(crate) fn write_atomic(
        &self,
        name: &str,
        data: &[u8],
        mode: WriteMode,
    ) -> Result<(), StoreError> {
        let path = self.child(name);
        if mode == WriteMode::CreateOnly && self.kind(name)?.is_some() {
            return Err(StoreError::AlreadyExists { path });
        }
        #[cfg(any(test, not(feature = "production")))]
        super::fault::check(&path)?;
        let temp = temp_name(name)?;
        let fd = rfs::openat2(
            &self.fd,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
            RESOLVE,
        )
        .map_err(|e| io_err("create temporary file for", &path, e))?;
        let result = write_and_rename(self, fd, &temp, name, data, mode);
        if result.is_err() {
            let _ = rfs::unlinkat(&self.fd, temp.as_str(), AtFlags::empty());
        }
        result?;
        self.sync()
    }

    /// Moves `name` from this folder to `target/target_name` without ever replacing an
    /// existing file (`RENAME_NOREPLACE`), then fsyncs both folders.
    pub(crate) fn move_to(
        &self,
        name: &str,
        target: &Dir,
        target_name: &str,
    ) -> Result<(), StoreError> {
        let to = target.child(target_name);
        #[cfg(any(test, not(feature = "production")))]
        super::fault::check(&to)?;
        match rfs::renameat_with(
            &self.fd,
            name,
            &target.fd,
            target_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => return Err(StoreError::AlreadyExists { path: to }),
            Err(error) => return Err(io_err("move into place", &to, error)),
        }
        target.sync()?;
        self.sync()
    }

    /// Deletes a regular file. Used only to discard a cancelled operation's staged files
    /// (FR-16); recovery and repair never delete.
    pub(crate) fn remove_file(&self, name: &str) -> Result<(), StoreError> {
        #[cfg(any(test, not(feature = "production")))]
        super::fault::check(&self.child(name))?;
        rfs::unlinkat(&self.fd, name, AtFlags::empty())
            .map_err(|e| io_err("delete", &self.child(name), e))?;
        self.sync()
    }

    /// Removes an empty sub-folder. Returns `false` (and changes nothing) if it is not empty.
    pub(crate) fn remove_empty_dir(&self, name: &str) -> Result<bool, StoreError> {
        match rfs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR) {
            Ok(()) => {
                self.sync()?;
                Ok(true)
            }
            Err(Errno::NOTEMPTY | Errno::EXIST | Errno::NOENT) => Ok(false),
            Err(error) => Err(io_err("remove folder", &self.child(name), error)),
        }
    }

    /// fsyncs this folder, so renames and new entries in it are durable.
    pub(crate) fn sync(&self) -> Result<(), StoreError> {
        rfs::fsync(&self.fd).map_err(|e| io_err("flush folder", &self.path, e))
    }

    /// Device and inode of this folder (to detect the same folder given twice).
    pub(crate) fn identity(&self) -> Result<(u64, u64), StoreError> {
        let stat = rfs::fstat(&self.fd).map_err(|e| io_err("inspect", &self.path, e))?;
        Ok((stat.st_dev, stat.st_ino))
    }
}

fn write_and_rename(
    dir: &Dir,
    fd: OwnedFd,
    temp: &str,
    name: &str,
    data: &[u8],
    mode: WriteMode,
) -> Result<(), StoreError> {
    let path = dir.child(name);
    let mut file = File::from(fd);
    file.write_all(data)
        .map_err(|e| io_err("write", &path, e))?;
    file.sync_all().map_err(|e| io_err("flush", &path, e))?;
    drop(file);
    let renamed = match mode {
        WriteMode::CreateOnly => {
            rfs::renameat_with(&dir.fd, temp, &dir.fd, name, RenameFlags::NOREPLACE)
        }
        WriteMode::Replace => rfs::renameat(&dir.fd, temp, &dir.fd, name),
    };
    match renamed {
        Ok(()) => Ok(()),
        Err(Errno::EXIST) => Err(StoreError::AlreadyExists { path }),
        Err(error) => Err(io_err("rename into place", &path, error)),
    }
}

fn temp_name(name: &str) -> Result<String, StoreError> {
    let mut random = [0u8; 8];
    fill(&mut random)?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(".{name}.tmp-{suffix}"))
}

fn kind_of(mode: u32) -> EntryKind {
    match FileType::from_raw_mode(mode) {
        FileType::RegularFile => EntryKind::File,
        FileType::Directory => EntryKind::Dir,
        _ => EntryKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_testkit::TestDrives;

    fn dir(drives: &TestDrives) -> Dir {
        Dir::open(drives.ca_drive(0)).expect("open")
    }

    #[test]
    fn fr12_ac4_atomic_write_leaves_no_temporary_file() {
        // Covers: FR-12 AC4
        let drives = TestDrives::new(1);
        let root = dir(&drives);
        root.write_atomic("a.txt", b"hello", WriteMode::CreateOnly)
            .expect("write");
        assert_eq!(root.read("a.txt", 100).expect("read"), b"hello");
        assert_eq!(root.read_back("a.txt", 100).expect("read"), b"hello");
        let names: Vec<String> = root
            .entries()
            .expect("list")
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(names, vec!["a.txt".to_string()]);
        root.write_atomic("a.txt", b"second", WriteMode::Replace)
            .expect("replace");
        assert_eq!(root.read("a.txt", 100).expect("read"), b"second");
        assert_eq!(root.entries().expect("list").len(), 1);
    }

    #[test]
    fn sec20_create_only_never_overwrites() {
        // Covers: SEC-20
        let drives = TestDrives::new(1);
        let root = dir(&drives);
        root.write_atomic("k.key", b"original", WriteMode::CreateOnly)
            .expect("write");
        let error = root
            .write_atomic("k.key", b"replacement", WriteMode::CreateOnly)
            .expect_err("must refuse");
        assert!(matches!(error, StoreError::AlreadyExists { .. }));
        assert_eq!(root.read("k.key", 100).expect("read"), b"original");
        // No temporary file is left behind.
        assert_eq!(root.entries().expect("list").len(), 1);
        // Moving onto an existing name is refused too.
        root.write_atomic("other", b"x", WriteMode::CreateOnly)
            .expect("write");
        assert!(matches!(
            root.move_to("other", &root, "k.key"),
            Err(StoreError::AlreadyExists { .. })
        ));
        assert_eq!(root.read("k.key", 100).expect("read"), b"original");
    }

    #[test]
    fn sec08_reads_refuse_links_large_files_and_non_files() {
        // Covers: SEC-08
        let drives = TestDrives::new(1);
        let root_path = drives.ca_drive(0);
        let root = dir(&drives);
        std::fs::write(root_path.join("big"), vec![b'x'; 101]).expect("write");
        assert!(matches!(
            root.read("big", 100),
            Err(StoreError::Parse {
                source: ParseError::TooLarge {
                    len: 101,
                    limit: 100
                },
                ..
            })
        ));
        std::os::unix::fs::symlink("/etc/hostname", root_path.join("link")).expect("symlink");
        assert!(matches!(
            root.read("link", 100),
            Err(StoreError::NotAFile { .. })
        ));
        std::fs::create_dir(root_path.join("folder")).expect("mkdir");
        assert!(matches!(
            root.read("folder", 100),
            Err(StoreError::NotAFile { .. })
        ));
        assert!(matches!(
            root.read("../x", 100),
            Err(StoreError::NotAFile { .. })
        ));
        std::os::unix::fs::symlink("folder", root_path.join("dirlink")).expect("symlink");
        assert!(matches!(
            root.open_dir("dirlink"),
            Err(StoreError::NotAFile { .. })
        ));
        assert!(root.read_if_exists("missing", 10).expect("ok").is_none());
        assert_eq!(root.kind("link").expect("kind"), Some(EntryKind::Other));
    }

    #[test]
    fn remove_empty_dir_keeps_non_empty_folders() {
        let drives = TestDrives::new(1);
        let root = dir(&drives);
        let sub = root.create_dir("sub").expect("mkdir");
        sub.write_atomic("f", b"x", WriteMode::CreateOnly)
            .expect("write");
        assert!(!root.remove_empty_dir("sub").expect("rmdir"));
        sub.remove_file("f").expect("rm");
        assert!(root.remove_empty_dir("sub").expect("rmdir"));
        assert!(matches!(
            root.create_dir("sub2")
                .and_then(|_| root.create_dir("sub2")),
            Err(StoreError::AlreadyExists { .. })
        ));
    }
}
