//! SEC-03: refuse to start with an inherited socket that is not AF_UNIX, or with an
//! inherited io_uring instance.
//!
//! A seccomp filter only stops *new* sockets. A process started by something else could
//! inherit an open network socket. At startup Keystone lists its open file descriptors in
//! `/proc/self/fd` (each socket reads as the link `socket:[<inode>]`) and looks the inodes
//! up in `/proc/self/net/unix`, the kernel's table of AF_UNIX sockets. Any socket that is
//! not in that table (AF_INET, AF_INET6, AF_PACKET, AF_NETLINK ...) stops the start. An
//! inherited io_uring instance (the link `anon_inode:[io_uring]`) stops it too: with
//! IORING_OP_SOCKET it can create an AF_INET socket without ever calling `socket()`, so
//! the seccomp filter (which also blocks `io_uring_setup`, `io_uring_enter` and
//! `io_uring_register`) is not the only guard. Only files are read; no socket API is used. The `/proc` root is a parameter so tests use a
//! fake tree. Decision: an unreadable `/proc` also stops the start (fail closed).
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use super::HardeningError;

/// The real `/proc`.
pub const PROC_ROOT: &str = "/proc";
/// Largest `/proc/self/net/unix` read.
const MAX_UNIX_TABLE_BYTES: u64 = 64 * 1024 * 1024;

fn unreadable(path: &Path, reason: impl ToString) -> HardeningError {
    HardeningError::ProcUnreadable {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

/// Parses the inode column of `/proc/<pid>/net/unix`.
pub fn parse_unix_table(text: &str) -> Result<BTreeSet<u64>, String> {
    let mut lines = text.lines();
    let header = lines.next().ok_or("empty table")?;
    if !header.starts_with("Num") || !header.contains("Inode") {
        return Err("unexpected table header".to_string());
    }
    let mut inodes = BTreeSet::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let inode = line
            .split_whitespace()
            .nth(6)
            .and_then(|field| field.parse().ok())
            .ok_or_else(|| format!("unexpected line {line:?}"))?;
        inodes.insert(inode);
    }
    Ok(inodes)
}

/// The link target of an io_uring instance in `/proc/<pid>/fd`.
const IO_URING_LINK: &str = "anon_inode:[io_uring]";

/// `socket:[123]` -> 123.
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Every open file descriptor of this process (under `proc_root`) with its link target.
fn descriptors(proc_root: &Path) -> Result<Vec<(u32, String)>, HardeningError> {
    let fd_dir = proc_root.join("self/fd");
    let mut out = Vec::new();
    for entry in fs::read_dir(&fd_dir).map_err(|e| unreadable(&fd_dir, e))? {
        let entry = entry.map_err(|e| unreadable(&fd_dir, e))?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        // The descriptor used to list the folder is gone by now: skip vanished entries.
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        out.push((fd, target.to_string_lossy().into_owned()));
    }
    out.sort_unstable();
    Ok(out)
}

/// File descriptors of this process (under `proc_root`) that are io_uring instances.
pub fn io_uring_instances(proc_root: &Path) -> Result<Vec<u32>, HardeningError> {
    Ok(descriptors(proc_root)?
        .into_iter()
        .filter(|(_, target)| target == IO_URING_LINK)
        .map(|(fd, _)| fd)
        .collect())
}

/// File descriptors of this process (under `proc_root`) that are sockets but not AF_UNIX.
pub fn non_unix_sockets(proc_root: &Path) -> Result<Vec<u32>, HardeningError> {
    let sockets: Vec<(u32, u64)> = descriptors(proc_root)?
        .into_iter()
        .filter_map(|(fd, target)| socket_inode(&target).map(|inode| (fd, inode)))
        .collect();
    if sockets.is_empty() {
        return Ok(Vec::new());
    }
    let table_path = proc_root.join("self/net/unix");
    let mut text = String::new();
    fs::File::open(&table_path)
        .map_err(|e| unreadable(&table_path, e))?
        .take(MAX_UNIX_TABLE_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| unreadable(&table_path, e))?;
    let unix = parse_unix_table(&text).map_err(|e| unreadable(&table_path, e))?;
    let mut refused: Vec<u32> = sockets
        .into_iter()
        .filter(|(_, inode)| !unix.contains(inode))
        .map(|(fd, _)| fd)
        .collect();
    refused.sort_unstable();
    Ok(refused)
}

/// SEC-03: an error naming every inherited non-AF_UNIX socket, or every inherited
/// io_uring instance, or `Ok`.
pub fn check_no_inherited_network_sockets(proc_root: &Path) -> Result<(), HardeningError> {
    let descriptors = non_unix_sockets(proc_root)?;
    if !descriptors.is_empty() {
        return Err(HardeningError::InheritedSocket { descriptors });
    }
    let descriptors = io_uring_instances(proc_root)?;
    if !descriptors.is_empty() {
        return Err(HardeningError::InheritedIoUring { descriptors });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const TABLE: &str = "Num       RefCount Protocol Flags    Type St Inode Path\n\
        0000000000000000: 00000002 00000000 00010000 0001 01 1001 /run/pcscd/pcscd.comm\n\
        0000000000000000: 00000003 00000000 00000000 0001 03 1002\n";

    fn fake_proc(links: &[(&str, &str)], table: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let fd = dir.path().join("self/fd");
        fs::create_dir_all(&fd).expect("mkdir");
        fs::create_dir_all(dir.path().join("self/net")).expect("mkdir");
        for (name, target) in links {
            symlink(target, fd.join(name)).expect("symlink");
        }
        if let Some(table) = table {
            fs::write(dir.path().join("self/net/unix"), table).expect("table");
        }
        dir
    }

    #[test]
    fn sec03_inherited_inet_socket_is_refused() {
        // Covers: SEC-03
        let proc_root = fake_proc(
            &[
                ("0", "/dev/pts/0"),
                ("3", "socket:[1001]"),
                ("4", "socket:[5555]"),
                ("7", "pipe:[42]"),
                ("9", "socket:[6666]"),
            ],
            Some(TABLE),
        );
        assert_eq!(
            non_unix_sockets(proc_root.path()).expect("read"),
            vec![4, 9]
        );
        let error = check_no_inherited_network_sockets(proc_root.path()).expect_err("refused");
        assert!(error.to_string().contains("4, 9"), "{error}");
    }

    #[test]
    fn sec03_unix_sockets_and_files_are_fine() {
        // Covers: SEC-03
        let proc_root = fake_proc(
            &[
                ("0", "/dev/null"),
                ("3", "socket:[1001]"),
                ("5", "socket:[1002]"),
            ],
            Some(TABLE),
        );
        assert!(check_no_inherited_network_sockets(proc_root.path()).is_ok());
        let no_sockets = fake_proc(&[("0", "/dev/null")], None);
        assert!(check_no_inherited_network_sockets(no_sockets.path()).is_ok());
    }

    #[test]
    fn regression_an_inherited_io_uring_instance_is_refused() {
        // Covers: SEC-03
        // Regression (review finding 12): an inherited io_uring descriptor could create
        // AF_INET sockets with IORING_OP_SOCKET without calling socket().
        let proc_root = fake_proc(
            &[
                ("0", "/dev/null"),
                ("3", "socket:[1001]"),
                ("6", "anon_inode:[io_uring]"),
                ("8", "anon_inode:[eventfd]"),
                ("11", "anon_inode:[io_uring]"),
            ],
            Some(TABLE),
        );
        assert_eq!(
            io_uring_instances(proc_root.path()).expect("read"),
            vec![6, 11]
        );
        let error = check_no_inherited_network_sockets(proc_root.path()).expect_err("refused");
        assert!(
            matches!(error, HardeningError::InheritedIoUring { ref descriptors } if descriptors == &[6, 11]),
            "{error}"
        );
        assert!(error.to_string().contains("io_uring"), "{error}");
    }

    #[test]
    fn sec03_unreadable_proc_fails_closed() {
        // Covers: SEC-03
        let missing_table = fake_proc(&[("3", "socket:[1001]")], None);
        assert!(matches!(
            check_no_inherited_network_sockets(missing_table.path()),
            Err(HardeningError::ProcUnreadable { .. })
        ));
        let bad_table = fake_proc(&[("3", "socket:[1001]")], Some("garbage\n"));
        assert!(check_no_inherited_network_sockets(bad_table.path()).is_err());
        let nothing = tempfile::tempdir().expect("tempdir");
        assert!(check_no_inherited_network_sockets(nothing.path()).is_err());
    }

    #[test]
    fn real_proc_is_readable() {
        // The real tables parse (the result depends on how the tests were started).
        assert!(non_unix_sockets(Path::new(PROC_ROOT)).is_ok());
        assert!(io_uring_instances(Path::new(PROC_ROOT)).is_ok());
        let table = fs::read_to_string("/proc/self/net/unix").expect("unix table");
        assert!(parse_unix_table(&table).is_ok());
    }
}
