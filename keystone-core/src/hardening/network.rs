//! FR-01: refuse to start while a network interface other than loopback is up.
//!
//! The check reads only local interface state from sysfs (`/sys/class/net/<name>/flags`
//! and `operstate`) with `std::fs`; it opens no socket of any kind (FR-01 AC3). The sysfs
//! folder is a parameter so tests use a fake tree in a temporary directory.
//!
//! Decision (conservative reading of "up"): an interface counts as up when it is
//! administratively up (`IFF_UP` in `flags`) *or* its `operstate` is `up`, `unknown`,
//! `dormant` or `testing`. So an Ethernet port that is switched on but has no cable, or
//! Wi-Fi that is on but not connected, also blocks start: either could connect at any
//! moment. Only interfaces with `IFF_LOOPBACK` are exempt. An interface whose state
//! cannot be read counts as up (fail closed).
#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use super::HardeningError;

/// Where Linux lists network interfaces.
pub const SYSFS_CLASS_NET: &str = "/sys/class/net";

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
/// Largest sysfs attribute read.
const MAX_ATTRIBUTE_BYTES: u64 = 4096;

/// A non-loopback interface that is up, and why it counts as up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveInterface {
    /// Interface name, for example `wlp2s0`.
    pub name: String,
    /// Why it counts as up.
    pub reason: String,
}

fn read_attribute(dir: &Path, name: &str) -> Option<String> {
    use std::io::Read;
    let file = fs::File::open(dir.join(name)).ok()?;
    let mut text = String::new();
    file.take(MAX_ATTRIBUTE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text.trim().to_string())
}

fn parse_flags(text: &str) -> Option<u32> {
    u32::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

/// Every interface under `class_net` that is up and not loopback (FR-01 AC1, AC3).
pub fn active_interfaces(class_net: &Path) -> Result<Vec<ActiveInterface>, HardeningError> {
    let unreadable = |reason: String| HardeningError::NetworkStateUnreadable {
        path: class_net.to_path_buf(),
        reason,
    };
    let mut active = Vec::new();
    for entry in fs::read_dir(class_net).map_err(|e| unreadable(e.to_string()))? {
        let entry = entry.map_err(|e| unreadable(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // sysfs entries are links to the device folders; follow them.
        let dir = entry.path();
        let flags = read_attribute(&dir, "flags")
            .as_deref()
            .and_then(parse_flags);
        let operstate = read_attribute(&dir, "operstate");
        let Some(flags) = flags else {
            active.push(ActiveInterface {
                name,
                reason: "its state cannot be read".to_string(),
            });
            continue;
        };
        if flags & IFF_LOOPBACK != 0 {
            continue;
        }
        let state = operstate.unwrap_or_else(|| "unreadable".to_string());
        let operational = matches!(
            state.as_str(),
            "up" | "unknown" | "dormant" | "testing" | "unreadable"
        );
        if flags & IFF_UP != 0 || operational {
            active.push(ActiveInterface {
                name,
                reason: format!(
                    "{}, state {state}",
                    if flags & IFF_UP != 0 {
                        "switched on"
                    } else {
                        "switched off"
                    }
                ),
            });
        }
    }
    active.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(active)
}

/// FR-01 AC1: an error naming every interface that is up, or `Ok` when none is.
pub fn check_no_active_network(class_net: &Path) -> Result<(), HardeningError> {
    let active = active_interfaces(class_net)?;
    if active.is_empty() {
        Ok(())
    } else {
        Err(HardeningError::NetworkInterfaceUp {
            interfaces: active.into_iter().map(|i| i.name).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct FakeSysfs {
        dir: tempfile::TempDir,
    }

    impl FakeSysfs {
        fn new() -> Self {
            FakeSysfs {
                dir: tempfile::tempdir().expect("tempdir"),
            }
        }

        fn add(&self, name: &str, flags: Option<&str>, operstate: Option<&str>) -> PathBuf {
            let dir = self.dir.path().join(name);
            fs::create_dir(&dir).expect("mkdir");
            if let Some(flags) = flags {
                fs::write(dir.join("flags"), format!("{flags}\n")).expect("flags");
            }
            if let Some(state) = operstate {
                fs::write(dir.join("operstate"), format!("{state}\n")).expect("operstate");
            }
            dir
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    #[test]
    fn fr01_ac1_an_interface_that_is_up_is_named() {
        // Covers: FR-01 AC1, FR-01 AC3
        let sysfs = FakeSysfs::new();
        sysfs.add("lo", Some("0x9"), Some("unknown"));
        sysfs.add("eth0", Some("0x1003"), Some("up"));
        sysfs.add("wlp2s0", Some("0x1003"), Some("dormant"));
        sysfs.add("usb0", Some("0x1002"), Some("down"));
        let active = active_interfaces(sysfs.path()).expect("read");
        let names: Vec<&str> = active.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["eth0", "wlp2s0"]);
        let error = check_no_active_network(sysfs.path()).expect_err("refused");
        let message = error.to_string();
        assert!(
            message.contains("eth0") && message.contains("wlp2s0"),
            "{message}"
        );
        assert!(
            !message.contains("usb0") && !message.contains("lo,"),
            "{message}"
        );
    }

    #[test]
    fn fr01_ac1_only_loopback_and_switched_off_interfaces_pass() {
        // Covers: FR-01 AC1
        let sysfs = FakeSysfs::new();
        sysfs.add("lo", Some("0x9"), Some("unknown"));
        sysfs.add("enp1s0", Some("0x1002"), Some("down"));
        sysfs.add("bnep0", Some("0x1002"), Some("lowerlayerdown"));
        assert!(check_no_active_network(sysfs.path()).is_ok());
    }

    #[test]
    fn fr01_ac1_switched_on_without_carrier_still_counts_as_up() {
        // Covers: FR-01 AC1
        for (flags, state) in [("0x1003", "down"), ("0x1002", "up"), ("0x1002", "unknown")] {
            let sysfs = FakeSysfs::new();
            sysfs.add("wwan0", Some(flags), Some(state));
            assert!(
                matches!(
                    check_no_active_network(sysfs.path()),
                    Err(HardeningError::NetworkInterfaceUp { ref interfaces }) if interfaces == &["wwan0"]
                ),
                "{flags} {state}"
            );
        }
    }

    #[test]
    fn fr01_unreadable_state_fails_closed() {
        // Covers: FR-01 AC1
        let sysfs = FakeSysfs::new();
        sysfs.add("eth9", None, Some("down"));
        sysfs.add("eth8", Some("garbage"), Some("down"));
        sysfs.add("eth7", Some("0x1002"), None);
        let error = check_no_active_network(sysfs.path()).expect_err("refused");
        assert!(
            matches!(error, HardeningError::NetworkInterfaceUp { ref interfaces } if interfaces.len() == 3)
        );
        let missing = sysfs.path().join("does-not-exist");
        assert!(matches!(
            check_no_active_network(&missing),
            Err(HardeningError::NetworkStateUnreadable { .. })
        ));
    }

    #[test]
    fn fr01_ac3_the_check_reads_only_sysfs_files() {
        // Covers: FR-01 AC3, SEC-03
        // The source of this module uses only std::fs: no socket, netlink or ioctl API.
        let source = include_str!("network.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .expect("code part")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<String>()
            .to_lowercase();
        for forbidden in ["socket", "netlink", "ioctl", "net::"] {
            assert!(
                !code.contains(forbidden),
                "network.rs must not use {forbidden}"
            );
        }
        // The real sysfs tree can be read too (whatever its state on this machine).
        assert!(active_interfaces(Path::new(SYSFS_CLASS_NET)).is_ok());
    }
}
