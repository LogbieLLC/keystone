//! Command-line options.
//!
//! A production build takes no arguments: the operator chooses the drives in the GUI
//! (conservative reading: nothing on the air-gapped laptop should depend on how the
//! program was started). Development and test builds also accept the drive folders,
//! a simulator setup and one test hook, so the E2E tests (TESTING.md) do not need a
//! file chooser.
//!
//! ```text
//! keystone [--primary DIR] [--backup DIR]... [--export DIR] [--new-drive DIR]
//!          [--test-hook passphrase-confirmation|slow-keygen] [--test-words N]
//!          [--sim-serial N] [--sim-firmware X.Y.Z]
//!          [--sim-slot empty|key-only|key-and-certificate|certificate-only]
//!          [--harden]
//! ```
//!
//! `--harden` (development builds only) installs the SEC-03 socket filter and refuses
//! inherited network sockets and io_uring instances before anything else starts, as the
//! production build always does; it is how the strace E2E run checks SEC-03 with the
//! YubiKey simulator. The FR-01 network-interface check stays production-only (FR-01
//! AC2). `--new-drive` prefills the new, empty drive of "Replace a lost drive".
#![forbid(unsafe_code)]

use std::path::PathBuf;

/// What the YubiKey simulator holds in slot 9C when it starts (development builds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SimSlot {
    /// Empty.
    #[default]
    Empty,
    /// A key without a certificate (an interrupted setup).
    KeyOnly,
    /// A key and a certificate.
    KeyAndCertificate,
    /// Only a certificate.
    CertificateOnly,
}

/// Simulator settings from the command line (development builds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SimOptions {
    /// Device serial number (`None`: the simulator default).
    pub serial: Option<u32>,
    /// Firmware `(major, minor, patch)` (`None`: the simulator default).
    pub firmware: Option<(u8, u8, u8)>,
    /// What slot 9C holds.
    pub slot: SimSlot,
}

/// Test hooks (development builds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestHook {
    /// Generate a master passphrase of `words` words and open its show-once screen.
    PassphraseConfirmation {
        /// Number of words (10 to 20).
        words: usize,
    },
    /// NFR-03: software key generation keeps running until the operator presses Cancel
    /// (or the backend's slow-keygen limit passes), so the E2E test can check that the
    /// window stays responsive and that Cancel works, whatever the machine's speed.
    SlowKeygen,
}

/// Parsed command-line options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options {
    /// Primary CA drive folder.
    pub primary: Option<PathBuf>,
    /// Backup CA drive folders.
    pub backups: Vec<PathBuf>,
    /// Export folder.
    pub export: Option<PathBuf>,
    /// Test hook, if any.
    pub test_hook: Option<TestHook>,
    /// Simulator settings.
    pub sim: SimOptions,
    /// The new, empty drive for "Replace a lost drive" (prefills its field).
    pub new_drive: Option<PathBuf>,
    /// Install the SEC-03 socket filter at start (development builds; production
    /// always does).
    pub harden: bool,
}

/// A command line that cannot be used. The message is shown to the operator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// Production builds take no arguments.
    #[error(
        "this production build of Keystone takes no command-line arguments; choose the drives in the window"
    )]
    ArgumentsInProduction,
    /// An option Keystone does not know.
    #[error("unknown command-line option {0:?}")]
    Unknown(String),
    /// An option without its value.
    #[error("the option {0} needs a value")]
    MissingValue(&'static str),
    /// A value that cannot be used.
    #[error("invalid value {value:?} for {option}: {reason}")]
    InvalidValue {
        /// The option.
        option: &'static str,
        /// The value given.
        value: String,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// The same single-value option twice.
    #[error("the option {0} was given twice")]
    Repeated(&'static str),
}

/// Fewest words for the passphrase test hook.
const MIN_TEST_WORDS: usize = 10;
/// Most words for the passphrase test hook.
const MAX_TEST_WORDS: usize = 20;

/// Parses the arguments after the program name. `production` is true in a production
/// build, which accepts no arguments at all.
pub fn parse(args: &[String], production: bool) -> Result<Options, CliError> {
    if production {
        return if args.is_empty() {
            Ok(Options::default())
        } else {
            Err(CliError::ArgumentsInProduction)
        };
    }
    let mut options = Options::default();
    let mut hook: Option<&str> = None;
    let mut words: Option<usize> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == HARDEN_FLAG {
            if options.harden {
                return Err(CliError::Repeated(HARDEN_FLAG));
            }
            options.harden = true;
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let option = known_option(name).ok_or_else(|| CliError::Unknown(arg.clone()))?;
        let value = match inline {
            Some(value) => value,
            None => iter.next().cloned().ok_or(CliError::MissingValue(option))?,
        };
        match option {
            "--primary" => set_once(&mut options.primary, option, path(option, &value)?)?,
            "--backup" => options.backups.push(path(option, &value)?),
            "--export" => set_once(&mut options.export, option, path(option, &value)?)?,
            "--new-drive" => set_once(&mut options.new_drive, option, path(option, &value)?)?,
            "--test-hook" => {
                if hook.is_some() {
                    return Err(CliError::Repeated(option));
                }
                hook = Some(match value.as_str() {
                    "passphrase-confirmation" => "passphrase-confirmation",
                    "slow-keygen" => "slow-keygen",
                    _ => {
                        return Err(CliError::InvalidValue {
                            option,
                            value,
                            reason: "the test hooks are passphrase-confirmation and slow-keygen",
                        });
                    }
                });
            }
            "--test-words" => {
                let parsed = value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (MIN_TEST_WORDS..=MAX_TEST_WORDS).contains(n))
                    .ok_or_else(|| CliError::InvalidValue {
                        option,
                        value: value.clone(),
                        reason: "use a whole number from 10 to 20",
                    })?;
                set_once(&mut words, option, parsed)?;
            }
            "--sim-serial" => {
                let serial = value
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| CliError::InvalidValue {
                        option,
                        value: value.clone(),
                        reason: "use a positive whole number",
                    })?;
                set_once(&mut options.sim.serial, option, serial)?;
            }
            "--sim-firmware" => {
                let firmware = parse_firmware(&value).ok_or_else(|| CliError::InvalidValue {
                    option,
                    value: value.clone(),
                    reason: "use MAJOR.MINOR.PATCH, for example 5.7.4",
                })?;
                set_once(&mut options.sim.firmware, option, firmware)?;
            }
            "--sim-slot" => {
                options.sim.slot = match value.as_str() {
                    "empty" => SimSlot::Empty,
                    "key-only" => SimSlot::KeyOnly,
                    "key-and-certificate" => SimSlot::KeyAndCertificate,
                    "certificate-only" => SimSlot::CertificateOnly,
                    _ => {
                        return Err(CliError::InvalidValue {
                            option,
                            value,
                            reason: "use empty, key-only, key-and-certificate or certificate-only",
                        });
                    }
                };
            }
            _ => return Err(CliError::Unknown(arg.clone())),
        }
    }
    match (hook, words) {
        (Some("slow-keygen"), None) => options.test_hook = Some(TestHook::SlowKeygen),
        (Some("passphrase-confirmation"), words) => {
            options.test_hook = Some(TestHook::PassphraseConfirmation {
                words: words.unwrap_or(MIN_TEST_WORDS),
            });
        }
        (_, Some(_)) => {
            return Err(CliError::InvalidValue {
                option: "--test-words",
                value: String::new(),
                reason: "it is used only with --test-hook passphrase-confirmation",
            });
        }
        (_, None) => {}
    }
    Ok(options)
}

/// The development-only flag that installs the SEC-03 socket filter at start.
pub const HARDEN_FLAG: &str = "--harden";

/// True when a development build was asked to install the socket filter. Read before
/// anything else starts, so it only looks for the flag; [`parse`] checks the rest.
pub fn wants_hardening(args: &[String], production: bool) -> bool {
    !production && args.iter().any(|arg| arg == HARDEN_FLAG)
}

fn known_option(name: &str) -> Option<&'static str> {
    [
        "--primary",
        "--backup",
        "--export",
        "--new-drive",
        "--test-hook",
        "--test-words",
        "--sim-serial",
        "--sim-firmware",
        "--sim-slot",
    ]
    .into_iter()
    .find(|known| *known == name)
}

fn set_once<T>(slot: &mut Option<T>, option: &'static str, value: T) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(CliError::Repeated(option));
    }
    *slot = Some(value);
    Ok(())
}

fn path(option: &'static str, value: &str) -> Result<PathBuf, CliError> {
    if value.is_empty() {
        return Err(CliError::InvalidValue {
            option,
            value: value.to_string(),
            reason: "the folder path is empty",
        });
    }
    Ok(PathBuf::from(value))
}

fn parse_firmware(text: &str) -> Option<(u8, u8, u8)> {
    let mut parts = text.split('.').map(|part| {
        (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse::<u8>().ok())
            .flatten()
    });
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn production_build_refuses_every_argument() {
        // Covers: NFR-10 (drives are chosen in the GUI), HR-1 (no hidden start modes)
        assert_eq!(parse(&[], true), Ok(Options::default()));
        assert_eq!(
            parse(&args(&["--primary", "/media/a"]), true),
            Err(CliError::ArgumentsInProduction)
        );
    }

    #[test]
    fn drive_folders_are_accepted_in_development_builds() {
        // Covers: TESTING.md E2E (paths without a file chooser)
        let options = parse(
            &args(&[
                "--primary",
                "/tmp/a",
                "--backup=/tmp/b",
                "--backup",
                "/tmp/c",
                "--export",
                "/tmp/e",
            ]),
            false,
        )
        .expect("valid");
        assert_eq!(options.primary, Some(PathBuf::from("/tmp/a")));
        assert_eq!(
            options.backups,
            vec![PathBuf::from("/tmp/b"), PathBuf::from("/tmp/c")]
        );
        assert_eq!(options.export, Some(PathBuf::from("/tmp/e")));
        assert_eq!(options.test_hook, None);
    }

    #[test]
    fn test_hook_and_simulator_options() {
        let options = parse(
            &args(&[
                "--test-hook",
                "passphrase-confirmation",
                "--test-words",
                "12",
                "--sim-firmware",
                "5.4.3",
                "--sim-slot",
                "key-only",
                "--sim-serial",
                "7",
            ]),
            false,
        )
        .expect("valid");
        assert_eq!(
            options.test_hook,
            Some(TestHook::PassphraseConfirmation { words: 12 })
        );
        assert_eq!(options.sim.firmware, Some((5, 4, 3)));
        assert_eq!(options.sim.slot, SimSlot::KeyOnly);
        assert_eq!(options.sim.serial, Some(7));
        let default_words =
            parse(&args(&["--test-hook=passphrase-confirmation"]), false).expect("valid");
        assert_eq!(
            default_words.test_hook,
            Some(TestHook::PassphraseConfirmation { words: 10 })
        );
    }

    #[test]
    fn sec03_harden_flag_is_a_development_option_only() {
        // Covers: SEC-03 (strace E2E with the filter on), FR-01 AC2
        let options = parse(&args(&["--harden", "--primary", "/tmp/a"]), false).expect("valid");
        assert!(options.harden);
        assert!(
            !parse(&args(&["--primary", "/tmp/a"]), false)
                .expect("valid")
                .harden
        );
        assert!(wants_hardening(
            &args(&["--primary", "/a", "--harden"]),
            false
        ));
        assert!(!wants_hardening(&args(&["--primary", "/a"]), false));
        // A production build installs the filter anyway and refuses every argument.
        assert!(!wants_hardening(&args(&["--harden"]), true));
        assert_eq!(
            parse(&args(&["--harden"]), true),
            Err(CliError::ArgumentsInProduction)
        );
        assert_eq!(
            parse(&args(&["--harden", "--harden"]), false),
            Err(CliError::Repeated("--harden"))
        );
    }

    #[test]
    fn nfr03_slow_keygen_hook_and_new_drive_folder() {
        // Covers: NFR-03, FR-16 AC2 (deterministic slow key generation for the E2E test)
        let options = parse(
            &args(&["--test-hook", "slow-keygen", "--new-drive", "/tmp/n"]),
            false,
        )
        .expect("valid");
        assert_eq!(options.test_hook, Some(TestHook::SlowKeygen));
        assert_eq!(options.new_drive, Some(PathBuf::from("/tmp/n")));
        assert!(matches!(
            parse(
                &args(&["--test-hook", "slow-keygen", "--test-words", "12"]),
                false
            ),
            Err(CliError::InvalidValue { .. })
        ));
        assert_eq!(
            parse(&args(&["--test-hook=slow-keygen"]), true),
            Err(CliError::ArgumentsInProduction)
        );
    }

    #[test]
    fn invalid_command_lines_are_refused_with_a_reason() {
        assert!(matches!(
            parse(&args(&["--frobnicate"]), false),
            Err(CliError::Unknown(_))
        ));
        assert_eq!(
            parse(&args(&["--primary"]), false),
            Err(CliError::MissingValue("--primary"))
        );
        assert_eq!(
            parse(&args(&["--primary", "/a", "--primary", "/b"]), false),
            Err(CliError::Repeated("--primary"))
        );
        for bad in [
            &[
                "--test-words",
                "9",
                "--test-hook",
                "passphrase-confirmation",
            ][..],
            &["--test-words", "12"][..],
            &["--test-hook", "something-else"][..],
            &["--sim-firmware", "5.7"][..],
            &["--sim-firmware", "5.x.1"][..],
            &["--sim-slot", "full"][..],
            &["--sim-serial", "0"][..],
            &["--export", ""][..],
        ] {
            assert!(
                matches!(parse(&args(bad), false), Err(CliError::InvalidValue { .. })),
                "{bad:?}"
            );
        }
    }
}
