//! Names and paths of the drive layout (see the `store` module documentation).
#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

use super::ParseError;

/// Folder on every CA drive that holds all Keystone files.
pub const KEYSTONE_DIR: &str = "keystone";
/// Folder on the export drive for files carried to issuing systems.
pub const EXPORT_DIR: &str = "keystone-export";
/// Drive identity file inside `keystone/`.
pub const IDENTITY_FILE: &str = "drive.json";
/// Audit log inside `keystone/`.
pub const AUDIT_LOG_FILE: &str = "audit.log";
/// SEC-19 binary hash record inside `keystone/`.
pub const BINARY_HASH_FILE: &str = "binary.sha256";
/// Operation journal folder inside `keystone/`.
pub const JOURNAL_DIR: &str = "journal";
/// Staging folder inside `keystone/`.
pub const STAGING_DIR: &str = "staging";
/// Issuance-record folder inside `keystone/`.
pub const RECORD_DIR: &str = "record";

/// Longest file or folder name Keystone writes.
pub const MAX_NAME_LEN: usize = 128;

/// True for a plain name Keystone may create: 1 to 128 of `[A-Za-z0-9._-]`, not
/// starting with `.` (names starting with `.` are temporary files).
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Folders inside `keystone/` that hold operation outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputDir {
    /// `certs/`: certificates and chain files.
    Certs,
    /// `keys/`: encrypted PKCS#8 private keys.
    Keys,
    /// `crls/`: certificate revocation lists.
    Crls,
    /// `record/`: issuance-record updates.
    Record,
}

impl OutputDir {
    /// Every output folder.
    pub const ALL: [OutputDir; 4] = [
        OutputDir::Certs,
        OutputDir::Keys,
        OutputDir::Crls,
        OutputDir::Record,
    ];

    /// The folder name.
    pub const fn name(self) -> &'static str {
        match self {
            OutputDir::Certs => "certs",
            OutputDir::Keys => "keys",
            OutputDir::Crls => "crls",
            OutputDir::Record => RECORD_DIR,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        OutputDir::ALL.into_iter().find(|dir| dir.name() == name)
    }
}

/// Path of an operation output inside `keystone/`: `<certs|keys|crls|record>/<name>`.
///
/// Paths read from journal entries are untrusted: only this exact shape is accepted,
/// so a damaged or hostile entry can never name a file outside the output folders.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OutputPath {
    dir: OutputDir,
    name: String,
}

impl OutputPath {
    /// A validated output path.
    pub fn new(dir: OutputDir, name: &str) -> Result<Self, ParseError> {
        if !is_valid_name(name) {
            return Err(ParseError::invalid(format!(
                "invalid output file name {name:?}"
            )));
        }
        Ok(OutputPath {
            dir,
            name: name.to_string(),
        })
    }

    /// Parses `dir/name`.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let (dir, name) = text
            .split_once('/')
            .ok_or_else(|| ParseError::invalid(format!("invalid output path {text:?}")))?;
        let dir = OutputDir::from_name(dir)
            .ok_or_else(|| ParseError::invalid(format!("invalid output folder in {text:?}")))?;
        OutputPath::new(dir, name)
    }

    /// The output folder.
    pub fn dir(&self) -> OutputDir {
        self.dir
    }

    /// The file name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for OutputPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.dir.name(), self.name)
    }
}

impl fmt::Debug for OutputPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputPath({self})")
    }
}

impl TryFrom<String> for OutputPath {
    type Error = ParseError;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        OutputPath::parse(&text)
    }
}

impl From<OutputPath> for String {
    fn from(path: OutputPath) -> Self {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec08_output_paths_never_leave_the_output_folders() {
        // Covers: SEC-08
        assert!(OutputPath::parse("certs/master.crt").is_ok());
        assert!(OutputPath::parse("record/op-000001.json").is_ok());
        for bad in [
            "../keys/x",
            "certs/../keys",
            "certs/.hidden",
            "certs/a/b",
            "journal/op-000001",
            "/etc/passwd",
            "certs/",
            "certs",
            "keys/a b",
            "keys/\u{e9}",
            "staging/x",
        ] {
            assert!(OutputPath::parse(bad).is_err(), "{bad}");
        }
        let long = format!("certs/{}", "a".repeat(129));
        assert!(OutputPath::parse(&long).is_err());
        let json =
            serde_json::to_string(&OutputPath::parse("crls/m-1.crl").expect("ok")).expect("json");
        assert_eq!(json, "\"crls/m-1.crl\"");
        assert!(serde_json::from_str::<OutputPath>("\"../x\"").is_err());
    }
}
