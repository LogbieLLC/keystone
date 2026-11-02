//! Drive selection (FR-12 AC1, FR-19 AC1, SEC-20).
//!
//! The operator names a primary CA drive, at least one backup CA drive and an export
//! drive. [`validate_form`] checks the form itself; [`assess`] turns
//! `store::classify_drive` results into "create a new CA", "open the existing CA" or a
//! list of plain reasons why the drives cannot be used.
//!
//! Decisions (most conservative reading):
//! - The export drive is required up front, because every flow writes to it (the first
//!   CRL in Flows A and B, FR-13 AC6).
//! - No folder may be the same as, or inside, another chosen folder.
//! - A drive recorded as a backup cannot be used as the primary, and the other way
//!   round: the roles recorded on the drives must match the operator's choice.
//! - Mixing empty drives with CA drives is refused; adding a new backup drive to an
//!   existing CA is not part of version 1's screens.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keystone_core::store::{CaId, DriveClass, DriveRole};

use super::{Line, Status};
use crate::backend::DriveSelection;

/// The text fields of the drive selection screen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriveForm {
    /// Primary drive folder.
    pub primary: String,
    /// Backup drive folders (empty fields are ignored).
    pub backups: Vec<String>,
    /// Export folder.
    pub export: String,
}

fn folder(label: &str, text: &str, problems: &mut Vec<String>) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() {
        problems.push(format!("Choose the {label}."));
        return None;
    }
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        problems.push(format!(
            "The {label} must be a full folder path starting with /."
        ));
        return None;
    }
    Some(path)
}

/// Validates the form (not the drives' contents). Every problem is listed.
pub fn validate_form(form: &DriveForm) -> Result<DriveSelection, Vec<String>> {
    let mut problems = Vec::new();
    let primary = folder("primary drive", &form.primary, &mut problems);
    let filled: Vec<&String> = form
        .backups
        .iter()
        .filter(|b| !b.trim().is_empty())
        .collect();
    let mut backups = Vec::new();
    if filled.is_empty() {
        problems.push(
            "Choose at least one backup drive: every change is written to the primary and at least one backup."
                .to_string(),
        );
    }
    for backup in filled {
        if let Some(path) = folder("backup drive", backup, &mut problems) {
            backups.push(path);
        }
    }
    let export = folder("export drive", &form.export, &mut problems);
    let mut all: Vec<&Path> = Vec::new();
    all.extend(primary.as_deref());
    all.extend(backups.iter().map(PathBuf::as_path));
    all.extend(export.as_deref());
    for (index, first) in all.iter().enumerate() {
        for second in &all[index + 1..] {
            if first == second {
                problems.push(format!(
                    "{} is chosen twice; each drive must be a different folder.",
                    first.display()
                ));
            } else if first.starts_with(second) || second.starts_with(first) {
                problems.push(format!(
                    "{} and {} are inside each other; choose separate drives.",
                    first.display(),
                    second.display()
                ));
            }
        }
    }
    match (primary, export) {
        (Some(primary), Some(export)) if problems.is_empty() => Ok(DriveSelection {
            primary,
            backups,
            export,
        }),
        _ => Err(problems),
    }
}

/// The role the operator gave a CA drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChosenRole {
    /// Chosen as the primary drive.
    Primary,
    /// Chosen as a backup drive.
    Backup,
}

/// What `classify_drive` found at one chosen folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveProbe {
    /// The folder.
    pub path: PathBuf,
    /// The role the operator chose.
    pub role: ChosenRole,
    /// The classification, or why the folder could not be read.
    pub class: Result<DriveClass, String>,
}

/// What can be done with the chosen drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveMode {
    /// Every CA drive is empty: a new CA can be created (Flow A).
    NewCa,
    /// Every CA drive belongs to this CA: open it (FR-19).
    ExistingCa(CaId),
    /// The drives cannot be used; the lines say why.
    Unusable,
}

/// The result shown under the drive fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveAssessment {
    /// What can be done.
    pub mode: DriveMode,
    /// One line per drive, then one line per problem.
    pub lines: Vec<Line>,
}

impl DriveAssessment {
    /// True when the operator may continue to the start-up checks.
    pub fn can_continue(&self) -> bool {
        self.mode != DriveMode::Unusable
    }
}

fn role_name(role: ChosenRole) -> &'static str {
    match role {
        ChosenRole::Primary => "Primary drive",
        ChosenRole::Backup => "Backup drive",
    }
}

/// Turns the probes of the CA drives and the export drive into a [`DriveAssessment`].
pub fn assess(ca: &[DriveProbe], export: &DriveProbe) -> DriveAssessment {
    let mut lines = Vec::new();
    let mut problems = Vec::new();
    let mut empty = 0usize;
    let mut ca_ids: Vec<CaId> = Vec::new();
    for probe in ca {
        let name = format!("{} {}", role_name(probe.role), probe.path.display());
        match &probe.class {
            Err(reason) => {
                lines.push(Line::new(
                    Status::Blocked,
                    format!("{name} cannot be read: {reason}"),
                ));
                problems.push(());
            }
            Ok(DriveClass::Empty) => {
                empty += 1;
                lines.push(Line::new(Status::Info, format!("{name} is empty.")));
            }
            Ok(DriveClass::KeystoneCa(identity)) => {
                let recorded = match identity.role {
                    DriveRole::Primary => ChosenRole::Primary,
                    DriveRole::Backup => ChosenRole::Backup,
                };
                if recorded == probe.role {
                    lines.push(Line::new(
                        Status::Ok,
                        format!(
                            "{name} holds Keystone CA {} (drive {}).",
                            identity.ca_id.short(),
                            identity.drive_id.short()
                        ),
                    ));
                } else {
                    lines.push(Line::new(
                        Status::Blocked,
                        format!(
                            "{name} is recorded as a {} drive of CA {}. Choose it in the matching field.",
                            match recorded {
                                ChosenRole::Primary => "primary",
                                ChosenRole::Backup => "backup",
                            },
                            identity.ca_id.short()
                        ),
                    ));
                    problems.push(());
                }
                ca_ids.push(identity.ca_id);
            }
            Ok(DriveClass::DamagedKeystone(reason)) => {
                lines.push(Line::new(
                    Status::Blocked,
                    format!(
                        "{name} has a damaged keystone folder ({reason}). Keystone will not use it or create a CA over it."
                    ),
                ));
                problems.push(());
            }
            Ok(DriveClass::KeystoneExport) => {
                lines.push(Line::new(
                    Status::Blocked,
                    format!("{name} is an export drive, not a CA drive."),
                ));
                problems.push(());
            }
            Ok(DriveClass::Other) => {
                lines.push(Line::new(
                    Status::Blocked,
                    format!(
                        "{name} holds other files. A new CA needs an empty drive; an existing CA needs its own drives."
                    ),
                ));
                problems.push(());
            }
        }
    }
    match &export.class {
        Err(reason) => {
            lines.push(Line::new(
                Status::Blocked,
                format!(
                    "Export drive {} cannot be read: {reason}",
                    export.path.display()
                ),
            ));
            problems.push(());
        }
        Ok(DriveClass::KeystoneCa(_) | DriveClass::DamagedKeystone(_)) => {
            lines.push(Line::new(
                Status::Blocked,
                format!(
                    "Export drive {} is a CA drive. CA drives are never carried to issuing systems; use a separate export drive.",
                    export.path.display()
                ),
            ));
            problems.push(());
        }
        Ok(_) => lines.push(Line::new(
            Status::Ok,
            format!(
                "Export drive {} can be used for files carried to issuing systems.",
                export.path.display()
            ),
        )),
    }
    let mut mode = DriveMode::Unusable;
    if problems.is_empty() {
        if empty == ca.len() && !ca.is_empty() {
            mode = DriveMode::NewCa;
            lines.push(Line::new(
                Status::Info,
                "All CA drives are empty: you can create a new CA.",
            ));
        } else if ca_ids.len() == ca.len() && !ca.is_empty() {
            if ca_ids.iter().all(|id| *id == ca_ids[0]) {
                mode = DriveMode::ExistingCa(ca_ids[0]);
                lines.push(Line::new(
                    Status::Ok,
                    format!(
                        "All CA drives belong to CA {}: Keystone will check and open it.",
                        ca_ids[0].short()
                    ),
                ));
            } else {
                lines.push(Line::new(
                    Status::Blocked,
                    "The CA drives belong to different CAs. Choose drives of one CA.",
                ));
            }
        } else {
            lines.push(Line::new(
                Status::Blocked,
                "Some CA drives are empty and some hold a CA. To open the CA, choose only its drives; to create a new CA, choose only empty drives.",
            ));
        }
    }
    DriveAssessment { mode, lines }
}

/// Classifies every chosen drive (reads the drives; run it off the GUI thread).
pub fn probe(selection: &DriveSelection) -> (Vec<DriveProbe>, DriveProbe) {
    let classify = |path: &Path, role| DriveProbe {
        path: path.to_path_buf(),
        role,
        class: keystone_core::store::classify_drive(path).map_err(|e| e.to_string()),
    };
    let mut ca = vec![classify(&selection.primary, ChosenRole::Primary)];
    ca.extend(
        selection
            .backups
            .iter()
            .map(|b| classify(b, ChosenRole::Backup)),
    );
    let export = classify(&selection.export, ChosenRole::Backup);
    (ca, export)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::model::Timestamp;
    use keystone_core::store::{DriveId, DriveIdentity};

    fn form(primary: &str, backups: &[&str], export: &str) -> DriveForm {
        DriveForm {
            primary: primary.to_string(),
            backups: backups.iter().map(|s| (*s).to_string()).collect(),
            export: export.to_string(),
        }
    }

    fn identity(ca: CaId, role: DriveRole) -> DriveIdentity {
        DriveIdentity {
            format: 1,
            ca_id: ca,
            drive_id: DriveId::random().expect("id"),
            role,
            created: Timestamp::utc(
                time::OffsetDateTime::from_unix_timestamp(1_793_491_200).expect("time"),
            ),
        }
    }

    fn probe_of(path: &str, role: ChosenRole, class: DriveClass) -> DriveProbe {
        DriveProbe {
            path: PathBuf::from(path),
            role,
            class: Ok(class),
        }
    }

    #[test]
    fn fr12_ac1_primary_and_one_backup_are_required() {
        // Covers: FR-12 AC1
        let problems = validate_form(&form("", &[""], "")).expect_err("incomplete");
        assert!(problems.iter().any(|p| p.contains("primary drive")));
        assert!(problems.iter().any(|p| p.contains("at least one backup")));
        assert!(problems.iter().any(|p| p.contains("export drive")));
        let selection = validate_form(&form("/m/a", &["/m/b", " "], "/m/e")).expect("valid");
        assert_eq!(selection.backups, vec![PathBuf::from("/m/b")]);
    }

    #[test]
    fn folders_must_be_separate_and_absolute() {
        let problems = validate_form(&form("/m/a", &["/m/a"], "/m/e")).expect_err("dup");
        assert!(problems[0].contains("chosen twice"), "{problems:?}");
        let problems = validate_form(&form("/m/a", &["/m/b"], "/m/a/export")).expect_err("nest");
        assert!(problems[0].contains("inside each other"), "{problems:?}");
        let problems = validate_form(&form("m/a", &["/m/b"], "/m/e")).expect_err("relative");
        assert!(problems[0].contains("full folder path"), "{problems:?}");
    }

    #[test]
    fn sec20_empty_drives_offer_a_new_ca() {
        // Covers: SEC-20, FR-19 AC1
        let ca = [
            probe_of("/m/a", ChosenRole::Primary, DriveClass::Empty),
            probe_of("/m/b", ChosenRole::Backup, DriveClass::Empty),
        ];
        let export = probe_of("/m/e", ChosenRole::Backup, DriveClass::Other);
        let result = assess(&ca, &export);
        assert_eq!(result.mode, DriveMode::NewCa);
        assert!(result.can_continue());
    }

    #[test]
    fn fr19_ac1_drives_of_one_ca_open_it() {
        // Covers: FR-19 AC1
        let id = CaId::random().expect("id");
        let ca = [
            probe_of(
                "/m/a",
                ChosenRole::Primary,
                DriveClass::KeystoneCa(identity(id, DriveRole::Primary)),
            ),
            probe_of(
                "/m/b",
                ChosenRole::Backup,
                DriveClass::KeystoneCa(identity(id, DriveRole::Backup)),
            ),
        ];
        let export = probe_of("/m/e", ChosenRole::Backup, DriveClass::Empty);
        assert_eq!(assess(&ca, &export).mode, DriveMode::ExistingCa(id));
    }

    #[test]
    fn sec20_unusable_drives_are_explained() {
        // Covers: SEC-20
        let id = CaId::random().expect("id");
        let other = CaId::random().expect("id");
        let ca_drive =
            |id, role, chosen| probe_of("/m/x", chosen, DriveClass::KeystoneCa(identity(id, role)));
        let export = probe_of("/m/e", ChosenRole::Backup, DriveClass::Empty);
        let cases: Vec<(Vec<DriveProbe>, &str)> = vec![
            (
                vec![
                    ca_drive(id, DriveRole::Primary, ChosenRole::Primary),
                    ca_drive(other, DriveRole::Backup, ChosenRole::Backup),
                ],
                "different CAs",
            ),
            (
                vec![
                    ca_drive(id, DriveRole::Backup, ChosenRole::Primary),
                    ca_drive(id, DriveRole::Primary, ChosenRole::Backup),
                ],
                "recorded as a backup",
            ),
            (
                vec![
                    ca_drive(id, DriveRole::Primary, ChosenRole::Primary),
                    probe_of("/m/b", ChosenRole::Backup, DriveClass::Empty),
                ],
                "Some CA drives are empty",
            ),
            (
                vec![
                    probe_of("/m/a", ChosenRole::Primary, DriveClass::Other),
                    probe_of("/m/b", ChosenRole::Backup, DriveClass::Empty),
                ],
                "holds other files",
            ),
            (
                vec![
                    probe_of(
                        "/m/a",
                        ChosenRole::Primary,
                        DriveClass::DamagedKeystone("drive.json is missing".into()),
                    ),
                    probe_of("/m/b", ChosenRole::Backup, DriveClass::Empty),
                ],
                "damaged keystone folder",
            ),
        ];
        for (ca, expected) in cases {
            let result = assess(&ca, &export);
            assert_eq!(result.mode, DriveMode::Unusable, "{expected}");
            assert!(
                result
                    .lines
                    .iter()
                    .any(|l| l.status == Status::Blocked && l.text.contains(expected)),
                "{expected}: {:?}",
                result.lines
            );
        }
        let ca = [
            probe_of("/m/a", ChosenRole::Primary, DriveClass::Empty),
            probe_of("/m/b", ChosenRole::Backup, DriveClass::Empty),
        ];
        let ca_export = probe_of(
            "/m/e",
            ChosenRole::Backup,
            DriveClass::KeystoneCa(identity(id, DriveRole::Backup)),
        );
        let result = assess(&ca, &ca_export);
        assert_eq!(result.mode, DriveMode::Unusable);
        assert!(
            result
                .lines
                .iter()
                .any(|l| l.text.contains("is a CA drive"))
        );
    }

    #[test]
    fn probe_reads_real_folders() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        let e = dir.path().join("e");
        for path in [&a, &b, &e] {
            std::fs::create_dir(path).expect("mkdir");
        }
        let selection = DriveSelection {
            primary: a,
            backups: vec![b],
            export: e,
        };
        let (ca, export) = probe(&selection);
        assert_eq!(assess(&ca, &export).mode, DriveMode::NewCa);
        let missing = DriveSelection {
            primary: dir.path().join("missing"),
            ..selection
        };
        let (ca, export) = probe(&missing);
        let result = assess(&ca, &export);
        assert_eq!(result.mode, DriveMode::Unusable);
        assert!(result.lines[0].text.contains("cannot be read"));
    }
}
