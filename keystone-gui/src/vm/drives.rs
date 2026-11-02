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
//! - A drive's role is the one it has now (`CaDrive::role`): its `drive.json` role, or
//!   primary after an audited promotion by "Replace a lost drive" (ADR 0003). A drive
//!   chosen in the other role is refused.
//! - A new CA needs the primary and at least one backup. An existing CA opens with a
//!   single drive too, but then only "Replace a lost drive" can write (ADR 0003); the
//!   start-up checks say so and keep every signing action disabled.
//! - Drives left behind by an interrupted CA setup (`store::unfinished_setup`) are not
//!   damaged: "Create new CA" finishes setting them up (Flow A's
//!   `DriveSetup::FinishInterruptedSetup`), adding only what is missing.
//! - Mixing empty drives with CA drives is refused; a new drive is added to an existing
//!   CA only through "Replace a lost drive".
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keystone_core::store::{CaId, DriveClass, DriveRole, DriveSet, UnfinishedSetup};

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

/// Validates the form (not the drives' contents). Every problem is listed. One CA
/// drive is accepted (the other may be lost, ADR 0003); with none, both the primary
/// and a backup are asked for.
pub fn validate_form(form: &DriveForm) -> Result<DriveSelection, Vec<String>> {
    let mut problems = Vec::new();
    let filled: Vec<&String> = form
        .backups
        .iter()
        .filter(|b| !b.trim().is_empty())
        .collect();
    let primary = if form.primary.trim().is_empty() && !filled.is_empty() {
        None
    } else {
        folder("primary drive", &form.primary, &mut problems)
    };
    let mut backups = Vec::new();
    if filled.is_empty() && form.primary.trim().is_empty() {
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
    match export {
        Some(export) if problems.is_empty() => Ok(DriveSelection {
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
    /// The drive's role now (`CaDrive::role`, which follows an audited promotion),
    /// when the chosen CA drives could be opened together; `None` otherwise (then the
    /// role in `drive.json` is used).
    pub effective_role: Option<DriveRole>,
}

/// Everything read about the chosen drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveProbes {
    /// The CA drives, primary first.
    pub ca: Vec<DriveProbe>,
    /// The export drive.
    pub export: DriveProbe,
    /// An interrupted CA setup these drives hold, if any.
    pub unfinished: Option<UnfinishedSetup>,
}

/// What can be done with the chosen drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveMode {
    /// Every CA drive is empty: a new CA can be created (Flow A).
    NewCa,
    /// Every CA drive belongs to this CA: open it (FR-19). With a single drive only
    /// "Replace a lost drive" can write.
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

/// Turns everything read about the drives into a [`DriveAssessment`].
pub fn assess_probes(probes: &DriveProbes) -> DriveAssessment {
    match &probes.unfinished {
        Some(setup) => assess_unfinished(&probes.ca, &probes.export, setup),
        None => assess(&probes.ca, &probes.export),
    }
}

/// Drives an interrupted CA setup left behind: Flow A finishes setting them up.
fn assess_unfinished(
    ca: &[DriveProbe],
    export: &DriveProbe,
    setup: &UnfinishedSetup,
) -> DriveAssessment {
    let mut lines: Vec<Line> = ca
        .iter()
        .map(|probe| {
            let name = format!("{} {}", role_name(probe.role), probe.path.display());
            Line::new(
                Status::Info,
                match &probe.class {
                    Ok(DriveClass::Empty) => format!("{name} is empty."),
                    _ => format!("{name} holds the start of an interrupted CA setup."),
                },
            )
        })
        .collect();
    let export_ok = export_line(export, &mut lines);
    let primary_and_backup = ca.iter().any(|p| p.role == ChosenRole::Primary)
        && ca.iter().any(|p| p.role == ChosenRole::Backup);
    if !primary_and_backup {
        lines.push(Line::new(
            Status::Blocked,
            "Choose the primary drive and at least one backup drive to finish setting up the new CA.",
        ));
    }
    let mode = if export_ok && primary_and_backup {
        lines.push(Line::new(
            Status::Info,
            format!(
                "An earlier setup of these drives{} was interrupted before any CA was created. Create new CA finishes setting them up: what is missing is added; nothing on them is overwritten or deleted.",
                setup
                    .ca_id
                    .map(|id| format!(" (CA {})", id.short()))
                    .unwrap_or_default()
            ),
        ));
        DriveMode::NewCa
    } else {
        DriveMode::Unusable
    };
    DriveAssessment { mode, lines }
}

/// The export drive's line; false when it cannot be used.
fn export_line(export: &DriveProbe, lines: &mut Vec<Line>) -> bool {
    match &export.class {
        Err(reason) => {
            lines.push(Line::new(
                Status::Blocked,
                format!(
                    "Export drive {} cannot be read: {reason}",
                    export.path.display()
                ),
            ));
            false
        }
        Ok(DriveClass::KeystoneCa(_) | DriveClass::DamagedKeystone(_)) => {
            lines.push(Line::new(
                Status::Blocked,
                format!(
                    "Export drive {} is a CA drive. CA drives are never carried to issuing systems; use a separate export drive.",
                    export.path.display()
                ),
            ));
            false
        }
        Ok(_) => {
            lines.push(Line::new(
                Status::Ok,
                format!(
                    "Export drive {} can be used for files carried to issuing systems.",
                    export.path.display()
                ),
            ));
            true
        }
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
                let recorded = match probe.effective_role.unwrap_or(identity.role) {
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
    if !export_line(export, &mut lines) {
        problems.push(());
    }
    let primary_and_backup = ca.iter().any(|p| p.role == ChosenRole::Primary)
        && ca.iter().any(|p| p.role == ChosenRole::Backup);
    let mut mode = DriveMode::Unusable;
    if problems.is_empty() {
        if empty == ca.len() && !ca.is_empty() {
            if primary_and_backup {
                mode = DriveMode::NewCa;
                lines.push(Line::new(
                    Status::Info,
                    "All CA drives are empty: you can create a new CA.",
                ));
            } else {
                lines.push(Line::new(
                    Status::Blocked,
                    "A new CA needs the primary drive and at least one backup drive: choose both.",
                ));
            }
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
                if !primary_and_backup {
                    lines.push(Line::new(
                        Status::Warning,
                        "Only one CA drive is chosen. Keystone opens the CA so that you can replace the lost drive; every signing action stays disabled until the primary and at least one backup are connected.",
                    ));
                }
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

/// The selection with each CA drive in the role it has now: after "Replace a lost
/// drive" promoted a backup, that drive becomes the primary. Unchanged when any role
/// is unknown or more than one drive is the primary.
pub fn normalize(selection: &DriveSelection, probes: &DriveProbes) -> DriveSelection {
    if probes.ca.is_empty() || probes.ca.iter().any(|p| p.effective_role.is_none()) {
        return selection.clone();
    }
    let with_role = |role: DriveRole| -> Vec<PathBuf> {
        probes
            .ca
            .iter()
            .filter(|p| p.effective_role == Some(role))
            .map(|p| p.path.clone())
            .collect()
    };
    let primaries = with_role(DriveRole::Primary);
    if primaries.len() > 1 {
        return selection.clone();
    }
    DriveSelection {
        primary: primaries.into_iter().next(),
        backups: with_role(DriveRole::Backup),
        export: selection.export.clone(),
    }
}

/// Classifies every chosen drive (reads the drives; run it off the GUI thread). When
/// every CA drive holds a CA, they are opened together to read each drive's role now
/// (a backup promoted by "Replace a lost drive" is the primary).
pub fn probe(selection: &DriveSelection) -> DriveProbes {
    let classify = |path: &Path, role| DriveProbe {
        path: path.to_path_buf(),
        role,
        class: keystone_core::store::classify_drive(path).map_err(|e| e.to_string()),
        effective_role: None,
    };
    let mut ca: Vec<DriveProbe> = selection
        .primary
        .iter()
        .map(|p| classify(p, ChosenRole::Primary))
        .collect();
    ca.extend(
        selection
            .backups
            .iter()
            .map(|b| classify(b, ChosenRole::Backup)),
    );
    let export = classify(&selection.export, ChosenRole::Backup);
    if ca
        .iter()
        .all(|probe| matches!(probe.class, Ok(DriveClass::KeystoneCa(_))))
        && let Ok(set) = DriveSet::open(&selection.ca_drives())
    {
        for probe in &mut ca {
            probe.effective_role = set
                .drives()
                .iter()
                .find(|drive| drive.root() == probe.path)
                .map(|drive| drive.role());
        }
    }
    let unfinished = match (&selection.primary, ca.is_empty()) {
        (Some(primary), false) => {
            let backups: Vec<&Path> = selection.backups.iter().map(PathBuf::as_path).collect();
            keystone_core::store::unfinished_setup(primary, &backups)
                .ok()
                .flatten()
        }
        _ => None,
    };
    DriveProbes {
        ca,
        export,
        unfinished,
    }
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
            effective_role: None,
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
        assert_eq!(selection.primary, Some(PathBuf::from("/m/a")));
    }

    #[test]
    fn adr0003_one_ca_drive_opens_the_ca_for_replacing_the_lost_drive() {
        // Covers: SEC-11 (ADR 0003), FR-12 AC1
        let lost_primary = validate_form(&form("", &["/m/b"], "/m/e")).expect("valid");
        assert_eq!(lost_primary.primary, None);
        assert_eq!(lost_primary.ca_drives(), vec![Path::new("/m/b")]);
        let lost_backup = validate_form(&form("/m/a", &[""], "/m/e")).expect("valid");
        assert!(lost_backup.backups.is_empty());
        let id = CaId::random().expect("id");
        let single = [probe_of(
            "/m/b",
            ChosenRole::Backup,
            DriveClass::KeystoneCa(identity(id, DriveRole::Backup)),
        )];
        let export = probe_of("/m/e", ChosenRole::Backup, DriveClass::Empty);
        let result = assess(&single, &export);
        assert_eq!(result.mode, DriveMode::ExistingCa(id));
        assert!(result.lines.iter().any(|l| l.status == Status::Warning
            && l.text.contains("replace the lost drive")
            && l.text.contains("signing action stays disabled")));
        // A new CA still needs both drives (FR-12 AC1).
        let empty = [probe_of("/m/a", ChosenRole::Primary, DriveClass::Empty)];
        let result = assess(&empty, &export);
        assert_eq!(result.mode, DriveMode::Unusable);
        assert!(
            result
                .lines
                .iter()
                .any(|l| l.text.contains("primary drive and at least one backup"))
        );
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
            primary: Some(a),
            backups: vec![b],
            export: e,
        };
        let probes = probe(&selection);
        assert_eq!(assess(&probes.ca, &probes.export).mode, DriveMode::NewCa);
        assert_eq!(assess_probes(&probes).mode, DriveMode::NewCa);
        let missing = DriveSelection {
            primary: Some(dir.path().join("missing")),
            ..selection
        };
        let probes = probe(&missing);
        let result = assess(&probes.ca, &probes.export);
        assert_eq!(result.mode, DriveMode::Unusable);
        assert!(result.lines[0].text.contains("cannot be read"));
    }

    fn folders(dir: &Path, names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|name| {
                let path = dir.join(name);
                std::fs::create_dir(&path).expect("mkdir");
                path
            })
            .collect()
    }

    #[test]
    fn interrupted_ca_setup_is_finished_by_flow_a_not_called_damaged() {
        // Covers: SEC-20, FR-22 AC4 (review finding 11: an interrupted drive setup)
        let dir = tempfile::tempdir().expect("tempdir");
        let roots = folders(dir.path(), &["a", "b", "e"]);
        // An interrupted DriveSet::create: the primary got its empty layout only.
        let keystone = roots[0].join("keystone");
        std::fs::create_dir(&keystone).expect("mkdir");
        for folder in ["journal", "record", "certs", "keys", "crls", "staging"] {
            std::fs::create_dir(keystone.join(folder)).expect("mkdir");
        }
        let selection = DriveSelection {
            primary: Some(roots[0].clone()),
            backups: vec![roots[1].clone()],
            export: roots[2].clone(),
        };
        let probes = probe(&selection);
        assert!(probes.unfinished.is_some(), "{probes:?}");
        let result = assess_probes(&probes);
        assert_eq!(result.mode, DriveMode::NewCa, "{:?}", result.lines);
        assert!(
            result
                .lines
                .iter()
                .any(|l| l.text.contains("interrupted CA setup"))
        );
        assert!(
            result
                .lines
                .iter()
                .any(|l| l.text.contains("Create new CA finishes setting them up"))
        );
        assert!(!result.lines.iter().any(|l| l.text.contains("damaged")));
    }

    #[test]
    fn adr0003_a_promoted_backup_is_used_as_the_primary() {
        // Covers: SEC-11 (ADR 0003), FR-19 AC1
        use keystone_core::clock::{assess as assess_clock, confirm};
        let dir = tempfile::tempdir().expect("tempdir");
        let roots = folders(dir.path(), &["a", "b", "new", "e"]);
        let created = keystone_core::model::Timestamp::utc(
            keystone_core::build_info::build_date() + time::Duration::hours(1),
        );
        DriveSet::create(&roots[0], &[roots[1].as_path()], created).expect("create");
        // The primary is lost: the backup and a new drive replace it.
        let ca = keystone_core::ops::Ca::open(&[roots[1].as_path()]).expect("open");
        let now = keystone_core::build_info::build_date() + time::Duration::days(1);
        let time = confirm(
            &assess_clock(now, None, keystone_core::build_info::build_date()),
            false,
        )
        .expect("time");
        let plan = ca.plan_replace_drive(&roots[2], time).expect("plan");
        assert!(plan.promotes().is_some());
        plan.execute(&ca, &keystone_core::ops::NoProgress)
            .expect("replace");
        // drive.json of b still says backup; its role now is primary.
        let selection = DriveSelection {
            primary: Some(roots[1].clone()),
            backups: vec![roots[2].clone()],
            export: roots[3].clone(),
        };
        let probes = probe(&selection);
        assert_eq!(probes.ca[0].effective_role, Some(DriveRole::Primary));
        let result = assess_probes(&probes);
        assert!(
            matches!(result.mode, DriveMode::ExistingCa(_)),
            "{:?}",
            result.lines
        );
        // After the replacement the new drive was added as a backup: the promoted
        // drive is moved to the primary role.
        let after = DriveSelection {
            primary: None,
            backups: vec![roots[1].clone(), roots[2].clone()],
            export: roots[3].clone(),
        };
        let normalized = normalize(&after, &probe(&after));
        assert_eq!(normalized.primary, Some(roots[1].clone()));
        assert_eq!(normalized.backups, vec![roots[2].clone()]);
        // Chosen as a backup, the promoted drive is refused.
        let swapped = DriveSelection {
            primary: Some(roots[2].clone()),
            backups: vec![roots[1].clone()],
            export: roots[3].clone(),
        };
        let result = assess_probes(&probe(&swapped));
        assert_eq!(result.mode, DriveMode::Unusable);
        assert!(
            result
                .lines
                .iter()
                .any(|l| l.text.contains("recorded as a primary drive"))
        );
    }
}
