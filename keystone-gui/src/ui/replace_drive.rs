//! "Replace a lost drive" (ADR 0003, SEC-11, FR-12): choose a new, empty drive, review
//! what `ops` will copy (and whether a backup becomes the primary), then copy the CA to
//! it. The result lists what was copied and that every file was read back and verified.
//!
//! Reached from the start-up checks when fewer than the primary and one backup are
//! connected, and from the home screen. It signs nothing and never overwrites or
//! deletes anything; `ops` refuses while drives diverge or an operation is pending.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::rc::Rc;

use gtk::prelude::*;

use super::clock::ClockPanel;
use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, drives, exec, startup};
use crate::backend::{DriveReplacementReview, DriveSelection, ReplaceDrivePlan};
use crate::vm::{Line, Status};
use crate::worker::gtk_glue;

/// Page ids.
pub const ID: &str = "replace-drive";
const REVIEW_ID: &str = "replace-drive-review";

/// The review lines in words (`Label: value.`), the warnings, and the promotion.
pub fn review_lines(review: &DriveReplacementReview) -> Vec<Line> {
    let mut lines: Vec<Line> = review
        .lines
        .iter()
        .map(|(label, value)| Line::new(Status::Info, format!("{label}: {value}.")))
        .collect();
    lines.extend(
        review
            .warnings
            .iter()
            .map(|warning| Line::new(Status::Warning, warning.clone())),
    );
    if let Some(label) = &review.promotes {
        lines.push(Line::new(
            Status::Warning,
            format!("The primary drive is not connected: {label} becomes the primary drive."),
        ));
    }
    lines
}

/// The drive selection after the replacement: the new drive is a backup (startup
/// re-reads every drive's role, so a promoted backup becomes the primary there).
pub fn selection_after(selection: &DriveSelection, new_drive: PathBuf) -> DriveSelection {
    let mut next = selection.clone();
    if !next.backups.contains(&new_drive) {
        next.backups.push(new_drive);
    }
    next
}

/// Shows the first step: the new drive and the time.
pub fn show(app: &Rc<App>) {
    let Some(selection) = app.drives() else {
        drives::show(app);
        return;
    };
    let mut page = PageBuilder::new(
        "Replace a lost drive",
        Some(
            "Use this when a CA drive is lost or broken. Connect the healthy CA drives you have and one new, empty drive. Keystone copies the complete CA to the new drive, checks every file by SHA-256 and writes the new drive's identity last. If the primary drive is lost, a backup becomes the primary. Nothing is signed, and nothing on the connected drives is overwritten or deleted.",
        ),
    );
    let (frame, inner) = widgets::group("Connected CA drives");
    let mut connected: Vec<Line> = selection
        .primary
        .iter()
        .map(|p| Line::new(Status::Info, format!("Primary drive {}.", p.display())))
        .collect();
    connected.extend(
        selection
            .backups
            .iter()
            .map(|b| Line::new(Status::Info, format!("Backup drive {}.", b.display()))),
    );
    inner.append(&widgets::status_list(&connected));
    page.add(&frame);
    let (frame, inner) = widgets::group("New drive");
    let entry = drives::folder_row(app, &inner, "_New, empty drive folder", "new drive");
    if let Some(path) = &app.options.new_drive {
        entry.set_text(&path.to_string_lossy());
    }
    page.add(&frame);
    let entries = app
        .session
        .borrow()
        .startup
        .as_ref()
        .map(|s| s.0.audit_entries.clone())
        .unwrap_or_default();
    let panel = ClockPanel::new(
        entries,
        "The replacement is recorded in the audit log on every drive with this time.",
    );
    page.add(panel.widget());
    let problem = StatusLine::new(&Line::new(Status::Info, ""));
    problem.set_visible(false);
    page.add(problem.widget());
    let back = page.secondary_button("_Back to the start-up checks");
    let app_ref = app.clone();
    back.connect_clicked(move |_| startup::show(&app_ref));
    let review = page.primary_button("_Review the replacement");
    review.set_sensitive(panel.confirmation().is_some());
    {
        let review = review.clone();
        let p = panel.clone();
        panel.connect_changed(move || review.set_sensitive(p.confirmation().is_some()));
    }
    page.focus_on(&entry);
    let app_ref = app.clone();
    review.connect_clicked(move |button| {
        let Some(clock) = panel.confirmation() else {
            return;
        };
        let text = entry.text().trim().to_string();
        let new_drive = PathBuf::from(&text);
        if text.is_empty() || !new_drive.is_absolute() {
            problem.set(&Line::new(
                Status::Blocked,
                "Choose the new drive: a full folder path starting with /.",
            ));
            problem.set_visible(true);
            return;
        }
        if selection
            .ca_drives()
            .iter()
            .chain(std::iter::once(&selection.export.as_path()))
            .any(|chosen| new_drive.starts_with(chosen) || chosen.starts_with(&new_drive))
        {
            problem.set(&Line::new(
                Status::Blocked,
                "The new drive must be a different drive from every connected CA drive and the export drive.",
            ));
            problem.set_visible(true);
            return;
        }
        problem.set(&Line::new(Status::Info, "Checking the drives…"));
        problem.set_visible(true);
        button.set_sensitive(false);
        let backend = app_ref.backend.clone();
        let app = app_ref.clone();
        let job_selection = selection.clone();
        let job_drive = new_drive.clone();
        let button = button.clone();
        let problem = problem.clone();
        gtk_glue::run(
            "Checking the drives",
            false,
            move |_| backend.review_replace_drive(&job_selection, &job_drive, &clock),
            |_| {},
            move |result| {
                button.set_sensitive(true);
                match result {
                    Ok(Ok(review)) => {
                        problem.set_visible(false);
                        show_review(&app, &review, new_drive.clone(), clock);
                    }
                    Ok(Err(error)) => {
                        problem.set(&Line::new(Status::Blocked, error.to_string()));
                    }
                    Err(failure) => {
                        problem.set(&Line::new(Status::Blocked, failure.to_string()));
                    }
                }
            },
        );
    });
    app.reset_to(ID, &page.build());
}

fn show_review(
    app: &Rc<App>,
    review: &DriveReplacementReview,
    new_drive: PathBuf,
    clock: crate::backend::ClockConfirmation,
) {
    let mut page = PageBuilder::new(
        "Replace a lost drive: review",
        Some("Check everything below. Nothing has been written yet."),
    );
    page.add(&widgets::status_list(&review_lines(review)));
    let back = page.secondary_button("_Back");
    let app_ref = app.clone();
    back.connect_clicked(move |_| {
        app_ref.back_to(ID);
    });
    let run = page.primary_button("_Replace the lost drive");
    let app_ref = app.clone();
    run.connect_clicked(move |_| {
        app_ref.session.borrow_mut().clock = Some(clock);
        let plan = ReplaceDrivePlan {
            new_drive: new_drive.clone(),
        };
        let added = new_drive.clone();
        exec::execute_then(
            &app_ref,
            "Replacing the lost drive",
            false,
            move |backend, ctx| backend.replace_drive(ctx, plan),
            move |app| {
                let next = app
                    .drives()
                    .map(|selection| selection_after(&selection, added));
                app.session.borrow_mut().drives = next;
            },
        );
    });
    app.push(REVIEW_ID, &page.build());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adr0003_review_shows_every_line_and_the_promotion() {
        // Covers: SEC-11 (ADR 0003), NFR-04
        let review = DriveReplacementReview {
            lines: vec![
                ("New drive".into(), "/m/new".into()),
                (
                    "Copy".into(),
                    "2 operations, 5 files and 3 audit entries".into(),
                ),
            ],
            warnings: vec!["Use this only when the primary drive is lost or broken.".into()],
            promotes: Some("backup drive 1a2b3c4d (/m/b)".into()),
        };
        let lines = review_lines(&review);
        assert_eq!(lines[0].text, "New drive: /m/new.");
        assert!(lines.iter().any(|l| {
            l.status == Status::Warning
                && l.text
                    .contains("backup drive 1a2b3c4d (/m/b) becomes the primary drive")
        }));
        assert!(lines.iter().any(|l| l.text.starts_with("Use this only")));
    }

    #[test]
    fn adr0003_the_new_drive_joins_the_selection() {
        // Covers: SEC-11 (ADR 0003)
        let selection = DriveSelection {
            primary: None,
            backups: vec!["/m/b".into()],
            export: "/m/e".into(),
        };
        let next = selection_after(&selection, "/m/new".into());
        assert_eq!(next.ca_drives().len(), 2);
        assert_eq!(selection_after(&next, "/m/new".into()), next);
    }
}
