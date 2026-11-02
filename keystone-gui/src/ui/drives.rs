//! Drive selection (FR-12 AC1, FR-19 AC1, SEC-20): the first screen of every session.
#![forbid(unsafe_code)]

use std::rc::Rc;

use gtk::prelude::*;

use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, startup};
use crate::vm::drives::{DriveForm, assess, probe, validate_form};
use crate::vm::{Line, Status};
use crate::worker::gtk_glue;

/// Page id.
pub const ID: &str = "drives";

fn folder_row(app: &Rc<App>, container: &gtk::Box, label: &str, title: &str) -> gtk::Entry {
    let row = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let entry = widgets::labelled_entry(&row, label);
    entry.set_hexpand(true);
    entry.set_activates_default(true);
    let choose = gtk::Button::with_label(&format!("Choose {title} folder…"));
    choose.set_halign(gtk::Align::Start);
    let window = app.window.clone();
    let target = entry.clone();
    let title = title.to_string();
    choose.connect_clicked(move |_| {
        let chooser = gtk::FileChooserNative::new(
            Some(&format!("Choose the {title} folder")),
            Some(&window),
            gtk::FileChooserAction::SelectFolder,
            Some("_Select"),
            Some("_Cancel"),
        );
        chooser.set_modal(true);
        let target = target.clone();
        let keep = Rc::new(std::cell::RefCell::new(Some(chooser.clone())));
        chooser.connect_response(move |chooser, response| {
            if response == gtk::ResponseType::Accept
                && let Some(path) = chooser.file().and_then(|f| f.path())
            {
                target.set_text(&path.to_string_lossy());
            }
            keep.borrow_mut().take();
        });
        chooser.show();
    });
    row.append(&choose);
    container.append(&row);
    entry
}

/// Shows the drive selection screen.
pub fn show(app: &Rc<App>) {
    let mut page = PageBuilder::new(
        "Choose the CA drives",
        Some(
            "Plug in the primary and backup USB drives and the export drive. Every change is written to the primary and every backup drive and read back to check it. The export drive carries files to issuing systems such as StarnetAuth; it is never a CA drive.",
        ),
    );
    let (frame, inner) = widgets::group("CA drives");
    let primary = folder_row(app, &inner, "_Primary drive folder", "primary drive");
    let backup = folder_row(app, &inner, "_Backup drive folder", "backup drive");
    let second = folder_row(
        app,
        &inner,
        "_Second backup drive folder (optional)",
        "second backup drive",
    );
    page.add(&frame);
    let (frame, inner) = widgets::group("Export drive");
    let export = folder_row(app, &inner, "_Export drive folder", "export drive");
    page.add(&frame);
    let status = gtk::Box::new(gtk::Orientation::Vertical, 6);
    page.add(&status);
    let check = page.primary_button("_Check drives");
    page.focus_on(&primary);

    let session = app.session.borrow();
    let prefill = |entry: &gtk::Entry, path: Option<&std::path::PathBuf>| {
        if let Some(path) = path {
            entry.set_text(&path.to_string_lossy());
        }
    };
    if let Some(selection) = &session.drives {
        prefill(&primary, Some(&selection.primary));
        prefill(&backup, selection.backups.first());
        prefill(&second, selection.backups.get(1));
        prefill(&export, Some(&selection.export));
    } else {
        prefill(&primary, app.options.primary.as_ref());
        prefill(&backup, app.options.backups.first());
        prefill(&second, app.options.backups.get(1));
        prefill(&export, app.options.export.as_ref());
    }
    drop(session);

    let app_ref = app.clone();
    check.connect_clicked(move |button| {
        let form = DriveForm {
            primary: primary.text().to_string(),
            backups: vec![backup.text().to_string(), second.text().to_string()],
            export: export.text().to_string(),
        };
        widgets::clear(&status);
        let selection = match validate_form(&form) {
            Ok(selection) => selection,
            Err(problems) => {
                for problem in problems {
                    status.append(StatusLine::new(&Line::new(Status::Blocked, problem)).widget());
                }
                return;
            }
        };
        button.set_sensitive(false);
        let checking = StatusLine::new(&Line::new(Status::Info, "Checking the drives…"));
        status.append(checking.widget());
        let app = app_ref.clone();
        let status = status.clone();
        let button = button.clone();
        let job_selection = selection.clone();
        gtk_glue::run(
            "Checking the drives",
            false,
            move |_| probe(&job_selection),
            |_| {},
            move |result| {
                button.set_sensitive(true);
                widgets::clear(&status);
                let (ca, export) = match result {
                    Ok(probes) => probes,
                    Err(failure) => {
                        status.append(
                            StatusLine::new(&Line::new(Status::Blocked, failure.to_string()))
                                .widget(),
                        );
                        return;
                    }
                };
                let assessment = assess(&ca, &export);
                widgets::set_status_list(&status, &assessment.lines);
                if assessment.can_continue() {
                    {
                        let mut session = app.session.borrow_mut();
                        session.drives = Some(selection.clone());
                        session.mode = Some(assessment.mode.clone());
                        session.startup = None;
                        session.clock = None;
                    }
                    app.set_subtitle(&format!(
                        "Primary {} · {} backup{} · export {}",
                        selection.primary.display(),
                        selection.backups.len(),
                        if selection.backups.len() == 1 {
                            ""
                        } else {
                            "s"
                        },
                        selection.export.display()
                    ));
                    startup::show(&app);
                }
            },
        );
    });
    app.reset_to(ID, &page.build());
}
