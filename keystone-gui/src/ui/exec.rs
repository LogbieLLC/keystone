//! Execute steps: progress with Cancel (FR-16, NFR-03), then the write-and-verify
//! result and the SHA-256 fingerprints (FR-12, FR-20), or the error.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;

use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, flows, startup};
use crate::backend::{Backend, BackendError, ExecContext, FlowOutcome};
use crate::vm::home::FlowKind;
use crate::vm::result;
use crate::vm::{Line, Status};
use crate::worker::{Progress, ProgressView, WorkerFailure, gtk_glue};

/// Page ids.
pub const PROGRESS_ID: &str = "progress";
const RESULT_ID: &str = "result";

/// Runs one execute step through the backend on a worker thread. The confirmed time
/// is used by this step only (SEC-16).
pub fn execute<F>(app: &Rc<App>, title: &str, cancellable: bool, call: F)
where
    F: FnOnce(&dyn Backend, ExecContext) -> Result<FlowOutcome, BackendError> + Send + 'static,
{
    let (drives, clock, token) = {
        let mut session = app.session.borrow_mut();
        (
            session.drives.clone(),
            session.clock.take(),
            session.token.clone(),
        )
    };
    let (Some(drives), Some(clock)) = (drives, clock) else {
        show_error(
            app,
            title,
            &BackendError::Failed(
                "Confirm the date and time before this step. Nothing was written.".to_string(),
            ),
        );
        return;
    };
    let mut page = PageBuilder::new(title, None);
    let spinner = gtk::Spinner::new();
    spinner.set_halign(gtk::Align::Start);
    spinner.start();
    page.add(&spinner);
    let bar = gtk::ProgressBar::new();
    bar.set_show_text(true);
    bar.set_visible(false);
    page.add(&bar);
    let message = StatusLine::new(&Line::new(Status::Info, "Starting…"));
    page.add(message.widget());
    let note = StatusLine::new(&Line::new(Status::Info, ""));
    note.set_visible(false);
    page.add(note.widget());
    let cancel = page.secondary_button("_Cancel");
    cancel.set_visible(false);
    page.focus_on(&cancel);
    app.reset_to(PROGRESS_ID, &page.build());

    let backend = app.backend.clone();
    let handle: Rc<RefCell<Option<Progress>>> = Rc::new(RefCell::new(None));
    {
        let handle = handle.clone();
        cancel.connect_clicked(move |button| {
            if let Some(progress) = handle.borrow().as_ref()
                && progress.request_cancel()
            {
                button.set_sensitive(false);
            }
        });
    }
    let update = {
        let cancel = cancel.clone();
        move |view: &ProgressView| {
            match view.fraction {
                Some(fraction) => {
                    bar.set_visible(true);
                    spinner.set_visible(false);
                    bar.set_fraction(fraction);
                    bar.set_text(Some(&format!("{:.0} %", fraction * 100.0)));
                }
                None => {
                    bar.set_visible(false);
                    spinner.set_visible(true);
                }
            }
            message.set(&Line::new(Status::Info, view.message.clone()));
            match view.cancel_note() {
                Some(text) => {
                    note.set(&Line::new(Status::Info, text));
                    note.set_visible(true);
                }
                None => note.set_visible(false),
            }
            cancel.set_visible(view.cancel_offered());
        }
    };
    let app_done = app.clone();
    let title_done = title.to_string();
    let progress = gtk_glue::run(
        "Starting…",
        cancellable,
        move |progress: &Progress| {
            let ctx = ExecContext {
                drives,
                clock,
                progress: progress.clone(),
                token,
            };
            call(backend.as_ref(), ctx)
        },
        update,
        move |result: Result<Result<FlowOutcome, BackendError>, WorkerFailure>| match result {
            Ok(Ok(outcome)) => show_result(&app_done, &outcome),
            Ok(Err(error)) => show_error(&app_done, &title_done, &error),
            Err(failure) => show_error(
                &app_done,
                &title_done,
                &BackendError::Failed(failure.to_string()),
            ),
        },
    );
    *handle.borrow_mut() = progress;
}

/// FR-20, FR-12: what was written and verified, and every fingerprint.
pub fn show_result(app: &Rc<App>, outcome: &FlowOutcome) {
    let view = result::view(outcome);
    let mut page = PageBuilder::new(&view.title, None);
    if !view.drives.is_empty() {
        let (frame, inner) = widgets::group("Written and verified");
        for (line, files) in view.drives.iter().zip(&view.drive_files) {
            inner.append(StatusLine::new(line).widget());
            for file in files {
                inner.append(&widgets::selectable(file));
            }
        }
        page.add(&frame);
    }
    if !view.export_files.is_empty() {
        let (frame, inner) = widgets::group("Export drive");
        for file in &view.export_files {
            inner.append(&widgets::selectable(file));
        }
        page.add(&frame);
    }
    for cert in &view.certificates {
        let (frame, inner) = widgets::group(&cert.title);
        inner.append(&widgets::paragraph(
            "Write this SHA-256 fingerprint down and keep it with your paper records. You can select and copy it.",
        ));
        let label = gtk::Label::new(Some("SHA-256 fingerprint"));
        label.set_xalign(0.0);
        label.add_css_class("heading");
        inner.append(&label);
        let fingerprint = widgets::selectable(&cert.fingerprint);
        fingerprint.add_css_class("title-4");
        label.set_mnemonic_widget(Some(&fingerprint));
        inner.append(&fingerprint);
        inner.append(&widgets::selectable(&cert.serial));
        page.add(&frame);
    }
    if !view.crls.is_empty() {
        let (frame, inner) = widgets::group("CRLs");
        for crl in &view.crls {
            inner.append(&widgets::paragraph(crl));
        }
        page.add(&frame);
    }
    for note in &view.notes {
        page.add(StatusLine::new(note).widget());
    }
    if view.offer_new_yubikey {
        let button = gtk::Button::with_label("Set up the new YubiKey now");
        button.set_halign(gtk::Align::Start);
        let app_ref = app.clone();
        button.connect_clicked(move |_| flows::start(&app_ref, FlowKind::SetupYubikey, None));
        page.add(&button);
    }
    let done = page.primary_button("_Done");
    let app_ref = app.clone();
    done.connect_clicked(move |_| startup::show(&app_ref));
    app.reset_to(RESULT_ID, &page.build());
}

/// The action did not complete; says what to do next.
pub fn show_error(app: &Rc<App>, title: &str, error: &BackendError) {
    let heading = match error {
        BackendError::NotConnected { .. } => "Not connected yet",
        BackendError::Cancelled => "Cancelled",
        BackendError::Failed(_) => "The action did not complete",
    };
    let mut page = PageBuilder::new(heading, None);
    page.add(&widgets::paragraph(title));
    let status = match error {
        BackendError::Cancelled => Status::Info,
        _ => Status::Blocked,
    };
    page.add(StatusLine::new(&Line::new(status, error.to_string())).widget());
    if matches!(error, BackendError::Failed(_)) {
        page.add(StatusLine::new(&Line::new(
            Status::Info,
            "Keystone checks the drives again on the start-up checks screen. An interrupted operation opens the recovery screen.",
        )).widget());
    }
    let done = page.primary_button("_Back to the start-up checks");
    let app_ref = app.clone();
    done.connect_clicked(move |_| startup::show(&app_ref));
    app.reset_to(RESULT_ID, &page.build());
}
