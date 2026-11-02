//! Start-up checks (PRD section 6 preamble, FR-12 AC3, FR-13 AC3, FR-14 AC3, FR-19,
//! FR-22 AC4, SEC-09, SEC-19).
#![forbid(unsafe_code)]

use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::store::DriveSet;
use time::OffsetDateTime;

use super::clock::{self, ClockPanel};
use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, drives, flows, recovery, replace_drive};
use crate::vm::drives::{DriveMode, assess_probes, normalize, probe};
use crate::vm::home::FlowKind;
use crate::vm::startup::{Gate, StartupView, evaluate, gather};
use crate::vm::{Line, Status};
use crate::worker::gtk_glue;

/// Page id.
pub const ID: &str = "startup";

/// Runs the start-up checks and shows their result. The drives are read again first:
/// what they hold may have changed (a CA created, a drive replaced and a backup
/// promoted), so the mode and every drive's role are taken from them.
pub fn show(app: &Rc<App>) {
    let Some(selection) = app.drives() else {
        drives::show(app);
        return;
    };
    let page = PageBuilder::new(
        "Start-up checks",
        Some(
            "Keystone is verifying the audit log on every drive, comparing the drives and looking for interrupted operations.",
        ),
    );
    let spinner = gtk::Spinner::new();
    spinner.start();
    spinner.set_halign(gtk::Align::Start);
    page.add(&spinner);
    page.add(StatusLine::new(&Line::new(Status::Info, "Checking the drives…")).widget());
    app.reset_to(ID, &page.build());
    let app = app.clone();
    gtk_glue::run(
        "Checking the drives",
        false,
        move |_| {
            let probes = probe(&selection);
            let selection = normalize(&selection, &probes);
            let assessment = assess_probes(&probe(&selection));
            let data = gather(&selection, assessment.mode == DriveMode::NewCa);
            (selection, assessment, data)
        },
        |_| {},
        move |result| match result {
            Ok((_, assessment, _)) if assessment.mode == DriveMode::Unusable => {
                let mut page = PageBuilder::new(
                    "Start-up checks",
                    Some("The chosen drives cannot be used as they are now."),
                );
                page.add(&widgets::status_list(&assessment.lines));
                let choose = page.primary_button("C_hoose other drives");
                let app_ref = app.clone();
                choose.connect_clicked(move |_| drives::show(&app_ref));
                app.reset_to(ID, &page.build());
            }
            Ok((selection, assessment, data)) => {
                {
                    let mut session = app.session.borrow_mut();
                    session.drives = Some(selection);
                    session.mode = Some(assessment.mode);
                }
                let view = evaluate(
                    &data,
                    keystone_core::build_info::is_production_build(),
                    OffsetDateTime::now_utc(),
                );
                let shared = Rc::new((data, view));
                app.session.borrow_mut().startup = Some(shared.clone());
                render(&app, &shared.1);
            }
            Err(failure) => {
                let mut page = PageBuilder::new("Start-up checks", None);
                page.add(
                    StatusLine::new(&Line::new(Status::Blocked, failure.to_string())).widget(),
                );
                let again = page.primary_button("Check _again");
                let app_again = app.clone();
                again.connect_clicked(move |_| show(&app_again));
                app.reset_to(ID, &page.build());
            }
        },
    );
}

fn render(app: &Rc<App>, view: &StartupView) {
    let mut page = PageBuilder::new(
        "Start-up checks",
        Some(
            "These checks run before every flow. Keystone signs nothing unless every drive holds the same verified history.",
        ),
    );
    for warning in &view.crl_warnings {
        let (banner, button) = widgets::banner(
            &Line::new(warning.status, warning.text.clone()),
            "_Refresh CRL…",
        );
        let app_ref = app.clone();
        let issuer = warning.issuer;
        button.set_sensitive(view.gate == Gate::Continue);
        button.connect_clicked(move |_| flows::start(&app_ref, FlowKind::RefreshCrl, Some(issuer)));
        page.add(&banner);
    }
    for section in &view.sections {
        let (frame, inner) = widgets::group(&section.title);
        inner.append(&widgets::status_list(&section.lines));
        page.add(&frame);
    }
    if !view.histories.is_empty() {
        let (frame, inner) = widgets::group("Divergent histories, side by side");
        inner.append(&widgets::paragraph(&format!(
            "Every drive shares the first {} audit entries. After that the histories differ. Keystone never chooses one, by length or otherwise. Decide which drive set is right with the paper records, and keep every drive as it is.",
            view.common_entries
        )));
        let columns = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        columns.set_homogeneous(true);
        for history in &view.histories {
            let (column, column_inner) = widgets::group(&history.title);
            for entry in &history.entries {
                column_inner.append(&widgets::paragraph(entry));
            }
            columns.append(&column);
        }
        let scroller = gtk::ScrolledWindow::new();
        scroller.set_vscrollbar_policy(gtk::PolicyType::Never);
        scroller.set_child(Some(&columns));
        scroller.set_propagate_natural_height(true);
        inner.append(&scroller);
        page.add(&frame);
    }
    let choose = page.secondary_button("C_hoose other drives");
    let app_ref = app.clone();
    choose.connect_clicked(move |_| drives::show(&app_ref));
    let again = page.secondary_button("Check _again");
    let app_ref = app.clone();
    again.connect_clicked(move |_| show(&app_ref));
    match &view.gate {
        Gate::Continue => {
            let next = page.primary_button("_Continue");
            let app_ref = app.clone();
            next.connect_clicked(move |_| clock::show(&app_ref, clock::Next::Home));
        }
        Gate::NeedsRecovery => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Blocked,
                    format!(
                        "{} interrupted operation{} must be resolved first.",
                        view.pending_operations,
                        if view.pending_operations == 1 {
                            ""
                        } else {
                            "s"
                        }
                    ),
                ))
                .widget(),
            );
            let open = page.primary_button("_Open recovery screen");
            let app_ref = app.clone();
            open.connect_clicked(move |_| recovery::show(&app_ref));
        }
        Gate::NeedsRepair => {
            let button = render_repair(app, &page, view);
            page.focus_on(&button);
        }
        Gate::NeedsDriveReplacement(reason) => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Blocked,
                    format!("Every signing action is disabled. {reason}"),
                ))
                .widget(),
            );
            let replace = page.primary_button("_Replace a lost drive…");
            let app_ref = app.clone();
            replace.connect_clicked(move |_| replace_drive::show(&app_ref));
        }
        Gate::Blocked(reason) => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Blocked,
                    format!("Every signing action is disabled. {reason}"),
                ))
                .widget(),
            );
            page.focus_on(&again);
        }
    }
    app.reset_to(ID, &page.build());
}

/// FR-12 AC3: lists the missing operations; copies them only after the operator ticks
/// that they checked the list. Returns the first widget to focus.
fn render_repair(app: &Rc<App>, page: &PageBuilder, view: &StartupView) -> gtk::Widget {
    let (frame, inner) = widgets::group("Drives behind");
    for repair in &view.repairs {
        inner.append(&widgets::paragraph(&repair.heading));
        for line in &repair.missing {
            inner.append(StatusLine::new(&Line::new(Status::Info, line.clone())).widget());
        }
    }
    inner.append(&widgets::paragraph(
        "Keystone copies each missing operation whole: its journal entries, every output file (each checked against its SHA-256) and its audit entries, and writes the operation's final journal entry last. Nothing is deleted or overwritten.",
    ));
    let entries = app
        .session
        .borrow()
        .startup
        .as_ref()
        .map(|s| s.0.audit_entries.clone())
        .unwrap_or_default();
    let panel = ClockPanel::new(
        entries,
        "The repair is recorded in the audit log with this time.",
    );
    inner.append(panel.widget());
    let tick = gtk::CheckButton::with_label("I have checked the missing operations listed above");
    inner.append(&tick);
    let copy = gtk::Button::with_label("Copy the missing operations");
    copy.set_halign(gtk::Align::Start);
    copy.set_sensitive(false);
    inner.append(&copy);
    let result = gtk::Box::new(gtk::Orientation::Vertical, 6);
    inner.append(&result);
    page.add(&frame);
    let update = {
        let panel = panel.clone();
        let tick = tick.clone();
        let copy = copy.clone();
        move || copy.set_sensitive(tick.is_active() && panel.confirmation().is_some())
    };
    let update = Rc::new(update);
    let u = update.clone();
    tick.connect_toggled(move |_| u());
    let u = update.clone();
    panel.connect_changed(move || u());
    let plans = view.repair_plans.clone();
    let app_ref = app.clone();
    copy.connect_clicked(move |button| {
        let Some(confirmation) = panel.confirmation() else {
            return;
        };
        let Some(selection) = app_ref.drives() else {
            return;
        };
        button.set_sensitive(false);
        widgets::clear(&result);
        result.append(
            StatusLine::new(&Line::new(Status::Info, "Copying the missing operations…")).widget(),
        );
        let plans = plans.clone();
        let app_done = app_ref.clone();
        let result = result.clone();
        gtk_glue::run(
            "Copying the missing operations",
            false,
            move |_| {
                DriveSet::open(&selection.ca_drives())
                    .and_then(|set| set.repair(&plans, confirmation.now()))
                    .map_err(|e| e.to_string())
            },
            |_| {},
            move |outcome| match outcome {
                Ok(Ok(())) => {
                    app_done.toast("The drives were repaired and verified.");
                    show(&app_done);
                }
                Ok(Err(message)) => {
                    widgets::clear(&result);
                    result.append(
                        StatusLine::new(&Line::new(
                            Status::Blocked,
                            format!("The repair did not complete: {message}"),
                        ))
                        .widget(),
                    );
                }
                Err(failure) => {
                    widgets::clear(&result);
                    result.append(
                        StatusLine::new(&Line::new(Status::Blocked, failure.to_string())).widget(),
                    );
                }
            },
        );
    });
    tick.upcast()
}
