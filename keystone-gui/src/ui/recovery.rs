//! The recovery screen (FR-22 AC4, AC5, AC7, AC8, SEC-22).
//!
//! One column per drive and one for the YubiKey, exactly what each holds for the
//! interrupted operation, and at most two actions, each with one plain sentence saying
//! what it will and will not do. Nothing here formats, deletes or overwrites anything;
//! the chosen action goes through the backend adapter (`Backend::recover`).
#![forbid(unsafe_code)]

use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::passphrase::EnteredPassphrase;
use keystone_core::store::{DriveSet, PendingOperation, RecoveryAction, YubikeySetupStep};
use keystone_core::token::{NewPin, NewPuk};

use super::clock::ClockPanel;
use super::forms::{CredentialPair, MasterPassphraseField, PinField};
use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, exec, startup};
use crate::backend::{RecoveryPlan, ResumeCredentials};
use crate::token;
use crate::vm::recovery::{ActionView, OperationView, operation_view};
use crate::vm::token::TokenState;
use crate::vm::{Line, Status};
use crate::worker::gtk_glue;

/// Page ids.
pub const ID: &str = "recovery";
const ACTION_ID: &str = "recovery-action";

type Loaded = (
    Result<Vec<PendingOperation>, String>,
    TokenState,
    Option<crate::backend::SharedToken>,
);

/// Reads the recovery report and the YubiKey, then shows the recovery screen.
pub fn show(app: &Rc<App>) {
    let Some(selection) = app.drives() else {
        return;
    };
    let page = PageBuilder::new(
        "Recover an interrupted operation",
        Some(
            "Keystone is reading what each drive and the YubiKey hold for the interrupted operation.",
        ),
    );
    let spinner = gtk::Spinner::new();
    spinner.start();
    spinner.set_halign(gtk::Align::Start);
    page.add(&spinner);
    app.reset_to(ID, &page.build());
    let existing = app.session.borrow().token.clone();
    let sim = app.options.sim;
    let app = app.clone();
    gtk_glue::run(
        "Reading the drives and the YubiKey",
        false,
        move |_| -> Loaded {
            let report = DriveSet::open(&selection.ca_drives())
                .and_then(|set| set.recovery_report())
                .map(|report| report.pending)
                .map_err(|e| e.to_string());
            let (state, token) = match existing {
                Some(token) => (token::read_state(&token), Some(token)),
                None => match token::connect(&sim) {
                    Ok(token) => (token::read_state(&token), Some(token)),
                    Err(state) => (state, None),
                },
            };
            (report, state, token)
        },
        |_| {},
        move |result| match result {
            Ok((report, state, token)) => {
                if token.is_some() {
                    app.session.borrow_mut().token = token;
                }
                render(&app, report, &state);
            }
            Err(failure) => {
                let mut page = PageBuilder::new("Recover an interrupted operation", None);
                page.add(
                    StatusLine::new(&Line::new(Status::Blocked, failure.to_string())).widget(),
                );
                let back = page.primary_button("_Back to the start-up checks");
                let app_ref = app.clone();
                back.connect_clicked(move |_| startup::show(&app_ref));
                app.reset_to(ID, &page.build());
            }
        },
    );
}

fn render(app: &Rc<App>, report: Result<Vec<PendingOperation>, String>, token: &TokenState) {
    let mut page = PageBuilder::new(
        "Recover an interrupted operation",
        Some(
            "An operation was interrupted. Below is exactly what each drive and the YubiKey hold for it. Keystone offers only safe actions: it never formats, deletes or overwrites anything.",
        ),
    );
    let back = page.secondary_button("_Back to the start-up checks");
    let app_ref = app.clone();
    back.connect_clicked(move |_| startup::show(&app_ref));
    let pending = match report {
        Ok(pending) => pending,
        Err(error) => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Blocked,
                    format!("The interrupted operations could not be read: {error}"),
                ))
                .widget(),
            );
            app.reset_to(ID, &page.build());
            return;
        }
    };
    if pending.is_empty() {
        page.add(StatusLine::new(&Line::new(Status::Ok, "No operation is interrupted.")).widget());
    }
    let mut first_action: Option<gtk::Button> = None;
    for operation in &pending {
        let view = operation_view(operation, token);
        let (frame, inner) = widgets::group(&view.heading);
        inner.append(&columns(&view));
        let (actions_frame, actions) = widgets::group("Recovery actions");
        if let Some(blocked) = &view.blocked {
            actions.append(StatusLine::new(&Line::new(Status::Blocked, blocked.clone())).widget());
        }
        for action in &view.actions {
            let button = gtk::Button::with_label(&action.label);
            button.set_halign(gtk::Align::Start);
            actions.append(&button);
            actions.append(&widgets::paragraph(&action.sentence));
            if first_action.is_none() {
                first_action = Some(button.clone());
            }
            let app_ref = app.clone();
            let action = action.clone();
            let op = operation.clone();
            button.connect_clicked(move |_| show_action(&app_ref, &op, &action));
        }
        inner.append(&actions_frame);
        page.add(&frame);
    }
    if let Some(first) = &first_action {
        page.focus_on(first);
    }
    app.reset_to(ID, &page.build());
}

/// One column per drive and one for the YubiKey (FR-22 AC8).
fn columns(view: &OperationView) -> gtk::ScrolledWindow {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.set_homogeneous(true);
    for column in &view.columns {
        let (frame, inner) = widgets::group(&column.title);
        frame.set_size_request(260, -1);
        inner.append(&widgets::status_list(&column.lines));
        row.append(&frame);
    }
    let scroller = gtk::ScrolledWindow::new();
    scroller.set_vscrollbar_policy(gtk::PolicyType::Never);
    scroller.set_propagate_natural_height(true);
    scroller.set_child(Some(&row));
    scroller
}

/// Secrets the remaining YubiKey setup steps need (FR-22 AC7). Nothing is stored.
struct ResumeFields {
    current_pin: Option<PinField>,
    new_pin: Option<CredentialPair>,
    new_puk: Option<CredentialPair>,
    master: Option<MasterPassphraseField>,
}

impl ResumeFields {
    fn new(
        container: &gtk::Box,
        operation: &PendingOperation,
        next: Option<YubikeySetupStep>,
    ) -> Self {
        let pin_changed = next != Some(YubikeySetupStep::PinChanged);
        let puk_pending = matches!(
            next,
            Some(YubikeySetupStep::PinChanged | YubikeySetupStep::PukChanged)
        );
        let signed = operation
            .drives
            .iter()
            .any(|drive| !drive.signed_certificates.is_empty());
        container.append(&widgets::paragraph(
            "Keystone reads the YubiKey's real state and continues from the first step that is not done. It asks again for a PIN or PUK you already set; it never stores them.",
        ));
        ResumeFields {
            current_pin: pin_changed.then(|| {
                PinField::new(
                    container,
                    "The YubiKey _PIN you set before the interruption",
                )
            }),
            new_pin: (!pin_changed).then(|| CredentialPair::new(container, "PIN")),
            new_puk: puk_pending.then(|| CredentialPair::new(container, "PUK")),
            master: (!signed).then(|| MasterPassphraseField::new(container)),
        }
    }

    fn take(&self) -> Result<ResumeCredentials, String> {
        let current_pin = match &self.current_pin {
            Some(field) => Some(field.take()?),
            None => None,
        };
        let new_pin = match &self.new_pin {
            Some(pair) => {
                let (first, second) = pair.take()?;
                Some(NewPin::from_entries(&first, &second).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        let new_puk = match &self.new_puk {
            Some(pair) => {
                let (first, second) = pair.take()?;
                Some(NewPuk::from_entries(&first, &second).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        let master_passphrase: Option<EnteredPassphrase> = match &self.master {
            Some(field) => Some(field.take()?),
            None => None,
        };
        Ok(ResumeCredentials {
            current_pin,
            new_pin,
            new_puk,
            master_passphrase,
        })
    }
}

fn show_action(app: &Rc<App>, operation: &PendingOperation, action: &ActionView) {
    let mut page = PageBuilder::new(&action.label, Some(&action.sentence));
    let entries = app
        .session
        .borrow()
        .startup
        .as_ref()
        .map(|s| s.0.audit_entries.clone())
        .unwrap_or_default();
    let panel = ClockPanel::new(
        entries,
        "This action is recorded in the audit log with this time.",
    );
    page.add(panel.widget());
    let fields = match &action.action {
        RecoveryAction::ResumeYubikeySetup { next_step } => {
            let (frame, inner) = widgets::group("YubiKey setup");
            let fields = ResumeFields::new(&inner, operation, *next_step);
            page.add(&frame);
            Some(fields)
        }
        _ => None,
    };
    let problem = StatusLine::new(&Line::new(Status::Info, ""));
    problem.set_visible(false);
    page.add(problem.widget());
    let back = page.secondary_button("_Back");
    let app_ref = app.clone();
    back.connect_clicked(move |_| show(&app_ref));
    let run = page.primary_button(&action.label.replace('_', "__"));
    run.set_sensitive(panel.confirmation().is_some());
    {
        let run = run.clone();
        let p = panel.clone();
        panel.connect_changed(move || run.set_sensitive(p.confirmation().is_some()));
    }
    let app_ref = app.clone();
    let op = operation.operation;
    let chosen = action.action.clone();
    let label = action.label.clone();
    run.connect_clicked(move |_| {
        let Some(confirmation) = panel.confirmation() else {
            return;
        };
        let resume = match &fields {
            Some(fields) => match fields.take() {
                Ok(resume) => Some(resume),
                Err(message) => {
                    problem.set(&Line::new(Status::Blocked, message));
                    problem.set_visible(true);
                    return;
                }
            },
            None => None,
        };
        app_ref.session.borrow_mut().clock = Some(confirmation);
        let plan = RecoveryPlan {
            operation: op,
            action: chosen.clone(),
            resume,
        };
        exec::execute(&app_ref, &label, false, move |backend, ctx| {
            backend.recover(ctx, plan)
        });
    });
    app.push(ACTION_ID, &page.build());
}
