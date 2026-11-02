//! The recovery screen (FR-22 AC4, AC5, AC7, AC8, SEC-22).
//!
//! One column per drive and one for the YubiKey, exactly what each holds for the
//! interrupted operation, and at most two actions, each with one plain sentence saying
//! what it will and will not do. The content comes from `ops::Ca::recovery_items`, read
//! with the YubiKey connected (`Backend::recovery_items`). Nothing here formats,
//! deletes or overwrites anything; the chosen action goes through `Backend::recover`.
#![forbid(unsafe_code)]

use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::model::CaLevel;
use keystone_core::ops::{RecoveryAction, RecoveryItem};
use keystone_core::passphrase::EnteredPassphrase;
use keystone_core::token::{NewPin, NewPuk};

use super::clock::ClockPanel;
use super::forms::{
    CredentialPair, CrlForm, MasterPassphraseField, NameForm, PinField, ValidityForm,
};
use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, exec, startup};
use crate::backend::{BackendError, RecoveryPlan, ResumeCredentials, ResumeMainIntermediate};
use crate::token;
use crate::vm::recovery::{ActionView, OperationView, ResumeNeeds, operation_view, resume_needs};
use crate::vm::token::TokenState;
use crate::vm::{Line, Status};
use crate::worker::gtk_glue;

/// Page ids.
pub const ID: &str = "recovery";
const ACTION_ID: &str = "recovery-action";

type Loaded = (
    Result<Vec<RecoveryItem>, BackendError>,
    TokenState,
    Option<crate::backend::SharedToken>,
);

/// Reads the interrupted operations and the YubiKey, then shows the recovery screen.
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
    let backend = app.backend.clone();
    let app = app.clone();
    gtk_glue::run(
        "Reading the drives and the YubiKey",
        false,
        move |_| -> Loaded {
            let (state, token) = match existing {
                Some(token) => (token::read_state(&token), Some(token)),
                None => match token::connect(&sim) {
                    Ok(token) => (token::read_state(&token), Some(token)),
                    Err(state) => (state, None),
                },
            };
            // A YubiKey that cannot be read gives no column; recovery still opens.
            let readable = matches!(state, TokenState::Present { .. });
            let items = backend.recovery_items(&selection, token.as_ref().filter(|_| readable));
            (items, state, token)
        },
        |_| {},
        move |result| match result {
            Ok((items, state, token)) => {
                if token.is_some() {
                    app.session.borrow_mut().token = token;
                }
                render(&app, items, &state);
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

fn render(app: &Rc<App>, items: Result<Vec<RecoveryItem>, BackendError>, token: &TokenState) {
    let mut page = PageBuilder::new(
        "Recover an interrupted operation",
        Some(
            "An operation was interrupted. Below is exactly what each drive and the YubiKey hold for it. Keystone offers only safe actions: it never formats, deletes or overwrites anything.",
        ),
    );
    let back = page.secondary_button("_Back to the start-up checks");
    let app_ref = app.clone();
    back.connect_clicked(move |_| startup::show(&app_ref));
    let items = match items {
        Ok(items) => items,
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
    if items.is_empty() {
        page.add(StatusLine::new(&Line::new(Status::Ok, "No operation is interrupted.")).widget());
    }
    let mut first_action: Option<gtk::Button> = None;
    for item in &items {
        let view = operation_view(item, token);
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
            let item = item.clone();
            button.connect_clicked(move |_| show_action(&app_ref, &item, &action));
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

/// The main intermediate's details, asked again while it is not signed (FR-22 AC7).
struct MainFields {
    name: Rc<NameForm>,
    validity: Rc<ValidityForm>,
    crl: Option<Rc<CrlForm>>,
}

/// What the action asks for. Nothing is stored (FR-22 AC7).
struct ActionFields {
    current_pin: Option<PinField>,
    new_pin: Option<CredentialPair>,
    new_puk: Option<CredentialPair>,
    master: Option<MasterPassphraseField>,
    main: Option<MainFields>,
}

impl ActionFields {
    fn none() -> Self {
        ActionFields {
            current_pin: None,
            new_pin: None,
            new_puk: None,
            master: None,
            main: None,
        }
    }

    fn resume(app: &App, container: &gtk::Box, needs: ResumeNeeds, ask_crl: bool) -> Self {
        container.append(&widgets::paragraph(
            "Keystone reads the YubiKey's real state and continues from the first step that is not done. It asks again for a PIN or PUK you already set; it never stores them.",
        ));
        let main = needs.unsigned.then(|| {
            let master_end = app
                .session
                .borrow()
                .startup
                .as_ref()
                .and_then(|s| s.0.record.clone())
                .and_then(Result::ok)
                .and_then(|record| {
                    record
                        .certificates()
                        .iter()
                        .find(|c| c.certificate.level == CaLevel::Master)
                        .map(|c| c.certificate.not_after.get())
                });
            container.append(&widgets::paragraph(
                "Nothing was signed yet: enter the main intermediate's name exactly as before, and its validity.",
            ));
            MainFields {
                name: NameForm::new(container, "main intermediate"),
                validity: ValidityForm::new(container, CaLevel::MainIntermediate, master_end),
                crl: ask_crl.then(|| CrlForm::new(container, "master", "main intermediate")),
            }
        });
        ActionFields {
            current_pin: needs.current_pin.then(|| {
                PinField::new(
                    container,
                    "The YubiKey _PIN you set before the interruption",
                )
            }),
            new_pin: (!needs.current_pin).then(|| CredentialPair::new(container, "PIN")),
            new_puk: needs.new_puk.then(|| CredentialPair::new(container, "PUK")),
            master: needs
                .unsigned
                .then(|| MasterPassphraseField::new(container)),
            main,
        }
    }

    fn take(&self) -> Result<Option<ResumeCredentials>, String> {
        if self.current_pin.is_none()
            && self.new_pin.is_none()
            && self.new_puk.is_none()
            && self.master.is_none()
            && self.main.is_none()
        {
            return Ok(None);
        }
        let main_intermediate = match &self.main {
            Some(main) => Some(ResumeMainIntermediate {
                name: main.name.value()?,
                validity_years: main.validity.value()?,
                master_crl: match &main.crl {
                    Some(crl) => Some(crl.value()?),
                    None => None,
                },
            }),
            None => None,
        };
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
        Ok(Some(ResumeCredentials {
            current_pin,
            new_pin,
            new_puk,
            master_passphrase,
            main_intermediate,
        }))
    }
}

fn show_action(app: &Rc<App>, item: &RecoveryItem, action: &ActionView) {
    let needs = resume_needs(item, &action.action);
    let resuming = matches!(
        action.action,
        RecoveryAction::ResumeYubikeySetup { .. } | RecoveryAction::CompleteSetupWithExistingKey
    );
    let master = app
        .session
        .borrow()
        .startup
        .as_ref()
        .and_then(|s| s.0.record.clone())
        .and_then(Result::ok)
        .and_then(|record| {
            record
                .certificates()
                .iter()
                .find(|c| c.certificate.level == CaLevel::Master)
                .map(|c| c.certificate.serial)
        });
    match (resuming && needs.unsigned, master, app.drives()) {
        (true, Some(master), Some(drives)) => {
            // FR-18: the master's CRL address is asked only while it is not stored.
            let backend = app.backend.clone();
            let app = app.clone();
            let item = item.clone();
            let action = action.clone();
            gtk_glue::run(
                "Reading the stored CRL address",
                false,
                move |_| backend.issuer_crl_location(&drives, master),
                |_| {},
                move |result| {
                    let ask = !matches!(result, Ok(Ok(Some(_))));
                    action_page(&app, &item, &action, ask);
                },
            );
        }
        _ => action_page(app, item, action, true),
    }
}

fn action_page(app: &Rc<App>, item: &RecoveryItem, action: &ActionView, ask_crl: bool) {
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
        RecoveryAction::ResumeYubikeySetup { .. }
        | RecoveryAction::CompleteSetupWithExistingKey => {
            let (frame, inner) = widgets::group("YubiKey setup");
            let fields =
                ActionFields::resume(app, &inner, resume_needs(item, &action.action), ask_crl);
            page.add(&frame);
            fields
        }
        RecoveryAction::RebuildFromJournal {
            needs_master_passphrase: true,
        } => {
            let (frame, inner) = widgets::group("The master signs its first CRL");
            let mut fields = ActionFields::none();
            fields.master = Some(MasterPassphraseField::new(&inner));
            page.add(&frame);
            fields
        }
        _ => ActionFields::none(),
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
    let op = item.operation;
    let chosen = action.action.clone();
    let label = action.label.clone();
    let cancellable = matches!(
        chosen,
        RecoveryAction::ResumeYubikeySetup { .. } | RecoveryAction::CompleteSetupWithExistingKey
    );
    run.connect_clicked(move |_| {
        let Some(confirmation) = panel.confirmation() else {
            return;
        };
        let resume = match fields.take() {
            Ok(resume) => resume,
            Err(message) => {
                problem.set(&Line::new(Status::Blocked, message));
                problem.set_visible(true);
                return;
            }
        };
        app_ref.session.borrow_mut().clock = Some(confirmation);
        let plan = RecoveryPlan {
            operation: op,
            action: chosen.clone(),
            resume,
        };
        exec::execute(&app_ref, &label, cancellable, move |backend, ctx| {
            backend.recover(ctx, plan)
        });
    });
    app.push(ACTION_ID, &page.build());
}
