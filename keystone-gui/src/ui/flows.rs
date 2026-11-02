//! Flow wizards A to E and Refresh CRL (PRD section 6). Each wizard collects and
//! validates input with core types, shows a review step, and hands one plan to the
//! backend adapter (`backend::Backend`) through `exec::execute`.
//!
//! Every flow starts after the start-up checks and a clock confirmation; a flow that
//! is started without a confirmed time goes to the clock screen first (SEC-16).
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::model::{CaLevel, RevocationReason, Serial};
use keystone_core::passphrase::{
    ConfirmedPassphrase, EnteredPassphrase, MASTER_MAX_WORDS, MASTER_MIN_WORDS, NewPassphrase,
    entropy_bits,
};
use keystone_core::profile::{CrlLocation, NameConstraintsChoice, ValidatedName, level_profile};
use keystone_core::store::{IssuanceRecord, RecordedCertificate, StatusFilter};
use keystone_core::token::{DeviceInfo, NewPin, NewPuk};
use time::OffsetDateTime;

use super::clock::{self, Next};
use super::forms::{
    ConstraintsForm, CredentialPair, CrlForm, MasterPassphraseField, NameForm, PinField,
    TypedSerialForm, ValidityForm, display_name,
};
use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, exec, home, passphrase, startup, token};
use crate::backend::{
    CreateMasterPlan, IssuerCredential, RefreshCrlPlan, ReplaceYubikeyPlan, RevokePlan,
    SetupYubikeyPlan, SubIntermediatePlan, WipeSlotPlan, YubikeyCredentials,
};
use crate::vm::forms::name_constraints_lines;
use crate::vm::home::FlowKind;
use crate::vm::record::{level_name, reason_name};
use crate::vm::startup::Gate;
use crate::vm::token::{TokenNext, TokenState, describe};
use crate::vm::{Line, Status, format_utc};
use crate::worker::gtk_glue;

/// Starts `flow`. `issuer` preselects the issuer of Refresh CRL (from the warning).
pub fn start(app: &Rc<App>, flow: FlowKind, issuer: Option<Serial>) {
    let gate_open = app
        .session
        .borrow()
        .startup
        .as_ref()
        .is_some_and(|s| s.1.gate == Gate::Continue);
    if !gate_open {
        app.toast("Run the start-up checks first.");
        startup::show(app);
        return;
    }
    if app.session.borrow().clock.is_none() {
        clock::show(app, Next::Flow(flow, issuer));
        return;
    }
    match flow {
        FlowKind::CreateMaster => flow_a(app),
        FlowKind::SetupYubikey => flow_b(app),
        FlowKind::NewSubIntermediate => flow_c(app),
        FlowKind::Revoke => flow_d(app),
        FlowKind::RefreshCrl => refresh_crl(app, issuer),
        FlowKind::ReplaceYubikey => flow_e(app),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A wizard step: Cancel (back to home), optional Back, and the main button.
struct Step {
    page: PageBuilder,
    next: gtk::Button,
}

fn step(
    app: &Rc<App>,
    title: &str,
    intro: Option<&str>,
    back: Option<&'static str>,
    next: &str,
) -> Step {
    let mut page = PageBuilder::new(title, intro);
    let cancel = page.secondary_button("_Cancel");
    let app_ref = app.clone();
    cancel.connect_clicked(move |_| home::show(&app_ref));
    if let Some(back) = back {
        let button = page.secondary_button("_Back");
        let app_ref = app.clone();
        button.connect_clicked(move |_| {
            app_ref.back_to(back);
        });
    }
    let next = page.primary_button(next);
    Step { page, next }
}

fn record(app: &App) -> IssuanceRecord {
    app.session
        .borrow()
        .startup
        .as_ref()
        .and_then(|s| s.0.record.clone())
        .and_then(Result::ok)
        .unwrap_or_else(IssuanceRecord::empty)
}

fn valid_of(record: &IssuanceRecord, level: CaLevel) -> Vec<RecordedCertificate> {
    record
        .filter(None, Some(StatusFilter::Valid), OffsetDateTime::now_utc())
        .into_iter()
        .filter(|cert| cert.certificate.level == level)
        .cloned()
        .collect()
}

fn profile_lines(level: CaLevel) -> Vec<Line> {
    let profile = level_profile(level);
    let key = match level {
        CaLevel::Master => "RSA 8,192-bit, stored only in an encrypted file",
        CaLevel::MainIntermediate => "RSA 4,096-bit, generated on the YubiKey and never leaving it",
        CaLevel::SubIntermediate => "RSA 4,096-bit, stored only in an encrypted file",
    };
    let path = match profile.path_len_constraint {
        None => "no path length limit".to_string(),
        Some(n) => format!("path length {n}"),
    };
    vec![
        Line::new(Status::Info, format!("Key: {key}.")),
        Line::new(Status::Info, "Signature: SHA-384 with RSA (PKCS#1 v1.5)."),
        Line::new(
            Status::Info,
            format!("basicConstraints (critical): CA, {path}."),
        ),
        Line::new(
            Status::Info,
            "keyUsage (critical): keyCertSign and cRLSign.",
        ),
        Line::new(
            Status::Info,
            "These settings are fixed in this version; only the name, validity, permitted names and CRL address can be changed.",
        ),
    ]
}

fn drive_lines(app: &App) -> Vec<Line> {
    let Some(drives) = app.drives() else {
        return Vec::new();
    };
    let mut lines: Vec<Line> = drives
        .primary
        .iter()
        .map(|primary| {
            Line::new(
                Status::Info,
                format!(
                    "Written to the primary drive {} and read back.",
                    primary.display()
                ),
            )
        })
        .collect();
    for backup in &drives.backups {
        lines.push(Line::new(
            Status::Info,
            format!(
                "Written to the backup drive {} and read back.",
                backup.display()
            ),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        format!(
            "Files for issuing systems go to the export drive {}.",
            drives.export.display()
        ),
    ));
    lines
}

fn clock_line(app: &App) -> Line {
    match app.session.borrow().clock {
        Some(clock) => Line::new(
            Status::Ok,
            format!(
                "Time confirmed: {}. It is used for this action only.",
                format_utc(clock.confirmed.get().get())
            ),
        ),
        None => Line::new(Status::Blocked, "The time is not confirmed."),
    }
}

/// Enables `button` when `ok()` is true now and whenever a form changes.
fn gate_button(button: &gtk::Button, ok: Rc<dyn Fn() -> bool>, forms: &[&super::forms::Listeners]) {
    button.set_sensitive(ok());
    for listeners in forms {
        let button = button.clone();
        let ok = ok.clone();
        listeners.add(move || button.set_sensitive(ok()));
    }
}

fn problem_line(page: &PageBuilder) -> StatusLine {
    let line = StatusLine::new(&Line::new(Status::Info, ""));
    line.set_visible(false);
    page.add(line.widget());
    line
}

fn show_problem(line: &StatusLine, text: impl Into<String>) {
    line.set(&Line::new(Status::Blocked, text));
    line.set_visible(true);
}

/// FR-18: asks the backend whether the issuer's CRL address is already set; calls
/// `on_done(true)` when it must be asked now.
fn crl_address_needed(
    app: &Rc<App>,
    issuer: Serial,
    on_done: impl FnOnce(&Rc<App>, bool) + 'static,
) {
    let Some(drives) = app.drives() else {
        on_done(app, true);
        return;
    };
    let backend = app.backend.clone();
    let app = app.clone();
    gtk_glue::run(
        "Reading the stored CRL address",
        false,
        move |_| backend.issuer_crl_location(&drives, issuer),
        |_| {},
        move |result| {
            let needed = !matches!(result, Ok(Ok(Some(_))));
            on_done(&app, needed);
        },
    );
}

// ---------------------------------------------------------------------------
// Flow A: create the master
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FlowA {
    name: Option<ValidatedName>,
    years: u8,
    passphrase: Option<ConfirmedPassphrase>,
}

fn flow_a(app: &Rc<App>) {
    let state = Rc::new(RefCell::new(FlowA::default()));
    let mut s = step(
        app,
        "Create the master: name and validity",
        Some(
            "The master (root) certificate signs the main intermediate and its CRLs. It is self-signed.",
        ),
        None,
        "_Continue",
    );
    let (frame, inner) = widgets::group("Name");
    let name = NameForm::new(&inner, "master");
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Validity");
    let validity = ValidityForm::new(&inner, CaLevel::Master, None);
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Fixed settings");
    inner.append(&widgets::status_list(&profile_lines(CaLevel::Master)));
    s.page.add(&frame);
    let ok: Rc<dyn Fn() -> bool> = {
        let name = name.clone();
        let validity = validity.clone();
        Rc::new(move || name.value().is_ok() && validity.value().is_ok())
    };
    gate_button(&s.next, ok, &[&name.changed, &validity.changed]);
    s.page.focus_on(name.first());
    let app_ref = app.clone();
    s.next.connect_clicked(move |_| {
        let (Ok(n), Ok(years)) = (name.value(), validity.value()) else {
            return;
        };
        {
            let mut st = state.borrow_mut();
            st.name = Some(n);
            st.years = years;
        }
        if state.borrow().passphrase.is_some() {
            flow_a_review(&app_ref, &state);
        } else {
            flow_a_length(&app_ref, &state);
        }
    });
    app.reset_to("flow-a-1", &s.page.build());
}

fn flow_a_length(app: &Rc<App>, state: &Rc<RefCell<FlowA>>) {
    let mut s = step(
        app,
        "Create the master: passphrase length",
        Some(
            "Keystone generates the master passphrase from the 7,776-word list using the system's secure random source. You cannot choose the words. More words are stronger; every word adds about 12.9 bits.",
        ),
        Some("flow-a-1"),
        "_Generate the passphrase",
    );
    let (frame, inner) = widgets::group("Number of words");
    let spin = widgets::labelled_spin(
        &inner,
        "_Number of words (10 to 20)",
        u8::try_from(MASTER_MIN_WORDS).unwrap_or(10),
        u8::try_from(MASTER_MAX_WORDS).unwrap_or(20),
        u8::try_from(MASTER_MIN_WORDS).unwrap_or(10),
    );
    let strength = StatusLine::new(&Line::new(Status::Info, ""));
    inner.append(strength.widget());
    let update = {
        let strength = strength.clone();
        move |spin: &gtk::SpinButton| {
            let words = usize::from(widgets::spin_value(spin));
            strength.set(&Line::new(
                Status::Info,
                format!(
                    "{words} words give about {:.0} bits of strength.",
                    entropy_bits(words)
                ),
            ));
        }
    };
    update(&spin);
    spin.connect_value_changed(update);
    s.page.add(&frame);
    s.page.add(
        StatusLine::new(&Line::new(
            Status::Info,
            "Have paper and a pen ready: the words are shown once, on the next screen.",
        ))
        .widget(),
    );
    let problem = problem_line(&s.page);
    s.page.focus_on(&spin);
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let words = usize::from(widgets::spin_value(&spin));
        match NewPassphrase::generate_master(words) {
            Ok(generated) => {
                let state_ok = state.clone();
                passphrase::start(
                    &app_ref,
                    generated,
                    "master",
                    move |app, confirmed| {
                        state_ok.borrow_mut().passphrase = Some(confirmed);
                        flow_a_review(app, &state_ok);
                    },
                    |app| {
                        app.back_to("flow-a-2");
                    },
                );
            }
            Err(error) => show_problem(&problem, error.to_string()),
        }
    });
    app.push("flow-a-2", &s.page.build());
}

fn flow_a_review(app: &Rc<App>, state: &Rc<RefCell<FlowA>>) {
    let s = step(
        app,
        "Create the master: review",
        Some(
            "Check everything below. Keystone then generates the RSA 8,192-bit key (this can take minutes; you can cancel until the first signature), self-signs the master certificate, signs its first empty CRL, encrypts the key with the passphrase and writes everything to every drive.",
        ),
        Some("flow-a-1"),
        "Create the _master",
    );
    let st = state.borrow();
    let mut lines = vec![clock_line(app)];
    if let Some(name) = &st.name {
        lines.push(Line::new(
            Status::Info,
            format!("Name: {}.", display_name(name)),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        format!("Validity: {} years.", st.years),
    ));
    if let Some(passphrase) = &st.passphrase {
        lines.push(Line::new(
            Status::Ok,
            format!(
                "Passphrase: {} words, confirmed. It will not be shown again.",
                passphrase.word_count()
            ),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        "The master's first, empty CRL goes to the export drive. Upload it to StarnetAuth before the master's first child is deployed.",
    ));
    drop(st);
    s.page.add(&widgets::status_list(&lines));
    s.page
        .add(&widgets::status_list(&profile_lines(CaLevel::Master)));
    s.page.add(&widgets::status_list(&drive_lines(app)));
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let mut st = state.borrow_mut();
        let (Some(name), Some(passphrase)) = (st.name.clone(), st.passphrase.take()) else {
            return;
        };
        let plan = CreateMasterPlan {
            name,
            validity_years: st.years,
            passphrase,
        };
        drop(st);
        exec::execute(
            &app_ref,
            "Creating the master",
            true,
            move |backend, ctx| backend.create_master(ctx, plan),
        );
    });
    app.push("flow-a-3", &s.page.build());
}

// ---------------------------------------------------------------------------
// Flow B: set up the YubiKey and create the main intermediate
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FlowB {
    device: Option<DeviceInfo>,
    harden: bool,
    credentials: Option<YubikeyCredentials>,
    master_crl: Option<CrlLocation>,
    ask_crl: bool,
    name: Option<ValidatedName>,
    years: u8,
    master_passphrase: Option<EnteredPassphrase>,
}

fn flow_b(app: &Rc<App>) {
    let page = PageBuilder::new(
        "Set up the YubiKey: insert it",
        Some(
            "Insert the YubiKey 5 (firmware 5.7 or newer). Keystone reads its serial number, firmware and signing slot before doing anything.",
        ),
    );
    let spinner = gtk::Spinner::new();
    spinner.start();
    spinner.set_halign(gtk::Align::Start);
    page.add(&spinner);
    app.reset_to("flow-b-1", &page.build());
    token::detect(app, |app, state| flow_b_detected(app, &state));
}

fn flow_b_detected(app: &Rc<App>, token_state: &TokenState) {
    let (lines, next) = describe(token_state);
    let label = match next {
        TokenNext::Harden | TokenNext::UseCurrentPin => "_Continue",
        TokenNext::OfferWipe => "_Wipe the signing slot…",
        TokenNext::Stop => "Check the YubiKey _again",
    };
    let s = step(app, "Set up the YubiKey: insert it", None, None, label);
    s.page.add(&widgets::status_list(&lines));
    let device = match token_state {
        TokenState::Present { info, .. } => Some(*info),
        _ => None,
    };
    let app_ref = app.clone();
    let token_state = token_state.clone();
    s.next.connect_clicked(move |_| match next {
        TokenNext::Stop => flow_b(&app_ref),
        TokenNext::OfferWipe => {
            if let Some(device) = device {
                wipe_slot(&app_ref, device, &token_state);
            }
        }
        TokenNext::Harden | TokenNext::UseCurrentPin => {
            let Some(device) = device else {
                return;
            };
            let state = Rc::new(RefCell::new(FlowB {
                device: Some(device),
                harden: next == TokenNext::Harden,
                ..FlowB::default()
            }));
            flow_b_credentials(&app_ref, &state);
        }
    });
    app.reset_to("flow-b-1", &s.page.build());
}

/// FR-07 AC4: the only way forward from an occupied slot is an explicit wipe, confirmed
/// by typing this YubiKey's serial number.
fn wipe_slot(app: &Rc<App>, device: DeviceInfo, token_state: &TokenState) {
    let mut s = step(
        app,
        "Wipe the YubiKey signing slot",
        Some(
            "The signing slot is not empty. Keystone never overwrites a slot silently. Wiping deletes the signing slot's key and certificate for good; if that key belongs to a valid main intermediate, that intermediate can no longer sign anything.",
        ),
        Some("flow-b-1"),
        "_Wipe the signing slot",
    );
    let (lines, _) = describe(token_state);
    s.page.add(&widgets::status_list(&lines));
    let (frame, inner) = widgets::group("Confirm the wipe");
    let typed = TypedSerialForm::new(&inner, device);
    let pin = PinField::new(&inner, "YubiKey _PIN");
    s.page.add(&frame);
    let problem = problem_line(&s.page);
    let ok: Rc<dyn Fn() -> bool> = {
        let typed = typed.clone();
        Rc::new(move || typed.value().is_ok())
    };
    gate_button(&s.next, ok, &[&typed.changed]);
    s.page.focus_on(typed.entry());
    let app_ref = app.clone();
    s.next.connect_clicked(move |_| {
        let Ok(confirmation) = typed.value() else {
            return;
        };
        let pin = match pin.take() {
            Ok(pin) => pin,
            Err(message) => {
                show_problem(&problem, message);
                return;
            }
        };
        let plan = WipeSlotPlan { confirmation, pin };
        exec::execute(
            &app_ref,
            "Wiping the YubiKey signing slot",
            false,
            move |backend, ctx| backend.wipe_signing_slot(ctx, plan),
        );
    });
    app.push("flow-b-wipe", &s.page.build());
}

fn flow_b_credentials(app: &Rc<App>, state: &Rc<RefCell<FlowB>>) {
    let harden = state.borrow().harden;
    let intro = if harden {
        "This YubiKey still has factory-default codes. Choose a new PIN and a new PUK (6 to 8 characters each, entered twice). Keystone then sets a random AES-256 management key, stored on the YubiKey and protected by the PIN, and requires the PIN and a touch for every signature. Write the PIN and PUK down; Keystone never stores them."
    } else {
        "This YubiKey is already hardened. Enter its PIN."
    };
    let s = step(
        app,
        "Set up the YubiKey: PIN and PUK",
        Some(intro),
        Some("flow-b-1"),
        "_Continue",
    );
    let (frame, inner) = widgets::group(if harden { "New PIN and PUK" } else { "PIN" });
    let pair_pin = harden.then(|| CredentialPair::new(&inner, "PIN"));
    let pair_puk = harden.then(|| CredentialPair::new(&inner, "PUK"));
    let current = (!harden).then(|| PinField::new(&inner, "YubiKey _PIN"));
    s.page.add(&frame);
    let problem = problem_line(&s.page);
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let credentials = if let (Some(pin), Some(puk)) = (&pair_pin, &pair_puk) {
            let taken = pin.take().and_then(|(a, b)| {
                let (c, d) = puk.take()?;
                Ok((a, b, c, d))
            });
            match taken.and_then(|(a, b, c, d)| {
                let pin = NewPin::from_entries(&a, &b).map_err(|e| e.to_string())?;
                let puk = NewPuk::from_entries(&c, &d).map_err(|e| e.to_string())?;
                Ok(YubikeyCredentials::SetNew { pin, puk })
            }) {
                Ok(credentials) => credentials,
                Err(message) => {
                    show_problem(&problem, format!("{message}. Type both values again."));
                    return;
                }
            }
        } else if let Some(current) = &current {
            match current.take() {
                Ok(pin) => YubikeyCredentials::Existing { pin },
                Err(message) => {
                    show_problem(&problem, message);
                    return;
                }
            }
        } else {
            return;
        };
        state.borrow_mut().credentials = Some(credentials);
        let master = valid_of(&record(&app_ref), CaLevel::Master);
        let Some(master) = master.first().map(|m| m.certificate.serial) else {
            show_problem(&problem, "The record holds no valid master certificate.");
            return;
        };
        let state = state.clone();
        crl_address_needed(&app_ref, master, move |app, needed| {
            state.borrow_mut().ask_crl = needed;
            if needed {
                flow_b_crl(app, &state);
            } else {
                flow_b_name(app, &state, "flow-b-2");
            }
        });
    });
    app.push("flow-b-2", &s.page.build());
}

fn flow_b_crl(app: &Rc<App>, state: &Rc<RefCell<FlowB>>) {
    let s = step(
        app,
        "Set up the YubiKey: the master's CRL address",
        None,
        Some("flow-b-2"),
        "_Continue",
    );
    let (frame, inner) = widgets::group("Master CRL address");
    let crl = CrlForm::new(&inner, "master", "main intermediate");
    s.page.add(&frame);
    let ok: Rc<dyn Fn() -> bool> = {
        let crl = crl.clone();
        Rc::new(move || crl.value().is_ok())
    };
    gate_button(&s.next, ok, &[&crl.changed]);
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let Ok(location) = crl.value() else {
            return;
        };
        state.borrow_mut().master_crl = Some(location);
        flow_b_name(&app_ref, &state, "flow-b-3");
    });
    app.push("flow-b-3", &s.page.build());
}

fn flow_b_name(app: &Rc<App>, state: &Rc<RefCell<FlowB>>, back: &'static str) {
    let master_end = valid_of(&record(app), CaLevel::Master)
        .first()
        .map(|m| m.certificate.not_after.get());
    let mut s = step(
        app,
        "Set up the YubiKey: main intermediate",
        None,
        Some(back),
        "_Continue",
    );
    let (frame, inner) = widgets::group("Name");
    let name = NameForm::new(&inner, "main intermediate");
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Validity");
    let validity = ValidityForm::new(&inner, CaLevel::MainIntermediate, master_end);
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Fixed settings");
    inner.append(&widgets::status_list(&profile_lines(
        CaLevel::MainIntermediate,
    )));
    s.page.add(&frame);
    let ok: Rc<dyn Fn() -> bool> = {
        let name = name.clone();
        let validity = validity.clone();
        Rc::new(move || name.value().is_ok() && validity.value().is_ok())
    };
    gate_button(&s.next, ok, &[&name.changed, &validity.changed]);
    s.page.focus_on(name.first());
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let (Ok(n), Ok(years)) = (name.value(), validity.value()) else {
            return;
        };
        {
            let mut st = state.borrow_mut();
            st.name = Some(n);
            st.years = years;
        }
        unlock_master(&app_ref, "flow-b-4", "flow-b-5", {
            let state = state.clone();
            move |app, passphrase| {
                state.borrow_mut().master_passphrase = Some(passphrase);
                flow_b_review(app, &state);
            }
        });
    });
    app.push("flow-b-4", &s.page.build());
}

/// The master passphrase step shared by Flows B, D, E and Refresh CRL.
fn unlock_master(
    app: &Rc<App>,
    back: &'static str,
    id: &'static str,
    on_done: impl Fn(&Rc<App>, EnteredPassphrase) + 'static,
) {
    let mut s = step(
        app,
        "Unlock the master",
        Some(
            "The master key signs this step. Keystone decrypts it only in locked memory and wipes it right after signing.",
        ),
        Some(back),
        "_Continue",
    );
    let (frame, inner) = widgets::group("Master passphrase");
    let field = MasterPassphraseField::new(&inner);
    s.page.add(&frame);
    let problem = problem_line(&s.page);
    s.page.focus_on(field.entry());
    let app_ref = app.clone();
    s.next.connect_clicked(move |_| match field.take() {
        Ok(passphrase) => on_done(&app_ref, passphrase),
        Err(message) => show_problem(&problem, message),
    });
    app.push(id, &s.page.build());
}

fn flow_b_review(app: &Rc<App>, state: &Rc<RefCell<FlowB>>) {
    let s = step(
        app,
        "Set up the YubiKey: review",
        Some("Check everything below. Touch the YubiKey when it blinks."),
        Some("flow-b-4"),
        "Set up the _YubiKey",
    );
    let st = state.borrow();
    let mut lines = vec![clock_line(app)];
    if let Some(device) = &st.device {
        lines.push(Line::new(
            Status::Info,
            format!(
                "YubiKey serial number {}, firmware {}.",
                device.serial, device.firmware
            ),
        ));
    }
    if st.harden {
        lines.push(Line::new(
            Status::Info,
            "Set the new PIN and PUK, then a random AES-256 management key protected by the PIN.",
        ));
    }
    lines.push(Line::new(
        Status::Info,
        "Generate the RSA 4,096-bit key on the YubiKey with PIN and touch required for every signature, and verify its attestation.",
    ));
    if let Some(name) = &st.name {
        lines.push(Line::new(
            Status::Info,
            format!("Main intermediate: {}.", display_name(name)),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        format!("Validity: {} years.", st.years),
    ));
    match &st.master_crl {
        Some(CrlLocation::Url(url)) => lines.push(Line::new(
            Status::Info,
            format!("Master CRL address: {url}."),
        )),
        Some(CrlLocation::ExplicitlyNone) => lines.push(Line::new(
            Status::Warning,
            keystone_core::profile::CRL_NONE_WARNING,
        )),
        None => lines.push(Line::new(Status::Info, "Master CRL address: already set.")),
    }
    lines.push(Line::new(
        Status::Info,
        "The main intermediate's first, empty CRL (YubiKey PIN and touch) goes to the export drive. Upload it to StarnetAuth before the first sub-intermediate is deployed.",
    ));
    drop(st);
    s.page.add(&widgets::status_list(&lines));
    s.page.add(&widgets::status_list(&drive_lines(app)));
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let mut st = state.borrow_mut();
        let (Some(device), Some(credentials), Some(name), Some(master_passphrase)) = (
            st.device,
            st.credentials.take(),
            st.name.clone(),
            st.master_passphrase.take(),
        ) else {
            drop(st);
            app_ref.toast("Some answers are missing; start the flow again.");
            home::show(&app_ref);
            return;
        };
        let plan = SetupYubikeyPlan {
            device,
            credentials,
            master_crl: st.master_crl.clone(),
            name,
            validity_years: st.years,
            master_passphrase,
        };
        drop(st);
        exec::execute(
            &app_ref,
            "Setting up the YubiKey",
            true,
            move |backend, ctx| backend.setup_yubikey(ctx, plan),
        );
    });
    app.push("flow-b-6", &s.page.build());
}

// ---------------------------------------------------------------------------
// Flow C: create a sub-intermediate
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FlowC {
    name: Option<ValidatedName>,
    years: u8,
    constraints: Option<NameConstraintsChoice>,
    issuer_crl: Option<CrlLocation>,
    passphrase: Option<ConfirmedPassphrase>,
}

fn flow_c(app: &Rc<App>) {
    let record = record(app);
    let main = valid_of(&record, CaLevel::MainIntermediate);
    let Some(main) = main.first().cloned() else {
        app.toast("There is no valid main intermediate.");
        home::show(app);
        return;
    };
    let state = Rc::new(RefCell::new(FlowC::default()));
    let mut s = step(
        app,
        "New sub-intermediate: name, validity and permitted names",
        Some(
            "A sub-intermediate is exported as an encrypted key with its own passphrase for an issuing system such as StarnetAuth. The YubiKey signs it.",
        ),
        None,
        "_Continue",
    );
    let (frame, inner) = widgets::group("Name");
    let name = NameForm::new(&inner, "sub-intermediate");
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Validity");
    let validity = ValidityForm::new(
        &inner,
        CaLevel::SubIntermediate,
        Some(main.certificate.not_after.get()),
    );
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Permitted names (name constraints)");
    let constraints = ConstraintsForm::new(&inner);
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Fixed settings");
    inner.append(&widgets::status_list(&profile_lines(
        CaLevel::SubIntermediate,
    )));
    s.page.add(&frame);
    let ok: Rc<dyn Fn() -> bool> = {
        let name = name.clone();
        let validity = validity.clone();
        let constraints = constraints.clone();
        Rc::new(move || {
            name.value().is_ok() && validity.value().is_ok() && constraints.value().is_ok()
        })
    };
    gate_button(
        &s.next,
        ok,
        &[&name.changed, &validity.changed, &constraints.changed],
    );
    s.page.focus_on(name.first());
    let app_ref = app.clone();
    let issuer = main.certificate.serial;
    s.next.connect_clicked(move |_| {
        let (Ok(n), Ok(years), Ok(choice)) = (name.value(), validity.value(), constraints.value())
        else {
            return;
        };
        {
            let mut st = state.borrow_mut();
            st.name = Some(n);
            st.years = years;
            st.constraints = Some(choice);
        }
        let state = state.clone();
        crl_address_needed(&app_ref, issuer, move |app, needed| {
            if needed {
                flow_c_crl(app, &state);
            } else {
                flow_c_passphrase(app, &state, "flow-c-1");
            }
        });
    });
    app.reset_to("flow-c-1", &s.page.build());
}

fn flow_c_crl(app: &Rc<App>, state: &Rc<RefCell<FlowC>>) {
    let s = step(
        app,
        "New sub-intermediate: the main intermediate's CRL address",
        None,
        Some("flow-c-1"),
        "_Continue",
    );
    let (frame, inner) = widgets::group("Main intermediate CRL address");
    let crl = CrlForm::new(&inner, "main intermediate", "sub-intermediate");
    s.page.add(&frame);
    let ok: Rc<dyn Fn() -> bool> = {
        let crl = crl.clone();
        Rc::new(move || crl.value().is_ok())
    };
    gate_button(&s.next, ok, &[&crl.changed]);
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let Ok(location) = crl.value() else {
            return;
        };
        state.borrow_mut().issuer_crl = Some(location);
        flow_c_passphrase(&app_ref, &state, "flow-c-2");
    });
    app.push("flow-c-2", &s.page.build());
}

fn flow_c_passphrase(app: &Rc<App>, state: &Rc<RefCell<FlowC>>, back: &'static str) {
    if state.borrow().passphrase.is_some() {
        flow_c_review(app, state);
        return;
    }
    let s = step(
        app,
        "New sub-intermediate: passphrase",
        Some(
            "Keystone generates a 10-word passphrase for the sub-intermediate's key. You will hand it to the issuing system together with the encrypted key. Have paper and a pen ready: the words are shown once, on the next screen.",
        ),
        Some(back),
        "_Generate the passphrase",
    );
    let problem = problem_line(&s.page);
    let app_ref = app.clone();
    let state = state.clone();
    s.next
        .connect_clicked(move |_| match NewPassphrase::generate_sub_intermediate() {
            Ok(generated) => {
                let state_ok = state.clone();
                passphrase::start(
                    &app_ref,
                    generated,
                    "sub-intermediate",
                    move |app, confirmed| {
                        state_ok.borrow_mut().passphrase = Some(confirmed);
                        flow_c_review(app, &state_ok);
                    },
                    |app| {
                        app.back_to("flow-c-3");
                    },
                );
            }
            Err(error) => show_problem(&problem, error.to_string()),
        });
    app.push("flow-c-3", &s.page.build());
}

fn flow_c_review(app: &Rc<App>, state: &Rc<RefCell<FlowC>>) {
    let mut s = step(
        app,
        "New sub-intermediate: review",
        Some(
            "Check everything below, including the permitted names. Then enter the YubiKey PIN and touch the YubiKey when it blinks: the main intermediate signs the certificate.",
        ),
        Some("flow-c-1"),
        "Create the _sub-intermediate",
    );
    let st = state.borrow();
    let mut lines = vec![clock_line(app)];
    if let Some(name) = &st.name {
        lines.push(Line::new(
            Status::Info,
            format!("Name: {}.", display_name(name)),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        format!("Validity: {} years.", st.years),
    ));
    if let Some(choice) = &st.constraints {
        for line in name_constraints_lines(choice) {
            let status = if matches!(choice, NameConstraintsChoice::ExplicitlyUnconstrained) {
                Status::Warning
            } else {
                Status::Info
            };
            lines.push(Line::new(status, line));
        }
    }
    match &st.issuer_crl {
        Some(CrlLocation::Url(url)) => lines.push(Line::new(
            Status::Info,
            format!("Main intermediate CRL address: {url}."),
        )),
        Some(CrlLocation::ExplicitlyNone) => lines.push(Line::new(
            Status::Warning,
            keystone_core::profile::CRL_NONE_WARNING,
        )),
        None => lines.push(Line::new(
            Status::Info,
            "Main intermediate CRL address: already set.",
        )),
    }
    if let Some(passphrase) = &st.passphrase {
        lines.push(Line::new(
            Status::Ok,
            format!(
                "Passphrase: {} words, confirmed. It will not be shown again.",
                passphrase.word_count()
            ),
        ));
    }
    lines.push(Line::new(
        Status::Info,
        "Output: the certificate (.crt), the encrypted key (.key) and the chain (-chain.pem) on every drive and on the export drive.",
    ));
    drop(st);
    s.page.add(&widgets::status_list(&lines));
    s.page.add(&widgets::status_list(&drive_lines(app)));
    let (frame, inner) = widgets::group("YubiKey");
    let yubikey = gtk::Box::new(gtk::Orientation::Vertical, 6);
    inner.append(&yubikey);
    let pin = Rc::new(PinField::new(&inner, "YubiKey _PIN"));
    s.page.add(&frame);
    let problem = problem_line(&s.page);
    s.page.focus_on(pin.entry());
    s.next.set_sensitive(false);
    {
        let next = s.next.clone();
        let yubikey = yubikey.clone();
        token::detect(app, move |_, token_state| {
            let (lines, _) = describe(&token_state);
            widgets::set_status_list(&yubikey, &lines);
            next.set_sensitive(matches!(token_state, TokenState::Present { .. }));
        });
    }
    let app_ref = app.clone();
    let state = state.clone();
    s.next.connect_clicked(move |_| {
        let pin = match pin.take() {
            Ok(pin) => pin,
            Err(message) => {
                show_problem(&problem, message);
                return;
            }
        };
        let mut st = state.borrow_mut();
        let (Some(name), Some(name_constraints), Some(passphrase)) = (
            st.name.clone(),
            st.constraints.clone(),
            st.passphrase.take(),
        ) else {
            return;
        };
        let plan = SubIntermediatePlan {
            name,
            validity_years: st.years,
            name_constraints,
            issuer_crl: st.issuer_crl.clone(),
            passphrase,
            pin,
        };
        drop(st);
        exec::execute(
            &app_ref,
            "Creating the sub-intermediate",
            true,
            move |backend, ctx| backend.create_sub_intermediate(ctx, plan),
        );
    });
    app.push("flow-c-4", &s.page.build());
}

// ---------------------------------------------------------------------------
// Flow D: revoke; Refresh CRL; shared credential step
// ---------------------------------------------------------------------------

/// The issuer's secret: the master passphrase (main intermediates) or the YubiKey PIN
/// (sub-intermediates).
struct CredentialStep {
    issuer_level: CaLevel,
    title: &'static str,
    review: Vec<Line>,
    back: &'static str,
    id: &'static str,
    button: &'static str,
}

fn credential_step(
    app: &Rc<App>,
    spec: CredentialStep,
    run: impl Fn(&Rc<App>, IssuerCredential) + 'static,
) {
    let CredentialStep {
        issuer_level,
        title,
        review,
        back,
        id,
        button,
    } = spec;
    let mut s = step(app, title, None, Some(back), button);
    let mut lines = vec![clock_line(app)];
    lines.extend(review);
    s.page.add(&widgets::status_list(&lines));
    s.page.add(&widgets::status_list(&drive_lines(app)));
    let problem = problem_line(&s.page);
    let (frame, inner) = widgets::group(match issuer_level {
        CaLevel::Master => "The master signs",
        _ => "The YubiKey signs",
    });
    let take: Box<dyn Fn() -> Result<IssuerCredential, String>> = match issuer_level {
        CaLevel::Master => {
            let field = MasterPassphraseField::new(&inner);
            s.page.focus_on(field.entry());
            Box::new(move || field.take().map(IssuerCredential::MasterPassphrase))
        }
        _ => {
            let yubikey = gtk::Box::new(gtk::Orientation::Vertical, 6);
            inner.append(&yubikey);
            inner.append(&widgets::paragraph(
                "Enter the YubiKey PIN, then touch the YubiKey when it blinks.",
            ));
            let field = PinField::new(&inner, "YubiKey _PIN");
            s.page.focus_on(field.entry());
            s.next.set_sensitive(false);
            let next = s.next.clone();
            token::detect(app, move |_, token_state| {
                let (lines, _) = describe(&token_state);
                widgets::set_status_list(&yubikey, &lines);
                next.set_sensitive(matches!(token_state, TokenState::Present { .. }));
            });
            Box::new(move || field.take().map(IssuerCredential::YubikeyPin))
        }
    };
    s.page.add(&frame);
    let app_ref = app.clone();
    s.next.connect_clicked(move |_| match take() {
        Ok(credential) => run(&app_ref, credential),
        Err(message) => show_problem(&problem, message),
    });
    app.push(id, &s.page.build());
}

fn cert_label(cert: &RecordedCertificate) -> String {
    format!(
        "{} ({}), serial {}, valid until {}",
        cert.certificate.subject.display(),
        level_name(cert.certificate.level),
        cert.certificate.serial,
        format_utc(cert.certificate.not_after.get())
    )
}

fn flow_d(app: &Rc<App>) {
    let record = record(app);
    let mut candidates = valid_of(&record, CaLevel::MainIntermediate);
    candidates.extend(valid_of(&record, CaLevel::SubIntermediate));
    let mut s = step(
        app,
        "Revoke a certificate",
        Some(
            "Choose the certificate to revoke and the reason. For a sub-intermediate the YubiKey signs the new CRL (PIN and touch); for a main intermediate the master signs it (passphrase).",
        ),
        None,
        "_Continue",
    );
    let (frame, inner) = widgets::group("Certificate");
    let mut buttons: Vec<(gtk::CheckButton, RecordedCertificate)> = Vec::new();
    for cert in &candidates {
        let button = gtk::CheckButton::with_label(&cert_label(cert));
        if let Some((first, _)) = buttons.first() {
            button.set_group(Some(first));
        } else {
            button.set_active(true);
        }
        inner.append(&button);
        buttons.push((button, cert.clone()));
    }
    if buttons.is_empty() {
        inner.append(
            StatusLine::new(&Line::new(
                Status::Info,
                "There is no valid intermediate to revoke.",
            ))
            .widget(),
        );
        s.next.set_sensitive(false);
    }
    s.page.add(&frame);
    let (frame, inner) = widgets::group("Reason");
    let reasons: Vec<&str> = RevocationReason::ALL
        .iter()
        .map(|r| reason_name(*r))
        .collect();
    let reason = widgets::labelled_dropdown(&inner, "_Revocation reason", &reasons);
    s.page.add(&frame);
    if let Some((first, _)) = buttons.first() {
        s.page.focus_on(first);
    }
    let app_ref = app.clone();
    s.next.connect_clicked(move |_| {
        let Some((_, cert)) = buttons.iter().find(|(b, _)| b.is_active()) else {
            return;
        };
        let Some(reason) = RevocationReason::ALL.get(reason.selected() as usize).copied() else {
            return;
        };
        let serial = cert.certificate.serial;
        let level = cert.certificate.level;
        let issuer_level = level.issuer_level().unwrap_or(CaLevel::Master);
        let review = vec![
            Line::new(Status::Warning, format!("Revoke: {}.", cert_label(cert))),
            Line::new(Status::Info, format!("Reason: {}.", reason_name(reason))),
            Line::new(
                Status::Info,
                "A new CRL is signed and written to every drive and the export drive. Upload it to where it is hosted.",
            ),
        ];
        credential_step(
            &app_ref,
            CredentialStep {
                issuer_level,
                title: "Revoke a certificate: review and sign",
                review,
                back: "flow-d-1",
                id: "flow-d-2",
                button: "_Revoke",
            },
            move |app, credential| {
                let plan = RevokePlan {
                    serial,
                    level,
                    reason,
                    credential,
                };
                exec::execute(app, "Revoking the certificate", true, move |backend, ctx| {
                    backend.revoke(ctx, plan)
                });
            },
        );
    });
    app.reset_to("flow-d-1", &s.page.build());
}

fn refresh_crl(app: &Rc<App>, preselected: Option<Serial>) {
    let record = record(app);
    let mut issuers = valid_of(&record, CaLevel::Master);
    issuers.extend(valid_of(&record, CaLevel::MainIntermediate));
    let mut s = step(
        app,
        "Refresh a CRL",
        Some(
            "Re-sign an issuer's current CRL with a new this-update, a new next-update and a higher CRL number, without any new revocation. The new CRL goes to the export drive for StarnetAuth to host.",
        ),
        None,
        "_Continue",
    );
    let (frame, inner) = widgets::group("Issuer");
    let mut buttons: Vec<(gtk::CheckButton, RecordedCertificate)> = Vec::new();
    for cert in &issuers {
        let button = gtk::CheckButton::with_label(&cert_label(cert));
        if let Some((first, _)) = buttons.first() {
            button.set_group(Some(first));
        }
        let selected = preselected.map_or(buttons.is_empty(), |s| s == cert.certificate.serial);
        button.set_active(selected);
        inner.append(&button);
        buttons.push((button, cert.clone()));
    }
    if buttons.is_empty() {
        inner.append(
            StatusLine::new(&Line::new(Status::Info, "There is no valid issuer.")).widget(),
        );
        s.next.set_sensitive(false);
    }
    s.page.add(&frame);
    if let Some((first, _)) = buttons
        .iter()
        .find(|(b, _)| b.is_active())
        .or(buttons.first())
    {
        s.page.focus_on(first);
    }
    let app_ref = app.clone();
    s.next.connect_clicked(move |_| {
        let Some((_, cert)) = buttons.iter().find(|(b, _)| b.is_active()) else {
            return;
        };
        let issuer = cert.certificate.serial;
        let review = vec![Line::new(
            Status::Info,
            format!("Refresh the CRL of {}.", cert_label(cert)),
        )];
        credential_step(
            &app_ref,
            CredentialStep {
                issuer_level: cert.certificate.level,
                title: "Refresh a CRL: review and sign",
                review,
                back: "flow-crl-1",
                id: "flow-crl-2",
                button: "_Refresh the CRL",
            },
            move |app, credential| {
                let plan = RefreshCrlPlan { issuer, credential };
                exec::execute(app, "Refreshing the CRL", true, move |backend, ctx| {
                    backend.refresh_crl(ctx, plan)
                });
            },
        );
    });
    app.reset_to("flow-crl-1", &s.page.build());
}

// ---------------------------------------------------------------------------
// Flow E: replace a lost YubiKey
// ---------------------------------------------------------------------------

fn flow_e(app: &Rc<App>) {
    let record = record(app);
    let mains = valid_of(&record, CaLevel::MainIntermediate);
    let Some(old) = mains.first().cloned() else {
        app.toast("There is no valid main intermediate.");
        home::show(app);
        return;
    };
    let children: Vec<String> = record
        .children_of(old.certificate.serial)
        .into_iter()
        .filter(|c| c.effective_status(OffsetDateTime::now_utc()) == StatusFilter::Valid)
        .map(cert_label)
        .collect();
    let mut s = step(
        app,
        "Replace lost YubiKey",
        Some(
            "The old YubiKey does not need to be present. The master revokes the old main intermediate and signs a new master CRL. Every sub-intermediate signed by the old main intermediate is marked \"revoked by ancestor\"; revoking the old main intermediate already cuts them off. Then you set up the new YubiKey and re-issue each sub-intermediate under it. The old main intermediate's last CRL stays hosted until it expires.",
        ),
        None,
        "_Continue",
    );
    let mut lines = vec![Line::new(
        Status::Warning,
        format!("Revoke: {}.", cert_label(&old)),
    )];
    if children.is_empty() {
        lines.push(Line::new(
            Status::Info,
            "No valid sub-intermediate was signed by it.",
        ));
    }
    for child in &children {
        lines.push(Line::new(
            Status::Warning,
            format!("Mark revoked by ancestor, then re-issue: {child}."),
        ));
    }
    s.page.add(&widgets::status_list(&lines));
    // A lost YubiKey's key may be in someone else's hands: "CA compromise" is
    // preselected (the most conservative reason); the operator can choose another.
    let (frame, inner) = widgets::group("Reason");
    let reasons: Vec<&str> = RevocationReason::ALL
        .iter()
        .map(|r| reason_name(*r))
        .collect();
    let reason = widgets::labelled_dropdown(&inner, "_Revocation reason", &reasons);
    if let Some(index) = RevocationReason::ALL
        .iter()
        .position(|r| *r == RevocationReason::CaCompromise)
    {
        reason.set_selected(u32::try_from(index).unwrap_or(0));
    }
    s.page.add(&frame);
    s.page.focus_on(&s.next.clone());
    let app_ref = app.clone();
    let old_serial = old.certificate.serial;
    s.next.connect_clicked(move |_| {
        let Some(reason) = RevocationReason::ALL
            .get(reason.selected() as usize)
            .copied()
        else {
            return;
        };
        unlock_master(
            &app_ref,
            "flow-e-1",
            "flow-e-2",
            move |app, master_passphrase| {
                let plan = ReplaceYubikeyPlan {
                    old_main_intermediate: old_serial,
                    reason,
                    master_passphrase,
                };
                exec::execute(
                    app,
                    "Replacing the lost YubiKey",
                    true,
                    move |backend, ctx| backend.replace_yubikey(ctx, plan),
                );
            },
        );
    });
    app.reset_to("flow-e-1", &s.page.build());
}
