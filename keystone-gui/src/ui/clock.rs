//! Clock confirmation (FR-17 AC1-AC3, SEC-16): the full screen, the "Correct clock
//! baseline" action, and a compact panel for repair and recovery actions.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use gtk::glib;
use gtk::prelude::*;
use keystone_core::clock::{
    ClockAssessment, ClockCorrection, assess_for_log, confirm, future_dated_certificates,
};
use keystone_core::model::Serial;
use keystone_core::store::{AuditEntry, DriveSet};
use time::OffsetDateTime;

use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, flows, home, startup};
use crate::backend::ClockConfirmation;
use crate::vm::clock::{ClockView, TimeSource, parse_entered_time, view};
use crate::vm::home::FlowKind;
use crate::vm::{Line, Status, format_utc};
use crate::worker::gtk_glue;

/// Page ids.
pub const ID: &str = "clock";
const BASELINE_ID: &str = "clock-baseline";

/// Where to go after the time is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// The home screen.
    Home,
    /// Straight into a flow (for example from the CRL warning banner).
    Flow(FlowKind, Option<Serial>),
}

struct Assessed {
    assessment: ClockAssessment,
    source: TimeSource,
    at: Instant,
}

impl Assessed {
    fn system(entries: &[AuditEntry]) -> Self {
        Assessed {
            assessment: assess_for_log(OffsetDateTime::now_utc(), entries),
            source: TimeSource::System,
            at: Instant::now(),
        }
    }

    fn view(&self) -> ClockView {
        view(&self.assessment, self.source)
    }

    fn confirmation(&self, ticked: bool) -> Option<ClockConfirmation> {
        confirm(&self.assessment, ticked)
            .ok()
            .map(|confirmed| ClockConfirmation {
                confirmed,
                at: self.at,
            })
    }
}

fn audit_entries(app: &App) -> Vec<AuditEntry> {
    app.session
        .borrow()
        .startup
        .as_ref()
        .map(|startup| startup.0.audit_entries.clone())
        .unwrap_or_default()
}

/// The local time, for the operator's convenience (Keystone itself works in UTC).
fn local_text(time: OffsetDateTime) -> Option<String> {
    let local = glib::DateTime::from_unix_local(time.unix_timestamp()).ok()?;
    local
        .format("%Y-%m-%d %H:%M:%S %Z")
        .ok()
        .map(|text| format!("Local time: {text}"))
}

/// Shows the clock confirmation screen.
pub fn show(app: &Rc<App>, next: Next) {
    let entries = audit_entries(app);
    let state = Rc::new(RefCell::new(Assessed::system(&entries)));
    let mut page = PageBuilder::new(
        "Confirm the date and time",
        Some(
            "Keystone uses this time for every signature and every audit entry. Check it against a watch or a phone that is not connected to this laptop.",
        ),
    );
    let time_label = gtk::Label::new(None);
    time_label.add_css_class("title-2");
    time_label.set_xalign(0.0);
    time_label.set_selectable(true);
    page.add(&time_label);
    let local_label = widgets::paragraph("");
    page.add(&local_label);
    let lines = gtk::Box::new(gtk::Orientation::Vertical, 6);
    page.add(&lines);
    let tick = gtk::CheckButton::with_label("I confirm that this date and time is correct");
    page.add(&tick);

    let (frame, inner) = widgets::group("Enter the correct time instead");
    inner.append(&widgets::paragraph(
        "If the system clock is wrong, correct it in the system settings and press Check the system time again, or type the correct time here. Keystone never changes the system clock.",
    ));
    let date = widgets::labelled_entry(&inner, "_Date in UTC (YYYY-MM-DD)");
    let time_entry = widgets::labelled_entry(&inner, "T_ime in UTC (HH:MM or HH:MM:SS)");
    let use_time = gtk::Button::with_label("Use the time I entered");
    use_time.set_halign(gtk::Align::Start);
    inner.append(&use_time);
    let entered_problem = StatusLine::new(&Line::new(Status::Info, ""));
    entered_problem.set_visible(false);
    inner.append(entered_problem.widget());
    page.add(&frame);

    let baseline = gtk::Button::with_label("Correct clock baseline…");
    baseline.set_halign(gtk::Align::Start);
    page.add(&baseline);

    let back = page.secondary_button("_Back");
    let again = page.secondary_button("Check the system _time again");
    let confirm_button = page.primary_button("C_onfirm date and time");

    let refresh: Rc<dyn Fn()> = {
        let state = state.clone();
        let time_label = time_label.clone();
        let local_label = local_label.clone();
        let lines = lines.clone();
        let tick = tick.clone();
        let confirm_button = confirm_button.clone();
        let baseline = baseline.clone();
        let has_entries = !entries.is_empty();
        Rc::new(move || {
            let assessed = state.borrow();
            let v = assessed.view();
            time_label.set_text(&v.time_text);
            local_label.set_text(&local_text(assessed.assessment.now).unwrap_or_default());
            widgets::set_status_list(&lines, &v.lines);
            tick.set_visible(v.needs_explicit_confirmation);
            if !v.needs_explicit_confirmation {
                tick.set_active(false);
            }
            confirm_button.set_sensitive(v.can_confirm(tick.is_active()));
            baseline.set_visible(v.offer_baseline_correction && has_entries);
        })
    };
    refresh();
    let r = refresh.clone();
    tick.connect_toggled(move |_| r());
    {
        let state = state.clone();
        let entries = entries.clone();
        let r = refresh.clone();
        again.connect_clicked(move |_| {
            *state.borrow_mut() = Assessed::system(&entries);
            r();
        });
    }
    {
        let state = state.clone();
        let entries = entries.clone();
        let r = refresh.clone();
        let date = date.clone();
        let time_entry = time_entry.clone();
        use_time.connect_clicked(move |_| {
            match parse_entered_time(&date.text(), &time_entry.text()) {
                Ok(entered) => {
                    entered_problem.set_visible(false);
                    *state.borrow_mut() = Assessed {
                        assessment: assess_for_log(entered, &entries),
                        source: TimeSource::Entered,
                        at: Instant::now(),
                    };
                    r();
                }
                Err(problem) => {
                    entered_problem.set(&Line::new(Status::Blocked, problem));
                    entered_problem.set_visible(true);
                }
            }
        });
    }
    {
        let app = app.clone();
        baseline.connect_clicked(move |_| show_baseline(&app, next));
    }
    {
        let app = app.clone();
        back.connect_clicked(move |_| startup::show(&app));
    }
    {
        let app = app.clone();
        let state = state.clone();
        let tick = tick.clone();
        confirm_button.connect_clicked(move |_| {
            let Some(confirmation) = state.borrow().confirmation(tick.is_active()) else {
                return;
            };
            app.session.borrow_mut().clock = Some(confirmation);
            app.toast(&format!(
                "Time confirmed: {}",
                format_utc(confirmation.confirmed.get().get())
            ));
            match next {
                Next::Home => home::show(&app),
                Next::Flow(flow, serial) => flows::start(&app, flow, serial),
            }
        });
    }
    page.focus_on(&confirm_button);
    let page = page.build();
    app.push(ID, &page);
    // Focus the first sensible control when Confirm is not available.
    if !confirm_button.is_sensitive() {
        again.grab_focus();
    }
}

/// FR-17 AC3: Correct clock baseline.
fn show_baseline(app: &Rc<App>, next: Next) {
    let entries = audit_entries(app);
    let mut page = PageBuilder::new(
        "Correct the clock baseline",
        Some(
            "Use this only if an audit entry was recorded with a wrong future date. Keystone appends a clock-correction entry that records the previous newest time and the time you confirm now. Existing entries are never changed. From then on the clock is checked against the confirmed time and every later entry, so it can never move back past it.",
        ),
    );
    let now = format_utc(OffsetDateTime::now_utc());
    let (frame, inner) = widgets::group("The correct current time");
    let date = widgets::labelled_entry(&inner, "_Date in UTC (YYYY-MM-DD)");
    let time_entry = widgets::labelled_entry(&inner, "T_ime in UTC (HH:MM or HH:MM:SS)");
    if let Some((d, rest)) = now.split_once(' ') {
        date.set_text(d);
        time_entry.set_text(rest.trim_end_matches(" UTC"));
    }
    let check = gtk::Button::with_label("Check this correction");
    check.set_halign(gtk::Align::Start);
    inner.append(&check);
    page.add(&frame);
    let plan_lines = gtk::Box::new(gtk::Orientation::Vertical, 6);
    page.add(&plan_lines);
    let tick = gtk::CheckButton::with_label("I confirm that this is the correct current time");
    tick.set_sensitive(false);
    page.add(&tick);
    let back = page.secondary_button("_Back");
    let record = page.primary_button("_Record the clock correction");
    record.set_sensitive(false);
    let planned: Rc<RefCell<Option<ClockCorrection>>> = Rc::new(RefCell::new(None));
    {
        let planned = planned.clone();
        let tick = tick.clone();
        let record = record.clone();
        let plan_lines = plan_lines.clone();
        check.connect_clicked(move |_| {
            planned.borrow_mut().take();
            tick.set_active(false);
            tick.set_sensitive(false);
            record.set_sensitive(false);
            let lines = match parse_entered_time(&date.text(), &time_entry.text()) {
                Err(problem) => vec![Line::new(Status::Blocked, problem)],
                Ok(confirmed) => match ClockCorrection::plan(
                    &entries,
                    confirmed,
                    keystone_core::build_info::build_date(),
                ) {
                    Err(error) => vec![Line::new(Status::Blocked, error.to_string())],
                    Ok(correction) => {
                        *planned.borrow_mut() = Some(correction);
                        tick.set_sensitive(true);
                        vec![
                            Line::new(
                                Status::Info,
                                format!(
                                    "Newest time in the audit log now: {} (the wrong future date).",
                                    format_utc(correction.previous_newest().get())
                                ),
                            ),
                            Line::new(
                                Status::Info,
                                format!(
                                    "Confirmed current time to record: {}.",
                                    format_utc(correction.confirmed().get())
                                ),
                            ),
                        ]
                    }
                },
            };
            widgets::set_status_list(&plan_lines, &lines);
        });
    }
    {
        let record = record.clone();
        let planned = planned.clone();
        tick.connect_toggled(move |tick| {
            record.set_sensitive(tick.is_active() && planned.borrow().is_some());
        });
    }
    {
        let app = app.clone();
        back.connect_clicked(move |_| show(&app, next));
    }
    {
        let app = app.clone();
        record.connect_clicked(move |button| {
            let Some(correction) = *planned.borrow() else {
                return;
            };
            let Some(selection) = app.drives() else {
                return;
            };
            button.set_sensitive(false);
            let app = app.clone();
            gtk_glue::run(
                "Recording the clock correction",
                false,
                move |_| -> Result<Vec<String>, String> {
                    let set = DriveSet::open(&selection.ca_drives()).map_err(|e| e.to_string())?;
                    correction.record(&set).map_err(|e| e.to_string())?;
                    let record = set.issuance_record().map_err(|e| e.to_string())?;
                    Ok(future_dated_certificates(&record, correction.confirmed())
                        .into_iter()
                        .map(|cert| {
                            format!(
                                "{} (serial {}), valid from {}: revoke and re-issue it.",
                                cert.certificate.subject.display(),
                                cert.certificate.serial,
                                format_utc(cert.certificate.not_before.get())
                            )
                        })
                        .collect())
                },
                |_| {},
                move |result| show_baseline_result(&app, result),
            );
        });
    }
    app.push(BASELINE_ID, &page.build());
}

fn show_baseline_result(
    app: &Rc<App>,
    result: Result<Result<Vec<String>, String>, crate::worker::WorkerFailure>,
) {
    let mut page = PageBuilder::new("Clock baseline", None);
    match result {
        Ok(Ok(future)) => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Ok,
                    "The clock correction was recorded on every drive and read back.",
                ))
                .widget(),
            );
            if future.is_empty() {
                page.add(
                    StatusLine::new(&Line::new(
                        Status::Ok,
                        "No certificate was signed with a future date.",
                    ))
                    .widget(),
                );
            } else {
                page.add(&widgets::heading("Certificates signed with a future date"));
                for line in future {
                    page.add(StatusLine::new(&Line::new(Status::Warning, line)).widget());
                }
            }
        }
        Ok(Err(message)) => {
            page.add(
                StatusLine::new(&Line::new(
                    Status::Blocked,
                    format!("The clock correction was not recorded: {message}"),
                ))
                .widget(),
            );
        }
        Err(failure) => {
            page.add(StatusLine::new(&Line::new(Status::Blocked, failure.to_string())).widget());
        }
    }
    let next = page.primary_button("_Continue to the start-up checks");
    let app_ref = app.clone();
    next.connect_clicked(move |_| startup::show(&app_ref));
    app.reset_to(BASELINE_ID, &page.build());
}

/// A compact clock check for actions that write an audit entry outside a flow (drive
/// repair, recovery). The operator sees the time that will be recorded.
pub struct ClockPanel {
    root: gtk::Box,
    lines: gtk::Box,
    tick: gtk::CheckButton,
    entries: Vec<AuditEntry>,
    state: RefCell<Assessed>,
    listeners: RefCell<Vec<Box<dyn Fn()>>>,
}

impl std::fmt::Debug for ClockPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClockPanel")
    }
}

impl ClockPanel {
    /// A panel checking the system time against `entries`.
    pub fn new(entries: Vec<AuditEntry>, note: &str) -> Rc<ClockPanel> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
        root.append(&widgets::paragraph(note));
        let lines = gtk::Box::new(gtk::Orientation::Vertical, 6);
        root.append(&lines);
        let tick = gtk::CheckButton::with_label("I confirm that this date and time is correct");
        root.append(&tick);
        let again = gtk::Button::with_label("Check the system time again");
        again.set_halign(gtk::Align::Start);
        root.append(&again);
        let state = RefCell::new(Assessed::system(&entries));
        let panel = Rc::new(ClockPanel {
            root,
            lines,
            tick,
            entries,
            state,
            listeners: RefCell::new(Vec::new()),
        });
        panel.refresh();
        let weak = Rc::downgrade(&panel);
        panel.tick.connect_toggled(move |_| {
            if let Some(panel) = weak.upgrade() {
                panel.changed();
            }
        });
        let weak = Rc::downgrade(&panel);
        again.connect_clicked(move |_| {
            if let Some(panel) = weak.upgrade() {
                *panel.state.borrow_mut() = Assessed::system(&panel.entries);
                panel.refresh();
                panel.changed();
            }
        });
        panel
    }

    fn refresh(&self) {
        let v = self.state.borrow().view();
        let mut lines = v.lines.clone();
        if v.blocked {
            lines.push(Line::new(
                Status::Blocked,
                "Correct the system clock, then press Check the system time again.",
            ));
        }
        widgets::set_status_list(&self.lines, &lines);
        self.tick.set_visible(v.needs_explicit_confirmation);
    }

    fn changed(&self) {
        for listener in self.listeners.borrow().iter() {
            listener();
        }
    }

    /// The widget.
    pub fn widget(&self) -> &gtk::Box {
        &self.root
    }

    /// The confirmed time, when the checks pass (and the warning is ticked if shown).
    pub fn confirmation(&self) -> Option<ClockConfirmation> {
        self.state.borrow().confirmation(self.tick.is_active())
    }

    /// Calls `listener` whenever the confirmation may have changed.
    pub fn connect_changed(&self, listener: impl Fn() + 'static) {
        self.listeners.borrow_mut().push(Box::new(listener));
    }
}
