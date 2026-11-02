//! The home screen: choose a flow (PRD section 6), see CRL warnings (FR-13 AC3) and
//! open the issuance record (FR-11 AC2).
#![forbid(unsafe_code)]

use std::rc::Rc;

use gtk::prelude::*;
use keystone_core::store::IssuanceRecord;
use time::OffsetDateTime;

use super::widgets::{self, PageBuilder, StatusLine};
use super::{App, drives, flows, record, startup};
use crate::vm::drives::DriveMode;
use crate::vm::home::{CaState, FlowKind, availability};
use crate::vm::{Line, Status, format_utc};

/// Page id.
pub const ID: &str = "home";

/// Shows the home screen.
pub fn show(app: &Rc<App>) {
    let mut page = PageBuilder::new("What do you want to do?", None);
    let session = app.session.borrow();
    let new_ca = matches!(session.mode, Some(DriveMode::NewCa));
    let startup = session.startup.clone();
    let clock = session.clock;
    drop(session);
    if let Some(clock) = clock {
        page.add(
            StatusLine::new(&Line::new(
                Status::Ok,
                format!(
                    "Time confirmed for the next action: {}.",
                    format_utc(clock.confirmed.get().get())
                ),
            ))
            .widget(),
        );
    }
    let record = startup
        .as_ref()
        .and_then(|s| s.0.record.clone())
        .and_then(Result::ok)
        .unwrap_or_else(IssuanceRecord::empty);
    if let Some(startup) = &startup {
        for warning in &startup.1.crl_warnings {
            let (banner, button) = widgets::banner(
                &Line::new(warning.status, warning.text.clone()),
                "_Refresh CRL…",
            );
            let app_ref = app.clone();
            let issuer = warning.issuer;
            button.connect_clicked(move |_| {
                flows::start(&app_ref, FlowKind::RefreshCrl, Some(issuer))
            });
            page.add(&banner);
        }
    }
    let state = if new_ca {
        CaState::NewCa
    } else {
        CaState::Existing {
            record: &record,
            blocked: None,
        }
    };
    let (frame, inner) = widgets::group("Actions");
    let mut first: Option<gtk::Button> = None;
    for item in availability(state, OffsetDateTime::now_utc()) {
        let row = gtk::Box::new(gtk::Orientation::Vertical, 4);
        let button = gtk::Button::with_label(item.flow.label());
        button.set_halign(gtk::Align::Start);
        row.append(&button);
        row.append(&widgets::paragraph(item.flow.summary()));
        match &item.unavailable {
            Some(reason) => {
                button.set_sensitive(false);
                row.append(StatusLine::new(&Line::new(Status::Info, reason.clone())).widget());
            }
            None => {
                if first.is_none() {
                    first = Some(button.clone());
                }
                let app_ref = app.clone();
                let flow = item.flow;
                button.connect_clicked(move |_| flows::start(&app_ref, flow, None));
            }
        }
        row.set_margin_bottom(6);
        inner.append(&row);
    }
    page.add(&frame);
    let (frame, inner) = widgets::group("Records");
    let open_record = gtk::Button::with_label("Issuance record");
    open_record.set_halign(gtk::Align::Start);
    open_record.set_sensitive(!new_ca);
    inner.append(&open_record);
    inner.append(&widgets::paragraph(
        "Every certificate Keystone signed, with its status, fingerprint and permitted names.",
    ));
    let app_ref = app.clone();
    open_record.connect_clicked(move |_| record::show(&app_ref));
    page.add(&frame);
    let choose = page.secondary_button("C_hoose other drives");
    let app_ref = app.clone();
    choose.connect_clicked(move |_| drives::show(&app_ref));
    let checks = page.secondary_button("_Start-up checks");
    let app_ref = app.clone();
    checks.connect_clicked(move |_| startup::show(&app_ref));
    if let Some(first) = first {
        page.focus_on(&first);
    }
    app.reset_to(ID, &page.build());
}
